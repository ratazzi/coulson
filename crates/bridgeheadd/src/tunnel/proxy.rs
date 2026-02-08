use std::sync::Arc;

use bytes::Bytes;
use h2::RecvStream;
use http::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::{debug, info, warn};

use crate::store::{self, AppRepository};

/// Proxy an HTTP request to the local Pingora proxy with a fixed Host header.
/// Used for per-app tunnels where the backend is not a TCP port (e.g. static_dir, managed).
pub async fn proxy_to_local_with_host(
    request: Request<RecvStream>,
    mut send_response: h2::server::SendResponse<Bytes>,
    local_proxy_port: u16,
    local_host: &str,
) -> anyhow::Result<()> {
    let (parts, mut body) = request.into_parts();

    let uri = format!(
        "http://127.0.0.1:{}{}",
        local_proxy_port,
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    info!(
        local_host = %local_host,
        uri = %uri,
        method = %parts.method,
        "proxying tunnel request with fixed host"
    );

    let mut local_req = http::Request::builder()
        .method(parts.method.clone())
        .uri(&uri);

    for (name, value) in &parts.headers {
        let name_str = name.as_str();
        if matches!(
            name_str,
            "host" | "content-length" | "transfer-encoding" | "connection"
        ) || name_str.starts_with(':')
            || name_str.starts_with("cf-cloudflared-")
            || name_str == "cf-ray"
        {
            continue;
        }
        let val_bytes = value.as_bytes();
        if val_bytes
            .iter()
            .any(|&b| b == b'\r' || b == b'\n' || b == b'\0')
        {
            debug!(header = %name_str, "skipping header with invalid HTTP/1.1 value bytes");
            continue;
        }
        local_req = local_req.header(name, value);
    }
    local_req = local_req.header("host", local_host);

    let mut body_bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        body_bytes.extend_from_slice(&chunk);
    }

    let local_req = local_req.body(http_body_util::Full::new(Bytes::from(body_bytes)))?;

    let client = Client::builder(TokioExecutor::new()).build_http();
    let local_resp = match client.request(local_req).await {
        Ok(resp) => resp,
        Err(err) => {
            warn!(error = %err, local_host = %local_host, "local proxy request failed");
            let response = http::Response::builder()
                .status(502)
                .body(())
                .unwrap();
            let mut send_stream = send_response.send_response(response, false)?;
            let msg = format!("Bad Gateway: {err}");
            send_stream.send_data(Bytes::from(msg), true)?;
            return Ok(());
        }
    };

    let (resp_parts, resp_body) = local_resp.into_parts();

    let mut response = http::Response::builder().status(resp_parts.status);
    for (name, value) in &resp_parts.headers {
        let n = name.as_str();
        if matches!(
            n,
            "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "upgrade"
        ) {
            continue;
        }
        response = response.header(name, value);
    }

    let response = response.body(()).unwrap();
    let mut send_stream = send_response.send_response(response, false)?;

    use http_body_util::BodyExt;
    let mut body_stream = resp_body;
    while let Some(frame) = body_stream.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            send_stream.send_data(data.clone(), false)?;
        }
    }

    send_stream.send_data(Bytes::new(), true)?;

    info!(status = %resp_parts.status, local_host = %local_host, "fixed-host tunnel response sent");
    Ok(())
}

/// Map a tunnel Host header to a local Pingora Host.
/// e.g. "myapp.dev.example.com" with tunnel_domain "dev.example.com" → "myapp"
/// Bare domain "dev.example.com" → "default"
pub fn map_tunnel_host_to_local(host: &str, tunnel_domain: &str, local_suffix: &str) -> String {
    // Strip port if present
    let host_no_port = host.split(':').next().unwrap_or(host);

    let suffix = format!(".{tunnel_domain}");
    if let Some(prefix) = host_no_port.strip_suffix(&suffix) {
        if prefix.is_empty() {
            format!("default.{local_suffix}")
        } else {
            format!("{prefix}.{local_suffix}")
        }
    } else if host_no_port == tunnel_domain {
        format!("default.{local_suffix}")
    } else {
        // Unknown host, forward as-is with local suffix
        format!("default.{local_suffix}")
    }
}

/// Proxy an HTTP request by mapping the Host header to a local Pingora host.
pub async fn proxy_by_host(
    request: Request<RecvStream>,
    mut send_response: h2::server::SendResponse<Bytes>,
    tunnel_domain: &str,
    local_suffix: &str,
    local_proxy_port: u16,
    app_store: &Arc<AppRepository>,
) -> anyhow::Result<()> {
    let (parts, mut body) = request.into_parts();

    let original_host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(tunnel_domain);

    let local_host = map_tunnel_host_to_local(original_host, tunnel_domain, local_suffix);

    // Check tunnel_exposed: extract domain prefix and verify it's allowed
    let domain_prefix = store::domain_to_db(&local_host, local_suffix);
    let exposed = app_store.is_tunnel_exposed(&domain_prefix).unwrap_or(false);
    if !exposed {
        warn!(
            original_host = %original_host,
            domain_prefix = %domain_prefix,
            "tunnel access denied: app not exposed"
        );
        let response = http::Response::builder()
            .status(403)
            .body(())
            .unwrap();
        let mut send_stream = send_response.send_response(response, false)?;
        send_stream.send_data(Bytes::from("403 Forbidden"), true)?;
        return Ok(());
    }

    let uri = format!(
        "http://127.0.0.1:{}{}",
        local_proxy_port,
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    info!(
        original_host = %original_host,
        local_host = %local_host,
        uri = %uri,
        method = %parts.method,
        "proxying named tunnel request"
    );

    let mut local_req = http::Request::builder()
        .method(parts.method.clone())
        .uri(&uri);

    // Forward headers, replacing Host with local mapping.
    // Skip hop-by-hop headers, CF internal headers, and headers with values
    // invalid for HTTP/1.1 (e.g. containing \r, \n, or \0 from HTTP/2).
    for (name, value) in &parts.headers {
        let name_str = name.as_str();
        if matches!(
            name_str,
            "host" | "content-length" | "transfer-encoding" | "connection"
        ) || name_str.starts_with(':')
            || name_str.starts_with("cf-cloudflared-")
            || name_str == "cf-ray"
        {
            continue;
        }
        // HTTP/2 allows header values that HTTP/1.1 rejects (control chars).
        // Validate before forwarding to avoid hyper "malformed headers" error.
        let val_bytes = value.as_bytes();
        if val_bytes
            .iter()
            .any(|&b| b == b'\r' || b == b'\n' || b == b'\0')
        {
            debug!(header = %name_str, "skipping header with invalid HTTP/1.1 value bytes");
            continue;
        }
        local_req = local_req.header(name, value);
    }
    local_req = local_req.header("host", &local_host);

    // Collect body
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        body_bytes.extend_from_slice(&chunk);
    }

    let local_req = local_req.body(http_body_util::Full::new(Bytes::from(body_bytes)))?;

    let client = Client::builder(TokioExecutor::new()).build_http();
    let local_resp = match client.request(local_req).await {
        Ok(resp) => resp,
        Err(err) => {
            warn!(error = %err, local_host = %local_host, "local proxy request failed");
            let response = http::Response::builder()
                .status(502)
                .body(())
                .unwrap();
            let mut send_stream = send_response.send_response(response, false)?;
            let msg = format!("Bad Gateway: {err}");
            send_stream.send_data(Bytes::from(msg), true)?;
            return Ok(());
        }
    };

    let (resp_parts, resp_body) = local_resp.into_parts();

    // Filter HTTP/1.1 hop-by-hop headers that are forbidden in HTTP/2
    let mut response = http::Response::builder().status(resp_parts.status);
    for (name, value) in &resp_parts.headers {
        let n = name.as_str();
        if matches!(
            n,
            "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "upgrade"
        ) {
            continue;
        }
        response = response.header(name, value);
    }

    let response = response.body(()).unwrap();
    let mut send_stream = send_response.send_response(response, false)?;

    use http_body_util::BodyExt;
    let mut body_stream = resp_body;
    while let Some(frame) = body_stream.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            send_stream.send_data(data.clone(), false)?;
        }
    }

    send_stream.send_data(Bytes::new(), true)?;

    info!(status = %resp_parts.status, local_host = %local_host, "named tunnel response sent");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_tunnel_host_to_local() {
        // Subdomain mapping
        assert_eq!(
            map_tunnel_host_to_local("myapp.dev.example.com", "dev.example.com", "test"),
            "myapp.test"
        );

        // Nested subdomain
        assert_eq!(
            map_tunnel_host_to_local("api.myapp.dev.example.com", "dev.example.com", "test"),
            "api.myapp.test"
        );

        // Bare domain → default
        assert_eq!(
            map_tunnel_host_to_local("dev.example.com", "dev.example.com", "test"),
            "default.test"
        );

        // With port
        assert_eq!(
            map_tunnel_host_to_local("myapp.dev.example.com:443", "dev.example.com", "test"),
            "myapp.test"
        );

        // Unknown host → default
        assert_eq!(
            map_tunnel_host_to_local("unknown.other.com", "dev.example.com", "test"),
            "default.test"
        );
    }
}
