use std::sync::Arc;

use bytes::Bytes;
use h2::RecvStream;
use http::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::{debug, info, warn};

use crate::store::{self, AppRepository};

const RESPONSE_USER_HEADERS: &str = "cf-cloudflared-response-headers";
const RESPONSE_META_HEADER: &str = "cf-cloudflared-response-meta";
const RESPONSE_META_ORIGIN: &str = r#"{"src":"origin"}"#;

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
        if should_strip_incoming_header(name_str) {
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

    // Let the backend know the original tunnel host and protocol
    let original_host = parts
        .uri
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            parts
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| local_host.to_string());
    append_forwarding_headers(&mut local_req, &original_host, &parts.headers);

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
            let msg = format!("Bad Gateway: {err}");
            let response = http::Response::builder()
                .status(502)
                .header("content-type", "text/plain")
                .body(())
                .unwrap();
            let mut send_stream = send_response.send_response(response, false)?;
            send_stream.send_data(Bytes::from(msg), true)?;
            return Ok(());
        }
    };

    send_proxied_response(local_resp, send_response).await?;

    info!(local_host = %local_host, "fixed-host tunnel response sent");
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

    // In HTTP/2, the host is in the :authority pseudo-header (mapped to URI authority),
    // not the "host" header. Check URI authority first, then fall back to host header.
    let original_host = parts
        .uri
        .authority()
        .map(|a| a.as_str())
        .or_else(|| parts.headers.get("host").and_then(|v| v.to_str().ok()))
        .unwrap_or(tunnel_domain);

    let local_host = map_tunnel_host_to_local(original_host, tunnel_domain, local_suffix);

    // Check tunnel access: extract domain prefix and verify the app allows tunnel access.
    // Apps with tunnel_mode "global", "quick", or "named" are allowed.
    // Apps with tunnel_mode "none" are not exposed through the tunnel.
    let domain_prefix = store::domain_to_db(&local_host, local_suffix);
    let exposed = match app_store.is_tunnel_exposed(&domain_prefix) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                original_host = %original_host,
                domain_prefix = %domain_prefix,
                error = %e,
                "is_tunnel_exposed query failed, denying access"
            );
            false
        }
    };
    if !exposed {
        debug!(
            original_host = %original_host,
            domain_prefix = %domain_prefix,
            "tunnel access denied: app not found or tunnel_mode is off"
        );
        let response = http::Response::builder()
            .status(403)
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        let mut send_stream = send_response.send_response(response, false)?;
        send_stream.send_data(Bytes::from("403 Forbidden: app not exposed via tunnel"), true)?;
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
    // Strip hop-by-hop, CF internal, and client-supplied forwarding headers
    // to prevent header spoofing — we set trusted values below.
    for (name, value) in &parts.headers {
        let name_str = name.as_str();
        if should_strip_incoming_header(name_str) {
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

    // Let the backend know the original tunnel host and protocol
    append_forwarding_headers(&mut local_req, original_host, &parts.headers);

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
            let msg = format!("Bad Gateway: {err}");
            let response = http::Response::builder()
                .status(502)
                .header("content-type", "text/plain")
                .body(())
                .unwrap();
            let mut send_stream = send_response.send_response(response, false)?;
            send_stream.send_data(Bytes::from(msg), true)?;
            return Ok(());
        }
    };

    send_proxied_response(local_resp, send_response).await?;

    info!(local_host = %local_host, "named tunnel response sent");
    Ok(())
}

/// Headers that must be stripped from incoming tunnel requests before
/// forwarding to the local backend. We set trusted values for these
/// ourselves — keeping client-supplied values would allow spoofing.
fn should_strip_incoming_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-real-ip"
            | "forwarded"
    ) || name.starts_with(':')
        || name.starts_with("cf-cloudflared-")
        || name == "cf-ray"
}

/// Append standard forwarding headers so the backend knows the original
/// tunnel host, protocol, and client IP.
fn append_forwarding_headers(
    builder: &mut http::request::Builder,
    original_host: &str,
    incoming_headers: &http::HeaderMap,
) {
    *builder = std::mem::take(builder)
        .header("x-forwarded-host", original_host)
        .header("x-forwarded-proto", "https");

    // Propagate client IP from Cloudflare headers
    if let Some(ip) = incoming_headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
    {
        *builder = std::mem::take(builder)
            .header("x-forwarded-for", ip)
            .header("x-real-ip", ip);
    }
}

/// Forward an HTTP/1.1 response from the local proxy back over the h2 tunnel stream.
/// Strips hop-by-hop headers forbidden in HTTP/2.
async fn send_proxied_response(
    local_resp: hyper::Response<hyper::body::Incoming>,
    mut send_response: h2::server::SendResponse<Bytes>,
) -> anyhow::Result<()> {
    use http_body_util::BodyExt;

    let (resp_parts, resp_body) = local_resp.into_parts();

    let mut response = http::Response::builder().status(resp_parts.status);
    let mut user_headers = http::HeaderMap::new();
    for (name, value) in &resp_parts.headers {
        let n = name.as_str().to_ascii_lowercase();
        if n == "content-length" {
            // cloudflared keeps content-length as an h2 header.
            response = response.header(name, value);
            continue;
        }
        if !is_control_response_header(&n) || is_websocket_client_header(&n) {
            user_headers.append(name.clone(), value.clone());
        }
    }
    let serialized_user_headers = serialize_headers(&user_headers);
    response = response
        .header(RESPONSE_USER_HEADERS, serialized_user_headers)
        .header(RESPONSE_META_HEADER, RESPONSE_META_ORIGIN);
    let response = response.body(()).unwrap();
    let mut send_stream = send_response.send_response(response, false)?;

    let mut body = resp_body;
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            send_stream.send_data(data.clone(), false)?;
        }
    }
    send_stream.send_data(Bytes::new(), true)?;

    Ok(())
}

fn is_control_response_header(name: &str) -> bool {
    name.starts_with(':')
        || name.starts_with("cf-int-")
        || name.starts_with("cf-cloudflared-")
        || name.starts_with("cf-proxy-")
}

fn is_websocket_client_header(name: &str) -> bool {
    matches!(name, "sec-websocket-accept" | "connection" | "upgrade")
}

fn serialize_headers(headers: &http::HeaderMap) -> String {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let mut out = String::new();
    for (name, value) in headers {
        let value_bytes = value.as_bytes();
        let enc_name = engine.encode(name.as_str().as_bytes());
        let enc_value = engine.encode(value_bytes);
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(&enc_name);
        out.push(':');
        out.push_str(&enc_value);
    }
    out
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
