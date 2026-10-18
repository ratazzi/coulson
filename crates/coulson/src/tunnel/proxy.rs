use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use h2::RecvStream;
use http::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::domain::{AppSpec, BackendTarget};
use crate::store::{self, AppRepository};

const RESPONSE_USER_HEADERS: &str = "cf-cloudflared-response-headers";
const RESPONSE_META_HEADER: &str = "cf-cloudflared-response-meta";
const RESPONSE_META_ORIGIN: &str = r#"{"src":"origin"}"#;
/// Over h2 the edge drops the hop-by-hop `Connection`/`Upgrade` headers and
/// flags WebSocket streams with this internal header instead.
const UPGRADE_HEADER: &str = "cf-cloudflared-proxy-connection-upgrade";

/// Sources needed to locate an app route and read that app's config file.
/// The store identifies the app only; config values are never copied into it.
#[derive(Clone)]
pub struct AppConfigSource {
    pub(crate) store: Arc<AppRepository>,
    apps_root: PathBuf,
}

impl AppConfigSource {
    pub fn new(store: Arc<AppRepository>, apps_root: PathBuf) -> Self {
        Self { store, apps_root }
    }
}

/// Internal marker header injected by the tunnel proxy so the Pingora proxy
/// can distinguish tunnel requests from local/LAN requests. Basic auth is
/// only enforced when this header is present. Stripped before forwarding to
/// the backend.
pub const VIA_TUNNEL_HEADER: &str = "x-coulson-via-tunnel";

/// Maximum request body buffered per tunnel request before returning 413.
/// Tunnel bodies are fully buffered in memory before being forwarded to the
/// local proxy, so this caps the peak memory a single (or many concurrent)
/// uploads can consume and prevents an unbounded-upload OOM of the daemon.
///
/// Configured via `CoulsonConfig::max_tunnel_body_mb` (toml `max_tunnel_body_mb`
/// / env `COULSON_MAX_TUNNEL_BODY_MB`) and pushed here once at daemon startup by
/// [`set_max_tunnel_request_body`]. The default (100 MiB) applies until then, so
/// paths that never call the setter (e.g. CLI quick tunnels) stay bounded.
static MAX_TUNNEL_REQUEST_BODY: AtomicUsize = AtomicUsize::new(100 * 1024 * 1024);

/// Set the per-request tunnel body cap (bytes). Called once at daemon startup
/// from the loaded `CoulsonConfig`.
pub fn set_max_tunnel_request_body(bytes: usize) {
    MAX_TUNNEL_REQUEST_BODY.store(bytes, Ordering::Relaxed);
}

#[derive(Default, Deserialize)]
struct ForwardedHostConfig {
    #[serde(default)]
    trusted_forwarded_hosts: Vec<String>,
}

/// Locate the source `.coulson.toml` for an app without copying any of its
/// values into `AppSpec` or SQLite.
pub fn config_path_for_app(app: &AppSpec, apps_root: &Path) -> Option<PathBuf> {
    config_path_for_source(&app.target, app.fs_entry.as_deref(), apps_root)
}

fn config_path_for_source(
    target: &BackendTarget,
    fs_entry: Option<&str>,
    apps_root: &Path,
) -> Option<PathBuf> {
    if let BackendTarget::Managed { root, .. } = target {
        return Some(Path::new(root).join(".coulson.toml"));
    }

    if let Some(fs_entry) = fs_entry {
        let entry = apps_root.join(fs_entry);
        match fs::metadata(&entry) {
            Ok(metadata) if metadata.is_dir() => return Some(entry.join(".coulson.toml")),
            Ok(metadata) if metadata.is_file() => {
                let target_is_toml = fs::canonicalize(&entry)
                    .ok()
                    .and_then(|path| path.extension().map(|ext| ext == "toml"))
                    .unwrap_or(false);
                return target_is_toml.then_some(entry);
            }
            Ok(_) => return None,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // A directory entry can disappear while an app is restarting.
                // Keep its conventional path so a recreated config is picked up.
                return Some(entry.join(".coulson.toml"));
            }
            Err(_) => return None,
        }
    }

    match target {
        BackendTarget::StaticDir { root } => Some(Path::new(root).join(".coulson.toml")),
        _ => None,
    }
}

/// Read the forwarded-host allowlist directly from the app config. Callers
/// invoke this for each tunnel request, so a restarted app observes the latest
/// `.coulson.toml` without a database update or daemon restart.
pub fn load_trusted_forwarded_hosts(config_path: Option<&Path>) -> anyhow::Result<Vec<String>> {
    let Some(path) = config_path else {
        return Ok(Vec::new());
    };
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(
                anyhow::Error::new(err).context(format!("failed to read {}", path.display()))
            )
        }
    };
    let config: ForwardedHostConfig =
        toml::from_str(&raw).with_context(|| format!("invalid TOML in {}", path.display()))?;
    Ok(config.trusted_forwarded_hosts)
}

/// True if `host` (port stripped, case-insensitive) matches any pattern.
/// `*.example.com` matches exactly one leading DNS label.
fn host_matches(host: &str, patterns: &[String]) -> bool {
    let Ok(authority) = host.parse::<http::uri::Authority>() else {
        return false;
    };
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    patterns.iter().any(|pattern| {
        let pattern = pattern.to_ascii_lowercase();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            match host.split_once('.') {
                Some((label, rest)) => !label.is_empty() && rest == suffix,
                None => false,
            }
        } else {
            host == pattern
        }
    })
}

/// Read the full h2 request body into memory, enforcing the configured
/// [`MAX_TUNNEL_REQUEST_BODY`] cap. Returns `Ok(None)` if the body exceeds it
/// (the caller should respond `413 Payload Too Large`). Flow-control capacity is
/// released as chunks arrive, matching the unbounded path's backpressure.
async fn collect_body_capped(body: &mut RecvStream) -> anyhow::Result<Option<Bytes>> {
    let max = MAX_TUNNEL_REQUEST_BODY.load(Ordering::Relaxed);
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        if body_bytes.len() + chunk.len() > max {
            return Ok(None);
        }
        body_bytes.extend_from_slice(&chunk);
    }
    Ok(Some(Bytes::from(body_bytes)))
}

/// Send a `413 Payload Too Large` response on the h2 stream.
fn send_payload_too_large(
    send_response: &mut h2::server::SendResponse<Bytes>,
) -> anyhow::Result<()> {
    let response = http::Response::builder()
        .status(413)
        .header("content-type", "text/plain")
        .body(())
        .unwrap();
    let mut send_stream = send_response.send_response(response, false)?;
    send_stream.send_data(Bytes::from_static(b"Payload Too Large"), true)?;
    Ok(())
}

/// Proxy an HTTP request to the local Pingora proxy with a fixed Host header.
/// Used for per-app tunnels where the backend is not a TCP port (e.g. static_dir, managed).
pub async fn proxy_to_local_with_host(
    request: Request<RecvStream>,
    mut send_response: h2::server::SendResponse<Bytes>,
    local_proxy_port: u16,
    local_host: &str,
    trusted_forwarded_hosts: &[String],
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
    local_req = local_req.header(VIA_TUNNEL_HEADER, "1");

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
    append_forwarding_headers(
        &mut local_req,
        &original_host,
        &parts.headers,
        trusted_forwarded_hosts,
    );

    if is_websocket_request(&parts.headers) {
        return proxy_websocket(local_req, body, send_response, local_proxy_port, local_host).await;
    }

    let body_bytes = match collect_body_capped(&mut body).await? {
        Some(b) => b,
        None => {
            warn!(local_host = %local_host, max = MAX_TUNNEL_REQUEST_BODY.load(Ordering::Relaxed), "tunnel request body exceeds cap; returning 413");
            send_payload_too_large(&mut send_response)?;
            return Ok(());
        }
    };

    let local_req = local_req.body(http_body_util::Full::new(body_bytes))?;

    let client = Client::builder(TokioExecutor::new()).build_http();
    let local_resp = match client.request(local_req).await {
        Ok(resp) => resp,
        Err(err) => {
            warn!(error = %err, local_host = %local_host, "local proxy request failed");
            return send_bad_gateway(&mut send_response, format!("Bad Gateway: {err}"));
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
    app_configs: &AppConfigSource,
    share_authorized: bool,
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
    let domain_prefix = store::domain_to_db(&local_host, local_suffix);

    // Check tunnel access: extract domain prefix and verify the app allows tunnel access.
    // Apps with tunnel_mode "global", "quick", or "named" are allowed.
    // Apps with tunnel_mode "none" are not exposed through the tunnel.
    // Skip this check if the request was already authorized via share auth.
    if !share_authorized {
        let exposed = match app_configs.store.is_tunnel_exposed(&domain_prefix) {
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
            send_stream.send_data(
                Bytes::from("403 Forbidden: app not exposed via tunnel"),
                true,
            )?;
            return Ok(());
        }
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
    local_req = local_req.header(VIA_TUNNEL_HEADER, "1");

    // Resolve the longest matching route, then read that app's source config.
    // A failed lookup/read/parse is fail-closed: the client-supplied header is
    // ignored. The value is never persisted in SQLite or AppSpec.
    let trusted_forwarded_hosts = match app_configs
        .store
        .get_enabled_by_route(&domain_prefix, parts.uri.path())
    {
        Ok(Some(app)) => {
            let config_path = config_path_for_app(&app, &app_configs.apps_root);
            match load_trusted_forwarded_hosts(config_path.as_deref()) {
                Ok(patterns) => patterns,
                Err(err) => {
                    warn!(
                        app_id = app.id.0,
                        original_host = %original_host,
                        error = %err,
                        "failed to read app trusted forwarded hosts; ignoring incoming header"
                    );
                    Vec::new()
                }
            }
        }
        Ok(None) => Vec::new(),
        Err(err) => {
            warn!(
                original_host = %original_host,
                domain_prefix = %domain_prefix,
                error = %err,
                "failed to resolve app config; ignoring incoming header"
            );
            Vec::new()
        }
    };

    // Let the backend know the original tunnel host and protocol.
    append_forwarding_headers(
        &mut local_req,
        original_host,
        &parts.headers,
        &trusted_forwarded_hosts,
    );

    if is_websocket_request(&parts.headers) {
        return proxy_websocket(
            local_req,
            body,
            send_response,
            local_proxy_port,
            &local_host,
        )
        .await;
    }

    // Collect body (capped to bound peak memory)
    let body_bytes = match collect_body_capped(&mut body).await? {
        Some(b) => b,
        None => {
            warn!(local_host = %local_host, max = MAX_TUNNEL_REQUEST_BODY.load(Ordering::Relaxed), "tunnel request body exceeds cap; returning 413");
            send_payload_too_large(&mut send_response)?;
            return Ok(());
        }
    };

    let local_req = local_req.body(http_body_util::Full::new(body_bytes))?;

    let client = Client::builder(TokioExecutor::new()).build_http();
    let local_resp = match client.request(local_req).await {
        Ok(resp) => resp,
        Err(err) => {
            warn!(error = %err, local_host = %local_host, "local proxy request failed");
            return send_bad_gateway(&mut send_response, format!("Bad Gateway: {err}"));
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
    trusted_forwarded_hosts: &[String],
) {
    // Trust the incoming x-forwarded-host only when it matches this app's
    // allowlist; the tunnel domain is publicly reachable, so anything else is
    // client-forgeable.
    let forwarded_host = incoming_headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .filter(|v| host_matches(v, trusted_forwarded_hosts))
        .unwrap_or(original_host)
        .to_string();

    *builder = std::mem::take(builder)
        .header("x-forwarded-host", forwarded_host)
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

    let response = tunnel_response_head(resp_parts.status, &resp_parts.headers);
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

/// True if the edge flagged this h2 stream as a WebSocket upgrade.
fn is_websocket_request(headers: &http::HeaderMap) -> bool {
    headers
        .get(UPGRADE_HEADER)
        .is_some_and(|v| v.as_bytes() == b"websocket")
}

fn send_bad_gateway(
    send_response: &mut h2::server::SendResponse<Bytes>,
    msg: String,
) -> anyhow::Result<()> {
    let response = http::Response::builder()
        .status(502)
        .header("content-type", "text/plain")
        .body(())
        .unwrap();
    let mut send_stream = send_response.send_response(response, false)?;
    send_stream.send_data(Bytes::from(msg), true)?;
    Ok(())
}

/// Proxy a WebSocket stream: replay the handshake to the local proxy as an
/// HTTP/1.1 upgrade, then pipe bytes between the h2 stream and the upgraded
/// connection. Mirrors cloudflared, which restores the upgrade headers the
/// edge stripped and answers a 101 with 200 since h2 has no 101.
async fn proxy_websocket(
    local_req: http::request::Builder,
    body: RecvStream,
    mut send_response: h2::server::SendResponse<Bytes>,
    local_proxy_port: u16,
    local_host: &str,
) -> anyhow::Result<()> {
    use http::header::{HeaderValue, CONNECTION, SEC_WEBSOCKET_VERSION, UPGRADE};
    use hyper_util::rt::TokioIo;

    let mut local_req = local_req.body(http_body_util::Empty::<Bytes>::new())?;
    let headers = local_req.headers_mut();
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));

    info!(local_host = %local_host, uri = %local_req.uri(), "proxying tunnel websocket");

    // A dedicated connection: upgraded connections can't go back to a pool.
    let local_resp = async {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", local_proxy_port)).await?;
        tcp.set_nodelay(true)?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                debug!(error = %err, "local websocket connection closed with error");
            }
        });
        anyhow::Ok(sender.send_request(local_req).await?)
    }
    .await;
    let local_resp = match local_resp {
        Ok(resp) => resp,
        Err(err) => {
            warn!(error = %err, local_host = %local_host, "local websocket request failed");
            return send_bad_gateway(&mut send_response, format!("Bad Gateway: {err}"));
        }
    };

    // Origin refused the upgrade (auth challenge, 404, ...): relay as plain HTTP.
    if local_resp.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        return send_proxied_response(local_resp, send_response).await;
    }

    let head = tunnel_response_head(http::StatusCode::OK, local_resp.headers());
    let upgraded = match hyper::upgrade::on(local_resp).await {
        Ok(upgraded) => upgraded,
        Err(err) => {
            warn!(error = %err, local_host = %local_host, "local websocket upgrade failed");
            return send_bad_gateway(&mut send_response, format!("Bad Gateway: {err}"));
        }
    };
    let send_stream = send_response.send_response(head, false)?;

    let mut eyeball = super::rpc::H2Stream::new(body, send_stream);
    let mut origin = TokioIo::new(upgraded);
    match tokio::io::copy_bidirectional(&mut eyeball, &mut origin).await {
        Ok((up, down)) => debug!(local_host = %local_host, up, down, "tunnel websocket closed"),
        Err(err) => {
            debug!(local_host = %local_host, error = %err, "tunnel websocket closed with error")
        }
    }
    Ok(())
}

/// Build the h2 response head the edge expects: user headers serialized into
/// one control header so h1 values bypass h2 header validation.
fn tunnel_response_head(status: http::StatusCode, headers: &http::HeaderMap) -> http::Response<()> {
    let mut response = http::Response::builder().status(status);
    let mut user_headers = http::HeaderMap::new();
    for (name, value) in headers {
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
    response
        .header(RESPONSE_USER_HEADERS, serialized_user_headers)
        .header(RESPONSE_META_HEADER, RESPONSE_META_ORIGIN)
        .body(())
        .unwrap()
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

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coulson-tunnel-{name}-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn trusted_forwarded_hosts_are_reloaded_from_app_config() {
        let dir = temp_test_dir("forwarded-host-reload");
        let config_path = dir.join(".coulson.toml");
        std::fs::write(
            &config_path,
            "trusted_forwarded_hosts = [\"old.example.com\"]\n",
        )
        .unwrap();
        assert_eq!(
            load_trusted_forwarded_hosts(Some(&config_path)).unwrap(),
            vec!["old.example.com"]
        );

        std::fs::write(
            &config_path,
            "trusted_forwarded_hosts = [\"new.example.com\"]\n",
        )
        .unwrap();
        assert_eq!(
            load_trusted_forwarded_hosts(Some(&config_path)).unwrap(),
            vec!["new.example.com"]
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn locates_managed_and_scanned_app_configs() {
        let apps_root = temp_test_dir("config-paths");
        let managed_root = apps_root.join("managed-source");
        let scanned_root = apps_root.join("scanned-app");
        std::fs::create_dir_all(&managed_root).unwrap();
        std::fs::create_dir_all(&scanned_root).unwrap();

        let managed = BackendTarget::Managed {
            app_id: 1,
            root: managed_root.to_string_lossy().to_string(),
            kind: "node".to_string(),
            name: "managed".to_string(),
        };
        assert_eq!(
            config_path_for_source(&managed, None, &apps_root),
            Some(managed_root.join(".coulson.toml"))
        );

        let scanned = BackendTarget::Tcp {
            host: "127.0.0.1".to_string(),
            port: 3000,
        };
        assert_eq!(
            config_path_for_source(&scanned, Some("scanned-app"), &apps_root),
            Some(scanned_root.join(".coulson.toml"))
        );

        std::fs::remove_dir_all(apps_root).unwrap();
    }

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

    #[test]
    fn test_host_matches() {
        let patterns = vec!["app.example.com".to_string(), "*.example.org".to_string()];

        // exact
        assert!(host_matches("app.example.com", &patterns));
        assert!(!host_matches("other.example.com", &patterns));

        // wildcard: exactly one label
        assert!(host_matches("app-sandbox2.example.org", &patterns));
        assert!(!host_matches("a.b.example.org", &patterns));
        assert!(!host_matches("example.org", &patterns));
        // suffix must match whole labels, not substrings
        assert!(!host_matches("app.evil-example.org", &patterns));

        // case-insensitive, port stripped
        assert!(host_matches("APP.Example.COM", &patterns));
        assert!(host_matches("app.example.com:8443", &patterns));
        assert!(host_matches("x.EXAMPLE.ORG", &patterns));

        // empties
        assert!(!host_matches("", &patterns));
        assert!(!host_matches("app.example.com", &[]));
    }

    #[test]
    fn test_append_forwarding_headers_trust_allowlist() {
        fn built_forwarded_host(
            original_host: &str,
            incoming: &http::HeaderMap,
            trusted_forwarded_hosts: &[String],
        ) -> String {
            let mut builder = http::Request::builder().uri("http://127.0.0.1/");
            append_forwarding_headers(
                &mut builder,
                original_host,
                incoming,
                trusted_forwarded_hosts,
            );
            builder
                .headers_ref()
                .unwrap()
                .get("x-forwarded-host")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        }

        let mut incoming = http::HeaderMap::new();
        incoming.insert("x-forwarded-host", "app.example.org".parse().unwrap());

        // default (empty allowlist): incoming value ignored
        assert_eq!(
            built_forwarded_host("tunnel.example.net", &incoming, &[]),
            "tunnel.example.net"
        );

        // allowlist hit: incoming value wins
        let example_org = vec!["*.example.org".to_string()];
        assert_eq!(
            built_forwarded_host("tunnel.example.net", &incoming, &example_org),
            "app.example.org"
        );

        // allowlist miss: fall back to original_host
        let mut spoofed = http::HeaderMap::new();
        spoofed.insert("x-forwarded-host", "evil.com".parse().unwrap());
        assert_eq!(
            built_forwarded_host("tunnel.example.net", &spoofed, &example_org),
            "tunnel.example.net"
        );

        // A colon suffix must be a real numeric port, not arbitrary authority
        // syntax that could be interpreted as a different host downstream.
        let example_com = vec!["app.example.com".to_string()];
        let mut malformed = http::HeaderMap::new();
        malformed.insert(
            "x-forwarded-host",
            "app.example.com:@evil.com".parse().unwrap(),
        );
        assert_eq!(
            built_forwarded_host("tunnel.example.net", &malformed, &example_com),
            "tunnel.example.net"
        );

        // header absent: fall back
        assert_eq!(
            built_forwarded_host("tunnel.example.net", &http::HeaderMap::new(), &example_com,),
            "tunnel.example.net"
        );

        // x-forwarded-proto untouched in all cases
        let mut builder = http::Request::builder().uri("http://127.0.0.1/");
        append_forwarding_headers(&mut builder, "tunnel.example.net", &incoming, &example_org);
        assert_eq!(
            builder
                .headers_ref()
                .unwrap()
                .get("x-forwarded-proto")
                .unwrap(),
            "https"
        );
    }
}
