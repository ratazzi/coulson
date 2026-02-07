use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use tracing::info;

use crate::domain::BackendTarget;
use crate::{RouteRule, SharedState};

#[derive(Clone)]
struct BridgeProxy {
    shared: SharedState,
}

#[derive(Default)]
struct ProxyCtx {
    target: Option<BackendTarget>,
    timeout_ms: Option<u64>,
    cors_enabled: bool,
    #[allow(dead_code)]
    spa_rewrite: bool,
}

#[async_trait]
impl ProxyHttp for BridgeProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let host = extract_host(
            session
                .req_header()
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok()),
        );
        let Some(host) = host else {
            write_json_error(session, 400, "missing_host").await?;
            return Ok(true);
        };
        let req_path = session.req_header().uri.path().to_string();

        let route = {
            let routes = self.shared.routes.read();
            resolve_target(&routes, &host, &self.shared.domain_suffix, &req_path)
        };

        let Some(route) = route else {
            write_json_error(session, 404, "route_not_found").await?;
            return Ok(true);
        };

        // --- Basic Auth ---
        if let (Some(expected_user), Some(expected_pass)) =
            (&route.basic_auth_user, &route.basic_auth_pass)
        {
            if !check_basic_auth(session, expected_user, expected_pass) {
                write_auth_required(session).await?;
                return Ok(true);
            }
        }

        // --- CORS Preflight ---
        if route.cors_enabled {
            let method = session.req_header().method.as_str();
            let has_origin = session.req_header().headers.get("origin").is_some();
            if method == "OPTIONS" && has_origin {
                write_cors_preflight(session).await?;
                return Ok(true);
            }
        }

        // --- Static directory serving ---
        if let BackendTarget::StaticDir { ref root } = route.target {
            serve_static(session, root, &req_path, route.cors_enabled).await?;
            return Ok(true);
        }

        // --- SPA Rewrite ---
        if route.spa_rewrite && should_rewrite_for_spa(&req_path) {
            let _ = session.req_header_mut().set_uri("/".try_into().unwrap());
        }

        ctx.target = Some(route.target);
        ctx.timeout_ms = route.timeout_ms;
        ctx.cors_enabled = route.cors_enabled;
        ctx.spa_rewrite = route.spa_rewrite;
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let Some(target) = ctx.target.take() else {
            return Error::e_explain(ErrorType::InternalError, "missing upstream target");
        };

        match target {
            BackendTarget::Tcp { host, port } => {
                let mut peer = Box::new(HttpPeer::new(format!("{host}:{port}"), false, host));
                if let Some(timeout_ms) = ctx.timeout_ms {
                    let timeout = Duration::from_millis(timeout_ms);
                    peer.options.connection_timeout = Some(timeout);
                    peer.options.total_connection_timeout = Some(timeout);
                    peer.options.read_timeout = Some(timeout);
                    peer.options.idle_timeout = Some(timeout);
                }
                Ok(peer)
            }
            BackendTarget::StaticDir { .. } => {
                // Should never reach here — static dirs are handled in request_filter
                Error::e_explain(ErrorType::InternalError, "static dir has no upstream")
            }
        }
    }

    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // --- CORS Headers ---
        if ctx.cors_enabled {
            upstream_response
                .insert_header("access-control-allow-origin", "*")
                .ok();
            upstream_response
                .insert_header(
                    "access-control-allow-methods",
                    "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                )
                .ok();
            upstream_response
                .insert_header("access-control-allow-headers", "*")
                .ok();
            upstream_response
                .insert_header("access-control-expose-headers", "*")
                .ok();
        }
        Ok(())
    }
}

pub async fn run_proxy(addr: SocketAddr, state: SharedState) -> anyhow::Result<()> {
    let bind = addr.to_string();
    info!(%bind, "proxy listening");

    tokio::task::spawn_blocking(move || run_proxy_blocking(&bind, state)).await??;
    Ok(())
}

fn run_proxy_blocking(bind: &str, state: SharedState) -> anyhow::Result<()> {
    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, BridgeProxy { shared: state });
    service.add_tcp(bind);
    server.add_service(service);
    server.run_forever();
}

// ---------------------------------------------------------------------------
// Static file serving + directory listing
// ---------------------------------------------------------------------------

async fn serve_static(
    session: &mut Session,
    root: &str,
    req_path: &str,
    cors: bool,
) -> Result<()> {
    let decoded = percent_decode(req_path);
    let clean = sanitize_path(&decoded);
    let full_path = PathBuf::from(root).join(&clean);

    // Security: ensure resolved path is under root
    let canonical_root = match std::fs::canonicalize(root) {
        Ok(p) => p,
        Err(_) => {
            write_json_error(session, 500, "static_root_missing").await?;
            return Ok(());
        }
    };
    let canonical_file = match std::fs::canonicalize(&full_path) {
        Ok(p) => p,
        Err(_) => {
            write_not_found(session).await?;
            return Ok(());
        }
    };
    if !canonical_file.starts_with(&canonical_root) {
        write_not_found(session).await?;
        return Ok(());
    }

    let meta = match std::fs::metadata(&canonical_file) {
        Ok(m) => m,
        Err(_) => {
            write_not_found(session).await?;
            return Ok(());
        }
    };

    if meta.is_dir() {
        // Try index.html first
        let index = canonical_file.join("index.html");
        if index.exists() && index.is_file() {
            return serve_file(session, &index, cors).await;
        }
        // Directory listing
        return serve_directory_listing(session, &canonical_file, &canonical_root, req_path, cors)
            .await;
    }

    if meta.is_file() {
        return serve_file(session, &canonical_file, cors).await;
    }

    write_not_found(session).await
}

async fn serve_file(session: &mut Session, path: &Path, cors: bool) -> Result<()> {
    let body = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            write_json_error(session, 500, "read_error").await?;
            return Ok(());
        }
    };

    let content_type = guess_content_type(path);
    let mut resp = ResponseHeader::build(200, None)?;
    resp.insert_header("content-type", content_type)?;
    resp.insert_header("content-length", body.len().to_string())?;
    if cors {
        resp.insert_header("access-control-allow-origin", "*")?;
    }

    session
        .write_response_header(Box::new(resp), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await?;
    Ok(())
}

async fn serve_directory_listing(
    session: &mut Session,
    dir: &Path,
    root: &Path,
    req_path: &str,
    cors: bool,
) -> Result<()> {
    let req_path = if req_path.ends_with('/') {
        req_path.to_string()
    } else {
        format!("{req_path}/")
    };

    let mut entries = Vec::new();
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => {
            write_json_error(session, 500, "read_dir_error").await?;
            return Ok(());
        }
    };

    for entry in read_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue; // hide dotfiles
        }
        let meta = entry.metadata().ok();
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(format_system_time)
            .unwrap_or_else(|| "-".to_string());
        let display_name = if is_dir {
            format!("{name}/")
        } else {
            name.clone()
        };
        let href = if is_dir {
            format!("{req_path}{name}/")
        } else {
            format!("{req_path}{name}")
        };
        entries.push(DirEntry {
            href,
            display_name,
            is_dir,
            size,
            modified,
        });
    }

    entries.sort_by(|a, b| {
        // dirs first, then alphabetical
        b.is_dir.cmp(&a.is_dir).then(a.display_name.cmp(&b.display_name))
    });

    let relative = dir
        .strip_prefix(root)
        .unwrap_or(dir)
        .to_string_lossy()
        .to_string();
    let title = if relative.is_empty() {
        "/".to_string()
    } else {
        format!("/{relative}/")
    };

    let body = render_directory_html(&title, &req_path, &entries);
    let mut resp = ResponseHeader::build(200, None)?;
    resp.insert_header("content-type", "text/html; charset=utf-8")?;
    resp.insert_header("content-length", body.len().to_string())?;
    if cors {
        resp.insert_header("access-control-allow-origin", "*")?;
    }

    session
        .write_response_header(Box::new(resp), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await?;
    Ok(())
}

struct DirEntry {
    href: String,
    display_name: String,
    is_dir: bool,
    size: u64,
    modified: String,
}

fn render_directory_html(title: &str, req_path: &str, entries: &[DirEntry]) -> String {
    let mut rows = String::new();

    // Parent directory link
    if req_path != "/" {
        let trimmed = req_path.trim_end_matches('/');
        let parent = match trimmed.rsplit_once('/') {
            Some(("", _)) => "/".to_string(),
            Some((p, _)) => format!("{p}/"),
            None => "/".to_string(),
        };
        rows.push_str(&format!(
            r#"<tr class="parent"><td><a href="{parent}">../</a></td><td>-</td><td>-</td></tr>"#
        ));
    }

    for e in entries {
        let size_str = if e.is_dir {
            "-".to_string()
        } else {
            format_size(e.size)
        };
        rows.push_str(&format!(
            r#"<tr><td><a href="{href}">{name}</a></td><td class="size">{size}</td><td class="mod">{modified}</td></tr>"#,
            href = html_escape(&e.href),
            name = html_escape(&e.display_name),
            size = size_str,
            modified = html_escape(&e.modified),
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Index of {title}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #f5f5f7; color: #1d1d1f; padding: 2rem;
  }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  h1 {{
    font-size: 1.5rem; font-weight: 600; margin-bottom: 1.5rem;
    padding-bottom: 0.75rem; border-bottom: 1px solid #d2d2d7;
    color: #1d1d1f;
  }}
  h1 code {{ font-size: 1.3rem; background: #e8e8ed; padding: 0.15em 0.5em; border-radius: 6px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  th {{ text-align: left; padding: 0.75rem 1rem; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: #86868b; background: #fafafa; border-bottom: 1px solid #e8e8ed; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #f0f0f2; font-size: 0.9rem; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover {{ background: #f5f5f7; }}
  a {{ color: #0066cc; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .size, .mod {{ color: #86868b; white-space: nowrap; }}
  .size {{ text-align: right; }}
  .parent a {{ color: #86868b; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #1d1d1f; color: #f5f5f7; }}
    h1 {{ color: #f5f5f7; border-bottom-color: #424245; }}
    h1 code {{ background: #2d2d30; }}
    table {{ background: #2d2d30; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }}
    th {{ background: #262628; color: #a1a1a6; border-bottom-color: #424245; }}
    td {{ border-bottom-color: #3a3a3c; }}
    tr:hover {{ background: #38383a; }}
    a {{ color: #2997ff; }}
    .size, .mod {{ color: #a1a1a6; }}
    .parent a {{ color: #a1a1a6; }}
  }}
</style>
</head>
<body>
<div class="container">
<h1>Index of <code>{title}</code></h1>
<table>
  <thead><tr><th>Name</th><th class="size">Size</th><th class="mod">Modified</th></tr></thead>
  <tbody>
    {rows}
  </tbody>
</table>
</div>
</body>
</html>"#,
        title = html_escape(title),
        rows = rows,
    )
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn format_system_time(time: std::time::SystemTime) -> String {
    let dur = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() as i64;
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => {
            let fmt = time::format_description::parse("[year]-[month]-[day] [hour]:[minute]")
                .unwrap_or_default();
            dt.format(&fmt).unwrap_or_else(|_| "-".to_string())
        }
        Err(_) => "-".to_string(),
    }
}

fn guess_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("txt") | Some("md") | Some("log") => "text/plain; charset=utf-8",
        Some("csv") => "text/csv; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("gz") | Some("tgz") => "application/gzip",
        Some("tar") => "application/x-tar",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mp3") => "audio/mpeg",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn sanitize_path(path: &str) -> String {
    let without_leading = path.trim_start_matches('/');
    let segments: Vec<&str> = without_leading
        .split('/')
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .collect();
    segments.join("/")
}

fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn write_not_found(session: &mut Session) -> Result<()> {
    write_json_error(session, 404, "not_found").await
}

// ---------------------------------------------------------------------------
// Basic Auth helpers
// ---------------------------------------------------------------------------

fn check_basic_auth(session: &Session, expected_user: &str, expected_pass: &str) -> bool {
    let Some(auth_header) = session.req_header().headers.get("authorization") else {
        return false;
    };
    let Ok(auth_str) = auth_header.to_str() else {
        return false;
    };
    let Some(encoded) = auth_str.strip_prefix("Basic ") else {
        return false;
    };
    decode_basic_auth(encoded)
        .map(|(u, p)| u == expected_user && p == expected_pass)
        .unwrap_or(false)
}

fn decode_basic_auth(encoded: &str) -> Option<(String, String)> {
    let decoded_bytes = base64_decode(encoded.trim())?;
    let decoded = String::from_utf8(decoded_bytes).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Minimal base64 decoder (standard alphabet, no padding required).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input.as_bytes() {
        if b == b'=' {
            break;
        }
        let val = TABLE.iter().position(|&c| c == b)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

async fn write_auth_required(session: &mut Session) -> Result<()> {
    let body = r#"{"error":"unauthorized"}"#;
    let mut resp = ResponseHeader::build(401, None)?;
    resp.insert_header("content-type", "application/json")?;
    resp.insert_header("content-length", body.len().to_string())?;
    resp.insert_header("www-authenticate", r#"Basic realm="bridgehead""#)?;
    resp.insert_header("connection", "close")?;

    session
        .write_response_header(Box::new(resp), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CORS helpers
// ---------------------------------------------------------------------------

async fn write_cors_preflight(session: &mut Session) -> Result<()> {
    let mut resp = ResponseHeader::build(204, None)?;
    resp.insert_header("access-control-allow-origin", "*")?;
    resp.insert_header(
        "access-control-allow-methods",
        "GET, POST, PUT, DELETE, PATCH, OPTIONS",
    )?;
    resp.insert_header("access-control-allow-headers", "*")?;
    resp.insert_header("access-control-max-age", "86400")?;
    resp.insert_header("content-length", "0")?;

    session
        .write_response_header(Box::new(resp), true)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SPA rewrite helpers
// ---------------------------------------------------------------------------

fn should_rewrite_for_spa(path: &str) -> bool {
    if path == "/" {
        return false;
    }
    let last_segment = path.rsplit('/').next().unwrap_or(path);
    if let Some(dot_pos) = last_segment.rfind('.') {
        if dot_pos > 0 {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Error / routing helpers
// ---------------------------------------------------------------------------

async fn write_json_error(session: &mut Session, status: u16, code: &str) -> Result<()> {
    let body = format!(r#"{{"error":"{code}"}}"#);
    let mut resp = ResponseHeader::build(status, None)?;
    resp.insert_header("content-type", "application/json")?;
    resp.insert_header("content-length", body.len().to_string())?;
    resp.insert_header("connection", "close")?;

    session
        .write_response_header(Box::new(resp), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await?;
    Ok(())
}

fn extract_host(raw: Option<&str>) -> Option<String> {
    let raw = raw?;
    let host = raw.split(':').next()?.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(host)
}

fn resolve_target(
    routes: &HashMap<String, Vec<RouteRule>>,
    host: &str,
    domain_suffix: &str,
    path: &str,
) -> Option<RouteRule> {
    if let Some(hit) = select_route(routes.get(host), path) {
        return Some(hit);
    }

    if let Some(hit) = select_wildcard_route(routes, host, path) {
        return Some(hit);
    }

    let mut parts: Vec<&str> = host.split('.').collect();
    while parts.len() > 2 {
        parts.remove(0);
        let candidate = parts.join(".");
        if let Some(hit) = select_route(routes.get(&candidate), path) {
            return Some(hit);
        }
    }

    let default_host = format!("default.{domain_suffix}");
    if let Some(hit) = select_route(routes.get(&default_host), path) {
        return Some(hit);
    }

    None
}

fn select_wildcard_route(
    routes: &HashMap<String, Vec<RouteRule>>,
    host: &str,
    path: &str,
) -> Option<RouteRule> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 3 {
        return None;
    }

    for i in 1..(parts.len() - 1) {
        let suffix = parts[i..].join(".");
        let candidate = format!("*.{suffix}");
        if let Some(hit) = select_route(routes.get(&candidate), path) {
            return Some(hit);
        }
    }
    None
}

fn select_route(candidates: Option<&Vec<RouteRule>>, path: &str) -> Option<RouteRule> {
    let candidates = candidates?;
    for route in candidates {
        match route.path_prefix.as_deref() {
            None => return Some(route.clone()),
            Some("/") => return Some(route.clone()),
            Some(prefix) if path == prefix || path.starts_with(&format!("{prefix}/")) => {
                return Some(route.clone());
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_is_normalized() {
        let host = extract_host(Some("MyApp.test:8080")).expect("host");
        assert_eq!(host, "myapp.test");
    }

    #[test]
    fn subdomain_falls_back_to_parent_host() {
        let mut routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        routes.insert(
            "myapp.test".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5006,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
            }],
        );
        let out = resolve_target(&routes, "www.myapp.test", "test", "/").expect("fallback");
        match out.target {
            BackendTarget::Tcp { host, port } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 5006);
            }
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn unknown_host_falls_back_to_default() {
        let mut routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        routes.insert(
            "default.test".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5007,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
            }],
        );
        let out = resolve_target(&routes, "totally-unknown.test", "test", "/").expect("default");
        match out.target {
            BackendTarget::Tcp { host, port } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 5007);
            }
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn longest_path_prefix_wins() {
        let mut routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        routes.insert(
            "myapp.test".to_string(),
            vec![
                RouteRule {
                    target: BackendTarget::Tcp {
                        host: "127.0.0.1".to_string(),
                        port: 5000,
                    },
                    path_prefix: Some("/api/v1".to_string()),
                    timeout_ms: None,
                    cors_enabled: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                },
                RouteRule {
                    target: BackendTarget::Tcp {
                        host: "127.0.0.1".to_string(),
                        port: 4000,
                    },
                    path_prefix: Some("/api".to_string()),
                    timeout_ms: None,
                    cors_enabled: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                },
            ],
        );
        let out = resolve_target(&routes, "myapp.test", "test", "/api/v1/users").expect("route");
        match out.target {
            BackendTarget::Tcp { port, .. } => assert_eq!(port, 5000),
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn wildcard_host_matches_subdomain() {
        let mut routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        routes.insert(
            "*.myapp.test".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5010,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
            }],
        );
        let out = resolve_target(&routes, "api.myapp.test", "test", "/").expect("wildcard");
        match out.target {
            BackendTarget::Tcp { port, .. } => assert_eq!(port, 5010),
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn exact_host_beats_wildcard() {
        let mut routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        routes.insert(
            "api.myapp.test".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5001,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
            }],
        );
        routes.insert(
            "*.myapp.test".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5002,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
            }],
        );
        let out = resolve_target(&routes, "api.myapp.test", "test", "/").expect("route");
        match out.target {
            BackendTarget::Tcp { port, .. } => assert_eq!(port, 5001),
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn wildcard_requires_subdomain() {
        let mut routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        routes.insert(
            "*.myapp.test".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5002,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
            }],
        );
        assert!(resolve_target(&routes, "myapp.test", "test", "/").is_none());
    }

    // --- New feature tests ---

    #[test]
    fn base64_decode_works() {
        let decoded = base64_decode("dGVzdDp0ZXN0").expect("decode");
        assert_eq!(String::from_utf8(decoded).unwrap(), "test:test");
    }

    #[test]
    fn decode_basic_auth_works() {
        let (user, pass) = decode_basic_auth("dGVzdDp0ZXN0").expect("decode");
        assert_eq!(user, "test");
        assert_eq!(pass, "test");
    }

    #[test]
    fn spa_rewrite_skips_root() {
        assert!(!should_rewrite_for_spa("/"));
    }

    #[test]
    fn spa_rewrite_skips_files() {
        assert!(!should_rewrite_for_spa("/static/app.js"));
        assert!(!should_rewrite_for_spa("/style.css"));
        assert!(!should_rewrite_for_spa("/favicon.ico"));
        assert!(!should_rewrite_for_spa("/images/logo.png"));
    }

    #[test]
    fn spa_rewrite_rewrites_paths() {
        assert!(should_rewrite_for_spa("/about"));
        assert!(should_rewrite_for_spa("/users/123"));
        assert!(should_rewrite_for_spa("/api/v1/items"));
        assert!(should_rewrite_for_spa("/dashboard"));
    }

    #[test]
    fn sanitize_path_removes_traversal() {
        assert_eq!(sanitize_path("/foo/../bar"), "foo/bar");
        assert_eq!(sanitize_path("/./foo/./bar"), "foo/bar");
        assert_eq!(sanitize_path("/../../../etc/passwd"), "etc/passwd");
    }

    #[test]
    fn percent_decode_works() {
        assert_eq!(percent_decode("/foo%20bar"), "/foo bar");
        assert_eq!(percent_decode("/a%2Fb"), "/a/b");
    }

    #[test]
    fn format_size_units() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1048576), "1.0 MB");
        assert_eq!(format_size(1073741824), "1.0 GB");
    }
}
