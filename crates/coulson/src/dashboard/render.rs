use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tera::{Context, Tera};

use crate::domain::{AppKind, AppSpec, BackendTarget};
use crate::runtime;
use crate::SharedState;

pub fn templates() -> &'static Tera {
    #[cfg(debug_assertions)]
    {
        use std::path::Path;
        const TEMPLATE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/dashboard/templates");
        let glob = format!("{}/**/*.html", TEMPLATE_DIR);
        let mut tera = Tera::new(&glob).unwrap_or_else(|e| {
            tracing::error!("template reload error: {e}");
            Tera::default()
        });
        let prefix = format!("{}/", TEMPLATE_DIR);
        let renames: Vec<(String, Option<String>)> = tera
            .get_template_names()
            .filter_map(|name| {
                let short = name.strip_prefix(&prefix)?;
                Some((name.to_string(), Some(short.to_string())))
            })
            .collect();
        if !renames.is_empty() {
            let pairs: Vec<(String, String)> = renames
                .iter()
                .filter_map(|(_long, short)| {
                    let short = short.as_ref()?;
                    let full_path = Path::new(TEMPLATE_DIR).join(short);
                    std::fs::read_to_string(&full_path)
                        .ok()
                        .map(|c| (short.clone(), c))
                })
                .collect();
            let raw: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(n, c)| (n.as_str(), c.as_str()))
                .collect();
            let mut fresh = Tera::default();
            fresh.add_raw_templates(raw).unwrap_or_else(|e| {
                tracing::error!("template parse error: {e}");
            });
            fresh.autoescape_on(vec![".html"]);
            return Box::leak(Box::new(fresh));
        }
        tera.autoescape_on(vec![".html"]);
        Box::leak(Box::new(tera))
    }
    #[cfg(not(debug_assertions))]
    {
        use std::sync::LazyLock;
        static TEMPLATES: LazyLock<Tera> = LazyLock::new(|| {
            let mut tera = Tera::default();
            tera.add_raw_templates(vec![
                ("base.html", include_str!("templates/base.html")),
                (
                    "pages/index.html",
                    include_str!("templates/pages/index.html"),
                ),
                (
                    "pages/warnings.html",
                    include_str!("templates/pages/warnings.html"),
                ),
                (
                    "pages/app_detail.html",
                    include_str!("templates/pages/app_detail.html"),
                ),
                (
                    "pages/not_found.html",
                    include_str!("templates/pages/not_found.html"),
                ),
                (
                    "partials/settings_modal.html",
                    include_str!("templates/partials/settings_modal.html"),
                ),
                (
                    "pages/processes.html",
                    include_str!("templates/pages/processes.html"),
                ),
                (
                    "pages/process_log.html",
                    include_str!("templates/pages/process_log.html"),
                ),
                (
                    "partials/stats.html",
                    include_str!("templates/partials/stats.html"),
                ),
                (
                    "partials/app_table.html",
                    include_str!("templates/partials/app_table.html"),
                ),
                (
                    "partials/app_row.html",
                    include_str!("templates/partials/app_row.html"),
                ),
                (
                    "partials/empty_state.html",
                    include_str!("templates/partials/empty_state.html"),
                ),
                (
                    "partials/toast.html",
                    include_str!("templates/partials/toast.html"),
                ),
                (
                    "partials/new_app_modal.html",
                    include_str!("templates/partials/new_app_modal.html"),
                ),
                (
                    "partials/detail/urls.html",
                    include_str!("templates/partials/detail/urls.html"),
                ),
                (
                    "partials/detail/info.html",
                    include_str!("templates/partials/detail/info.html"),
                ),
                (
                    "partials/detail/features.html",
                    include_str!("templates/partials/detail/features.html"),
                ),
                (
                    "partials/detail/tunnel.html",
                    include_str!("templates/partials/detail/tunnel.html"),
                ),
                (
                    "partials/detail/danger.html",
                    include_str!("templates/partials/detail/danger.html"),
                ),
                (
                    "pages/requests.html",
                    include_str!("templates/pages/requests.html"),
                ),
                (
                    "pages/request_detail.html",
                    include_str!("templates/pages/request_detail.html"),
                ),
                (
                    "partials/request_row.html",
                    include_str!("templates/partials/request_row.html"),
                ),
            ])
            .expect("template parse error");
            tera.autoescape_on(vec![".html"]);
            tera
        });
        &TEMPLATES
    }
}

#[derive(Serialize)]
pub struct AppView {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub domain_href: String,
    pub path_prefix: Option<String>,
    pub target_display: String,
    pub target_port: Option<u16>,
    pub kind_label: &'static str,
    pub enabled: bool,
    pub tunnel_url: Option<String>,
    pub tunnel_exposed: bool,
    pub tunnel_mode: String,
    pub app_tunnel_id: Option<String>,
    pub app_tunnel_domain: Option<String>,
    pub cors_enabled: bool,
    pub force_https: bool,
    pub spa_rewrite: bool,
    pub basic_auth_user: Option<String>,
    pub basic_auth_pass_set: bool,
    pub timeout_display: String,
    pub timeout_ms: Option<u64>,
    pub listen_port: Option<u16>,
    pub inspect_enabled: bool,
    pub app_tunnel_token_hint: bool,
}

#[derive(Serialize)]
pub struct UrlView {
    pub href: String,
    pub is_link: bool,
}

impl AppView {
    pub fn from_spec(app: &AppSpec, port: u16) -> Self {
        let path = app.path_prefix.as_deref().unwrap_or("/");
        let domain_href = format!("http://{}:{}{}", &app.domain.0, port, path);
        let target_port = if let BackendTarget::Tcp { port, .. } = &app.target {
            Some(*port)
        } else {
            None
        };
        Self {
            id: app.id.0.to_string(),
            name: app.name.clone(),
            domain: app.domain.0.clone(),
            domain_href,
            path_prefix: app.path_prefix.clone(),
            target_display: format_target(&app.target),
            target_port,
            kind_label: effective_kind_label(app.kind, &app.target),
            enabled: app.enabled,
            tunnel_url: app.tunnel_url.clone(),
            tunnel_exposed: app.tunnel_mode.is_exposed(),
            tunnel_mode: app.tunnel_mode.as_str().to_string(),
            app_tunnel_id: app.app_tunnel_id.clone(),
            app_tunnel_domain: app.app_tunnel_domain.clone(),
            cors_enabled: app.cors_enabled,
            force_https: app.force_https,
            spa_rewrite: app.spa_rewrite,
            basic_auth_user: app.basic_auth_user.clone(),
            basic_auth_pass_set: app.basic_auth_pass.is_some(),
            timeout_display: app
                .timeout_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "default".to_string()),
            timeout_ms: app.timeout_ms,
            listen_port: app.listen_port,
            inspect_enabled: app.inspect_enabled,
            app_tunnel_token_hint: app.app_tunnel_creds.is_some(),
        }
    }
}

#[derive(Serialize)]
pub struct ProcessView {
    pub app_id: i64,
    pub app_name: Option<String>,
    pub pid: u32,
    pub kind: String,
    pub uptime_display: String,
    pub idle_display: String,
    pub alive: bool,
}

pub fn process_views(
    infos: &[crate::process::ProcessInfo],
    state: &SharedState,
) -> Vec<ProcessView> {
    infos
        .iter()
        .map(|info| {
            let app_name = state
                .store
                .get_by_id(info.app_id)
                .ok()
                .flatten()
                .map(|a| a.name);
            ProcessView {
                app_id: info.app_id,
                app_name,
                pid: info.pid,
                kind: info.kind.clone(),
                uptime_display: format_duration(info.uptime_secs),
                idle_display: format_duration(info.idle_secs),
                alive: info.alive,
            }
        })
        .collect()
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[derive(Serialize)]
pub struct TunnelStatusView {
    pub connected: bool,
    pub tunnel_domain: String,
    pub connections: Vec<TunnelConnView>,
    pub conn_count: usize,
    pub locations: String,
}

#[derive(Serialize)]
pub struct TunnelConnView {
    pub location: String,
    pub conn_index: u8,
    pub uptime_display: String,
}

#[derive(Serialize)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct RequestView {
    pub id: String,
    pub method: String,
    pub method_color: &'static str,
    pub path: String,
    pub query_string: Option<String>,
    pub status_code: Option<u16>,
    pub status_color: &'static str,
    pub response_time_ms: Option<u64>,
    pub timestamp_ms: i64,
    pub request_headers_display: String,
    pub request_body_display: Option<String>,
    pub response_headers_display: Option<String>,
    pub response_body_display: Option<String>,
    pub request_headers_list: Vec<HeaderPair>,
    pub response_headers_list: Vec<HeaderPair>,
}

impl RequestView {
    pub fn from_captured(req: &crate::store::CapturedRequest) -> Self {
        let method_color = match req.method.as_str() {
            "GET" => "bg-blue-50 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300",
            "POST" => "bg-green-50 text-green-700 dark:bg-green-900/40 dark:text-green-300",
            "PUT" | "PATCH" => {
                "bg-amber-50 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300"
            }
            "DELETE" => "bg-red-50 text-red-700 dark:bg-red-900/40 dark:text-red-300",
            _ => "bg-zinc-50 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
        };
        let status_color = match req.status_code {
            Some(s) if s < 300 => {
                "bg-emerald-50 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
            }
            Some(s) if s < 400 => "bg-blue-50 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300",
            Some(s) if s < 500 => {
                "bg-amber-50 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300"
            }
            Some(_) => "bg-red-50 text-red-700 dark:bg-red-900/40 dark:text-red-300",
            None => "bg-zinc-50 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400",
        };
        Self {
            id: req.id.clone(),
            method: req.method.clone(),
            method_color,
            path: req.path.clone(),
            query_string: req.query_string.clone(),
            status_code: req.status_code,
            status_color,
            response_time_ms: req.response_time_ms,
            timestamp_ms: req.timestamp,
            request_headers_display: format_headers_json(&req.request_headers),
            request_body_display: req.request_body.as_ref().map(|b| body_to_display(b)),
            response_headers_display: req
                .response_headers
                .as_ref()
                .map(|h| format_headers_json(h)),
            response_body_display: req.response_body.as_ref().map(|b| body_to_display(b)),
            request_headers_list: parse_headers_list(&req.request_headers),
            response_headers_list: req
                .response_headers
                .as_ref()
                .map(|h| parse_headers_list(h))
                .unwrap_or_default(),
        }
    }
}

#[derive(Serialize)]
pub struct ReplayView {
    pub status_code: u16,
    pub status_color: &'static str,
    pub body_display: Option<String>,
}

pub struct ReplayOutcome {
    pub status_code: Option<u16>,
    pub response_time_ms: u64,
    pub response_headers: std::collections::HashMap<String, String>,
    pub body: Option<String>,
    pub error: Option<String>,
}

fn unsupported_replay(msg: &str) -> ReplayOutcome {
    ReplayOutcome {
        status_code: None,
        response_time_ms: 0,
        response_headers: Default::default(),
        body: None,
        error: Some(msg.into()),
    }
}

pub async fn execute_replay(
    store: &crate::store::AppRepository,
    app_name: &str,
    request_id: &str,
) -> anyhow::Result<ReplayOutcome> {
    let app = store
        .get_by_name(app_name)?
        .ok_or_else(|| anyhow::anyhow!("app not found"))?;
    let captured = store
        .get_request_log(request_id)?
        .ok_or_else(|| anyhow::anyhow!("request not found"))?;
    if captured.app_id != app.id.0 {
        anyhow::bail!("request does not belong to app");
    }

    let base_url = match &app.target {
        BackendTarget::Tcp { host, port } => format!("http://{host}:{port}"),
        BackendTarget::UnixSocket { .. } => {
            return Ok(unsupported_replay(
                "Replay not supported for Unix socket targets",
            ));
        }
        _ => {
            return Ok(unsupported_replay(
                "Replay not supported for this target type",
            ));
        }
    };

    let path = &captured.path;
    let query = captured
        .query_string
        .as_ref()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let url = format!("{base_url}{path}{query}");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();
    let method: reqwest::Method = captured.method.parse().unwrap_or(reqwest::Method::GET);
    let mut req_builder = client.request(method, &url);

    let orig_headers: std::collections::HashMap<String, String> =
        serde_json::from_str(&captured.request_headers).unwrap_or_default();
    for (k, v) in &orig_headers {
        let lower = k.to_lowercase();
        if lower == "host" || lower == "content-length" || lower == "transfer-encoding" {
            continue;
        }
        req_builder = req_builder.header(k.as_str(), v.as_str());
    }
    if let Some(ref body) = captured.request_body {
        req_builder = req_builder.body(body.clone());
    }

    let start = std::time::Instant::now();
    match req_builder.send().await {
        Ok(resp) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let status = resp.status().as_u16();
            let response_headers: std::collections::HashMap<String, String> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body_bytes = resp.bytes().await.unwrap_or_default();
            let body = if body_bytes.is_empty() {
                None
            } else {
                Some(body_to_display(&body_bytes))
            };
            Ok(ReplayOutcome {
                status_code: Some(status),
                response_time_ms: elapsed,
                response_headers,
                body,
                error: None,
            })
        }
        Err(e) => Ok(ReplayOutcome {
            status_code: None,
            response_time_ms: start.elapsed().as_millis() as u64,
            response_headers: Default::default(),
            body: None,
            error: Some(format!("Replay failed: {e}")),
        }),
    }
}

pub fn tunnel_status_view(state: &SharedState) -> Option<TunnelStatusView> {
    let guard = state.named_tunnel.lock();
    let handle = guard.as_ref()?;
    let tunnel_domain = handle.tunnel_domain.clone();
    drop(guard);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let conns = state.tunnel_conns.read();
    let mut connections: Vec<TunnelConnView> = conns
        .iter()
        .map(|c| {
            let elapsed_ms = (now_ms - c.connected_at).max(0) as u64;
            let elapsed_secs = elapsed_ms / 1000;
            let uptime_display = if elapsed_secs < 60 {
                format!("{elapsed_secs}s")
            } else if elapsed_secs < 3600 {
                format!("{}m {}s", elapsed_secs / 60, elapsed_secs % 60)
            } else {
                format!("{}h {}m", elapsed_secs / 3600, (elapsed_secs % 3600) / 60)
            };
            TunnelConnView {
                location: c.location.clone(),
                conn_index: c.conn_index,
                uptime_display,
            }
        })
        .collect();
    connections.sort_by_key(|c| c.conn_index);

    let mut seen = Vec::new();
    for c in &connections {
        if !seen.contains(&c.location) {
            seen.push(c.location.clone());
        }
    }
    let locations = seen.join(", ");
    let conn_count = connections.len();

    Some(TunnelStatusView {
        connected: conn_count > 0,
        tunnel_domain,
        connections,
        conn_count,
        locations,
    })
}

pub fn global_tunnel_domain(state: &SharedState) -> Option<String> {
    let guard = state.named_tunnel.lock();
    guard.as_ref().map(|h| h.tunnel_domain.clone())
}

pub fn base_context(state: &SharedState) -> Context {
    let mut ctx = Context::new();
    ctx.insert("suffix", &state.domain_suffix);
    ctx.insert("warning_count", &get_warning_count(state));
    ctx.insert("version", env!("CARGO_PKG_VERSION"));
    if let Some(ts) = tunnel_status_view(state) {
        ctx.insert("tunnel", &ts);
    }
    ctx.insert(
        "default_app",
        &state
            .store
            .get_setting("default_app")
            .unwrap_or(None)
            .unwrap_or_default(),
    );
    ctx
}

pub fn render_page(
    template: &str,
    state: &SharedState,
    customize: impl FnOnce(&mut Context),
) -> String {
    let mut ctx = base_context(state);
    ctx.insert("title", "Coulson");
    ctx.insert("active_nav", "");
    customize(&mut ctx);
    templates()
        .render(template, &ctx)
        .unwrap_or_else(|e| format!("<html><body><pre>Template error: {e}</pre></body></html>"))
}

pub fn render_not_found(state: &SharedState) -> String {
    render_page("pages/not_found.html", state, |ctx| {
        ctx.insert("title", "Not Found");
    })
}

pub fn render_partial(template: &str, ctx: &Context) -> String {
    templates().render(template, ctx).unwrap_or_default()
}

pub fn stats_context(apps: &[AppSpec]) -> Context {
    let total = apps.len();
    let enabled = apps.iter().filter(|a| a.enabled).count();
    let disabled = total - enabled;
    let managed = apps
        .iter()
        .filter(|a| matches!(a.kind, AppKind::Asgi | AppKind::Node))
        .count();
    let mut ctx = Context::new();
    ctx.insert("total", &total);
    ctx.insert("enabled_count", &enabled);
    ctx.insert("disabled_count", &disabled);
    ctx.insert("managed_count", &managed);
    ctx
}

pub fn app_views(apps: &[AppSpec], port: u16) -> Vec<AppView> {
    apps.iter().map(|a| AppView::from_spec(a, port)).collect()
}

pub fn build_urls(
    app: &AppSpec,
    port: u16,
    https_port: Option<u16>,
    global_tunnel_domain: Option<&str>,
) -> Vec<UrlView> {
    let mut urls = Vec::new();
    let path = app.path_prefix.as_deref().unwrap_or("/");
    urls.push(UrlView {
        href: format!("http://{}:{}{}", &app.domain.0, port, path),
        is_link: true,
    });
    if let Some(hp) = https_port {
        urls.push(UrlView {
            href: format!("https://{}:{}{}", &app.domain.0, hp, path),
            is_link: true,
        });
    }
    match &app.target {
        BackendTarget::Tcp { host, port } => urls.push(UrlView {
            href: format!("http://{host}:{port}/"),
            is_link: true,
        }),
        BackendTarget::UnixSocket { path } => urls.push(UrlView {
            href: format!("unix://{path}"),
            is_link: false,
        }),
        BackendTarget::StaticDir { root } => urls.push(UrlView {
            href: format!("file://{root}"),
            is_link: false,
        }),
        _ => {}
    }
    if app.tunnel_mode.is_exposed() {
        if let Some(ref tunnel_domain) = app.app_tunnel_domain {
            let href = format!("https://{tunnel_domain}");
            if !urls.iter().any(|u| u.href == href) {
                urls.push(UrlView {
                    href,
                    is_link: true,
                });
            }
        }
    }
    if matches!(app.tunnel_mode, crate::domain::TunnelMode::Global) {
        if let Some(td) = global_tunnel_domain {
            let href = format!("https://{}.{td}", app.name);
            if !urls.iter().any(|u| u.href == href) {
                urls.push(UrlView {
                    href,
                    is_link: true,
                });
            }
        }
    }
    if let Some(ref url) = app.tunnel_url {
        if !urls.iter().any(|u| u.href == *url) {
            urls.push(UrlView {
                href: url.clone(),
                is_link: true,
            });
        }
    }
    urls
}

pub fn turbo_replace(target: &str, content: &str) -> String {
    format!(
        r#"<turbo-stream action="replace" target="{target}"><template>{content}</template></turbo-stream>"#
    )
}

pub fn turbo_remove(target: &str) -> String {
    format!(r#"<turbo-stream action="remove" target="{target}"></turbo-stream>"#)
}

pub fn turbo_prepend(target: &str, content: &str) -> String {
    format!(
        r#"<turbo-stream action="prepend" target="{target}"><template>{content}</template></turbo-stream>"#
    )
}

pub fn turbo_stream_response(body: &str) -> Response {
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/vnd.turbo-stream.html; charset=utf-8",
            ),
            (axum::http::header::CACHE_CONTROL, "no-cache, no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

pub fn html_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-cache, no-store"),
        ],
        body,
    )
        .into_response()
}

pub fn format_target(target: &BackendTarget) -> String {
    match target {
        BackendTarget::Tcp { host, port } => format!("{host}:{port}"),
        BackendTarget::UnixSocket { path } => {
            format!("unix:{}", path.rsplit('/').next().unwrap_or(path))
        }
        BackendTarget::StaticDir { root } => {
            format!("dir:{}", root.rsplit('/').next().unwrap_or(root))
        }
        BackendTarget::Managed { root, .. } => {
            format!("managed:{}", root.rsplit('/').next().unwrap_or(root))
        }
    }
}

fn is_proxy_target(target: &BackendTarget) -> bool {
    matches!(
        target,
        BackendTarget::Tcp { .. } | BackendTarget::UnixSocket { .. }
    )
}

pub fn effective_kind_label(kind: AppKind, target: &BackendTarget) -> &'static str {
    match kind {
        AppKind::Static if is_proxy_target(target) => "Proxy",
        AppKind::Static => "Static",
        AppKind::Rack => "Rack",
        AppKind::Asgi => "ASGI",
        AppKind::Node => "Node",
        AppKind::Container => "Container",
    }
}

pub fn get_warning_count(state: &SharedState) -> usize {
    runtime::read_scan_warnings(&state.scan_warnings_path)
        .ok()
        .flatten()
        .map(|w| w.scan.warning_count)
        .unwrap_or(0)
}

pub fn status_color_for(code: u16) -> &'static str {
    match code {
        c if c < 300 => {
            "bg-emerald-50 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
        }
        c if c < 400 => "bg-blue-50 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300",
        c if c < 500 => "bg-amber-50 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300",
        _ => "bg-red-50 text-red-700 dark:bg-red-900/40 dark:text-red-300",
    }
}

pub fn format_headers_json(json_str: &str) -> String {
    let headers: std::collections::HashMap<String, String> =
        serde_json::from_str(json_str).unwrap_or_default();
    let mut lines: Vec<String> = headers.iter().map(|(k, v)| format!("{k}: {v}")).collect();
    lines.sort();
    lines.join("\n")
}

pub fn parse_headers_list(json_str: &str) -> Vec<HeaderPair> {
    let headers: std::collections::HashMap<String, String> =
        serde_json::from_str(json_str).unwrap_or_default();
    let mut pairs: Vec<HeaderPair> = headers
        .into_iter()
        .map(|(name, value)| HeaderPair { name, value })
        .collect();
    pairs.sort_by(|a, b| a.name.cmp(&b.name));
    pairs
}

pub fn body_to_display(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(s) {
                serde_json::to_string_pretty(&val).unwrap_or_else(|_| s.to_string())
            } else {
                s.to_string()
            }
        }
        Err(_) => {
            let limit = bytes.len().min(512);
            bytes[..limit]
                .chunks(16)
                .map(|chunk| {
                    chunk
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_parse_correctly() {
        let _ = templates();
    }

    #[test]
    fn format_target_display() {
        assert_eq!(
            format_target(&BackendTarget::Tcp {
                host: "127.0.0.1".into(),
                port: 5006
            }),
            "127.0.0.1:5006"
        );
        assert_eq!(
            format_target(&BackendTarget::UnixSocket {
                path: "/tmp/app.sock".into()
            }),
            "unix:app.sock"
        );
        assert_eq!(
            format_target(&BackendTarget::StaticDir {
                root: "/var/www/public".into()
            }),
            "dir:public"
        );
        assert_eq!(
            format_target(&BackendTarget::Managed {
                app_id: 1,
                root: "/home/user/myapp".into(),
                kind: "asgi".into(),
                name: "myapp".into(),
            }),
            "managed:myapp"
        );
    }

    #[test]
    fn turbo_stream_helpers() {
        let replace = turbo_replace("target-1", "<p>hi</p>");
        assert!(replace.contains(r#"action="replace""#));
        assert!(replace.contains(r#"target="target-1""#));
        assert!(replace.contains("<p>hi</p>"));

        let remove = turbo_remove("row-1");
        assert!(remove.contains(r#"action="remove""#));
        assert!(remove.contains(r#"target="row-1""#));

        let prepend = turbo_prepend("list", "<li>new</li>");
        assert!(prepend.contains(r#"action="prepend""#));
        assert!(prepend.contains("<li>new</li>"));
    }

    #[test]
    fn render_stats_partial() {
        let mut ctx = Context::new();
        ctx.insert("total", &5usize);
        ctx.insert("enabled_count", &3usize);
        ctx.insert("disabled_count", &2usize);
        ctx.insert("managed_count", &1usize);
        let html = render_partial("partials/stats.html", &ctx);
        assert!(html.contains("stats-frame"));
        assert!(html.contains(">5<"));
        assert!(html.contains(">3<"));
    }

    #[test]
    fn render_empty_state_has_wrapper_id() {
        let html = render_partial("partials/empty_state.html", &Context::new());
        assert!(html.contains(r#"id="app-table-wrapper""#));
    }

    #[test]
    fn render_toast_partial() {
        let mut ctx = Context::new();
        ctx.insert("message", "test msg");
        ctx.insert("success", &true);
        let html = render_partial("partials/toast.html", &ctx);
        assert!(html.contains("test msg"));
        assert!(html.contains("emerald"));
    }
}
