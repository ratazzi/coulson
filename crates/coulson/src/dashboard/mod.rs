use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use serde::Serialize;
use tera::{Context, Tera};
use tokio::sync::broadcast;

use crate::domain::{AppKind, AppSpec, BackendTarget};
use crate::runtime;
use crate::scanner;
use crate::SharedState;

// ---------------------------------------------------------------------------
// Tera template engine
// ---------------------------------------------------------------------------

/// In debug builds, reload templates from disk on every request so you can
/// edit HTML and refresh the browser without recompiling.
/// In release builds, templates are compiled into the binary via include_str!.
fn templates() -> &'static Tera {
    #[cfg(debug_assertions)]
    {
        use std::path::Path;

        // Tera glob relative to the crate source directory.
        // CARGO_MANIFEST_DIR is set at compile time but the path stays valid
        // as long as you run from a normal cargo build (not a relocated binary).
        const TEMPLATE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/dashboard/templates");

        // Leak a fresh Tera on every call so the returned reference is 'static.
        // The tiny allocation is negligible for dev use.
        let glob = format!("{}/**/*.html", TEMPLATE_DIR);
        let mut tera = Tera::new(&glob).unwrap_or_else(|e| {
            tracing::error!("template reload error: {e}");
            Tera::default()
        });
        // Tera::new uses filesystem paths as template names; remap them to
        // the short names used by the rest of the code (e.g. "pages/index.html").
        let prefix = format!("{}/", TEMPLATE_DIR);
        let renames: Vec<(String, Option<String>)> = tera
            .get_template_names()
            .filter_map(|name| {
                let short = name.strip_prefix(&prefix)?;
                Some((name.to_string(), Some(short.to_string())))
            })
            .collect();
        if !renames.is_empty() {
            // Re-read with short names by adding raw templates read from disk.
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

// ---------------------------------------------------------------------------
// View models (serializable structs for template context)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AppView {
    id: String,
    name: String,
    domain: String,
    domain_href: String,
    path_prefix: Option<String>,
    target_display: String,
    target_port: Option<u16>,
    kind_label: &'static str,
    enabled: bool,
    tunnel_url: Option<String>,
    tunnel_exposed: bool,
    tunnel_mode: String,
    app_tunnel_id: Option<String>,
    app_tunnel_domain: Option<String>,
    cors_enabled: bool,
    spa_rewrite: bool,
    basic_auth_user: Option<String>,
    timeout_display: String,
    listen_port: Option<u16>,
    inspect_enabled: bool,
}

#[derive(Serialize)]
struct UrlView {
    href: String,
    is_link: bool,
}

impl AppView {
    fn from_spec(app: &AppSpec, port: u16) -> Self {
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
            spa_rewrite: app.spa_rewrite,
            basic_auth_user: app.basic_auth_user.clone(),
            timeout_display: app
                .timeout_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "default".to_string()),
            listen_port: app.listen_port,
            inspect_enabled: app.inspect_enabled,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns true if the host matches the dashboard's dedicated domain
/// (`dashboard.{suffix}`).
pub fn is_dashboard_host(host: &str, domain_suffix: &str) -> bool {
    let dashboard_host = format!("dashboard.{domain_suffix}");
    host == dashboard_host
}

/// Returns true if the host matches the "default" entry point:
/// bare domain suffix (e.g. "coulson.local") or IP direct access.
pub fn is_default_host(host: &str, domain_suffix: &str) -> bool {
    host == domain_suffix
        || host == "127.0.0.1"
        || host == "localhost"
        || host == "::1"
        || host == "[::1]"
}

/// Handle an incoming dashboard request. Writes the full HTTP response.
pub async fn handle(session: &mut Session, state: &SharedState) -> Result<()> {
    let path = session.req_header().uri.path().to_owned();
    let method = session.req_header().method.as_str().to_owned();

    match method.as_str() {
        "GET" => {
            if path == "/" {
                return page_index(session, state).await;
            }
            if path == "/warnings" {
                return page_warnings(session, state).await;
            }
            // /apps/{id}/requests/stream (SSE)
            if let Some(id) = parse_app_requests_stream(&path) {
                return sse_requests(session, state, id).await;
            }
            // /apps/{id}/requests/{req_id}
            if let Some((app_id, req_id)) = parse_app_request_detail(&path) {
                return page_request_detail(session, state, app_id, req_id).await;
            }
            // /apps/{id}/requests
            if let Some(id) = parse_app_requests(&path) {
                return page_requests(session, state, id).await;
            }
            if let Some(id) = strip_app_name(&path) {
                return page_app_detail(session, state, id).await;
            }
            write_html(session, 404, &render_not_found(state)).await
        }
        "POST" => {
            if path == "/scan" {
                return action_scan(session, state).await;
            }
            // /apps/{id}/requests/{req_id}/replay
            if let Some((app_id, req_id)) = parse_app_request_replay(&path) {
                return action_replay(session, state, app_id, req_id).await;
            }
            // /apps/{id}/requests/clear
            if let Some(id) = parse_app_requests_clear(&path) {
                return action_clear_requests(session, state, id).await;
            }
            if let Some((id, action)) = parse_app_action(&path) {
                match action {
                    "toggle" => action_toggle(session, state, id).await,
                    "delete" => action_delete(session, state, id).await,
                    "delete-go" => action_delete_redirect(session, state, id).await,
                    "toggle-cors" => {
                        action_toggle_bool(session, state, id, SettingKind::Cors).await
                    }
                    "toggle-spa" => action_toggle_bool(session, state, id, SettingKind::Spa).await,
                    "toggle-inspect" => action_toggle_inspect(session, state, id).await,
                    _ => write_html(session, 404, &render_not_found(state)).await,
                }
            } else {
                write_html(session, 404, &render_not_found(state)).await
            }
        }
        _ => {
            write_html(
                session,
                405,
                &render_page("pages/not_found.html", state, |_| {}),
            )
            .await
        }
    }
}

/// Which boolean setting to toggle on the detail page.
enum SettingKind {
    Cors,
    Spa,
}

/// Extract bare app id from `/apps/<id>` (no trailing slash / action).
fn strip_app_name(path: &str) -> Option<&str> {
    let id = path.strip_prefix("/apps/")?;
    if id.is_empty() || id.contains('/') {
        return None;
    }
    Some(id)
}

fn parse_app_action(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/apps/")?;
    let (id, action) = rest.rsplit_once('/')?;
    if id.is_empty() || id.contains('/') {
        return None;
    }
    Some((id, action))
}

/// Match `/apps/{id}/requests`
fn parse_app_requests(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/apps/")?;
    let (id, tail) = rest.split_once('/')?;
    if id.is_empty() {
        return None;
    }
    if tail == "requests" {
        Some(id)
    } else {
        None
    }
}

/// Match `/apps/{id}/requests/{req_id}`
fn parse_app_request_detail(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/apps/")?;
    let (id, tail) = rest.split_once("/requests/")?;
    if id.is_empty() || tail.is_empty() || tail.contains('/') {
        return None;
    }
    Some((id, tail))
}

/// Match `/apps/{id}/requests/{req_id}/replay`
fn parse_app_request_replay(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/apps/")?;
    let (id, tail) = rest.split_once("/requests/")?;
    if id.is_empty() {
        return None;
    }
    let req_id = tail.strip_suffix("/replay")?;
    if req_id.is_empty() || req_id.contains('/') {
        return None;
    }
    Some((id, req_id))
}

/// Match `/apps/{id}/requests/clear`
fn parse_app_requests_clear(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/apps/")?;
    let (id, tail) = rest.split_once('/')?;
    if id.is_empty() {
        return None;
    }
    if tail == "requests/clear" {
        Some(id)
    } else {
        None
    }
}

/// Match `/apps/{id}/requests/stream`
fn parse_app_requests_stream(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/apps/")?;
    let (id, tail) = rest.split_once('/')?;
    if id.is_empty() {
        return None;
    }
    if tail == "requests/stream" {
        Some(id)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Template rendering helpers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TunnelStatusView {
    connected: bool,
    tunnel_domain: String,
    connections: Vec<TunnelConnView>,
    conn_count: usize,
    locations: String,
}

#[derive(Serialize)]
struct TunnelConnView {
    location: String,
    conn_index: u8,
    uptime_display: String,
}

fn tunnel_status_view(state: &SharedState) -> Option<TunnelStatusView> {
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

fn base_context(state: &SharedState) -> Context {
    let mut ctx = Context::new();
    ctx.insert("suffix", &state.domain_suffix);
    ctx.insert("warning_count", &get_warning_count(state));
    ctx.insert("version", env!("CARGO_PKG_VERSION"));
    if let Some(ts) = tunnel_status_view(state) {
        ctx.insert("tunnel", &ts);
    }
    ctx
}

fn render_page(
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

fn render_not_found(state: &SharedState) -> String {
    render_page("pages/not_found.html", state, |ctx| {
        ctx.insert("title", "Not Found");
    })
}

fn render_partial(template: &str, ctx: &Context) -> String {
    templates().render(template, ctx).unwrap_or_default()
}

fn stats_context(apps: &[AppSpec]) -> Context {
    let total = apps.len();
    let enabled = apps.iter().filter(|a| a.enabled).count();
    let disabled = total - enabled;
    let managed = apps.iter().filter(|a| a.kind == AppKind::Asgi).count();
    let mut ctx = Context::new();
    ctx.insert("total", &total);
    ctx.insert("enabled_count", &enabled);
    ctx.insert("disabled_count", &disabled);
    ctx.insert("managed_count", &managed);
    ctx
}

fn app_views(apps: &[AppSpec], port: u16) -> Vec<AppView> {
    apps.iter().map(|a| AppView::from_spec(a, port)).collect()
}

// ---------------------------------------------------------------------------
// Page handlers
// ---------------------------------------------------------------------------

async fn page_index(session: &mut Session, state: &SharedState) -> Result<()> {
    let apps = state.store.list_all().unwrap_or_default();
    let port = state.listen_http.port();
    let page = render_page("pages/index.html", state, |ctx| {
        ctx.insert("title", "Apps");
        ctx.insert("active_nav", "apps");
        ctx.extend(stats_context(&apps));
        ctx.insert("apps", &app_views(&apps, port));
    });
    write_html(session, 200, &page).await
}

async fn page_warnings(session: &mut Session, state: &SharedState) -> Result<()> {
    let warnings = runtime::read_scan_warnings(&state.scan_warnings_path)
        .ok()
        .flatten();
    let page = render_page("pages/warnings.html", state, |ctx| {
        ctx.insert("title", "Warnings");
        ctx.insert("active_nav", "warnings");
        if let Some(ref w) = warnings {
            ctx.insert("has_warnings", &true);
            ctx.insert("scan", &w.scan);
            ctx.insert("conflict_domains", &w.scan.conflict_domains);
            ctx.insert("parse_warnings", &w.scan.parse_warnings);
        } else {
            ctx.insert("has_warnings", &false);
            ctx.insert("conflict_domains", &Vec::<String>::new());
            ctx.insert("parse_warnings", &Vec::<String>::new());
        }
    });
    write_html(session, 200, &page).await
}

async fn page_app_detail(session: &mut Session, state: &SharedState, id: &str) -> Result<()> {
    let app = match state.store.get_by_name(id) {
        Ok(Some(app)) => app,
        _ => {
            return write_html(session, 404, &render_not_found(state)).await;
        }
    };
    let port = state.listen_http.port();
    let https_port = state.listen_https.map(|a| a.port());
    let app_view = AppView::from_spec(&app, port);
    let urls = build_urls(&app, port, https_port, &state.domain_suffix);
    let title = format!("{} — Detail", app.domain.0);
    let page = render_page("pages/app_detail.html", state, |ctx| {
        ctx.insert("title", &title);
        ctx.insert("app", &app_view);
        ctx.insert("urls", &urls);
    });
    write_html(session, 200, &page).await
}

fn build_urls(
    app: &AppSpec,
    port: u16,
    https_port: Option<u16>,
    domain_suffix: &str,
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
        BackendTarget::Tcp { host, port } => {
            urls.push(UrlView {
                href: format!("http://{host}:{port}/"),
                is_link: true,
            });
        }
        BackendTarget::UnixSocket { path } => {
            urls.push(UrlView {
                href: format!("unix://{path}"),
                is_link: false,
            });
        }
        BackendTarget::StaticDir { root } => {
            urls.push(UrlView {
                href: format!("file://{root}"),
                is_link: false,
            });
        }
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
        } else {
            let dot_suffix = format!(".{domain_suffix}");
            let _prefix = if app.domain.0.ends_with(&dot_suffix) {
                app.domain.0.trim_end_matches(&dot_suffix).to_string()
            } else {
                app.domain.0.clone()
            };
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

// ---------------------------------------------------------------------------
// Action handlers (return Turbo Streams)
// ---------------------------------------------------------------------------

async fn action_toggle(session: &mut Session, state: &SharedState, id: &str) -> Result<()> {
    let app = match state.store.get_by_name(id) {
        Ok(Some(app)) => app,
        _ => return write_html(session, 404, "Not found").await,
    };

    let new_enabled = !app.enabled;
    if state.store.set_enabled(app.id.0, new_enabled).is_err() {
        return write_html(session, 500, "Toggle failed").await;
    }
    let _ = state.reload_routes();

    let updated = state
        .store
        .get_by_name(id)
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            let mut a = app.clone();
            a.enabled = new_enabled;
            a
        });

    let port = state.listen_http.port();
    let all = state.store.list_all().unwrap_or_default();

    let row_ctx = {
        let mut ctx = Context::new();
        ctx.insert("app", &AppView::from_spec(&updated, port));
        ctx
    };
    let stats_ctx = stats_context(&all);

    let mut streams = turbo_replace(
        &format!("app-row-{id}"),
        &render_partial("partials/app_row.html", &row_ctx),
    );
    streams.push_str(&turbo_replace(
        "stats-frame",
        &render_partial("partials/stats.html", &stats_ctx),
    ));
    write_turbo_stream(session, &streams).await
}

async fn action_delete(session: &mut Session, state: &SharedState, id: &str) -> Result<()> {
    let app = match state.store.get_by_name(id) {
        Ok(Some(app)) => app,
        _ => return write_html(session, 404, "Not found").await,
    };
    let _ = state.store.delete(app.id.0);
    let _ = state.reload_routes();

    let all = state.store.list_all().unwrap_or_default();
    let stats_ctx = stats_context(&all);

    let mut streams = turbo_remove(&format!("app-row-{id}"));
    streams.push_str(&turbo_replace(
        "stats-frame",
        &render_partial("partials/stats.html", &stats_ctx),
    ));
    if all.is_empty() {
        streams.push_str(&turbo_replace(
            "app-table-wrapper",
            &render_partial("partials/empty_state.html", &Context::new()),
        ));
    }
    write_turbo_stream(session, &streams).await
}

async fn action_scan(session: &mut Session, state: &SharedState) -> Result<()> {
    let stats = scanner::sync_from_apps_root(state);
    if let Ok(ref s) = stats {
        let _ = runtime::write_scan_warnings(&state.scan_warnings_path, s);
        let _ = state.reload_routes();
    }

    let port = state.listen_http.port();
    let all = state.store.list_all().unwrap_or_default();
    let msg = match &stats {
        Ok(s) => format!(
            "Scan complete — {} discovered, {} inserted, {} updated, {} pruned",
            s.discovered, s.inserted, s.updated, s.pruned
        ),
        Err(e) => format!("Scan failed: {e}"),
    };

    let table_ctx = {
        let mut ctx = Context::new();
        ctx.insert("apps", &app_views(&all, port));
        ctx
    };
    let stats_ctx = stats_context(&all);
    let toast_ctx = {
        let mut ctx = Context::new();
        ctx.insert("message", &msg);
        ctx.insert("success", &stats.is_ok());
        ctx
    };

    let table_html = if all.is_empty() {
        render_partial("partials/empty_state.html", &Context::new())
    } else {
        render_partial("partials/app_table.html", &table_ctx)
    };

    let mut streams = turbo_replace("app-table-wrapper", &table_html);
    streams.push_str(&turbo_replace(
        "stats-frame",
        &render_partial("partials/stats.html", &stats_ctx),
    ));
    streams.push_str(&turbo_prepend(
        "toast-container",
        &render_partial("partials/toast.html", &toast_ctx),
    ));
    write_turbo_stream(session, &streams).await
}

/// Delete from the detail page — redirect to index after deletion.
async fn action_delete_redirect(
    session: &mut Session,
    state: &SharedState,
    id: &str,
) -> Result<()> {
    if let Ok(Some(app)) = state.store.get_by_name(id) {
        let _ = state.store.delete(app.id.0);
    }
    let _ = state.reload_routes();
    write_redirect(session, "/").await
}

/// Toggle a boolean setting and re-render the detail page.
async fn action_toggle_bool(
    session: &mut Session,
    state: &SharedState,
    id: &str,
    kind: SettingKind,
) -> Result<()> {
    let app = match state.store.get_by_name(id) {
        Ok(Some(a)) => a,
        _ => return write_redirect(session, "/").await,
    };

    let (cors, spa) = match kind {
        SettingKind::Cors => (Some(!app.cors_enabled), None),
        SettingKind::Spa => (None, Some(!app.spa_rewrite)),
    };

    let _ = state
        .store
        .update_settings(app.id.0, cors, None, None, spa, None);
    let _ = state.reload_routes();
    write_redirect(session, &format!("/apps/{id}")).await
}

// ---------------------------------------------------------------------------
// Request Inspector handlers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HeaderPair {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct RequestView {
    id: String,
    method: String,
    method_color: &'static str,
    path: String,
    query_string: Option<String>,
    status_code: Option<u16>,
    status_color: &'static str,
    response_time_ms: Option<u64>,
    timestamp_ms: i64,
    // Detail fields
    request_headers_display: String,
    request_body_display: Option<String>,
    response_headers_display: Option<String>,
    response_body_display: Option<String>,
    request_headers_list: Vec<HeaderPair>,
    response_headers_list: Vec<HeaderPair>,
}

impl RequestView {
    fn from_captured(req: &crate::store::CapturedRequest) -> Self {
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

        let request_headers_display = format_headers_json(&req.request_headers);
        let request_body_display = req.request_body.as_ref().map(|b| body_to_display(b));
        let response_headers_display = req
            .response_headers
            .as_ref()
            .map(|h| format_headers_json(h));
        let response_body_display = req.response_body.as_ref().map(|b| body_to_display(b));
        let request_headers_list = parse_headers_list(&req.request_headers);
        let response_headers_list = req
            .response_headers
            .as_ref()
            .map(|h| parse_headers_list(h))
            .unwrap_or_default();

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
            request_headers_display,
            request_body_display,
            response_headers_display,
            response_body_display,
            request_headers_list,
            response_headers_list,
        }
    }
}

#[derive(Serialize)]
struct ReplayView {
    status_code: u16,
    status_color: &'static str,
    body_display: Option<String>,
}

fn format_headers_json(json_str: &str) -> String {
    let headers: std::collections::HashMap<String, String> =
        serde_json::from_str(json_str).unwrap_or_default();
    let mut lines: Vec<String> = headers.iter().map(|(k, v)| format!("{k}: {v}")).collect();
    lines.sort();
    lines.join("\n")
}

fn parse_headers_list(json_str: &str) -> Vec<HeaderPair> {
    let headers: std::collections::HashMap<String, String> =
        serde_json::from_str(json_str).unwrap_or_default();
    let mut pairs: Vec<HeaderPair> = headers
        .into_iter()
        .map(|(name, value)| HeaderPair { name, value })
        .collect();
    pairs.sort_by(|a, b| a.name.cmp(&b.name));
    pairs
}

fn body_to_display(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => {
            // Try to pretty-print JSON
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(s) {
                serde_json::to_string_pretty(&val).unwrap_or_else(|_| s.to_string())
            } else {
                s.to_string()
            }
        }
        Err(_) => {
            // Show hex dump for binary data (first 512 bytes)
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

fn status_color_for(code: u16) -> &'static str {
    match code {
        c if c < 300 => {
            "bg-emerald-50 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
        }
        c if c < 400 => "bg-blue-50 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300",
        c if c < 500 => "bg-amber-50 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300",
        _ => "bg-red-50 text-red-700 dark:bg-red-900/40 dark:text-red-300",
    }
}

async fn page_requests(session: &mut Session, state: &SharedState, id: &str) -> Result<()> {
    let app = match state.store.get_by_name(id) {
        Ok(Some(app)) => app,
        _ => return write_html(session, 404, &render_not_found(state)).await,
    };
    let port = state.listen_http.port();
    let app_view = AppView::from_spec(&app, port);
    let requests = state
        .store
        .list_request_logs(app.id.0, state.inspect_max_requests)
        .unwrap_or_default();
    let request_count = requests.len();
    let request_views: Vec<RequestView> = requests.iter().map(RequestView::from_captured).collect();

    let page = render_page("pages/requests.html", state, |ctx| {
        ctx.insert("title", &format!("Requests — {}", app.name));
        ctx.insert("app", &app_view);
        ctx.insert("requests", &request_views);
        ctx.insert("request_count", &request_count);
    });
    write_html(session, 200, &page).await
}

async fn page_request_detail(
    session: &mut Session,
    state: &SharedState,
    app_id: &str,
    req_id: &str,
) -> Result<()> {
    let app = match state.store.get_by_name(app_id) {
        Ok(Some(app)) => app,
        _ => return write_html(session, 404, &render_not_found(state)).await,
    };
    let captured = match state.store.get_request_log(req_id) {
        Ok(Some(r)) => r,
        _ => return write_html(session, 404, &render_not_found(state)).await,
    };
    let port = state.listen_http.port();
    let app_view = AppView::from_spec(&app, port);
    let req_view = RequestView::from_captured(&captured);

    let page = render_page("pages/request_detail.html", state, |ctx| {
        ctx.insert(
            "title",
            &format!("{} {} — Detail", captured.method, captured.path),
        );
        ctx.insert("app", &app_view);
        ctx.insert("req", &req_view);
    });
    write_html(session, 200, &page).await
}

async fn action_toggle_inspect(session: &mut Session, state: &SharedState, id: &str) -> Result<()> {
    let app = match state.store.get_by_name(id) {
        Ok(Some(a)) => a,
        _ => return write_redirect(session, "/").await,
    };
    let _ = state
        .store
        .set_inspect_enabled(app.id.0, !app.inspect_enabled);
    let _ = state.reload_routes();
    write_redirect(session, &format!("/apps/{id}/requests")).await
}

async fn action_clear_requests(session: &mut Session, state: &SharedState, id: &str) -> Result<()> {
    if let Ok(Some(app)) = state.store.get_by_name(id) {
        let _ = state.store.delete_request_logs_for_app(app.id.0);
    }
    write_redirect(session, &format!("/apps/{id}/requests")).await
}

async fn action_replay(
    session: &mut Session,
    state: &SharedState,
    app_id: &str,
    req_id: &str,
) -> Result<()> {
    let app = match state.store.get_by_name(app_id) {
        Ok(Some(app)) => app,
        _ => return write_html(session, 404, &render_not_found(state)).await,
    };
    let captured = match state.store.get_request_log(req_id) {
        Ok(Some(r)) => r,
        _ => return write_html(session, 404, &render_not_found(state)).await,
    };

    // Build replay URL from app's backend target
    let base_url = match &app.target {
        BackendTarget::Tcp { host, port } => format!("http://{host}:{port}"),
        BackendTarget::UnixSocket { .. } => {
            // reqwest doesn't support UDS easily; show error
            return show_replay_error(
                session,
                state,
                &app,
                &captured,
                "Replay not supported for Unix socket targets",
            )
            .await;
        }
        _ => {
            return show_replay_error(
                session,
                state,
                &app,
                &captured,
                "Replay not supported for this target type",
            )
            .await;
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

    // Add original headers (skip host and content-length)
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

    let replay_result = req_builder.send().await;

    let port = state.listen_http.port();
    let app_view = AppView::from_spec(&app, port);
    let req_view = RequestView::from_captured(&captured);

    let replay_view = match replay_result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body_bytes = resp.bytes().await.unwrap_or_default();
            let body_display = if body_bytes.is_empty() {
                None
            } else {
                Some(body_to_display(&body_bytes))
            };
            ReplayView {
                status_code: status,
                status_color: status_color_for(status),
                body_display,
            }
        }
        Err(e) => ReplayView {
            status_code: 0,
            status_color: "bg-red-50 text-red-700 dark:bg-red-900/40 dark:text-red-300",
            body_display: Some(format!("Replay failed: {e}")),
        },
    };

    let page = render_page("pages/request_detail.html", state, |ctx| {
        ctx.insert(
            "title",
            &format!("{} {} — Replay", captured.method, captured.path),
        );
        ctx.insert("app", &app_view);
        ctx.insert("req", &req_view);
        ctx.insert("replay", &replay_view);
    });
    write_html(session, 200, &page).await
}

async fn show_replay_error(
    session: &mut Session,
    state: &SharedState,
    app: &crate::domain::AppSpec,
    captured: &crate::store::CapturedRequest,
    error_msg: &str,
) -> Result<()> {
    let port = state.listen_http.port();
    let app_view = AppView::from_spec(app, port);
    let req_view = RequestView::from_captured(captured);
    let replay_view = ReplayView {
        status_code: 0,
        status_color: "bg-red-50 text-red-700 dark:bg-red-900/40 dark:text-red-300",
        body_display: Some(error_msg.to_string()),
    };

    let page = render_page("pages/request_detail.html", state, |ctx| {
        ctx.insert(
            "title",
            &format!("{} {} — Replay Error", captured.method, captured.path),
        );
        ctx.insert("app", &app_view);
        ctx.insert("req", &req_view);
        ctx.insert("replay", &replay_view);
    });
    write_html(session, 200, &page).await
}

// ---------------------------------------------------------------------------
// SSE handler
// ---------------------------------------------------------------------------

async fn sse_requests(session: &mut Session, state: &SharedState, app_name: &str) -> Result<()> {
    let numeric_id = match state.store.get_by_name(app_name) {
        Ok(Some(app)) => app.id.0,
        _ => return write_html(session, 404, "Not found").await,
    };

    let mut resp = ResponseHeader::build(200, None)?;
    resp.insert_header("content-type", "text/event-stream")?;
    resp.insert_header("cache-control", "no-cache")?;
    resp.insert_header("x-accel-buffering", "no")?;
    session.write_response_header(Box::new(resp), false).await?;

    let mut rx = state.inspect_tx.subscribe();

    loop {
        match rx.recv().await {
            Ok(event) if event.app_id == numeric_id => {
                let data = serde_json::to_string(&event).unwrap_or_default();
                let sse = format!("data: {data}\n\n");
                if session
                    .write_response_body(Some(Bytes::from(sse)), false)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(_) => continue,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }

    let _ = session.write_response_body(Some(Bytes::new()), true).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

async fn write_redirect(session: &mut Session, location: &str) -> Result<()> {
    let mut resp = ResponseHeader::build(303, None)?;
    resp.insert_header("location", location)?;
    resp.insert_header("content-length", "0")?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::new()), true)
        .await?;
    Ok(())
}

async fn write_html(session: &mut Session, status: u16, body: &str) -> Result<()> {
    let bytes = body.as_bytes();
    let mut resp = ResponseHeader::build(status, None)?;
    resp.insert_header("content-type", "text/html; charset=utf-8")?;
    resp.insert_header("content-length", bytes.len().to_string())?;
    resp.insert_header("cache-control", "no-cache, no-store")?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::copy_from_slice(bytes)), true)
        .await?;
    Ok(())
}

async fn write_turbo_stream(session: &mut Session, body: &str) -> Result<()> {
    let bytes = body.as_bytes();
    let mut resp = ResponseHeader::build(200, None)?;
    resp.insert_header("content-type", "text/vnd.turbo-stream.html; charset=utf-8")?;
    resp.insert_header("content-length", bytes.len().to_string())?;
    resp.insert_header("cache-control", "no-cache, no-store")?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::copy_from_slice(bytes)), true)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Turbo Stream helpers
// ---------------------------------------------------------------------------

fn turbo_replace(target: &str, content: &str) -> String {
    format!(
        r#"<turbo-stream action="replace" target="{target}"><template>{content}</template></turbo-stream>"#
    )
}

fn turbo_remove(target: &str) -> String {
    format!(r#"<turbo-stream action="remove" target="{target}"></turbo-stream>"#)
}

fn turbo_prepend(target: &str, content: &str) -> String {
    format!(
        r#"<turbo-stream action="prepend" target="{target}"><template>{content}</template></turbo-stream>"#
    )
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

fn format_target(target: &BackendTarget) -> String {
    match target {
        BackendTarget::Tcp { host, port } => format!("{host}:{port}"),
        BackendTarget::UnixSocket { path } => {
            let short = path.rsplit('/').next().unwrap_or(path);
            format!("unix:{short}")
        }
        BackendTarget::StaticDir { root } => {
            let short = root.rsplit('/').next().unwrap_or(root);
            format!("dir:{short}")
        }
        BackendTarget::Managed { root, .. } => {
            let short = root.rsplit('/').next().unwrap_or(root);
            format!("managed:{short}")
        }
    }
}

/// Is this a proxy target (Tcp/UnixSocket) under the "Static" kind umbrella?
fn is_proxy_target(target: &BackendTarget) -> bool {
    matches!(
        target,
        BackendTarget::Tcp { .. } | BackendTarget::UnixSocket { .. }
    )
}

fn effective_kind_label(kind: AppKind, target: &BackendTarget) -> &'static str {
    match kind {
        AppKind::Static if is_proxy_target(target) => "Proxy",
        AppKind::Static => "Static",
        AppKind::Rack => "Rack",
        AppKind::Asgi => "ASGI",
        AppKind::Container => "Container",
    }
}

fn get_warning_count(state: &SharedState) -> usize {
    runtime::read_scan_warnings(&state.scan_warnings_path)
        .ok()
        .flatten()
        .map(|w| w.scan.warning_count)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_host_matches_dedicated_subdomain() {
        assert!(is_dashboard_host(
            "dashboard.coulson.local",
            "coulson.local"
        ));
        assert!(!is_dashboard_host("coulson.local", "coulson.local"));
        assert!(!is_dashboard_host("myapp.coulson.local", "coulson.local"));
        assert!(!is_dashboard_host("127.0.0.1", "coulson.local"));
    }

    #[test]
    fn default_host_matches_bare_suffix_and_loopback() {
        assert!(is_default_host("coulson.local", "coulson.local"));
        assert!(is_default_host("127.0.0.1", "coulson.local"));
        assert!(is_default_host("localhost", "coulson.local"));
        assert!(is_default_host("::1", "coulson.local"));
        assert!(is_default_host("[::1]", "coulson.local"));
        assert!(!is_default_host("myapp.coulson.local", "coulson.local"));
        assert!(!is_default_host("dashboard.coulson.local", "coulson.local"));
    }

    #[test]
    fn parse_app_action_works() {
        assert_eq!(
            parse_app_action("/apps/abc-123/toggle"),
            Some(("abc-123", "toggle"))
        );
        assert_eq!(
            parse_app_action("/apps/abc-123/delete"),
            Some(("abc-123", "delete"))
        );
        assert_eq!(parse_app_action("/apps//toggle"), None);
        assert_eq!(parse_app_action("/other/path"), None);
    }

    #[test]
    fn format_target_display() {
        assert_eq!(
            format_target(&BackendTarget::Tcp {
                host: "127.0.0.1".to_string(),
                port: 5006
            }),
            "127.0.0.1:5006"
        );
        assert_eq!(
            format_target(&BackendTarget::UnixSocket {
                path: "/tmp/app.sock".to_string()
            }),
            "unix:app.sock"
        );
        assert_eq!(
            format_target(&BackendTarget::StaticDir {
                root: "/var/www/public".to_string()
            }),
            "dir:public"
        );
        assert_eq!(
            format_target(&BackendTarget::Managed {
                app_id: 1,
                root: "/home/user/myapp".to_string(),
                kind: "asgi".to_string(),
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
    fn templates_parse_correctly() {
        // Force initialization — will panic if any template has syntax errors
        let _ = templates();
    }

    #[test]
    fn strip_app_name_works() {
        assert_eq!(strip_app_name("/apps/abc-123"), Some("abc-123"));
        assert_eq!(strip_app_name("/apps/abc-123/toggle"), None);
        assert_eq!(strip_app_name("/apps/"), None);
        assert_eq!(strip_app_name("/other/abc"), None);
    }

    #[test]
    fn render_stats_partial() {
        let ctx = {
            let mut c = Context::new();
            c.insert("total", &5usize);
            c.insert("enabled_count", &3usize);
            c.insert("disabled_count", &2usize);
            c.insert("managed_count", &1usize);
            c
        };
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
        let ctx = {
            let mut c = Context::new();
            c.insert("message", "test msg");
            c.insert("success", &true);
            c
        };
        let html = render_partial("partials/toast.html", &ctx);
        assert!(html.contains("test msg"));
        assert!(html.contains("emerald"));
    }
}
