use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;

use crate::domain::{AppKind, AppSpec, BackendTarget, TunnelMode};
use crate::runtime;
use crate::scanner;
use crate::SharedState;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns true if the host matches the dashboard's reserved domain
/// (the bare domain suffix with no app prefix, e.g. "coulson.local"),
/// or a loopback address (127.0.0.1 / localhost / [::1]).
pub fn is_dashboard_host(host: &str, domain_suffix: &str) -> bool {
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
    let not_found = || layout("Not Found", "", 0, &state.domain_suffix, NOT_FOUND_HTML);

    match method.as_str() {
        "GET" => {
            if path == "/" {
                return page_index(session, state).await;
            }
            if path == "/warnings" {
                return page_warnings(session, state).await;
            }
            // /apps/<id> → detail page
            if let Some(id) = strip_app_id(&path) {
                return page_app_detail(session, state, id).await;
            }
            write_html(session, 404, &not_found()).await
        }
        "POST" => {
            if path == "/scan" {
                return action_scan(session, state).await;
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
                    _ => write_html(session, 404, &not_found()).await,
                }
            } else {
                write_html(session, 404, &not_found()).await
            }
        }
        _ => {
            write_html(
                session,
                405,
                &layout(
                    "Error",
                    "",
                    0,
                    &state.domain_suffix,
                    "<p class=\"text-zinc-500\">Method not allowed.</p>",
                ),
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
fn strip_app_id(path: &str) -> Option<&str> {
    let id = path.strip_prefix("/apps/")?;
    if id.is_empty() || id.contains('/') {
        return None;
    }
    Some(id)
}

fn parse_app_action(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/apps/")?;
    let (id, action) = rest.rsplit_once('/')?;
    if id.is_empty() {
        return None;
    }
    Some((id, action))
}

// ---------------------------------------------------------------------------
// Page handlers
// ---------------------------------------------------------------------------

async fn page_index(session: &mut Session, state: &SharedState) -> Result<()> {
    let apps = state.store.list_all().unwrap_or_default();
    let wc = get_warning_count(state);
    let port = state.listen_http.port();
    let mut content = render_stats(&apps);
    content.push_str("\n<div class=\"mt-6\">");
    content.push_str(&render_app_table(&apps, port));
    content.push_str("</div>");
    let page = layout("Apps", "apps", wc, &state.domain_suffix, &content);
    write_html(session, 200, &page).await
}

async fn page_warnings(session: &mut Session, state: &SharedState) -> Result<()> {
    let warnings = runtime::read_scan_warnings(&state.scan_warnings_path)
        .ok()
        .flatten();
    let wc = warnings.as_ref().map(|w| w.scan.warning_count).unwrap_or(0);
    let content = render_warnings_content(&warnings);
    let page = layout("Warnings", "warnings", wc, &state.domain_suffix, &content);
    write_html(session, 200, &page).await
}

async fn page_app_detail(session: &mut Session, state: &SharedState, id: &str) -> Result<()> {
    let app = match state.store.get_by_id(id) {
        Ok(Some(app)) => app,
        _ => {
            let wc = get_warning_count(state);
            return write_html(
                session,
                404,
                &layout("Not Found", "", wc, &state.domain_suffix, NOT_FOUND_HTML),
            )
            .await;
        }
    };
    let wc = get_warning_count(state);
    let port = state.listen_http.port();
    let content = render_detail_content(&app, port, &state.domain_suffix);
    let title = format!("{} — Detail", app.domain.0);
    let page = layout(&title, "", wc, &state.domain_suffix, &content);
    write_html(session, 200, &page).await
}

// ---------------------------------------------------------------------------
// Action handlers (return Turbo Streams)
// ---------------------------------------------------------------------------

async fn action_toggle(session: &mut Session, state: &SharedState, id: &str) -> Result<()> {
    let app = match state.store.get_by_id(id) {
        Ok(Some(app)) => app,
        _ => return write_html(session, 404, "Not found").await,
    };

    let new_enabled = !app.enabled;
    if state.store.set_enabled(id, new_enabled).is_err() {
        return write_html(session, 500, "Toggle failed").await;
    }
    let _ = state.reload_routes();

    let updated = state.store.get_by_id(id).ok().flatten().unwrap_or_else(|| {
        let mut a = app.clone();
        a.enabled = new_enabled;
        a
    });

    let port = state.listen_http.port();
    let all = state.store.list_all().unwrap_or_default();
    let mut streams = turbo_replace(&format!("app-row-{}", id), &render_app_row(&updated, port));
    streams.push_str(&turbo_replace("stats-frame", &render_stats(&all)));
    write_turbo_stream(session, &streams).await
}

async fn action_delete(session: &mut Session, state: &SharedState, id: &str) -> Result<()> {
    let _ = state.store.delete(id);
    let _ = state.reload_routes();

    let all = state.store.list_all().unwrap_or_default();
    let mut streams = turbo_remove(&format!("app-row-{}", id));
    streams.push_str(&turbo_replace("stats-frame", &render_stats(&all)));
    if all.is_empty() {
        streams.push_str(&turbo_replace("app-table-wrapper", &render_empty_state()));
    }
    write_turbo_stream(session, &streams).await
}

async fn action_scan(session: &mut Session, state: &SharedState) -> Result<()> {
    let stats = scanner::sync_from_apps_root(state);
    if let Ok(ref s) = stats {
        let _ = runtime::write_scan_warnings(&state.scan_warnings_path, s);
        let _ = state.reload_routes();
        let scan_state = state.clone();
        tokio::spawn(async move {
            crate::control::reconcile_quick_tunnels(&scan_state).await;
        });
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

    let mut streams = turbo_replace("app-table-wrapper", &render_app_table(&all, port));
    streams.push_str(&turbo_replace("stats-frame", &render_stats(&all)));
    streams.push_str(&turbo_prepend(
        "toast-container",
        &render_toast(&msg, stats.is_ok()),
    ));
    write_turbo_stream(session, &streams).await
}

/// Delete from the detail page — redirect to index after deletion.
async fn action_delete_redirect(
    session: &mut Session,
    state: &SharedState,
    id: &str,
) -> Result<()> {
    let _ = state.store.delete(id);
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
    let app = match state.store.get_by_id(id) {
        Ok(Some(a)) => a,
        _ => return write_redirect(session, "/").await,
    };

    let (cors, spa) = match kind {
        SettingKind::Cors => (Some(!app.cors_enabled), None),
        SettingKind::Spa => (None, Some(!app.spa_rewrite)),
    };

    let _ = state.store.update_settings(id, cors, None, None, spa, None);
    let _ = state.reload_routes();
    write_redirect(session, &format!("/apps/{id}")).await
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
// Layout template
// ---------------------------------------------------------------------------

const NAV_ACTIVE: &str = "bg-zinc-100 text-zinc-900 dark:bg-zinc-800 dark:text-zinc-100";
const NAV_INACTIVE: &str = "text-zinc-600 hover:text-zinc-900 hover:bg-zinc-50 dark:text-zinc-400 dark:hover:text-zinc-100 dark:hover:bg-zinc-800/50";
const NOT_FOUND_HTML: &str = r#"<div class="rounded-xl border border-zinc-200 bg-white p-12 text-center shadow-sm dark:border-zinc-800 dark:bg-zinc-900"><p class="text-zinc-500 dark:text-zinc-400">Page not found.</p></div>"#;

fn layout(
    title: &str,
    active_nav: &str,
    warning_count: usize,
    domain_suffix: &str,
    content: &str,
) -> String {
    let nav_apps = if active_nav == "apps" {
        NAV_ACTIVE
    } else {
        NAV_INACTIVE
    };
    let nav_warnings = if active_nav == "warnings" {
        NAV_ACTIVE
    } else {
        NAV_INACTIVE
    };
    let warning_badge = if warning_count > 0 {
        format!(
            r#" <span class="ml-1 inline-flex items-center rounded-full bg-amber-100 px-1.5 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-400">{warning_count}</span>"#
        )
    } else {
        String::new()
    };

    LAYOUT_TEMPLATE
        .replace("{{TITLE}}", &esc(title))
        .replace("{{NAV_APPS_CLASS}}", nav_apps)
        .replace("{{NAV_WARNINGS_CLASS}}", nav_warnings)
        .replace("{{WARNING_BADGE}}", &warning_badge)
        .replace("{{SUFFIX}}", &esc(domain_suffix))
        .replace("{{CONTENT}}", content)
}

const LAYOUT_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}} — Coulson</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config = { darkMode: 'media' }</script>
<script type="module" src="https://cdn.jsdelivr.net/npm/@hotwired/turbo@8.0.4/dist/turbo.es2017-esm.js"></script>
<script type="module">
import { Application, Controller } from "https://cdn.jsdelivr.net/npm/@hotwired/stimulus@3.2.2/dist/stimulus.js"
const Stimulus = Application.start()
Stimulus.register("toast", class extends Controller {
  connect() {
    setTimeout(() => {
      this.element.style.transition = "opacity 0.5s ease-out"
      this.element.style.opacity = "0"
      setTimeout(() => this.element.remove(), 500)
    }, 4000)
  }
})
</script>
<style>
  turbo-frame { display: contents; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .animate-spin-slow { animation: spin 1.5s linear infinite; }
</style>
</head>
<body class="bg-zinc-50 text-zinc-900 antialiased min-h-screen dark:bg-zinc-950 dark:text-zinc-50">
<div id="toast-container" class="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm"></div>
<header class="sticky top-0 z-40 border-b border-zinc-200 bg-white/80 backdrop-blur supports-[backdrop-filter]:bg-white/60 dark:border-zinc-800 dark:bg-zinc-950/80">
  <div class="mx-auto max-w-6xl flex items-center justify-between px-6 h-14">
    <div class="flex items-center gap-6">
      <a href="/" class="font-semibold text-base tracking-tight flex items-center gap-2">
        <span class="inline-flex items-center justify-center h-6 w-6 rounded bg-zinc-900 text-white text-xs font-bold dark:bg-zinc-100 dark:text-zinc-900">B</span>
        Coulson
      </a>
      <nav class="flex items-center gap-1">
        <a href="/" data-turbo-action="advance" class="text-sm font-medium px-3 py-1.5 rounded-md transition-colors {{NAV_APPS_CLASS}}">Apps</a>
        <a href="/warnings" data-turbo-action="advance" class="text-sm font-medium px-3 py-1.5 rounded-md transition-colors {{NAV_WARNINGS_CLASS}}">Warnings{{WARNING_BADGE}}</a>
      </nav>
    </div>
    <div class="flex items-center gap-3">
      <span class="hidden sm:inline text-xs text-zinc-400 dark:text-zinc-600 font-mono">.{{SUFFIX}}</span>
      <form method="post" action="/scan">
        <button type="submit" class="inline-flex items-center gap-1.5 rounded-md bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white shadow-sm hover:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-900 transition-colors dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">
          <svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182M2.985 14.652"/></svg>
          Scan
        </button>
      </form>
    </div>
  </div>
</header>
<main class="mx-auto max-w-6xl px-6 py-8">
{{CONTENT}}
</main>
<footer class="mx-auto max-w-6xl px-6 py-6 mt-8 border-t border-zinc-200 dark:border-zinc-800">
  <p class="text-xs text-zinc-400 dark:text-zinc-600">Coulson — local development gateway</p>
</footer>
</body>
</html>"#;

// ---------------------------------------------------------------------------
// Stats cards
// ---------------------------------------------------------------------------

fn render_stats(apps: &[AppSpec]) -> String {
    let total = apps.len();
    let enabled = apps.iter().filter(|a| a.enabled).count();
    let disabled = total - enabled;
    let managed = apps.iter().filter(|a| a.kind == AppKind::Asgi).count();

    format!(
        r#"<div id="stats-frame" class="grid grid-cols-2 md:grid-cols-4 gap-4">
  <div class="rounded-xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
    <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Total Apps</p>
    <p class="text-2xl font-semibold mt-1">{total}</p>
  </div>
  <div class="rounded-xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
    <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Enabled</p>
    <p class="text-2xl font-semibold mt-1 text-emerald-600 dark:text-emerald-400">{enabled}</p>
  </div>
  <div class="rounded-xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
    <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Disabled</p>
    <p class="text-2xl font-semibold mt-1 text-zinc-400 dark:text-zinc-500">{disabled}</p>
  </div>
  <div class="rounded-xl border border-zinc-200 bg-white p-4 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
    <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Managed</p>
    <p class="text-2xl font-semibold mt-1 text-blue-600 dark:text-blue-400">{managed}</p>
  </div>
</div>"#
    )
}

// ---------------------------------------------------------------------------
// App table
// ---------------------------------------------------------------------------

fn render_app_table(apps: &[AppSpec], port: u16) -> String {
    if apps.is_empty() {
        return render_empty_state();
    }
    let rows = render_app_rows(apps, port);
    format!(
        r#"<div id="app-table-wrapper" class="rounded-xl border border-zinc-200 bg-white shadow-sm overflow-hidden dark:border-zinc-800 dark:bg-zinc-900">
  <table class="w-full">
    <thead>
      <tr class="border-b border-zinc-200 dark:border-zinc-800">
        <th class="text-left pl-4 pr-2 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider dark:text-zinc-400 w-8"></th>
        <th class="text-left px-3 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider dark:text-zinc-400">Name</th>
        <th class="text-left px-3 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider dark:text-zinc-400">Domain</th>
        <th class="text-left px-3 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider dark:text-zinc-400 hidden md:table-cell">Target</th>
        <th class="text-left px-3 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider dark:text-zinc-400 hidden sm:table-cell">Kind</th>
        <th class="text-right px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wider dark:text-zinc-400">Actions</th>
      </tr>
    </thead>
    <tbody id="app-table-body">
{rows}
    </tbody>
  </table>
</div>"#
    )
}

fn render_app_rows(apps: &[AppSpec], port: u16) -> String {
    let mut html = String::new();
    for app in apps {
        html.push_str(&render_app_row(app, port));
        html.push('\n');
    }
    html
}

fn render_app_row(app: &AppSpec, port: u16) -> String {
    let id = &app.id.0;
    let status_dot = if app.enabled {
        r#"<span class="relative flex h-2.5 w-2.5"><span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span><span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span></span>"#
    } else {
        r#"<span class="inline-flex h-2.5 w-2.5 rounded-full bg-zinc-300 dark:bg-zinc-600"></span>"#
    };

    let toggle_label = if app.enabled { "Disable" } else { "Enable" };
    let toggle_class = if app.enabled {
        "text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
    } else {
        "text-emerald-600 hover:text-emerald-700 dark:text-emerald-400 dark:hover:text-emerald-300"
    };

    let kind_text = kind_label(app.kind);
    let kind_color = match app.kind {
        AppKind::Asgi => "bg-blue-50 text-blue-700 ring-blue-700/10 dark:bg-blue-900/30 dark:text-blue-400 dark:ring-blue-400/20",
        AppKind::Container => "bg-purple-50 text-purple-700 ring-purple-700/10 dark:bg-purple-900/30 dark:text-purple-400 dark:ring-purple-400/20",
        AppKind::Rack => "bg-orange-50 text-orange-700 ring-orange-700/10 dark:bg-orange-900/30 dark:text-orange-400 dark:ring-orange-400/20",
        AppKind::Static => "bg-zinc-50 text-zinc-600 ring-zinc-500/10 dark:bg-zinc-800 dark:text-zinc-300 dark:ring-zinc-400/20",
    };

    let target_str = format_target(&app.target);
    let path_suffix = app
        .path_prefix
        .as_deref()
        .map(|p| {
            format!(
                "<span class=\"text-zinc-400 dark:text-zinc-500\">{}</span>",
                esc(p)
            )
        })
        .unwrap_or_default();

    let domain_href = {
        let path = app.path_prefix.as_deref().unwrap_or("/");
        format!("http://{}:{}{}", esc(&app.domain.0), port, esc(path))
    };

    let tunnel_badge = app.tunnel_url.as_deref().map(|url| {
        format!(
            r#" <a href="{}" target="_blank" rel="noopener" class="inline-flex items-center gap-0.5 text-xs text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300"><svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25"/></svg>tunnel</a>"#,
            esc(url)
        )
    }).unwrap_or_default();

    format!(
        r#"      <tr id="app-row-{id}" class="border-b border-zinc-100 last:border-0 hover:bg-zinc-50/50 transition-colors dark:border-zinc-800/50 dark:hover:bg-zinc-800/30">
        <td class="pl-4 pr-2 py-3">{status_dot}</td>
        <td class="px-3 py-3"><a href="/apps/{id}" class="text-sm font-medium hover:text-blue-600 dark:hover:text-blue-400 transition-colors">{name}</a></td>
        <td class="px-3 py-3">
          <a href="{domain_href}" target="_blank" rel="noopener" class="group inline-flex items-center gap-1">
            <code class="text-xs bg-zinc-100 text-zinc-700 px-1.5 py-0.5 rounded font-mono group-hover:bg-zinc-200 transition-colors dark:bg-zinc-800 dark:text-zinc-300 dark:group-hover:bg-zinc-700">{domain}{path_suffix}</code>
            <span class="text-zinc-300 group-hover:text-zinc-500 text-xs dark:text-zinc-600 dark:group-hover:text-zinc-400">↗</span>
          </a>{tunnel_badge}
        </td>
        <td class="px-3 py-3 hidden md:table-cell"><span class="text-xs text-zinc-500 dark:text-zinc-400 font-mono">{target}</span></td>
        <td class="px-3 py-3 hidden sm:table-cell"><span class="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset {kind_color}">{kind_text}</span></td>
        <td class="px-4 py-3 text-right">
          <div class="flex items-center justify-end gap-3">
            <form method="post" action="/apps/{id}/toggle"><button type="submit" class="text-xs font-medium transition-colors {toggle_class}">{toggle_label}</button></form>
            <form method="post" action="/apps/{id}/delete"><button type="submit" data-turbo-confirm="Delete {name_raw}?" class="text-xs font-medium text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 transition-colors">Delete</button></form>
          </div>
        </td>
      </tr>"#,
        id = esc(id),
        status_dot = status_dot,
        name = esc(&app.name),
        name_raw = esc(&app.name),
        domain = esc(&app.domain.0),
        domain_href = domain_href,
        path_suffix = path_suffix,
        tunnel_badge = tunnel_badge,
        target = esc(&target_str),
        kind_color = kind_color,
        kind_text = kind_text,
        toggle_class = toggle_class,
        toggle_label = toggle_label,
    )
}

fn render_empty_state() -> String {
    r#"<div id="app-table-wrapper" class="rounded-xl border border-zinc-200 bg-white p-12 text-center shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
  <svg class="mx-auto h-10 w-10 text-zinc-300 dark:text-zinc-600" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M21 7.5l-2.25-1.313M21 7.5v2.25m0-2.25l-2.25 1.313M3 7.5l2.25-1.313M3 7.5l2.25 1.313M3 7.5v2.25m9 3l2.25-1.313M12 12.75l-2.25-1.313M12 12.75V15m0 6.75l2.25-1.313M12 21.75V15m0 0l-2.25 1.313M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5"/></svg>
  <p class="mt-3 text-sm font-medium text-zinc-500 dark:text-zinc-400">No apps registered</p>
  <p class="mt-1 text-xs text-zinc-400 dark:text-zinc-500">Add files to your apps directory or use the control API to get started.</p>
</div>"#.to_string()
}

// ---------------------------------------------------------------------------
// Detail page content
// ---------------------------------------------------------------------------

fn render_detail_content(app: &AppSpec, port: u16, domain_suffix: &str) -> String {
    let id = &app.id.0;
    let mut html = String::new();

    // Back link
    html.push_str(r#"<a href="/" class="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100 mb-6 transition-colors"><svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5"/></svg>Back to Apps</a>"#);

    // Header
    html.push_str(&format!(
        r#"<div class="flex items-start justify-between mb-8">
  <div>
    <h1 class="text-2xl font-semibold tracking-tight">{name}</h1>
    <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400 font-mono">{domain}</p>
  </div>
  <div class="flex items-center gap-3">{status_badge}
    <form method="post" action="/apps/{id}/toggle">
      <button type="submit" class="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium shadow-sm transition-colors {toggle_btn}">{toggle_label}</button>
    </form>
  </div>
</div>"#,
        name = esc(&app.name),
        domain = esc(&app.domain.0),
        id = esc(id),
        status_badge = if app.enabled {
            r#"<span class="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-700 ring-1 ring-inset ring-emerald-600/20 dark:bg-emerald-900/30 dark:text-emerald-400 dark:ring-emerald-400/20"><span class="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>Running</span>"#
        } else {
            r#"<span class="inline-flex items-center gap-1.5 rounded-full bg-zinc-100 px-3 py-1 text-xs font-medium text-zinc-600 ring-1 ring-inset ring-zinc-500/10 dark:bg-zinc-800 dark:text-zinc-400 dark:ring-zinc-400/20"><span class="h-1.5 w-1.5 rounded-full bg-zinc-400"></span>Stopped</span>"#
        },
        toggle_btn = if app.enabled {
            "bg-zinc-100 text-zinc-700 hover:bg-zinc-200 dark:bg-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-700"
        } else {
            "bg-emerald-600 text-white hover:bg-emerald-700 dark:bg-emerald-500 dark:hover:bg-emerald-400 dark:text-zinc-900"
        },
        toggle_label = if app.enabled { "Disable" } else { "Enable" },
    ));

    html.push_str(r#"<div class="grid gap-6">"#);

    // --- URLs ---
    html.push_str(&detail_section_urls(app, port, domain_suffix));

    // --- Info ---
    html.push_str(&detail_section_info(app));

    // --- Features ---
    html.push_str(&detail_section_features(app));

    // --- Tunnel ---
    html.push_str(&detail_section_tunnel(app));

    // --- Danger Zone ---
    html.push_str(&detail_section_danger(app));

    html.push_str("</div>");
    html
}

fn detail_section_urls(app: &AppSpec, port: u16, domain_suffix: &str) -> String {
    let proxy_url = {
        let path = app.path_prefix.as_deref().unwrap_or("/");
        format!("http://{}:{}{}", esc(&app.domain.0), port, esc(path))
    };
    let mut urls = vec![proxy_url];

    match &app.target {
        BackendTarget::Tcp { host, port } => {
            urls.push(format!("http://{}:{}/", esc(host), port));
        }
        BackendTarget::UnixSocket { path } => {
            urls.push(format!("unix://{}", esc(path)));
        }
        BackendTarget::StaticDir { root } => {
            urls.push(format!("file://{}", esc(root)));
        }
        _ => {}
    }

    // Tunnel URL
    if app.tunnel_mode.is_exposed() {
        if let Some(ref tunnel_domain) = app.app_tunnel_domain {
            urls.push(format!("https://{}", esc(tunnel_domain)));
        } else {
            // Named tunnel domain
            let dot_suffix = format!(".{}", domain_suffix);
            let prefix = if app.domain.0.ends_with(&dot_suffix) {
                app.domain.0.trim_end_matches(&dot_suffix).to_string()
            } else {
                app.domain.0.clone()
            };
            if let Some(ref url) = app.tunnel_url {
                urls.push(esc(url));
            } else if !prefix.is_empty() {
                // Show placeholder
            }
        }
    }
    if let Some(ref url) = app.tunnel_url {
        if !urls.contains(&esc(url)) {
            urls.push(esc(url));
        }
    }

    let rows: String = urls
        .iter()
        .enumerate()
        .map(|(i, url)| {
            let divider = if i > 0 {
                r#"<div class="border-t border-zinc-100 dark:border-zinc-800"></div>"#
            } else {
                ""
            };
            let is_external = url.starts_with("http://") || url.starts_with("https://");
            let link = if is_external {
                format!(
                    r#"<a href="{url}" target="_blank" rel="noopener" class="group inline-flex items-center gap-1.5 font-mono text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300">{url}<svg class="h-3.5 w-3.5 text-zinc-300 group-hover:text-blue-500 dark:text-zinc-600" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25"/></svg></a>"#
                )
            } else {
                format!(r#"<span class="font-mono text-sm text-zinc-600 dark:text-zinc-400">{url}</span>"#)
            };
            format!(
                r#"{divider}<div class="flex items-center justify-between px-5 py-3">{link}<button onclick="navigator.clipboard.writeText('{url}')" class="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors" title="Copy"><svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9.75a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"/></svg></button></div>"#
            )
        })
        .collect();

    detail_card("URLs", &rows)
}

fn detail_section_info(app: &AppSpec) -> String {
    let target_str = format_target(&app.target);
    let kind_text = kind_label(app.kind);
    let kind_badge = match app.kind {
        AppKind::Asgi => "bg-blue-50 text-blue-700 ring-blue-700/10 dark:bg-blue-900/30 dark:text-blue-400",
        AppKind::Container => "bg-purple-50 text-purple-700 ring-purple-700/10 dark:bg-purple-900/30 dark:text-purple-400",
        AppKind::Rack => "bg-orange-50 text-orange-700 ring-orange-700/10 dark:bg-orange-900/30 dark:text-orange-400",
        AppKind::Static => "bg-zinc-50 text-zinc-600 ring-zinc-500/10 dark:bg-zinc-800 dark:text-zinc-300",
    };

    let mut rows = Vec::new();

    rows.push(info_row(
        "Kind",
        &format!(
            r#"<span class="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset {kind_badge}">{kind_text}</span>"#
        ),
    ));
    rows.push(info_row(
        "Target",
        &format!(
            r#"<span class="font-mono text-sm">{}</span>"#,
            esc(&target_str)
        ),
    ));

    if let BackendTarget::Tcp { port, .. } = &app.target {
        rows.push(info_row(
            "Port",
            &format!(r#"<span class="font-mono text-sm">{port}</span>"#),
        ));
    }

    if let Some(ref prefix) = app.path_prefix {
        rows.push(info_row(
            "Path Prefix",
            &format!(r#"<span class="font-mono text-sm">{}</span>"#, esc(prefix)),
        ));
    }

    rows.push(info_row(
        "Timeout",
        &format!(
            r#"<span class="text-sm">{}</span>"#,
            app.timeout_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "default".to_string())
        ),
    ));

    if let Some(port) = app.listen_port {
        rows.push(info_row(
            "Listen Port",
            &format!(r#"<span class="font-mono text-sm">{port}</span>"#),
        ));
    }

    let body = rows.join(r#"<div class="border-t border-zinc-100 dark:border-zinc-800"></div>"#);
    detail_card("Info", &body)
}

fn detail_section_features(app: &AppSpec) -> String {
    let id = &app.id.0;
    let mut rows = Vec::new();

    rows.push(toggle_row(
        "CORS",
        app.cors_enabled,
        &format!("/apps/{}/toggle-cors", esc(id)),
    ));
    rows.push(toggle_row(
        "SPA Rewrite",
        app.spa_rewrite,
        &format!("/apps/{}/toggle-spa", esc(id)),
    ));

    let auth_value = match (&app.basic_auth_user, &app.basic_auth_pass) {
        (Some(user), Some(_)) => format!(
            r#"<span class="inline-flex items-center gap-1.5"><span class="h-1.5 w-1.5 rounded-full bg-emerald-500"></span><span class="font-mono text-sm">{}</span></span>"#,
            esc(user)
        ),
        _ => r#"<span class="text-sm text-zinc-400 dark:text-zinc-500">Off</span>"#.to_string(),
    };
    rows.push(info_row("Basic Auth", &auth_value));

    let body = rows.join(r#"<div class="border-t border-zinc-100 dark:border-zinc-800"></div>"#);
    detail_card("Features", &body)
}

fn detail_section_tunnel(app: &AppSpec) -> String {
    let mut rows = Vec::new();

    if let Some(ref url) = app.tunnel_url {
        rows.push(info_row(
            "Tunnel URL",
            &format!(
                r#"<a href="{}" target="_blank" rel="noopener" class="font-mono text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400">{}</a>"#,
                esc(url),
                esc(url)
            ),
        ));
    }

    if app.tunnel_mode.is_exposed() {
        rows.push(info_row(
            "Tunnel Mode",
            &format!(
                r#"<span class="text-sm">{}</span>"#,
                esc(app.tunnel_mode.as_str())
            ),
        ));
    }

    if let Some(ref tid) = app.app_tunnel_id {
        rows.push(info_row(
            "Tunnel ID",
            &format!(
                r#"<span class="font-mono text-xs text-zinc-500 dark:text-zinc-400">{}</span>"#,
                esc(tid)
            ),
        ));
    }
    if let Some(ref domain) = app.app_tunnel_domain {
        rows.push(info_row(
            "Tunnel Domain",
            &format!(
                r#"<a href="https://{d}" target="_blank" rel="noopener" class="font-mono text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400">{d}</a>"#,
                d = esc(domain)
            ),
        ));
    }

    let body = rows.join(r#"<div class="border-t border-zinc-100 dark:border-zinc-800"></div>"#);
    detail_card("Tunnel", &body)
}

fn detail_section_danger(app: &AppSpec) -> String {
    let id = &app.id.0;
    format!(
        r#"<div class="rounded-xl border border-red-200 bg-white shadow-sm dark:border-red-900/50 dark:bg-zinc-900">
  <div class="px-5 py-3 border-b border-red-100 dark:border-red-900/30">
    <h2 class="text-sm font-semibold text-red-600 dark:text-red-400">Danger Zone</h2>
  </div>
  <div class="px-5 py-4 flex items-center justify-between">
    <div>
      <p class="text-sm font-medium">Delete this app</p>
      <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">This will remove the app from Coulson. The underlying service is not affected.</p>
    </div>
    <form method="post" action="/apps/{id}/delete-go">
      <button type="submit" data-turbo-confirm="Delete {name}?" class="inline-flex items-center gap-1.5 rounded-md bg-red-600 px-3 py-1.5 text-sm font-medium text-white shadow-sm hover:bg-red-700 transition-colors">
        <svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/></svg>
        Delete
      </button>
    </form>
  </div>
</div>"#,
        id = esc(id),
        name = esc(&app.name),
    )
}

// Detail card wrapper
fn detail_card(title: &str, body: &str) -> String {
    format!(
        r#"<div class="rounded-xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
  <div class="px-5 py-3 border-b border-zinc-100 dark:border-zinc-800">
    <h2 class="text-xs font-semibold text-zinc-500 uppercase tracking-wider dark:text-zinc-400">{title}</h2>
  </div>
  {body}
</div>"#
    )
}

fn info_row(label: &str, value_html: &str) -> String {
    format!(
        r#"<div class="flex items-center justify-between px-5 py-3">
  <span class="text-sm text-zinc-500 dark:text-zinc-400">{label}</span>
  {value_html}
</div>"#
    )
}

fn toggle_row(label: &str, enabled: bool, action: &str) -> String {
    let (dot_color, text) = if enabled {
        ("bg-emerald-500", "On")
    } else {
        ("bg-zinc-300 dark:bg-zinc-600", "Off")
    };
    format!(
        r#"<div class="flex items-center justify-between px-5 py-3">
  <span class="text-sm text-zinc-500 dark:text-zinc-400">{label}</span>
  <form method="post" action="{action}">
    <button type="submit" class="inline-flex items-center gap-1.5 text-sm font-medium transition-colors hover:text-zinc-900 dark:hover:text-zinc-100">
      <span class="h-2 w-2 rounded-full {dot_color}"></span>
      {text}
    </button>
  </form>
</div>"#
    )
}

// ---------------------------------------------------------------------------
// Warnings page content
// ---------------------------------------------------------------------------

fn render_warnings_content(warnings: &Option<runtime::ScanWarningsFile>) -> String {
    let Some(w) = warnings else {
        return r#"<div class="rounded-xl border border-zinc-200 bg-white p-12 text-center shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
  <svg class="mx-auto h-10 w-10 text-zinc-300 dark:text-zinc-600" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"/></svg>
  <p class="mt-3 text-sm font-medium text-zinc-500 dark:text-zinc-400">No scan data available</p>
  <p class="mt-1 text-xs text-zinc-400 dark:text-zinc-500">Run a scan to check for issues.</p>
</div>"#.to_string();
    };

    let mut html = String::new();

    // Scan summary card
    html.push_str(&format!(
        r#"<div class="rounded-xl border border-zinc-200 bg-white p-6 shadow-sm mb-6 dark:border-zinc-800 dark:bg-zinc-900">
  <h2 class="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Last Scan Summary</h2>
  <dl class="mt-3 grid grid-cols-2 sm:grid-cols-5 gap-4">
    <div><dt class="text-xs text-zinc-500 dark:text-zinc-400">Discovered</dt><dd class="text-lg font-semibold">{}</dd></div>
    <div><dt class="text-xs text-zinc-500 dark:text-zinc-400">Inserted</dt><dd class="text-lg font-semibold text-emerald-600 dark:text-emerald-400">{}</dd></div>
    <div><dt class="text-xs text-zinc-500 dark:text-zinc-400">Updated</dt><dd class="text-lg font-semibold text-blue-600 dark:text-blue-400">{}</dd></div>
    <div><dt class="text-xs text-zinc-500 dark:text-zinc-400">Pruned</dt><dd class="text-lg font-semibold text-amber-600 dark:text-amber-400">{}</dd></div>
    <div><dt class="text-xs text-zinc-500 dark:text-zinc-400">Skipped (manual)</dt><dd class="text-lg font-semibold text-zinc-500">{}</dd></div>
  </dl>
</div>"#,
        w.scan.discovered,
        w.scan.inserted,
        w.scan.updated,
        w.scan.pruned,
        w.scan.skipped_manual,
    ));

    if !w.scan.has_issues {
        html.push_str(
            r#"<div class="rounded-xl border border-emerald-200 bg-emerald-50 p-8 text-center dark:border-emerald-800/50 dark:bg-emerald-900/20">
  <svg class="mx-auto h-8 w-8 text-emerald-500 dark:text-emerald-400" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
  <p class="mt-2 font-medium text-emerald-800 dark:text-emerald-300">All clear — no warnings</p>
</div>"#,
        );
        return html;
    }

    if !w.scan.conflict_domains.is_empty() {
        html.push_str(
            r#"<div class="rounded-xl border border-amber-200 bg-amber-50 p-6 mb-4 dark:border-amber-800/50 dark:bg-amber-900/20">
  <h3 class="text-sm font-semibold text-amber-800 dark:text-amber-300 flex items-center gap-2">
    <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/></svg>
    Domain Conflicts
  </h3>
  <ul class="mt-3 space-y-1">"#,
        );
        for domain in &w.scan.conflict_domains {
            html.push_str(&format!(
                r#"    <li class="text-sm text-amber-700 dark:text-amber-400 font-mono">{}</li>"#,
                esc(domain)
            ));
            html.push('\n');
        }
        html.push_str("  </ul>\n</div>\n");
    }

    if !w.scan.parse_warnings.is_empty() {
        html.push_str(
            r#"<div class="rounded-xl border border-amber-200 bg-amber-50 p-6 dark:border-amber-800/50 dark:bg-amber-900/20">
  <h3 class="text-sm font-semibold text-amber-800 dark:text-amber-300 flex items-center gap-2">
    <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/></svg>
    Parse Warnings
  </h3>
  <ul class="mt-3 space-y-1">"#,
        );
        for warn in &w.scan.parse_warnings {
            html.push_str(&format!(
                r#"    <li class="text-sm text-amber-700 dark:text-amber-400">{}</li>"#,
                esc(warn)
            ));
            html.push('\n');
        }
        html.push_str("  </ul>\n</div>\n");
    }

    html
}

// ---------------------------------------------------------------------------
// Toast notification
// ---------------------------------------------------------------------------

fn render_toast(message: &str, success: bool) -> String {
    let (border, icon_color, icon_path) = if success {
        (
            "border-emerald-200 dark:border-emerald-800/50",
            "text-emerald-500",
            r#"<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>"#,
        )
    } else {
        (
            "border-red-200 dark:border-red-800/50",
            "text-red-500",
            r#"<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"/>"#,
        )
    };
    format!(
        r#"<div data-controller="toast" class="pointer-events-auto rounded-lg border {border} bg-white px-4 py-3 shadow-lg dark:bg-zinc-900 flex items-start gap-3">
  <svg class="h-5 w-5 flex-shrink-0 {icon_color}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">{icon_path}</svg>
  <p class="text-sm text-zinc-700 dark:text-zinc-300">{message}</p>
</div>"#,
        border = border,
        icon_color = icon_color,
        icon_path = icon_path,
        message = esc(message),
    )
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

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

fn kind_label(kind: AppKind) -> &'static str {
    match kind {
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
    fn dashboard_host_matches_bare_suffix() {
        assert!(is_dashboard_host("coulson.local", "coulson.local"));
        assert!(!is_dashboard_host(
            "myapp.coulson.local",
            "coulson.local"
        ));
        assert!(!is_dashboard_host("other.test", "coulson.local"));
    }

    #[test]
    fn dashboard_host_matches_loopback() {
        assert!(is_dashboard_host("127.0.0.1", "coulson.local"));
        assert!(is_dashboard_host("localhost", "coulson.local"));
        assert!(is_dashboard_host("::1", "coulson.local"));
        assert!(is_dashboard_host("[::1]", "coulson.local"));
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
    fn html_escape_works() {
        assert_eq!(esc("<b>test</b>"), "&lt;b&gt;test&lt;/b&gt;");
        assert_eq!(esc("a&b"), "a&amp;b");
        assert_eq!(esc(r#"x="y""#), "x=&quot;y&quot;");
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
                app_id: "x".to_string(),
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
    fn layout_renders_with_placeholders() {
        let html = layout("Test", "apps", 3, "coulson.local", "<p>content</p>");
        assert!(html.contains("<title>Test — Coulson</title>"));
        assert!(html.contains("<p>content</p>"));
        assert!(html.contains(".coulson.local"));
        assert!(html.contains(">3<")); // warning badge
    }

    #[test]
    fn layout_no_warning_badge_when_zero() {
        let html = layout("Test", "apps", 0, "test.local", "");
        assert!(!html.contains("bg-amber-100")); // no badge
    }

    #[test]
    fn empty_state_has_wrapper_id() {
        let html = render_empty_state();
        assert!(html.contains(r#"id="app-table-wrapper""#));
    }

    #[test]
    fn strip_app_id_works() {
        assert_eq!(strip_app_id("/apps/abc-123"), Some("abc-123"));
        assert_eq!(strip_app_id("/apps/abc-123/toggle"), None); // has action
        assert_eq!(strip_app_id("/apps/"), None); // empty id
        assert_eq!(strip_app_id("/other/abc"), None); // wrong prefix
    }

    #[test]
    fn detail_card_renders_structure() {
        let html = detail_card("Test", "<p>body</p>");
        assert!(html.contains("Test"));
        assert!(html.contains("<p>body</p>"));
        assert!(html.contains("rounded-xl"));
    }

    #[test]
    fn toggle_row_shows_on_off() {
        let on = toggle_row("CORS", true, "/apps/x/toggle-cors");
        assert!(on.contains("On"));
        assert!(on.contains("bg-emerald-500"));

        let off = toggle_row("CORS", false, "/apps/x/toggle-cors");
        assert!(off.contains("Off"));
        assert!(!off.contains("bg-emerald-500"));
    }

    #[test]
    fn info_row_renders_label_and_value() {
        let html = info_row("Port", r#"<span class="font-mono">5006</span>"#);
        assert!(html.contains("Port"));
        assert!(html.contains("5006"));
    }
}
