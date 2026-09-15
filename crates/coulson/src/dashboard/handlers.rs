use std::convert::Infallible;

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use tera::Context;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use super::render::*;
use super::DashboardState;
use crate::domain::TunnelMode;
use crate::service;
use crate::SharedState;

const EMBEDDED_HEADER: &str = "x-coulson-embedded";
const EMBEDDED_BASE: &str = "/_coulson";

/// Detect embedded inspector mode from the `x-coulson-embedded` header.
/// Returns `(is_embedded, base_path)` for URL generation in templates.
fn embedded_base(headers: &HeaderMap, app_name: &str) -> (bool, String) {
    if headers.contains_key(EMBEDDED_HEADER) {
        (true, EMBEDDED_BASE.to_string())
    } else {
        (false, format!("/apps/{app_name}"))
    }
}

/// Return the last `max_lines` lines of `log_path`.
///
/// Only reads up to ~1 MiB from the tail, so arbitrarily large log files do
/// not cause full-file reads. Uses lossy UTF-8 decoding so non-UTF-8 bytes
/// (ANSI escapes, binary panic traces) are preserved as replacement
/// characters instead of causing the history to silently disappear.
fn read_log_tail_lines(log_path: &std::path::Path, max_lines: usize) -> Option<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    const TAIL_CAP: u64 = 1 << 20; // 1 MiB

    let mut file = std::fs::File::open(log_path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return Some(Vec::new());
    }
    let start_offset = len.saturating_sub(TAIL_CAP);
    file.seek(SeekFrom::Start(start_offset)).ok()?;
    let mut buf = Vec::with_capacity((len - start_offset) as usize);
    file.read_to_end(&mut buf).ok()?;
    // If we truncated the head, drop any partial leading line so we never
    // emit half of a log entry as if it were whole.
    let slice: &[u8] = if start_offset > 0 {
        match buf.iter().position(|&b| b == b'\n') {
            Some(idx) => &buf[idx + 1..],
            None => &[],
        }
    } else {
        &buf
    };
    let text = String::from_utf8_lossy(slice);
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let start = lines.len().saturating_sub(max_lines);
    Some(lines[start..].to_vec())
}

pub async fn favicon() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "image/svg+xml"),
            ("cache-control", "public, max-age=86400"),
        ],
        include_str!("templates/favicon.svg"),
    )
}

pub async fn page_index(State(state): State<DashboardState>) -> Html<String> {
    let apps = state.shared.store.list_all().unwrap_or_default();
    let port = state.shared.listen_http.port();
    let page = render_page("pages/index.html", &state.shared, |ctx| {
        ctx.insert("title", "Apps");
        ctx.insert("active_nav", "apps");
        ctx.extend(stats_context(&apps));
        ctx.insert(
            "apps",
            &app_views(&apps, port, state.shared.use_default_http_port()),
        );
        ctx.insert("error", "");
        ctx.insert("form_name", "");
        ctx.insert("form_target_value", "");
        ctx.insert("form_path_prefix", "");
        ctx.insert("form_timeout_ms", "");
    });
    Html(page)
}

pub async fn page_warnings(State(state): State<DashboardState>) -> Html<String> {
    let warnings = service::apps_warnings(&state.shared).ok().flatten();
    let page = render_page("pages/warnings.html", &state.shared, |ctx| {
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
    Html(page)
}

pub async fn page_app_detail(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Response {
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared)),
    };
    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port, state.shared.use_default_http_port());
    let title = format!("{} — Detail", app.domain.0);
    let page = render_page("pages/app_detail.html", &state.shared, |ctx| {
        ctx.insert("title", &title);
        ctx.insert("app", &app_view);
        ctx.insert("settings_error", "");
        ctx.insert(
            "form_timeout_ms",
            &app.timeout_ms.map(|v| v.to_string()).unwrap_or_default(),
        );
        ctx.insert(
            "form_listen_port",
            &app.listen_port.map(|v| v.to_string()).unwrap_or_default(),
        );
    });
    Html(page).into_response()
}

pub async fn page_requests(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared)),
    };
    let (embedded, base_path) = embedded_base(&headers, &id);
    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port, state.shared.use_default_http_port());
    let requests = state
        .shared
        .store
        .list_request_logs(app.id.0, state.shared.inspect_max_requests)
        .unwrap_or_default();
    let request_count = requests.len();
    let request_views: Vec<RequestView> = requests.iter().map(RequestView::from_captured).collect();

    let page = render_page("pages/requests.html", &state.shared, |ctx| {
        ctx.insert("title", &format!("Requests — {}", app.name));
        ctx.insert("app", &app_view);
        ctx.insert("requests", &request_views);
        ctx.insert("request_count", &request_count);
        ctx.insert("embedded", &embedded);
        ctx.insert("base_path", &base_path);
    });
    Html(page).into_response()
}

pub async fn page_request_detail(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path((app_id, req_id)): Path<(String, String)>,
) -> Response {
    let app = match state.shared.store.get_by_name(&app_id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared)),
    };
    let captured = match state.shared.store.get_request_log(&req_id) {
        Ok(Some(r)) if r.app_id == app.id.0 => r,
        _ => return html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared)),
    };
    let (embedded, base_path) = embedded_base(&headers, &app_id);
    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port, state.shared.use_default_http_port());
    let req_view = RequestView::from_captured(&captured);

    let page = render_page("pages/request_detail.html", &state.shared, |ctx| {
        ctx.insert(
            "title",
            &format!("{} {} — Detail", captured.method, captured.path),
        );
        ctx.insert("app", &app_view);
        ctx.insert("req", &req_view);
        ctx.insert("embedded", &embedded);
        ctx.insert("base_path", &base_path);
    });
    Html(page).into_response()
}

pub async fn sse_requests(State(state): State<DashboardState>, Path(id): Path<String>) -> Response {
    let numeric_id = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app.id.0,
        _ => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };

    let rx = state.shared.inspect_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |result| match result {
        Ok(event) if event.app_id == numeric_id => {
            let data = serde_json::to_string(&event).unwrap_or_default();
            Some(Ok::<_, Infallible>(Event::default().data(data)))
        }
        _ => None,
    });

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

pub async fn frame_tunnel(State(state): State<DashboardState>, Path(id): Path<String>) -> Response {
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };
    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port, state.shared.use_default_http_port());
    let mut ctx = base_context(&state.shared);
    ctx.insert("app", &app_view);
    Html(render_partial("partials/detail/tunnel.html", &ctx)).into_response()
}

pub async fn frame_features(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Response {
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };
    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port, state.shared.use_default_http_port());
    let mut ctx = base_context(&state.shared);
    ctx.insert("app", &app_view);
    Html(render_partial("partials/detail/features.html", &ctx)).into_response()
}

pub async fn frame_urls(State(state): State<DashboardState>, Path(id): Path<String>) -> Response {
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };
    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port, state.shared.use_default_http_port());
    let gtd = global_tunnel_domain(&state.shared);
    let url_ctx = crate::domain::UrlContext {
        http_port: port,
        https_port: state.shared.listen_https.map(|a| a.port()),
        use_default_http_port: state.shared.use_default_http_port(),
        use_default_https_port: state.shared.use_default_https_port(),
        domain_suffix: &state.shared.domain_suffix,
        global_tunnel_domain: gtd.as_deref(),
    };
    let urls = build_urls(&app, &url_ctx);
    let mut ctx = base_context(&state.shared);
    ctx.insert("app", &app_view);
    ctx.insert("urls", &urls);
    Html(render_partial("partials/detail/urls.html", &ctx)).into_response()
}

pub async fn sse_app_detail(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Response {
    if state.shared.store.get_by_name(&id).ok().flatten().is_none() {
        return html_response(StatusCode::NOT_FOUND, "Not found".to_string());
    }
    let rx = state.shared.change_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        result
            .ok()
            .map(|frames| Ok::<_, Infallible>(Event::default().data(frames)))
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

pub async fn action_toggle_lan_access(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Response {
    if let Ok(app) = service::app_get_by_name(&state.shared, &id) {
        let _ = service::app_update_settings(
            &state.shared,
            app.id.0,
            &service::UpdateSettingsParams {
                cors_enabled: None,
                force_https: None,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: None,
                listen_port: None,
                timeout_ms: None,
                lan_access: Some(!app.lan_access),
                cname: None,
            },
        );
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn action_scan(State(state): State<DashboardState>) -> Response {
    let stats = service::apps_scan(&state.shared).await;

    let port = state.shared.listen_http.port();
    let all = state.shared.store.list_all().unwrap_or_default();
    let msg = match &stats {
        Ok(s) => format!(
            "Scan complete — {} discovered, {} inserted, {} updated, {} pruned",
            s.discovered, s.inserted, s.updated, s.pruned
        ),
        Err(e) => format!("Scan failed: {e}"),
    };

    let default_app = state
        .shared
        .store
        .get_setting("default_app")
        .unwrap_or(None)
        .unwrap_or_default();
    let table_ctx = {
        let mut ctx = Context::new();
        ctx.insert(
            "apps",
            &app_views(&all, port, state.shared.use_default_http_port()),
        );
        ctx.insert("default_app", &default_app);
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
    turbo_stream_response(&streams)
}

pub async fn action_toggle(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Response {
    let app = match service::app_get_by_name(&state.shared, &id) {
        Ok(app) => app,
        Err(_) => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };

    let new_enabled = !app.enabled;
    if service::app_set_enabled(&state.shared, app.id.0, new_enabled).is_err() {
        return html_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Toggle failed".to_string(),
        );
    }

    let updated = service::app_get_by_name(&state.shared, &id).unwrap_or_else(|_| {
        let mut a = app.clone();
        a.enabled = new_enabled;
        a
    });

    let port = state.shared.listen_http.port();
    let all = state.shared.store.list_all().unwrap_or_default();

    let default_app = state
        .shared
        .store
        .get_setting("default_app")
        .unwrap_or(None)
        .unwrap_or_default();
    let row_ctx = {
        let mut ctx = Context::new();
        ctx.insert(
            "app",
            &AppView::from_spec(&updated, port, state.shared.use_default_http_port()),
        );
        ctx.insert("default_app", &default_app);
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
    turbo_stream_response(&streams)
}

pub async fn action_delete(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Response {
    let app = match service::app_get_by_name(&state.shared, &id) {
        Ok(app) => app,
        Err(_) => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };
    if let Err(e) = service::app_delete(&state.shared, app.id.0).await {
        tracing::error!(error = %e, app_id = app.id.0, "delete failed");
        return html_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Delete failed".to_string(),
        );
    }

    let all = state.shared.store.list_all().unwrap_or_default();
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
    turbo_stream_response(&streams)
}

pub async fn action_delete_redirect(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Response {
    if let Ok(app) = service::app_get_by_name(&state.shared, &id) {
        if let Err(e) = service::app_delete(&state.shared, app.id.0).await {
            tracing::error!(error = %e, app_id = app.id.0, "delete failed");
            return html_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Delete failed".to_string(),
            );
        }
    }
    Redirect::to("/").into_response()
}

pub async fn action_toggle_cors(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Response {
    if let Ok(app) = service::app_get_by_name(&state.shared, &id) {
        let _ = service::app_update_settings(
            &state.shared,
            app.id.0,
            &service::UpdateSettingsParams {
                cors_enabled: Some(!app.cors_enabled),
                force_https: None,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: None,
                listen_port: None,
                timeout_ms: None,
                lan_access: None,
                cname: None,
            },
        );
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn action_toggle_https(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Response {
    if let Ok(app) = service::app_get_by_name(&state.shared, &id) {
        let _ = service::app_update_settings(
            &state.shared,
            app.id.0,
            &service::UpdateSettingsParams {
                cors_enabled: None,
                force_https: Some(!app.force_https),
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: None,
                listen_port: None,
                timeout_ms: None,
                lan_access: None,
                cname: None,
            },
        );
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn action_toggle_spa(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Response {
    if let Ok(app) = service::app_get_by_name(&state.shared, &id) {
        let _ = service::app_update_settings(
            &state.shared,
            app.id.0,
            &service::UpdateSettingsParams {
                cors_enabled: None,
                force_https: None,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: Some(!app.spa_rewrite),
                listen_port: None,
                timeout_ms: None,
                lan_access: None,
                cname: None,
            },
        );
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn page_processes(State(state): State<DashboardState>) -> Html<String> {
    let infos = state.shared.process_manager.lock().await.list_status();
    let views = process_views(&infos, &state.shared);
    let page = render_page("pages/processes.html", &state.shared, |ctx| {
        ctx.insert("title", "Processes");
        ctx.insert("active_nav", "processes");
        ctx.insert("processes", &views);
    });
    Html(page)
}

pub async fn action_restart_process(
    State(state): State<DashboardState>,
    Path(app_id): Path<i64>,
) -> Redirect {
    if let Ok(Some(app)) = state.shared.store.get_by_id(app_id) {
        if let crate::domain::BackendTarget::Managed {
            root, kind, name, ..
        } = &app.target
        {
            state
                .shared
                .process_manager
                .lock()
                .await
                .mark_starting_if_inactive(app_id, name, std::path::Path::new(root), kind);
            let env_url_env = match crate::process::prefetch_env_url(std::path::Path::new(root))
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(app_id, error = %e, "env_url fetch failed, aborting restart");
                    let error = e.context(crate::app_status::StartFailure {
                        code: "environment_failed",
                        message: "Could not fetch startup environment; check env_url configuration"
                            .into(),
                    });
                    state
                        .shared
                        .process_manager
                        .lock()
                        .await
                        .record_start_failure(
                            app_id,
                            name,
                            std::path::Path::new(root),
                            kind,
                            &error,
                        );
                    return Redirect::to("/processes");
                }
            };
            let mut pm = state.shared.process_manager.lock().await;
            pm.kill_process(app_id).await;
            let _ = pm
                .ensure_running(app_id, name, std::path::Path::new(root), kind, env_url_env)
                .await;
        }
    }
    Redirect::to("/processes")
}

pub async fn page_process_log(
    State(state): State<DashboardState>,
    Path(app_id): Path<i64>,
) -> Response {
    let app = match state.shared.store.get_by_id(app_id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared)),
    };
    let app_dir = state.shared.runtime_dir.join("managed").join(&app.name);
    let log_dir = match &app.target {
        crate::domain::BackendTarget::Managed { root, .. } => {
            let root = std::path::Path::new(root);
            let manifest = crate::process::load_coulson_toml_manifest(root);
            crate::process::resolve_log_dir(&manifest, root, &app_dir)
        }
        _ => app_dir,
    };
    let log_path = crate::process::process_log_path(&log_dir, "web");
    let log_content = read_log_tail_lines(&log_path, 200).map(|lines| lines.join("\n"));
    let page = render_page("pages/process_log.html", &state.shared, |ctx| {
        ctx.insert("title", &format!("{} — Log", app.name));
        ctx.insert("active_nav", "processes");
        ctx.insert("app_name", &app.name);
        ctx.insert("log_path", &log_path.to_string_lossy().to_string());
        if let Some(ref content) = log_content {
            ctx.insert("log_content", content);
        }
    });
    Html(page).into_response()
}

pub async fn action_toggle_inspect(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Redirect {
    if let Ok(Some(app)) = state.shared.store.get_by_name(&id) {
        let _ = state
            .shared
            .store
            .set_inspect_enabled(app.id.0, !app.inspect_enabled);
        let _ = state.shared.reload_routes();
    }
    let (_, base) = embedded_base(&headers, &id);
    Redirect::to(&format!("{base}/requests"))
}

pub async fn action_clear_requests(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Redirect {
    if let Ok(Some(app)) = state.shared.store.get_by_name(&id) {
        let _ = state.shared.store.delete_request_logs_for_app(app.id.0);
    }
    let (_, base) = embedded_base(&headers, &id);
    Redirect::to(&format!("{base}/requests"))
}

pub async fn action_replay(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path((app_id, req_id)): Path<(String, String)>,
) -> Response {
    let app = match state.shared.store.get_by_name(&app_id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared)),
    };
    let captured = match state.shared.store.get_request_log(&req_id) {
        Ok(Some(r)) if r.app_id == app.id.0 => r,
        _ => return html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared)),
    };

    let outcome = execute_replay(&state.shared, &app_id, &req_id).await.ok();

    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port, state.shared.use_default_http_port());
    let req_view = RequestView::from_captured(&captured);

    let replay_view = match outcome.as_ref() {
        Some(o) if o.error.is_some() => ReplayView {
            status_code: 0,
            status_color: "bg-red-50 text-red-700 dark:bg-red-900/40 dark:text-red-300",
            body_display: o.error.clone(),
        },
        Some(o) => {
            let status = o.status_code.unwrap_or(0);
            ReplayView {
                status_code: status,
                status_color: status_color_for(status),
                body_display: o.body.clone(),
            }
        }
        None => ReplayView {
            status_code: 0,
            status_color: "bg-red-50 text-red-700 dark:bg-red-900/40 dark:text-red-300",
            body_display: Some("Replay failed".to_string()),
        },
    };

    let (embedded, base_path) = embedded_base(&headers, &app_id);
    let page = render_page("pages/request_detail.html", &state.shared, |ctx| {
        ctx.insert(
            "title",
            &format!("{} {} — Replay", captured.method, captured.path),
        );
        ctx.insert("app", &app_view);
        ctx.insert("req", &req_view);
        ctx.insert("replay", &replay_view);
        ctx.insert("embedded", &embedded);
        ctx.insert("base_path", &base_path);
    });
    Html(page).into_response()
}

#[derive(Deserialize)]
pub struct DefaultAppForm {
    pub default_app: Option<String>,
}

pub async fn action_set_default_app(
    State(state): State<DashboardState>,
    Form(form): Form<DefaultAppForm>,
) -> Redirect {
    let value = form
        .default_app
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    match value {
        Some(name) => {
            let name = name.to_ascii_lowercase();
            // Only set if app exists
            if service::app_get_by_name(&state.shared, &name).is_ok() {
                let _ = service::set_default_app(&state.shared, Some(&name));
            }
        }
        None => {
            let _ = service::set_default_app(&state.shared, None);
        }
    }
    Redirect::to("/")
}

#[derive(Deserialize)]
pub struct EditSettingsForm {
    pub timeout_ms: Option<String>,
    pub listen_port: Option<String>,
}

pub async fn action_update_settings(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
    Form(form): Form<EditSettingsForm>,
) -> Response {
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared)),
    };

    let timeout_raw = form.timeout_ms.as_deref().map(|s| s.trim()).unwrap_or("");
    let timeout_ms: Option<Option<u64>> = if timeout_raw.is_empty() {
        Some(None) // clear
    } else {
        match timeout_raw.parse::<u64>() {
            Ok(v) => Some(Some(v)),
            Err(_) => {
                return render_settings_modal_error(&state, &app, "Invalid timeout value", &form);
            }
        }
    };
    let port_raw = form.listen_port.as_deref().map(|s| s.trim()).unwrap_or("");
    let listen_port: Option<Option<u16>> = if port_raw.is_empty() {
        Some(None) // clear
    } else {
        match port_raw.parse::<u16>() {
            Ok(v) => Some(Some(v)),
            Err(_) => {
                return render_settings_modal_error(&state, &app, "Invalid port value", &form);
            }
        }
    };

    match service::app_update_settings(
        &state.shared,
        app.id.0,
        &service::UpdateSettingsParams {
            cors_enabled: None,
            force_https: None,
            basic_auth_user: None,
            basic_auth_pass: None,
            spa_rewrite: None,
            listen_port,
            timeout_ms,
            lan_access: None,
            cname: None,
        },
    ) {
        Ok(_) => Redirect::to(&format!("/apps/{id}")).into_response(),
        Err(e) => {
            render_settings_modal_error(&state, &app, &format!("Failed to update: {e}"), &form)
        }
    }
}

#[derive(Deserialize, Default)]
pub struct CreateAppForm {
    pub name: String,
    pub target_value: String,
    pub path_prefix: Option<String>,
    pub timeout_ms: Option<String>,
}

pub async fn action_create_app(
    State(state): State<DashboardState>,
    Form(form): Form<CreateAppForm>,
) -> Response {
    let suffix = &state.shared.domain_suffix;

    // Basic form validation
    let name = form.name.trim().to_string();
    if name.is_empty() {
        return render_new_app_modal_error(&state, "Name is required.", &form);
    }
    let target_value = form.target_value.trim().to_string();
    if target_value.is_empty() {
        return render_new_app_modal_error(&state, "Target is required.", &form);
    }

    let domain_prefix = name.to_ascii_lowercase();
    let full_domain = format!("{domain_prefix}.{suffix}");
    let timeout_ms = form
        .timeout_ms
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok());

    let create_params = service::CreateAppParams {
        name: name.clone(),
        domain: full_domain,
        path_prefix: form.path_prefix.clone(),
        target_type: "tcp".to_string(),
        target_value,
        timeout_ms,
        cors_enabled: false,
        force_https: false,
        basic_auth_user: None,
        basic_auth_pass: None,
        spa_rewrite: false,
        listen_port: None,
    };

    match service::app_create(&state.shared, &create_params) {
        Ok(_) => {
            let port = state.shared.listen_http.port();
            let all = state.shared.store.list_all().unwrap_or_default();

            let default_app = state
                .shared
                .store
                .get_setting("default_app")
                .unwrap_or(None)
                .unwrap_or_default();
            let table_ctx = {
                let mut ctx = Context::new();
                ctx.insert(
                    "apps",
                    &app_views(&all, port, state.shared.use_default_http_port()),
                );
                ctx.insert("default_app", &default_app);
                ctx
            };
            let stats_ctx = stats_context(&all);
            let toast_ctx = {
                let mut ctx = Context::new();
                ctx.insert("message", &format!("App '{}' created", name));
                ctx.insert("success", &true);
                ctx
            };
            let reset_ctx = new_app_modal_context(&state.shared, "", &CreateAppForm::default());

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
            // Reset modal form to blank
            streams.push_str(&turbo_replace(
                "new-app-modal-content",
                &render_partial("partials/new_app_modal.html", &reset_ctx),
            ));
            // Close dialog via inline script
            streams.push_str(&turbo_prepend(
                "toast-container",
                "<script>document.querySelector('dialog[data-modal-target=\"dialog\"]')?.close()</script>",
            ));
            turbo_stream_response(&streams)
        }
        Err(e) => {
            let msg = if matches!(e, service::ServiceError::DomainConflict) {
                "An app with this domain and path prefix already exists.".to_string()
            } else {
                format!("Failed to create app: {e}")
            };
            render_new_app_modal_error(&state, &msg, &form)
        }
    }
}

fn new_app_modal_context(shared: &SharedState, error: &str, form: &CreateAppForm) -> Context {
    let mut ctx = Context::new();
    ctx.insert("suffix", &shared.domain_suffix);
    ctx.insert("error", error);
    ctx.insert("form_name", &form.name);
    ctx.insert("form_target_value", &form.target_value);
    ctx.insert(
        "form_path_prefix",
        form.path_prefix.as_deref().unwrap_or(""),
    );
    ctx.insert("form_timeout_ms", form.timeout_ms.as_deref().unwrap_or(""));
    ctx
}

fn render_new_app_modal_error(
    state: &DashboardState,
    error: &str,
    form: &CreateAppForm,
) -> Response {
    let ctx = new_app_modal_context(&state.shared, error, form);
    let streams = turbo_replace(
        "new-app-modal-content",
        &render_partial("partials/new_app_modal.html", &ctx),
    );
    turbo_stream_response(&streams)
}

fn render_settings_modal_error(
    state: &DashboardState,
    app: &crate::domain::AppSpec,
    error: &str,
    form: &EditSettingsForm,
) -> Response {
    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(app, port, state.shared.use_default_http_port());
    let mut ctx = Context::new();
    ctx.insert("app", &app_view);
    ctx.insert("settings_error", error);
    ctx.insert("form_timeout_ms", &form.timeout_ms.as_deref().unwrap_or(""));
    ctx.insert(
        "form_listen_port",
        &form.listen_port.as_deref().unwrap_or(""),
    );
    let streams = turbo_replace(
        "settings-modal-content",
        &render_partial("partials/settings_modal.html", &ctx),
    );
    turbo_stream_response(&streams)
}

#[derive(Deserialize)]
pub struct BasicAuthForm {
    pub basic_auth_user: Option<String>,
    pub basic_auth_pass: Option<String>,
}

pub async fn action_set_basic_auth(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
    Form(form): Form<BasicAuthForm>,
) -> Response {
    if let Ok(app) = service::app_get_by_name(&state.shared, &id) {
        let user: Option<Option<String>> = Some(
            form.basic_auth_user
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        );
        let pass: Option<Option<String>> = Some(
            form.basic_auth_pass
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        );
        let _ = service::app_update_settings(
            &state.shared,
            app.id.0,
            &service::UpdateSettingsParams {
                cors_enabled: None,
                force_https: None,
                basic_auth_user: user,
                basic_auth_pass: pass,
                spa_rewrite: None,
                listen_port: None,
                timeout_ms: None,
                lan_access: None,
                cname: None,
            },
        );
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
pub struct TunnelModeForm {
    pub tunnel_mode: String,
    pub app_tunnel_domain: Option<String>,
    pub app_tunnel_token: Option<String>,
}

pub async fn action_set_tunnel_mode(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
    Form(form): Form<TunnelModeForm>,
) -> Response {
    let app = match service::app_get_by_name(&state.shared, &id) {
        Ok(app) => app,
        Err(_) => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };

    let new_mode = match form.tunnel_mode.as_str() {
        "none" => TunnelMode::None,
        "quick" => TunnelMode::Quick,
        "global" => TunnelMode::Global,
        "named" => TunnelMode::Named,
        _ => return StatusCode::NO_CONTENT.into_response(),
    };

    if let Err(e) = service::app_set_tunnel_mode(
        &state.shared,
        app.id.0,
        new_mode,
        form.app_tunnel_domain.as_deref(),
        form.app_tunnel_token.as_deref(),
        false,
    )
    .await
    {
        tracing::error!(error = %e, app_id = app.id.0, "tunnel mode switch failed");
    }

    StatusCode::NO_CONTENT.into_response()
}

pub async fn page_logs(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared)),
    };

    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port, state.shared.use_default_http_port());
    let (embedded, base_path) = embedded_base(&headers, &app.name);

    // Only managed apps have logs
    let root = match &app.target {
        crate::domain::BackendTarget::Managed { root, .. } => std::path::PathBuf::from(root),
        _ => {
            let page = render_page("pages/log_tail.html", &state.shared, |ctx| {
                ctx.insert("title", &format!("{} — Logs", app.name));
                ctx.insert("app", &app_view);
                ctx.insert("unsupported", &true);
                ctx.insert("embedded", &embedded);
                ctx.insert("base_path", &base_path);
                ctx.insert("full_width", &true);
            });
            return Html(page).into_response();
        }
    };

    let manifest = crate::process::load_coulson_toml_manifest(&root);
    let app_dir = state.shared.runtime_dir.join("managed").join(&app.name);
    let log_dir = crate::process::resolve_log_dir(&manifest, &root, &app_dir);

    let runtime_types = {
        let pm = state.shared.process_manager.lock().await;
        pm.process_types(app.id.0)
    };

    // Scan the app's log directory for `{ptype}.log` files so we can offer
    // switchers for worker/scheduler/etc. even when the process is not
    // currently running. Each app owns its log directory, so a `*.log` stem
    // is directly the process type — no app-name prefix to strip and no way
    // to read an unrelated app's log.
    let mut disk_types: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&log_dir) {
        for entry in entries.flatten() {
            let fname_os = entry.file_name();
            let Some(fname) = fname_os.to_str() else {
                continue;
            };
            if let Some(ptype) = fname.strip_suffix(".log") {
                if crate::process::is_valid_process_type(ptype) {
                    disk_types.push(ptype.to_string());
                }
            }
        }
    }

    // Merge runtime + disk types, keeping order; dedupe; force "web" first.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut process_types: Vec<String> = Vec::new();
    for t in runtime_types.iter().chain(disk_types.iter()) {
        if seen.insert(t.clone()) {
            process_types.push(t.clone());
        }
    }
    if process_types.is_empty() {
        process_types.push("web".to_string());
    } else if let Some(pos) = process_types.iter().position(|x| x == "web") {
        if pos != 0 {
            process_types.swap(0, pos);
        }
    }

    // Map each process_type to its on-disk log path (`{log_dir}/{ptype}.log`)
    // so the UI can show the filename when the user switches tabs.
    let mut process_log_paths: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for pt in &process_types {
        let p = crate::process::process_log_path(&log_dir, pt);
        process_log_paths.insert(pt.clone(), p.to_string_lossy().into_owned());
    }
    let initial_process = process_types
        .first()
        .cloned()
        .unwrap_or_else(|| "web".to_string());
    let initial_log_path = process_log_paths
        .get(&initial_process)
        .cloned()
        .unwrap_or_else(|| {
            crate::process::process_log_path(&log_dir, "web")
                .to_string_lossy()
                .into_owned()
        });

    let page = render_page("pages/log_tail.html", &state.shared, |ctx| {
        ctx.insert("title", &format!("{} — Logs", app.name));
        ctx.insert("app", &app_view);
        ctx.insert("log_path", &initial_log_path);
        ctx.insert("initial_process", &initial_process);
        ctx.insert("process_log_paths", &process_log_paths);
        ctx.insert("process_types", &process_types);
        ctx.insert("embedded", &embedded);
        ctx.insert("base_path", &base_path);
        ctx.insert("full_width", &true);
    });
    Html(page).into_response()
}

pub async fn sse_logs_default(
    state: State<DashboardState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    sse_logs(state, headers, Path((id, "web".to_string()))).await
}

pub async fn sse_logs(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Path((id, process_type)): Path<(String, String)>,
) -> Response {
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };

    // Reject process_types that would escape the `{ptype}.log` filename into a
    // nested path or non-ASCII filesystem segment. "web" is the only
    // companion-less case that bypasses the format, so it is always admitted
    // even though it also matches the charset.
    if process_type != "web" && !crate::process::is_valid_process_type(&process_type) {
        return html_response(StatusCode::NOT_FOUND, "Not found".to_string());
    }

    // EventSource sends Accept: text/event-stream; plain curl does not.
    let want_sse = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/event-stream"));

    // Resolve the log file for this process_type: `{log_dir}/{ptype}.log`.
    // The app owns its log directory, so there is no way to read another
    // app's log here.
    let root = match &app.target {
        crate::domain::BackendTarget::Managed { root, .. } => std::path::PathBuf::from(root),
        _ => {
            if want_sse {
                return Sse::new(futures::stream::pending::<Result<Event, Infallible>>())
                    .keep_alive(KeepAlive::default())
                    .into_response();
            }
            return plain_text_stream(futures::stream::pending::<String>());
        }
    };
    let manifest = crate::process::load_coulson_toml_manifest(&root);
    let app_dir = state.shared.runtime_dir.join("managed").join(&app.name);
    let log_dir = crate::process::resolve_log_dir(&manifest, &root, &app_dir);
    let log_path = crate::process::process_log_path(&log_dir, &process_type);

    let has_broadcast = {
        let pm = state.shared.process_manager.lock().await;
        pm.has_log_broadcast()
    };

    let app_id = app.id.0;
    let ptype_for_filter = process_type.clone();

    // Subscribe / capture live cursor BEFORE reading history so no lines are
    // lost in the window between the file read and the live stream
    // starting. Any overlap is tolerable — duplicated lines look
    // harmless — but a missed line is invisible and confusing.
    if has_broadcast {
        let rx = state.shared.log_tx.subscribe();
        let history = read_log_tail_lines(&log_path, 200).unwrap_or_default();
        let history_stream = futures::stream::iter(history);
        let live_stream = BroadcastStream::new(rx).filter_map(move |result| match result {
            Ok(log_line)
                if log_line.app_id == app_id && log_line.process_type == ptype_for_filter =>
            {
                Some(log_line.line)
            }
            _ => None,
        });
        if want_sse {
            // Tag history events so the client can skip the fade-in animation
            // for replayed lines (only real-time lines should animate).
            let history_events = history_stream
                .map(|line| Ok::<_, Infallible>(Event::default().event("history").data(line)));
            let live_events =
                live_stream.map(|line| Ok::<_, Infallible>(Event::default().data(line)));
            let stream = history_events.chain(live_events);
            Sse::new(stream)
                .keep_alive(KeepAlive::default())
                .into_response()
        } else {
            plain_text_stream(history_stream.chain(live_stream))
        }
    } else {
        // Tmux fallback: poll the companion log file for new lines.
        //
        // Capture the live cursor (current file length) BEFORE reading
        // history. Any lines written between the two reads end up in
        // history AND in the next poll — duplicates are tolerable, gaps
        // are not.
        let initial_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
        let history = read_log_tail_lines(&log_path, 200).unwrap_or_default();
        let history_stream = futures::stream::iter(history);

        struct TailState {
            path: std::path::PathBuf,
            offset: u64,
            pending: std::collections::VecDeque<String>,
            // When we read a chunk with no newline and below the
            // `POLL_CAP`, remember the file length we saw. If the next
            // poll still sees the exact same length, the writer has
            // gone quiet (e.g. the process exited leaving a trailing
            // line without `\n`) and we flush the buffered tail as a
            // synthetic line instead of hiding it forever.
            stale_len: Option<u64>,
        }

        let tail = TailState {
            path: log_path,
            offset: initial_offset,
            pending: std::collections::VecDeque::new(),
            stale_len: None,
        };

        let live_stream = futures::stream::unfold(tail, |mut st| async move {
            // Cap a single poll so a large append spike cannot balloon
            // into an unbounded allocation.
            const POLL_CAP: u64 = 1 << 20; // 1 MiB

            loop {
                if let Some(line) = st.pending.pop_front() {
                    return Some((line, st));
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Ok(mut file) = std::fs::File::open(&st.path) else {
                    continue;
                };
                let len = file.metadata().map(|m| m.len()).unwrap_or(0);
                if len <= st.offset {
                    // File shrank or has no new bytes — reset quiescence
                    // tracking; there is nothing buffered to flush.
                    st.stale_len = None;
                    continue;
                }
                use std::io::{Read, Seek, SeekFrom};
                if file.seek(SeekFrom::Start(st.offset)).is_err() {
                    continue;
                }
                let to_read = std::cmp::min(len - st.offset, POLL_CAP) as usize;
                let mut chunk = vec![0u8; to_read];
                let n = file.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    continue;
                }
                chunk.truncate(n);
                // Mirror `spawn_tee_task`: split on `\n`, decode each
                // line with `from_utf8_lossy` so non-UTF-8 bytes survive
                // instead of aborting the tail. Prefer tail -f semantics
                // (only advance past complete newlines), but guard
                // against two failure modes: a `POLL_CAP`-sized chunk
                // with no newline would otherwise stall the stream, and
                // a trailing unterminated fragment after the writer has
                // exited would otherwise be hidden forever.
                match chunk.iter().rposition(|&b| b == b'\n') {
                    Some(last_nl) => {
                        let consumable = &chunk[..=last_nl];
                        let mut line_start = 0;
                        for (i, b) in consumable.iter().enumerate() {
                            if *b == b'\n' {
                                let slice = &consumable[line_start..i];
                                let slice = if slice.last() == Some(&b'\r') {
                                    &slice[..slice.len() - 1]
                                } else {
                                    slice
                                };
                                st.pending
                                    .push_back(String::from_utf8_lossy(slice).into_owned());
                                line_start = i + 1;
                            }
                        }
                        st.offset += (last_nl + 1) as u64;
                        st.stale_len = None;
                    }
                    None if n as u64 == POLL_CAP => {
                        // Chunk completely fills the cap with no newline:
                        // emit it as a synthetic line and advance past
                        // it so the tail keeps moving. Any partial
                        // fragment still buffered upstream will be
                        // flushed on the next write.
                        st.pending
                            .push_back(String::from_utf8_lossy(&chunk).into_owned());
                        st.offset += n as u64;
                        st.stale_len = None;
                    }
                    None if st.stale_len == Some(len) => {
                        // Second poll observing the same file length with
                        // no newline — the writer has gone quiet. Flush
                        // the buffered tail as a synthetic line so a
                        // process that exited mid-line (crash, prompt,
                        // tool output without trailing `\n`) still shows
                        // up in the live view.
                        st.pending
                            .push_back(String::from_utf8_lossy(&chunk).into_owned());
                        st.offset += n as u64;
                        st.stale_len = None;
                    }
                    None => {
                        // First time we see this partial tail. Remember
                        // the file length and wait one more poll —
                        // active writers virtually always continue
                        // within 1 s, so this only triggers once output
                        // has actually stopped.
                        st.stale_len = Some(len);
                        continue;
                    }
                }
            }
        });

        if want_sse {
            let history_events = history_stream
                .map(|line| Ok::<_, Infallible>(Event::default().event("history").data(line)));
            let live_events =
                live_stream.map(|line| Ok::<_, Infallible>(Event::default().data(line)));
            let stream = history_events.chain(live_events);
            Sse::new(stream)
                .keep_alive(KeepAlive::default())
                .into_response()
        } else {
            plain_text_stream(history_stream.chain(live_stream))
        }
    }
}

/// Wrap a `Stream<Item = String>` into a chunked `text/plain` response (one line per chunk).
fn plain_text_stream<S>(stream: S) -> Response
where
    S: futures::Stream<Item = String> + Send + 'static,
{
    use axum::body::Body;

    let body_stream = stream.map(|line| Ok::<_, Infallible>(format!("{line}\n")));
    let body = Body::from_stream(body_stream);
    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            ),
            (axum::http::header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

pub async fn not_found(
    State(state): State<DashboardState>,
    request: axum::extract::Request,
) -> Response {
    if request.method() != axum::http::Method::GET {
        return html_response(
            StatusCode::METHOD_NOT_ALLOWED,
            render_page("pages/not_found.html", &state.shared, |_| {}),
        );
    }
    html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared))
}
