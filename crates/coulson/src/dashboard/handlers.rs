use std::convert::Infallible;

use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use tera::Context;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use super::render::*;
use super::DashboardState;
use crate::domain::{DomainName, TunnelMode};
use crate::runtime;
use crate::scanner;
use crate::store::StaticAppInput;
use crate::tunnel;
use crate::SharedState;

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
        ctx.insert("apps", &app_views(&apps, port));
        ctx.insert("error", "");
        ctx.insert("form_name", "");
        ctx.insert("form_target_value", "");
        ctx.insert("form_path_prefix", "");
        ctx.insert("form_timeout_ms", "");
    });
    Html(page)
}

pub async fn page_warnings(State(state): State<DashboardState>) -> Html<String> {
    let warnings = runtime::read_scan_warnings(&state.shared.scan_warnings_path)
        .ok()
        .flatten();
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
    let https_port = state.shared.listen_https.map(|a| a.port());
    let app_view = AppView::from_spec(&app, port);
    let gtd = global_tunnel_domain(&state.shared);
    let urls = build_urls(&app, port, https_port, gtd.as_deref());
    let title = format!("{} — Detail", app.domain.0);
    let page = render_page("pages/app_detail.html", &state.shared, |ctx| {
        ctx.insert("title", &title);
        ctx.insert("app", &app_view);
        ctx.insert("urls", &urls);
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
    Path(id): Path<String>,
) -> Response {
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, render_not_found(&state.shared)),
    };
    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port);
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
    });
    Html(page).into_response()
}

pub async fn page_request_detail(
    State(state): State<DashboardState>,
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
    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port);
    let req_view = RequestView::from_captured(&captured);

    let page = render_page("pages/request_detail.html", &state.shared, |ctx| {
        ctx.insert(
            "title",
            &format!("{} {} — Detail", captured.method, captured.path),
        );
        ctx.insert("app", &app_view);
        ctx.insert("req", &req_view);
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

pub async fn action_scan(State(state): State<DashboardState>) -> Response {
    let stats = scanner::sync_from_apps_root(&state.shared);
    if let Ok(ref s) = stats {
        let _ = runtime::write_scan_warnings(&state.shared.scan_warnings_path, s);
        let _ = state.shared.reload_routes();
    }

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
        ctx.insert("apps", &app_views(&all, port));
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
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };

    let new_enabled = !app.enabled;
    if state
        .shared
        .store
        .set_enabled(app.id.0, new_enabled)
        .is_err()
    {
        return html_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Toggle failed".to_string(),
        );
    }
    let _ = state.shared.reload_routes();

    let updated = state
        .shared
        .store
        .get_by_name(&id)
        .ok()
        .flatten()
        .unwrap_or_else(|| {
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
        ctx.insert("app", &AppView::from_spec(&updated, port));
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
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };
    if let Some(ref fs_entry) = app.fs_entry {
        scanner::remove_app_fs_entry(&state.shared.apps_root, fs_entry);
    }
    let _ = state.shared.store.delete(app.id.0);
    let _ = state.shared.reload_routes();

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
) -> Redirect {
    if let Ok(Some(app)) = state.shared.store.get_by_name(&id) {
        if let Some(ref fs_entry) = app.fs_entry {
            scanner::remove_app_fs_entry(&state.shared.apps_root, fs_entry);
        }
        let _ = state.shared.store.delete(app.id.0);
    }
    let _ = state.shared.reload_routes();
    Redirect::to("/")
}

pub async fn action_toggle_cors(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Redirect {
    if let Ok(Some(app)) = state.shared.store.get_by_name(&id) {
        let _ = state.shared.store.update_settings(
            app.id.0,
            Some(!app.cors_enabled),
            None,
            None,
            None,
            None,
            None,
        );
        let _ = state.shared.reload_routes();
    }
    Redirect::to(&format!("/apps/{id}"))
}

pub async fn action_toggle_spa(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Redirect {
    if let Ok(Some(app)) = state.shared.store.get_by_name(&id) {
        let _ = state.shared.store.update_settings(
            app.id.0,
            None,
            None,
            None,
            Some(!app.spa_rewrite),
            None,
            None,
        );
        let _ = state.shared.reload_routes();
    }
    Redirect::to(&format!("/apps/{id}"))
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
    state
        .shared
        .process_manager
        .lock()
        .await
        .kill_process(app_id);
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
    let log_path = state
        .shared
        .runtime_dir
        .join("managed")
        .join(format!("{}.log", app.name));
    let log_content = std::fs::read_to_string(&log_path).ok().map(|content| {
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(200);
        lines[start..].join("\n")
    });
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
    Path(id): Path<String>,
) -> Redirect {
    if let Ok(Some(app)) = state.shared.store.get_by_name(&id) {
        let _ = state
            .shared
            .store
            .set_inspect_enabled(app.id.0, !app.inspect_enabled);
        let _ = state.shared.reload_routes();
    }
    Redirect::to(&format!("/apps/{id}/requests"))
}

pub async fn action_clear_requests(
    State(state): State<DashboardState>,
    Path(id): Path<String>,
) -> Redirect {
    if let Ok(Some(app)) = state.shared.store.get_by_name(&id) {
        let _ = state.shared.store.delete_request_logs_for_app(app.id.0);
    }
    Redirect::to(&format!("/apps/{id}/requests"))
}

pub async fn action_replay(
    State(state): State<DashboardState>,
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

    let outcome = execute_replay(&state.shared.store, &app_id, &req_id)
        .await
        .ok();

    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(&app, port);
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

    let page = render_page("pages/request_detail.html", &state.shared, |ctx| {
        ctx.insert(
            "title",
            &format!("{} {} — Replay", captured.method, captured.path),
        );
        ctx.insert("app", &app_view);
        ctx.insert("req", &req_view);
        ctx.insert("replay", &replay_view);
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
            if state
                .shared
                .store
                .get_by_name(&name)
                .ok()
                .flatten()
                .is_some()
            {
                let _ = state.shared.store.set_setting("default_app", &name);
            }
        }
        None => {
            let _ = state.shared.store.delete_setting("default_app");
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

    match state.shared.store.update_settings(
        app.id.0,
        None,
        None,
        None,
        None,
        listen_port,
        timeout_ms,
    ) {
        Ok(_) => {
            let _ = state.shared.reload_routes();
            Redirect::to(&format!("/apps/{id}")).into_response()
        }
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

    // Validate name
    let name = form.name.trim().to_string();
    if name.is_empty() {
        return render_new_app_modal_error(&state, "Name is required.", &form);
    }

    // Domain derived from name
    let domain_prefix = name.to_ascii_lowercase();
    let full_domain = format!("{domain_prefix}.{suffix}");
    let domain = match DomainName::parse(&full_domain, suffix) {
        Ok(d) => d,
        Err(e) => {
            return render_new_app_modal_error(&state, &format!("Invalid domain: {e}"), &form)
        }
    };

    // Validate target (modal only supports TCP)
    let target_value = form.target_value.trim().to_string();
    if target_value.is_empty() {
        return render_new_app_modal_error(&state, "Target is required.", &form);
    }
    if let Some((_, port_str)) = target_value.rsplit_once(':') {
        if port_str.parse::<u16>().unwrap_or(0) == 0 {
            return render_new_app_modal_error(
                &state,
                "Invalid target: port must be 1–65535.",
                &form,
            );
        }
    } else {
        return render_new_app_modal_error(
            &state,
            "Target must be host:port (e.g. 127.0.0.1:5006).",
            &form,
        );
    }
    let target_type = "tcp";

    let path_prefix = form
        .path_prefix
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let timeout_ms = form
        .timeout_ms
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok());

    let input = StaticAppInput {
        name: &name,
        domain: &domain,
        path_prefix,
        target_type,
        target_value: &target_value,
        timeout_ms,
        cors_enabled: false,
        basic_auth_user: None,
        basic_auth_pass: None,
        spa_rewrite: false,
        listen_port: None,
    };

    match state.shared.store.insert_static(&input) {
        Ok(_) => {
            let _ = state.shared.reload_routes();

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
                ctx.insert("apps", &app_views(&all, port));
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
            let msg = if e.to_string().contains("domain conflict") {
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

fn render_detail_stream(state: &DashboardState, id: &str) -> Response {
    let app = match state.shared.store.get_by_name(id) {
        Ok(Some(app)) => app,
        _ => return Redirect::to(&format!("/apps/{id}")).into_response(),
    };
    let port = state.shared.listen_http.port();
    let https_port = state.shared.listen_https.map(|a| a.port());
    let app_view = AppView::from_spec(&app, port);
    let gtd = global_tunnel_domain(&state.shared);
    let urls = build_urls(&app, port, https_port, gtd.as_deref());

    let mut ctx = base_context(&state.shared);
    ctx.insert("app", &app_view);
    ctx.insert("urls", &urls);

    let mut streams = turbo_replace(
        "detail-tunnel",
        &render_partial("partials/detail/tunnel.html", &ctx),
    );
    streams.push_str(&turbo_replace(
        "detail-urls",
        &render_partial("partials/detail/urls.html", &ctx),
    ));
    streams.push_str(&turbo_replace(
        "detail-features",
        &render_partial("partials/detail/features.html", &ctx),
    ));
    turbo_stream_response(&streams)
}

fn render_settings_modal_error(
    state: &DashboardState,
    app: &crate::domain::AppSpec,
    error: &str,
    form: &EditSettingsForm,
) -> Response {
    let port = state.shared.listen_http.port();
    let app_view = AppView::from_spec(app, port);
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
    if let Ok(Some(app)) = state.shared.store.get_by_name(&id) {
        let user: Option<Option<&str>> = Some(
            form.basic_auth_user
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty()),
        );
        let pass: Option<Option<&str>> = Some(
            form.basic_auth_pass
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty()),
        );
        let _ = state
            .shared
            .store
            .update_settings(app.id.0, None, user, pass, None, None, None);
        let _ = state.shared.reload_routes();
    }
    render_detail_stream(&state, &id)
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
    let app = match state.shared.store.get_by_name(&id) {
        Ok(Some(app)) => app,
        _ => return html_response(StatusCode::NOT_FOUND, "Not found".to_string()),
    };

    let new_mode = match form.tunnel_mode.as_str() {
        "none" => TunnelMode::None,
        "quick" => TunnelMode::Quick,
        "global" => TunnelMode::Global,
        "named" => TunnelMode::Named,
        _ => return render_detail_stream(&state, &id),
    };

    let old_mode = &app.tunnel_mode;
    if *old_mode == new_mode {
        return render_detail_stream(&state, &id);
    }

    let app_id = app.id.0;
    let routing = tunnel::transport::TunnelRouting::FixedHost {
        local_host: app.domain.0.clone(),
        local_proxy_port: state.shared.listen_http.port(),
    };

    // Pre-validate named mode params before teardown to avoid losing current tunnel
    if new_mode == TunnelMode::Named {
        let has_domain = form
            .app_tunnel_domain
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .is_some()
            || app.app_tunnel_domain.is_some();
        let has_token = form
            .app_tunnel_token
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .and_then(|t| tunnel::decode_tunnel_token(t).ok())
            .is_some();
        let has_saved_creds = app
            .app_tunnel_creds
            .as_ref()
            .and_then(|c| serde_json::from_str::<tunnel::TunnelCredentials>(c).ok())
            .is_some();
        if !has_domain || (!has_token && !has_saved_creds) {
            return render_detail_stream(&state, &id);
        }
    }

    // Teardown old mode
    match old_mode {
        TunnelMode::Quick => {
            let _ = tunnel::stop_tunnel(&state.shared.tunnels, app_id);
            let _ = state.shared.store.update_tunnel_url(app_id, None);
            let _ = state.shared.store.set_tunnel_mode(app_id, TunnelMode::None);
        }
        TunnelMode::Named => {
            let _ = tunnel::stop_app_named_tunnel(&state.shared.app_tunnels, app_id);
            let _ = state.shared.store.set_tunnel_mode(app_id, TunnelMode::None);
        }
        TunnelMode::Global => {
            let _ = state.shared.store.set_tunnel_mode(app_id, TunnelMode::None);
        }
        TunnelMode::None => {}
    }

    // Setup new mode
    match new_mode {
        TunnelMode::Quick => {
            match tunnel::start_quick_tunnel(state.shared.tunnels.clone(), app_id, routing).await {
                Ok(hostname) => {
                    let url = format!("https://{hostname}");
                    let _ = state.shared.store.update_tunnel_url(app_id, Some(&url));
                    let _ = state
                        .shared
                        .store
                        .set_tunnel_mode(app_id, TunnelMode::Quick);
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to start quick tunnel");
                }
            }
        }
        TunnelMode::Global => {
            let _ = state
                .shared
                .store
                .set_tunnel_mode(app_id, TunnelMode::Global);
        }
        TunnelMode::Named => {
            let tunnel_domain = form
                .app_tunnel_domain
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .or(app.app_tunnel_domain.as_deref())
                .unwrap() // safe: pre-validated above
                .to_string();

            // Try token-based connect first (only if decodable), then saved creds
            let decoded_token = form
                .app_tunnel_token
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .and_then(|t| tunnel::decode_tunnel_token(t).ok());

            if let Some(credentials) = decoded_token {
                // Token-based connect
                let tunnel_id = credentials.tunnel_id.clone();
                match tunnel::start_app_named_tunnel(
                    state.shared.app_tunnels.clone(),
                    app_id,
                    credentials.clone(),
                    tunnel_domain.clone(),
                    routing,
                )
                .await
                {
                    Ok(_) => {
                        let creds_json = serde_json::to_string(&credentials).unwrap_or_default();
                        let _ = state.shared.store.set_app_tunnel_state(
                            app_id,
                            Some(&tunnel_id),
                            Some(&tunnel_domain),
                            None,
                            Some(&creds_json),
                            TunnelMode::Named,
                        );
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to start named tunnel");
                    }
                }
            } else if let Some(creds) = app
                .app_tunnel_creds
                .as_ref()
                .and_then(|c| serde_json::from_str::<tunnel::TunnelCredentials>(c).ok())
            {
                // Reconnect with saved creds
                match tunnel::start_app_named_tunnel(
                    state.shared.app_tunnels.clone(),
                    app_id,
                    creds,
                    tunnel_domain.clone(),
                    routing,
                )
                .await
                {
                    Ok(_) => {
                        let _ = state.shared.store.set_app_tunnel_state(
                            app_id,
                            app.app_tunnel_id.as_deref(),
                            Some(&tunnel_domain),
                            None,
                            app.app_tunnel_creds.as_deref(),
                            TunnelMode::Named,
                        );
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to reconnect named tunnel");
                    }
                }
            }
        }
        TunnelMode::None => {}
    }

    let _ = state.shared.reload_routes();
    render_detail_stream(&state, &id)
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
