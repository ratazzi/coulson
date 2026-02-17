use std::convert::Infallible;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use tera::Context;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use super::render::*;
use super::DashboardState;
use crate::runtime;
use crate::scanner;

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
    let urls = build_urls(&app, port, https_port, &state.shared.domain_suffix);
    let title = format!("{} — Detail", app.domain.0);
    let page = render_page("pages/app_detail.html", &state.shared, |ctx| {
        ctx.insert("title", &title);
        ctx.insert("app", &app_view);
        ctx.insert("urls", &urls);
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
        );
        let _ = state.shared.reload_routes();
    }
    Redirect::to(&format!("/apps/{id}"))
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
