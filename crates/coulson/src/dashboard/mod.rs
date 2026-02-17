mod handlers;
pub mod render;

use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use http_body_util::BodyExt;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use tower::ServiceExt;

use crate::SharedState;

pub use render::execute_replay;

#[derive(Clone)]
pub struct DashboardState {
    pub shared: SharedState,
}

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

pub fn router(state: DashboardState) -> Router {
    Router::new()
        .route("/favicon.svg", get(handlers::favicon))
        .route("/", get(handlers::page_index))
        .route("/warnings", get(handlers::page_warnings))
        .route("/apps/{id}", get(handlers::page_app_detail))
        .route("/apps/{id}/requests", get(handlers::page_requests))
        .route("/apps/{id}/requests/stream", get(handlers::sse_requests))
        .route(
            "/apps/{id}/requests/{req_id}",
            get(handlers::page_request_detail),
        )
        .route("/apps/new", post(handlers::action_create_app))
        .route("/processes", get(handlers::page_processes))
        .route(
            "/processes/{app_id}/restart",
            post(handlers::action_restart_process),
        )
        .route("/processes/{app_id}/log", get(handlers::page_process_log))
        .route(
            "/settings/default-app",
            post(handlers::action_set_default_app),
        )
        .route("/scan", post(handlers::action_scan))
        .route("/apps/{id}/toggle", post(handlers::action_toggle))
        .route("/apps/{id}/delete", post(handlers::action_delete))
        .route(
            "/apps/{id}/delete-go",
            post(handlers::action_delete_redirect),
        )
        .route(
            "/apps/{id}/settings",
            post(handlers::action_update_settings),
        )
        .route("/apps/{id}/tunnel", post(handlers::action_set_tunnel_mode))
        .route(
            "/apps/{id}/basic-auth",
            post(handlers::action_set_basic_auth),
        )
        .route("/apps/{id}/stream", get(handlers::sse_app_detail))
        .route("/apps/{id}/frames/tunnel", get(handlers::frame_tunnel))
        .route("/apps/{id}/frames/features", get(handlers::frame_features))
        .route("/apps/{id}/frames/urls", get(handlers::frame_urls))
        .route("/apps/{id}/toggle-cors", post(handlers::action_toggle_cors))
        .route("/apps/{id}/toggle-spa", post(handlers::action_toggle_spa))
        .route(
            "/apps/{id}/toggle-inspect",
            post(handlers::action_toggle_inspect),
        )
        .route(
            "/apps/{id}/requests/clear",
            post(handlers::action_clear_requests),
        )
        .route(
            "/apps/{id}/requests/{req_id}/replay",
            post(handlers::action_replay),
        )
        .fallback(handlers::not_found)
        .with_state(state)
}

fn copy_headers(
    resp: &mut ResponseHeader,
    headers: &[(String, String)],
    skip_streaming: bool,
) -> Result<()> {
    for (name, value) in headers {
        if skip_streaming && (name == "content-length" || name == "transfer-encoding") {
            continue;
        }
        let hn: http::HeaderName = name
            .parse()
            .map_err(|e| Error::explain(ErrorType::InternalError, format!("header name: {e}")))?;
        let hv: http::HeaderValue = value
            .parse()
            .map_err(|e| Error::explain(ErrorType::InternalError, format!("header value: {e}")))?;
        resp.insert_header(hn, hv)?;
    }
    Ok(())
}

/// Bridge a Pingora session to the axum dashboard router.
pub async fn bridge(session: &mut Session, dashboard_router: Router) -> Result<()> {
    let method = session.req_header().method.clone();
    let uri = session.req_header().uri.clone();
    let mut builder = http::Request::builder().method(method).uri(uri);
    for (name, value) in session.req_header().headers.iter() {
        builder = builder.header(name, value);
    }

    // Read request body with 1MB limit
    const MAX_BODY: usize = 1_048_576;
    let mut body_bytes = Vec::new();
    loop {
        match session.read_request_body().await {
            Ok(Some(chunk)) => {
                if body_bytes.len() + chunk.len() > MAX_BODY {
                    return Err(Error::explain(
                        ErrorType::InternalError,
                        "request body too large",
                    ));
                }
                body_bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                return Err(Error::explain(
                    ErrorType::InternalError,
                    format!("read body: {e}"),
                ));
            }
        }
    }

    let body = if body_bytes.is_empty() {
        axum::body::Body::empty()
    } else {
        axum::body::Body::from(body_bytes)
    };
    let request = builder
        .body(body)
        .map_err(|e| Error::explain(ErrorType::InternalError, format!("build request: {e}")))?;

    let response = dashboard_router
        .into_service()
        .oneshot(request)
        .await
        .map_err(|e| Error::explain(ErrorType::InternalError, format!("axum oneshot: {e}")))?;

    let (parts, body) = response.into_parts();
    let status_code = parts.status.as_u16();
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let is_sse = headers
        .iter()
        .any(|(k, v)| k == "content-type" && v.contains("text/event-stream"));

    if is_sse {
        let mut resp = ResponseHeader::build(status_code, None)?;
        copy_headers(&mut resp, &headers, true)?;
        session.write_response_header(Box::new(resp), false).await?;
        let mut body = body;
        while let Some(Ok(frame)) = body.frame().await {
            if let Ok(data) = frame.into_data() {
                if session
                    .write_response_body(Some(data), false)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
        let _ = session.write_response_body(Some(Bytes::new()), true).await;
    } else {
        let body_bytes = body
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        let mut resp = ResponseHeader::build(status_code, None)?;
        copy_headers(&mut resp, &headers, false)?;
        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(body_bytes), true).await?;
    }

    Ok(())
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
}
