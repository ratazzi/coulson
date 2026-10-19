mod handlers;
pub mod render;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use http_body_util::BodyExt;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use tower::ServiceExt;

use crate::config::LOCALHOST_SUFFIX;
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
        || (domain_suffix != LOCALHOST_SUFFIX && host == format!("dashboard.{LOCALHOST_SUFFIX}"))
}

/// Returns true if the host matches the "default" entry point:
/// bare domain suffix (e.g. "coulson.local") or IP direct access.
pub fn is_default_host(host: &str, domain_suffix: &str) -> bool {
    if host == domain_suffix
        || host == "127.0.0.1"
        || host == "localhost"
        || host == "::1"
        || host == "[::1]"
    {
        return true;
    }
    // bare suffix .localhost equivalent: coulson.local → coulson.localhost
    if domain_suffix != LOCALHOST_SUFFIX {
        if let Some(prefix) = domain_suffix.split('.').next() {
            if host == format!("{prefix}.{LOCALHOST_SUFFIX}") {
                return true;
            }
        }
    }
    false
}

pub fn router(state: DashboardState) -> Router {
    Router::new()
        .route("/favicon.svg", get(handlers::favicon))
        .route("/", get(handlers::page_index))
        .route("/warnings", get(handlers::page_warnings))
        .route("/apps/{id}", get(handlers::page_app_detail))
        .route("/apps/{id}/requests", get(handlers::page_requests))
        .route("/apps/{id}/requests/stream", get(handlers::sse_requests))
        .route("/apps/{id}/logs", get(handlers::page_logs))
        .route("/apps/{id}/logs/stream", get(handlers::sse_logs_default))
        .route(
            "/apps/{id}/logs/stream/{process_type}",
            get(handlers::sse_logs),
        )
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
        .route(
            "/apps/{id}/toggle-lan",
            post(handlers::action_toggle_lan_access),
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
        .route(
            "/apps/{id}/toggle-https",
            post(handlers::action_toggle_https),
        )
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
        .layer(axum::middleware::from_fn(reject_cross_site))
        .with_state(state)
}

/// Reject cross-site state-changing requests (CSRF). The dashboard has no
/// session to tie a token to, and its forms are simple requests a foreign
/// page can auto-submit: over loopback, or with the embedded inspector's
/// basic auth, which browsers attach automatically.
async fn reject_cross_site(req: Request, next: Next) -> Response {
    if !req.method().is_safe() && !is_same_origin_request(req.headers()) {
        return (http::StatusCode::FORBIDDEN, "cross-site request rejected").into_response();
    }
    next.run(req).await
}

fn is_same_origin_request(headers: &http::HeaderMap) -> bool {
    // Fetch metadata is set by the browser and can't be forged by a page. It
    // also holds through the tunnel, where Host is rewritten to the local name.
    if let Some(site) = headers.get("sec-fetch-site") {
        return matches!(site.as_bytes(), b"same-origin" | b"none");
    }
    // Older browsers: the Origin must name this host. Requests without Origin
    // come from non-browser clients, which carry no ambient credentials.
    let Some(origin) = headers.get(http::header::ORIGIN) else {
        return true;
    };
    let Some(origin) = origin
        .to_str()
        .ok()
        .and_then(|o| o.parse::<http::Uri>().ok())
        .and_then(|u| u.authority().cloned())
    else {
        return false;
    };
    [http::header::HOST.as_str(), "x-forwarded-host"]
        .into_iter()
        .filter_map(|name| headers.get(name)?.to_str().ok())
        .any(|host| host.eq_ignore_ascii_case(origin.as_str()))
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
    let mut builder = http::Request::builder()
        .method(method.clone())
        .uri(uri.clone());
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

    let is_streaming = !headers.iter().any(|(k, _)| k == "content-length");

    if is_streaming {
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
        // Skip axum's content-length/transfer-encoding since we collected the
        // full body and know the exact size.  Copying a stale
        // `transfer-encoding: chunked` while writing raw bytes corrupts
        // HTTP/1.1 keep-alive connections and violates HTTP/2 framing rules.
        copy_headers(&mut resp, &headers, true)?;
        let cl: http::HeaderValue = body_bytes.len().to_string().parse().unwrap();
        resp.insert_header(http::header::CONTENT_LENGTH, cl)?;
        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(body_bytes), true).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        pairs
            .iter()
            .map(|(k, v)| (k.parse().unwrap(), v.parse().unwrap()))
            .collect()
    }

    #[test]
    fn same_origin_check_trusts_fetch_metadata() {
        assert!(is_same_origin_request(&headers(&[(
            "sec-fetch-site",
            "same-origin"
        )])));
        assert!(is_same_origin_request(&headers(&[(
            "sec-fetch-site",
            "none"
        )])));
        // Fetch metadata wins over a matching Origin.
        for site in ["cross-site", "same-site"] {
            assert!(!is_same_origin_request(&headers(&[
                ("sec-fetch-site", site),
                ("origin", "http://dashboard.coulson.local"),
                ("host", "dashboard.coulson.local"),
            ])));
        }
    }

    #[test]
    fn same_origin_check_falls_back_to_origin() {
        let host = ("host", "dashboard.coulson.local:18080");
        assert!(is_same_origin_request(&headers(&[
            ("origin", "http://dashboard.coulson.local:18080"),
            host,
        ])));
        assert!(!is_same_origin_request(&headers(&[
            ("origin", "https://evil.example"),
            host
        ])));
        assert!(!is_same_origin_request(&headers(&[
            ("origin", "null"),
            host
        ])));
        // Port is part of the origin.
        assert!(!is_same_origin_request(&headers(&[
            ("origin", "http://dashboard.coulson.local"),
            host,
        ])));
        // Tunnel: Host is rewritten locally, the public name is forwarded.
        assert!(is_same_origin_request(&headers(&[
            ("origin", "https://myapp.example.com"),
            ("host", "myapp.coulson.local"),
            ("x-forwarded-host", "myapp.example.com"),
        ])));
        // Non-browser clients send neither header.
        assert!(is_same_origin_request(&headers(&[host])));
    }

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
