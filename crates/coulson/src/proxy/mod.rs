use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use base64::prelude::*;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{http_proxy_service, FailToProxy};
use pingora::server::{RunArgs, ShutdownSignal, ShutdownSignalWatch};
use tokio::sync::watch;
use tracing::info;

use percent_encoding::percent_decode_str;
use serde::Serialize;
use tera::{Context, Tera};

use crate::config::LOCALHOST_SUFFIX;
use crate::domain::BackendTarget;
use crate::process::{ListenTarget, ProcessManagerHandle, StartStatus};
use crate::store::CapturedRequest;
use crate::{RouteRule, SharedState};

// ---------------------------------------------------------------------------
// Middleware pipeline
// ---------------------------------------------------------------------------

/// Controls whether the middleware pipeline should continue or stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// Response already written — stop the pipeline.
    Done,
    /// Continue to the next middleware / backend resolution.
    Next,
}

async fn mw_auth(session: &mut Session, route: &RouteRule) -> Result<Flow> {
    // Only enforce basic auth for requests arriving via CF tunnel.
    // Local and LAN requests are trusted and skip auth.
    let via_tunnel = session
        .req_header()
        .headers
        .get(crate::tunnel::proxy::VIA_TUNNEL_HEADER)
        .is_some();
    if via_tunnel {
        if let (Some(user), Some(pass)) = (&route.basic_auth_user, &route.basic_auth_pass) {
            if !check_basic_auth(session, user, pass) {
                write_auth_required(session, "coulson").await?;
                return Ok(Flow::Done);
            }
        }
    }
    Ok(Flow::Next)
}

async fn mw_cors(session: &mut Session, route: &RouteRule) -> Result<Flow> {
    if route.cors_enabled {
        let method = session.req_header().method.as_str();
        let has_origin = session.req_header().headers.get("origin").is_some();
        if method == "OPTIONS" && has_origin {
            write_cors_preflight(session).await?;
            return Ok(Flow::Done);
        }
    }
    Ok(Flow::Next)
}

async fn mw_force_https(
    session: &mut Session,
    route: &RouteRule,
    https_port: Option<u16>,
    use_default_https_port: bool,
) -> Result<Flow> {
    if !route.force_https {
        return Ok(Flow::Next);
    }
    let Some(https_port) = https_port else {
        // No HTTPS listener configured — skip redirect
        return Ok(Flow::Next);
    };
    // Skip if connection is already TLS, or X-Forwarded-Proto says https, or via CF tunnel
    let is_tls = session.digest().is_some_and(|d| d.ssl_digest.is_some());
    let forwarded_https = session
        .req_header()
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("https"));
    if is_tls
        || forwarded_https
        || session
            .req_header()
            .headers
            .get(crate::tunnel::proxy::VIA_TUNNEL_HEADER)
            .is_some()
    {
        return Ok(Flow::Next);
    }
    // Extract hostname (without port) from Host header, then build redirect with HTTPS port
    let raw_host = session
        .req_header()
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let hostname = raw_host.rsplit_once(':').map_or(raw_host, |(h, _)| h);
    let pq = session
        .req_header()
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let location =
        crate::domain::format_url("https", hostname, https_port, pq, use_default_https_port);
    let mut resp = ResponseHeader::build(302, None)?;
    resp.insert_header("location", &location)?;
    resp.insert_header("content-length", "0")?;
    session.write_response_header(Box::new(resp), true).await?;
    Ok(Flow::Done)
}

async fn mw_static(session: &mut Session, route: &RouteRule, req_path: &str) -> Result<Flow> {
    if let Some(ref root) = route.static_root {
        if try_serve_static(session, root, req_path, route.cors_enabled).await? {
            return Ok(Flow::Done);
        }
    }
    Ok(Flow::Next)
}

#[derive(Clone)]
struct BridgeProxy {
    shared: SharedState,
    process_manager: ProcessManagerHandle,
    dashboard_router: axum::Router,
}

const INSPECTOR_PATH_PREFIX: &str = "/_coulson";
const EMBEDDED_HEADER: &str = "x-coulson-embedded";
/// Internal marker header injected by `execute_replay` so the proxy skips
/// `mw_auth`, `mw_force_https` and inspector capture for replay requests.
/// Stripped before forwarding to the backend.
pub const REPLAY_HEADER: &str = "x-coulson-replay";

fn is_inspector_path(path: &str) -> bool {
    path.starts_with("/_coulson/") || path == "/_coulson"
}

impl BridgeProxy {
    /// Handle `/_coulson/` embedded inspector requests.
    /// Authenticates with independent basic auth, rewrites URI to dashboard paths,
    /// and bridges to the existing dashboard router.
    async fn handle_embedded_inspector(
        &self,
        session: &mut Session,
        route: &RouteRule,
        req_path: &str,
    ) -> Result<bool> {
        // Inspector auth: must be configured, otherwise pretend it doesn't exist
        let (Some(ref user), Some(ref pass)) = (
            &self.shared.inspector_username,
            &self.shared.inspector_password,
        ) else {
            write_error_page(session, 404, "route_not_found").await?;
            return Ok(true);
        };

        // Respect the app's force_https setting — redirect before auth challenge
        // so credentials are never sent over plain HTTP.
        if mw_force_https(
            session,
            route,
            self.shared.listen_https.map(|a| a.port()),
            self.shared.use_default_https_port(),
        )
        .await?
            == Flow::Done
        {
            return Ok(true);
        }

        // Always require basic auth (local + tunnel)
        if !check_basic_auth(session, user, pass) {
            write_auth_required(session, "Coulson Inspector").await?;
            return Ok(true);
        }

        // Resolve app name from route
        let app_name = match route.app_id {
            Some(id) => match self.shared.store.get_by_id(id) {
                Ok(Some(app)) => app.name,
                _ => {
                    write_error_page(session, 404, "route_not_found").await?;
                    return Ok(true);
                }
            },
            None => {
                write_error_page(session, 404, "route_not_found").await?;
                return Ok(true);
            }
        };

        // Rewrite URI: /_coulson/... → /apps/{name}/...
        let sub_path = req_path.strip_prefix(INSPECTOR_PATH_PREFIX).unwrap_or("/");
        let new_path = if sub_path.is_empty() || sub_path == "/" {
            format!("/apps/{app_name}/requests")
        } else {
            format!("/apps/{app_name}{sub_path}")
        };

        if let Ok(uri) = new_path.parse::<http::Uri>() {
            session.req_header_mut().set_uri(uri);
        }

        // Signal embedded mode to dashboard handlers
        session
            .req_header_mut()
            .insert_header(EMBEDDED_HEADER, "1")?;

        crate::dashboard::bridge(session, self.dashboard_router.clone()).await?;
        Ok(true)
    }

    /// Handle a loopback-authenticated replay request pinned to a specific
    /// app id. The caller already verified `is_loopback_client(session)` and
    /// stripped `REPLAY_HEADER`. This bypasses host routing — the route is
    /// looked up by `app_id` directly so `default_app`/CNAME/domain drift
    /// since capture cannot cause the replay to hit a different app. It also
    /// skips `mw_auth` and `mw_force_https`, which makes sense because the
    /// dashboard already authenticated the user and the request is strictly
    /// in-process over 127.0.0.1.
    ///
    /// The route is built directly from `store.get_by_id(app_id)` rather than
    /// scanned from the live route table. That table only holds *enabled*
    /// apps (`list_enabled()` in `reload_routes`), so going through it would
    /// regress replay to 404 whenever a user temporarily disables an app but
    /// still wants to diagnose an old request from the dashboard.
    async fn handle_replay_request(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCtx,
        app_id: i64,
    ) -> Result<bool> {
        let req_path = session.req_header().uri.path().to_string();

        // Look up the app by id. Works for disabled apps as well, because the
        // store does not filter on `enabled`. If the row is gone we genuinely
        // have nothing to replay against.
        let app = match self.shared.store.get_by_id(app_id) {
            Ok(Some(app)) => app,
            Ok(None) => {
                write_error_page(session, 404, "route_not_found").await?;
                return Ok(true);
            }
            Err(e) => {
                tracing::warn!(app_id, error = %e, "replay: failed to load app from store");
                write_error_page(session, 500, "internal_error").await?;
                return Ok(true);
            }
        };

        let route = RouteRule::from_app_spec(app);

        // The captured request path must still fit the app's configured
        // `path_prefix`; otherwise the replay would be meaningless (we'd be
        // sending to an upstream the app was never responsible for).
        let path_ok = match route.path_prefix.as_deref() {
            None | Some("/") => true,
            Some(prefix) => req_path == prefix || req_path.starts_with(&format!("{prefix}/")),
        };
        if !path_ok {
            write_error_page(session, 404, "route_not_found").await?;
            return Ok(true);
        }

        // CORS and static lookups still apply — they're not auth checks.
        if mw_cors(session, &route).await? == Flow::Done {
            return Ok(true);
        }
        if mw_static(session, &route, &req_path).await? == Flow::Done {
            return Ok(true);
        }

        // Resolve the concrete upstream target.
        if let BackendTarget::StaticDir { ref root } = route.target {
            serve_static(session, root, &req_path, route.cors_enabled).await?;
            return Ok(true);
        }

        let resolved_target = if let BackendTarget::Managed {
            ref app_id,
            ref root,
            ref kind,
            ref name,
        } = route.target
        {
            let root_path = std::path::PathBuf::from(root);
            let status = crate::process::prepare_and_ensure_started(
                &self.process_manager,
                *app_id,
                name,
                &root_path,
                kind,
            )
            .await
            .map_err(|e| Error::explain(ErrorType::ConnectError, format!("{e}")))?;
            match status {
                StartStatus::Ready(listen_target) => {
                    pm_mark_active(&self.process_manager, *app_id).await;
                    listen_target_to_backend(listen_target)
                }
                StartStatus::Starting => {
                    match await_managed_ready(
                        session,
                        &self.process_manager,
                        *app_id,
                        name,
                        &root_path,
                        kind,
                    )
                    .await?
                    {
                        Some(target) => target,
                        None => return Ok(true),
                    }
                }
            }
        } else {
            route.target.clone()
        };

        if route.spa_rewrite && should_rewrite_for_spa(&req_path) {
            session.req_header_mut().set_uri("/".try_into().unwrap());
        }

        // Inspector capture — replay is recorded just like any other request,
        // so users can see what the replay actually sent/received.
        if route.inspect_enabled {
            ctx.inspect = true;
            ctx.inspect_app_id = route.app_id;
            ctx.inspect_store = Some(self.shared.store.clone());
            ctx.inspect_max_requests = self.shared.inspect_max_requests;
            ctx.inspect_tx = Some(self.shared.inspect_tx.clone());
            ctx.inspect_start = Some(std::time::Instant::now());
            ctx.inspect_method = Some(session.req_header().method.to_string());
            let uri = &session.req_header().uri;
            ctx.inspect_path = Some(uri.path().to_string());
            ctx.inspect_query = uri.query().map(|q| q.to_string());
            let headers: std::collections::HashMap<String, String> = session
                .req_header()
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            ctx.inspect_req_headers = serde_json::to_string(&headers).ok();
        }

        ctx.target = Some(resolved_target);
        ctx.timeout_ms = route.timeout_ms;
        ctx.cors_enabled = route.cors_enabled;
        ctx.spa_rewrite = route.spa_rewrite;
        ctx.is_upgrade = session.req_header().headers.get("upgrade").is_some();
        Ok(false)
    }
}

const INSPECT_BODY_MAX: usize = 65536;

#[derive(Default)]
struct ProxyCtx {
    target: Option<BackendTarget>,
    timeout_ms: Option<u64>,
    cors_enabled: bool,
    spa_rewrite: bool,
    is_upgrade: bool,
    // Request inspector fields
    inspect: bool,
    inspect_app_id: Option<i64>,
    inspect_store: Option<std::sync::Arc<crate::store::AppRepository>>,
    inspect_max_requests: usize,
    inspect_start: Option<std::time::Instant>,
    inspect_method: Option<String>,
    inspect_path: Option<String>,
    inspect_query: Option<String>,
    inspect_req_headers: Option<String>,
    inspect_req_body: Option<Vec<u8>>,
    inspect_status: Option<u16>,
    inspect_resp_headers: Option<String>,
    inspect_resp_body: Option<Vec<u8>>,
    inspect_tx: Option<tokio::sync::broadcast::Sender<crate::InspectEvent>>,
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
        // Replay marker handling. The header carries the captured app's id so
        // replay is pinned to that specific app, NOT to whatever the current
        // host routing would resolve to (default_app/CNAME/domain config may
        // have drifted since capture). The marker is only honored when the
        // client is a loopback address — otherwise it's a forgery attempt and
        // we strip it so normal auth/force-https still apply.
        if session.req_header().headers.contains_key(REPLAY_HEADER) {
            let header_val = session
                .req_header()
                .headers
                .get(REPLAY_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            // Always strip — the header is internal-only and must never reach
            // upstream or be re-used by a second hop.
            session.req_header_mut().remove_header(REPLAY_HEADER);
            if is_loopback_client(session) {
                if let Some(app_id) = header_val.as_deref().and_then(|s| s.parse::<i64>().ok()) {
                    return self.handle_replay_request(session, ctx, app_id).await;
                }
            } else {
                tracing::warn!("rejecting x-coulson-replay header from non-loopback client");
            }
        }

        // HTTP/2 uses :authority pseudo-header; HTTP/1.1 uses Host header
        let raw_host = session
            .req_header()
            .uri
            .authority()
            .map(|a| a.as_str())
            .or_else(|| {
                session
                    .req_header()
                    .headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
            });
        let host = extract_host(raw_host);
        let Some(host) = host else {
            write_error_page(session, 400, "missing_host").await?;
            return Ok(true);
        };

        // Dashboard dedicated domain: dashboard.{suffix}
        if crate::dashboard::is_dashboard_host(&host, &self.shared.domain_suffix) {
            if !is_loopback_client(session) {
                write_error_page(session, 403, "lan_access_denied").await?;
                return Ok(true);
            }
            crate::dashboard::bridge(session, self.dashboard_router.clone()).await?;
            return Ok(true);
        }

        // Default host: bare suffix + IP direct access
        if crate::dashboard::is_default_host(&host, &self.shared.domain_suffix) {
            // If default_app is set, resolve it as the effective host
            let effective_host = match self.shared.store.get_setting("default_app") {
                Ok(Some(app_domain)) => Some(app_domain),
                _ => None,
            };
            if let Some(ref app_domain) = effective_host {
                // Proxy to default app — strict lookup (no default.{suffix} fallback)
                let req_path = session.req_header().uri.path().to_string();
                // Embedded inspector intercept: must run before path_prefix matching
                if is_inspector_path(&req_path) {
                    let route = {
                        let routes = self.shared.routes.read();
                        any_route(routes.get(app_domain.as_str()))
                    };
                    if let Some(route) = route {
                        return self
                            .handle_embedded_inspector(session, &route, &req_path)
                            .await;
                    }
                }
                let route = {
                    let routes = self.shared.routes.read();
                    select_route(routes.get(app_domain.as_str()), &req_path)
                };
                if let Some(route) = route {
                    // Per-app LAN access gate (same as normal routing)
                    if !route.lan_access && !is_loopback_client(session) {
                        write_error_page(session, 403, "lan_access_denied").await?;
                        return Ok(true);
                    }
                    // Run the same pipeline as normal routing below
                    if mw_auth(session, &route).await? == Flow::Done {
                        return Ok(true);
                    }
                    if mw_force_https(
                        session,
                        &route,
                        self.shared.listen_https.map(|a| a.port()),
                        self.shared.use_default_https_port(),
                    )
                    .await?
                        == Flow::Done
                    {
                        return Ok(true);
                    }
                    if mw_cors(session, &route).await? == Flow::Done {
                        return Ok(true);
                    }
                    if mw_static(session, &route, &req_path).await? == Flow::Done {
                        return Ok(true);
                    }
                    if let BackendTarget::StaticDir { ref root } = route.target {
                        serve_static(session, root, &req_path, route.cors_enabled).await?;
                        return Ok(true);
                    }
                    let resolved_target = if let BackendTarget::Managed {
                        ref app_id,
                        ref root,
                        ref kind,
                        ref name,
                    } = route.target
                    {
                        let root_path = std::path::PathBuf::from(root);
                        let status = crate::process::prepare_and_ensure_started(
                            &self.process_manager,
                            *app_id,
                            name,
                            &root_path,
                            kind,
                        )
                        .await
                        .map_err(|e| Error::explain(ErrorType::ConnectError, format!("{e}")))?;
                        match status {
                            StartStatus::Ready(listen_target) => {
                                pm_mark_active(&self.process_manager, *app_id).await;
                                listen_target_to_backend(listen_target)
                            }
                            StartStatus::Starting => {
                                match await_managed_ready(
                                    session,
                                    &self.process_manager,
                                    *app_id,
                                    name,
                                    &root_path,
                                    kind,
                                )
                                .await?
                                {
                                    Some(target) => target,
                                    None => return Ok(true),
                                }
                            }
                        }
                    } else {
                        route.target.clone()
                    };
                    if route.spa_rewrite && should_rewrite_for_spa(&req_path) {
                        let _ = session.req_header_mut().set_uri("/".try_into().unwrap());
                    }
                    if route.inspect_enabled {
                        ctx.inspect = true;
                        ctx.inspect_app_id = route.app_id;
                        ctx.inspect_store = Some(self.shared.store.clone());
                        ctx.inspect_max_requests = self.shared.inspect_max_requests;
                        ctx.inspect_tx = Some(self.shared.inspect_tx.clone());
                        ctx.inspect_start = Some(std::time::Instant::now());
                        ctx.inspect_method = Some(session.req_header().method.to_string());
                        let uri = &session.req_header().uri;
                        ctx.inspect_path = Some(uri.path().to_string());
                        ctx.inspect_query = uri.query().map(|q| q.to_string());
                        let headers: std::collections::HashMap<String, String> = session
                            .req_header()
                            .headers
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();
                        ctx.inspect_req_headers = serde_json::to_string(&headers).ok();
                    }
                    ctx.target = Some(resolved_target);
                    ctx.timeout_ms = route.timeout_ms;
                    ctx.cors_enabled = route.cors_enabled;
                    ctx.spa_rewrite = route.spa_rewrite;
                    ctx.is_upgrade = session.req_header().headers.get("upgrade").is_some();
                    return Ok(false);
                }
                // default_app route not found → fall through to dashboard
            }
            if !is_loopback_client(session) {
                write_error_page(session, 403, "lan_access_denied").await?;
                return Ok(true);
            }
            crate::dashboard::bridge(session, self.dashboard_router.clone()).await?;
            return Ok(true);
        }

        let req_path = session.req_header().uri.path().to_string();

        // Embedded inspector intercept: must run before route resolution
        // because /_coulson/ paths won't match app path_prefix rules.
        if is_inspector_path(&req_path) {
            let route = {
                let routes = self.shared.routes.read();
                resolve_any_route(&routes, &host, &self.shared.domain_suffix)
            };
            if let Some(route) = route {
                return self
                    .handle_embedded_inspector(session, &route, &req_path)
                    .await;
            }
            write_error_page(session, 404, "route_not_found").await?;
            return Ok(true);
        }

        let route = {
            let routes = self.shared.routes.read();
            resolve_target(&routes, &host, &self.shared.domain_suffix, &req_path)
        };

        let Some(route) = route else {
            write_error_page(session, 404, "route_not_found").await?;
            return Ok(true);
        };

        // Per-app LAN access gate: reject non-loopback clients when disabled
        if !route.lan_access && !is_loopback_client(session) {
            write_error_page(session, 403, "lan_access_denied").await?;
            return Ok(true);
        }

        // --- Middleware pipeline ---
        if mw_auth(session, &route).await? == Flow::Done {
            return Ok(true);
        }
        if mw_force_https(
            session,
            &route,
            self.shared.listen_https.map(|a| a.port()),
            self.shared.use_default_https_port(),
        )
        .await?
            == Flow::Done
        {
            return Ok(true);
        }
        if mw_cors(session, &route).await? == Flow::Done {
            return Ok(true);
        }
        if mw_static(session, &route, &req_path).await? == Flow::Done {
            return Ok(true);
        }

        // --- Static directory serving (full, with 404 / directory listing) ---
        if let BackendTarget::StaticDir { ref root } = route.target {
            serve_static(session, root, &req_path, route.cors_enabled).await?;
            return Ok(true);
        }

        // --- Managed process ---
        let resolved_target = if let BackendTarget::Managed {
            ref app_id,
            ref root,
            ref kind,
            ref name,
        } = route.target
        {
            let root_path = std::path::PathBuf::from(root);
            let status = crate::process::prepare_and_ensure_started(
                &self.process_manager,
                *app_id,
                name,
                &root_path,
                kind,
            )
            .await
            .map_err(|e| Error::explain(ErrorType::ConnectError, format!("{e}")))?;
            match status {
                StartStatus::Ready(listen_target) => {
                    pm_mark_active(&self.process_manager, *app_id).await;
                    listen_target_to_backend(listen_target)
                }
                StartStatus::Starting => {
                    match await_managed_ready(
                        session,
                        &self.process_manager,
                        *app_id,
                        name,
                        &root_path,
                        kind,
                    )
                    .await?
                    {
                        Some(target) => target,
                        None => return Ok(true),
                    }
                }
            }
        } else {
            route.target.clone()
        };

        // --- SPA Rewrite ---
        if route.spa_rewrite && should_rewrite_for_spa(&req_path) {
            let _ = session.req_header_mut().set_uri("/".try_into().unwrap());
        }

        // --- Request Inspector ---
        if route.inspect_enabled {
            ctx.inspect = true;
            ctx.inspect_app_id = route.app_id;
            ctx.inspect_store = Some(self.shared.store.clone());
            ctx.inspect_max_requests = self.shared.inspect_max_requests;
            ctx.inspect_tx = Some(self.shared.inspect_tx.clone());
            ctx.inspect_start = Some(std::time::Instant::now());
            ctx.inspect_method = Some(session.req_header().method.to_string());
            let uri = &session.req_header().uri;
            ctx.inspect_path = Some(uri.path().to_string());
            ctx.inspect_query = uri.query().map(|q| q.to_string());
            let headers: std::collections::HashMap<String, String> = session
                .req_header()
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            ctx.inspect_req_headers = serde_json::to_string(&headers).ok();
        }

        ctx.target = Some(resolved_target);
        ctx.timeout_ms = route.timeout_ms;
        ctx.cors_enabled = route.cors_enabled;
        ctx.spa_rewrite = route.spa_rewrite;
        ctx.is_upgrade = session.req_header().headers.get("upgrade").is_some();
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
                    if !ctx.is_upgrade {
                        peer.options.read_timeout = Some(timeout);
                        peer.options.idle_timeout = Some(timeout);
                    }
                }
                Ok(peer)
            }
            BackendTarget::UnixSocket { path } => {
                let mut peer = HttpPeer::new_uds(&path, false, String::new())?;
                if let Some(timeout_ms) = ctx.timeout_ms {
                    let timeout = Duration::from_millis(timeout_ms);
                    peer.options.connection_timeout = Some(timeout);
                    peer.options.total_connection_timeout = Some(timeout);
                    if !ctx.is_upgrade {
                        peer.options.read_timeout = Some(timeout);
                        peer.options.idle_timeout = Some(timeout);
                    }
                }
                Ok(Box::new(peer))
            }
            BackendTarget::StaticDir { .. } | BackendTarget::Managed { .. } => {
                // Should never reach here — handled in request_filter
                Error::e_explain(ErrorType::InternalError, "non-proxy target has no upstream")
            }
        }
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Strip internal tunnel marker before forwarding to backend
        upstream_request.remove_header(crate::tunnel::proxy::VIA_TUNNEL_HEADER);

        // RFC 9113 §8.2.3: when proxying HTTP/2 → HTTP/1.1, multiple Cookie
        // headers MUST be concatenated with "; " into a single header.
        // Puma/Rack uses the generic ", " join for duplicate headers, which
        // breaks cookie parsing and causes CSRF failures.
        let cookies: Vec<Vec<u8>> = upstream_request
            .headers
            .get_all(http::header::COOKIE)
            .iter()
            .map(|v| v.as_bytes().to_vec())
            .collect();
        if cookies.len() > 1 {
            upstream_request.remove_header(http::header::COOKIE.as_str());
            let merged = cookies.join(&b"; "[..]);
            let value = http::HeaderValue::from_bytes(&merged).map_err(|e| {
                Error::because(ErrorType::InternalError, "invalid cookie header", e)
            })?;
            upstream_request.insert_header(http::header::COOKIE, value)?;
        }

        if let Some(upgrade) = _session.req_header().headers.get("upgrade").cloned() {
            upstream_request.insert_header("Upgrade", upgrade)?;
            upstream_request.insert_header("Connection", "Upgrade")?;
        }

        // Set X-Forwarded-Host from the original Host header if not already present.
        if upstream_request.headers.get("X-Forwarded-Host").is_none() {
            if let Some(host) = _session.req_header().headers.get("host") {
                upstream_request.insert_header("X-Forwarded-Host", host)?;
            }
        }

        // Set X-Forwarded-Proto based on downstream connection type.
        // For tunnel requests, the tunnel proxy already set this to "https"
        // — only override if not already present.
        if upstream_request.headers.get("X-Forwarded-Proto").is_none() {
            let is_tls = _session.digest().is_some_and(|d| d.ssl_digest.is_some());
            upstream_request
                .insert_header("X-Forwarded-Proto", if is_tls { "https" } else { "http" })?;
        }

        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        inspect_capture_req_body(ctx, body);
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
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
        inspect_capture_response_meta(ctx, upstream_response);
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        inspect_capture_resp_body(ctx, body, end_of_stream);
        Ok(None)
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        _ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let code = error_to_status_code(e);
        if code > 0 {
            write_error_page(session, code, "upstream_error")
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("failed to send error page: {e}");
                });
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
}

pub struct TlsConfig {
    pub bind: String,
    pub ca_path: String,
    pub sni_callback: crate::certs::SniCallback,
}

/// Stops a Pingora server run by coulson once the paired sender sends `true`
/// or is dropped.
///
/// Pingora's default watcher handles SIGTERM itself: it sleeps through a fixed
/// grace period, and `run_forever` then calls `process::exit`, racing the
/// daemon's own cleanup. With this watcher the daemon decides when a proxy
/// stops, and `Server::run` returns instead of exiting the process.
struct ProxyShutdown(watch::Receiver<bool>);

#[async_trait]
impl ShutdownSignalWatch for ProxyShutdown {
    async fn recv(&self) -> ShutdownSignal {
        let mut rx = self.0.clone();
        let _ = rx.wait_for(|stop| *stop).await;
        ShutdownSignal::FastShutdown
    }
}

fn run_until_shutdown(server: Server, shutdown: watch::Receiver<bool>) {
    server.run(RunArgs {
        shutdown_signal: Box::new(ProxyShutdown(shutdown)),
    });
}

pub async fn run_proxy(
    addr: SocketAddr,
    tls: Option<TlsConfig>,
    state: SharedState,
    process_manager: ProcessManagerHandle,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let bind = addr.to_string();
    info!("proxy listening http://{bind}");
    if let Some(ref tls) = tls {
        info!(bind = %tls.bind, "proxy listening (HTTPS)");
    }

    tokio::task::spawn_blocking(move || {
        run_proxy_blocking(&bind, tls, state, process_manager, shutdown)
    })
    .await??;
    Ok(())
}

fn run_proxy_blocking(
    bind: &str,
    tls: Option<TlsConfig>,
    state: SharedState,
    process_manager: ProcessManagerHandle,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    // When TLS is enabled, set ca_file on ServerConf to avoid loading macOS system
    // certificates (which may contain unsupported critical extensions that crash rustls).
    let mut conf = pingora::server::configuration::ServerConf {
        threads: 4,
        ..Default::default()
    };
    if let Some(ref tls) = tls {
        conf.ca_file = Some(tls.ca_path.clone());
    }
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let dashboard_state = crate::dashboard::DashboardState {
        shared: state.clone(),
    };
    let dashboard_router = crate::dashboard::router(dashboard_state);

    let mut service = http_proxy_service(
        &server.configuration,
        BridgeProxy {
            shared: state,
            process_manager,
            dashboard_router,
        },
    );
    // Bind with IPv6 support:
    // - 0.0.0.0 → bind [::] instead (dual-stack covers both IPv4 and IPv6)
    // - 127.0.0.1 → bind both 127.0.0.1 and [::1] (specific addresses, no conflict)
    // - other → bind as-is (no IPv6 counterpart)
    if let Ok(addr) = bind.parse::<std::net::SocketAddr>() {
        if addr.ip() == std::net::Ipv4Addr::UNSPECIFIED {
            let v6_bind = format!("[::]:{}", addr.port());
            service.add_tcp(&v6_bind);
        } else {
            service.add_tcp(bind);
            if addr.ip() == std::net::Ipv4Addr::LOCALHOST {
                let v6_bind = format!("[::1]:{}", addr.port());
                service.add_tcp(&v6_bind);
            }
        }
    } else {
        service.add_tcp(bind);
    }

    // TLS listener with HTTP/2 + HTTP/1.1 ALPN via dynamic SNI cert callback
    if let Some(tls) = tls {
        let add_tls_listener = |svc: &mut pingora::services::listening::Service<_>,
                                bind_addr: &str| {
            let cb: pingora::listeners::TlsAcceptCallbacks = Box::new(tls.sni_callback.clone());
            let mut settings = pingora::listeners::tls::TlsSettings::with_callbacks(cb)
                .expect("TLS settings init");
            settings.enable_h2();
            svc.add_tls_with_settings(bind_addr, None, settings);
        };

        if let Ok(addr) = tls.bind.parse::<std::net::SocketAddr>() {
            if addr.ip() == std::net::Ipv4Addr::UNSPECIFIED {
                let v6_bind = format!("[::]:{}", addr.port());
                add_tls_listener(&mut service, &v6_bind);
            } else {
                add_tls_listener(&mut service, &tls.bind);
                if addr.ip() == std::net::Ipv4Addr::LOCALHOST {
                    let v6_bind = format!("[::1]:{}", addr.port());
                    add_tls_listener(&mut service, &v6_bind);
                }
            }
        } else {
            add_tls_listener(&mut service, &tls.bind);
        }
    }

    server.add_service(service);
    run_until_shutdown(server, shutdown);
    Ok(())
}

// ---------------------------------------------------------------------------
// Dedicated per-app proxy (listen_port)
// Thin reverse proxy: rewrites Host header and forwards to the main proxy.
// All business logic (auth, CORS, managed process, etc.) is handled by main.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct DedicatedProxy {
    /// Main proxy address, e.g. "127.0.0.1:8080"
    upstream_addr: String,
    /// App domain used as Host header, e.g. "asgi.coulson.local"
    host: String,
}

#[async_trait]
impl ProxyHttp for DedicatedProxy {
    type CTX = ();

    fn new_ctx(&self) {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            &self.upstream_addr,
            false,
            String::new(),
        )))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        upstream_request.insert_header("host", &self.host)?;

        if let Some(upgrade) = session.req_header().headers.get("upgrade").cloned() {
            upstream_request.insert_header("Upgrade", upgrade)?;
            upstream_request.insert_header("Connection", "Upgrade")?;
        }

        Ok(())
    }
}

pub fn run_dedicated_proxy_blocking(
    port: u16,
    upstream_addr: &str,
    host: &str,
    ca_file: Option<String>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let bind = format!("0.0.0.0:{port}");
    // Avoid loading macOS system certificates which may contain unsupported
    // critical extensions that crash rustls. Use provided CA or /dev/null.
    let conf = pingora::server::configuration::ServerConf {
        ca_file: Some(ca_file.unwrap_or_else(|| "/dev/null".to_string())),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let mut service = http_proxy_service(
        &server.configuration,
        DedicatedProxy {
            upstream_addr: upstream_addr.to_string(),
            host: host.to_string(),
        },
    );
    service.add_tcp(&bind);
    server.add_service(service);
    run_until_shutdown(server, shutdown);
    Ok(())
}

// ---------------------------------------------------------------------------
// Static file serving + directory listing
// ---------------------------------------------------------------------------

/// Try to serve a static file from `root`. Returns `Ok(true)` if the file was
/// found and served, `Ok(false)` if the file does not exist (caller should
/// fall through to the backend). Only returns `Err` on I/O or write failures.
async fn try_serve_static(
    session: &mut Session,
    root: &str,
    req_path: &str,
    cors: bool,
) -> Result<bool> {
    let decoded = percent_decode_str(req_path).decode_utf8_lossy();
    let clean = sanitize_path(&decoded);
    let full_path = PathBuf::from(root).join(&clean);

    let canonical_root = match tokio::fs::canonicalize(root).await {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let canonical_file = match tokio::fs::canonicalize(&full_path).await {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    if !canonical_file.starts_with(&canonical_root) {
        return Ok(false);
    }

    let meta = match tokio::fs::metadata(&canonical_file).await {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };

    if meta.is_dir() {
        let index = canonical_file.join("index.html");
        if let Ok(m) = tokio::fs::metadata(&index).await {
            if m.is_file() {
                serve_file(session, &index, cors).await?;
                return Ok(true);
            }
        }
        // Directory without index.html → fall through to backend
        return Ok(false);
    }

    if meta.is_file() {
        serve_file(session, &canonical_file, cors).await?;
        return Ok(true);
    }

    Ok(false)
}

async fn serve_static(session: &mut Session, root: &str, req_path: &str, cors: bool) -> Result<()> {
    let decoded = percent_decode_str(req_path).decode_utf8_lossy();
    let clean = sanitize_path(&decoded);
    let full_path = PathBuf::from(root).join(&clean);

    // Security: ensure resolved path is under root
    let canonical_root = match tokio::fs::canonicalize(root).await {
        Ok(p) => p,
        Err(_) => {
            write_error_page(session, 500, "static_root_missing").await?;
            return Ok(());
        }
    };
    let canonical_file = match tokio::fs::canonicalize(&full_path).await {
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

    let meta = match tokio::fs::metadata(&canonical_file).await {
        Ok(m) => m,
        Err(_) => {
            write_not_found(session).await?;
            return Ok(());
        }
    };

    if meta.is_dir() {
        // Try index.html first
        let index = canonical_file.join("index.html");
        if let Ok(m) = tokio::fs::metadata(&index).await {
            if m.is_file() {
                return serve_file(session, &index, cors).await;
            }
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
    let body = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(_) => {
            write_error_page(session, 500, "read_error").await?;
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

    session.write_response_header(Box::new(resp), false).await?;
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
    let mut read_dir = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => {
            write_error_page(session, 500, "read_dir_error").await?;
            return Ok(());
        }
    };

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue; // hide dotfiles
        }
        let meta = entry.metadata().await.ok();
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
        let size_display = if is_dir {
            "-".to_string()
        } else {
            format_size(size)
        };
        entries.push(DirEntry {
            href,
            display_name,
            is_dir,
            size_display,
            modified,
        });
    }

    entries.sort_by(|a, b| {
        // dirs first, then alphabetical
        b.is_dir
            .cmp(&a.is_dir)
            .then(a.display_name.cmp(&b.display_name))
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

    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await?;
    Ok(())
}

#[derive(Serialize)]
struct DirEntry {
    href: String,
    display_name: String,
    is_dir: bool,
    size_display: String,
    modified: String,
}

fn directory_tera() -> &'static Tera {
    use std::sync::LazyLock;
    static T: LazyLock<Tera> = LazyLock::new(|| {
        let mut tera = Tera::default();
        tera.add_raw_templates(vec![(
            "directory_listing.html",
            include_str!("directory_listing.html"),
        )])
        .expect("directory listing template parse error");
        tera.autoescape_on(vec![".html"]);
        tera
    });
    &T
}

fn render_directory_html(title: &str, req_path: &str, entries: &[DirEntry]) -> String {
    let mut ctx = Context::new();
    ctx.insert("title", title);
    ctx.insert("entries", entries);
    if req_path != "/" {
        let trimmed = req_path.trim_end_matches('/');
        let parent = match trimmed.rsplit_once('/') {
            Some(("", _)) => "/".to_string(),
            Some((p, _)) => format!("{p}/"),
            None => "/".to_string(),
        };
        ctx.insert("parent", &parent);
    }
    directory_tera()
        .render("directory_listing.html", &ctx)
        .unwrap_or_else(|e| format!("<html><body><pre>Template error: {e}</pre></body></html>"))
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

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn write_not_found(session: &mut Session) -> Result<()> {
    write_error_page(session, 404, "not_found").await
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
    let decoded_bytes = BASE64_STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded_bytes).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

async fn write_auth_required(session: &mut Session, realm: &str) -> Result<()> {
    let body = r#"{"error":"unauthorized"}"#;
    let mut resp = ResponseHeader::build(401, None)?;
    resp.insert_header("content-type", "application/json")?;
    resp.insert_header("content-length", body.len().to_string())?;
    resp.insert_header("www-authenticate", format!(r#"Basic realm="{realm}""#))?;
    resp.insert_header("connection", "close")?;

    session.write_response_header(Box::new(resp), false).await?;
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

    session.write_response_header(Box::new(resp), true).await?;
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
// Process manager helper
// ---------------------------------------------------------------------------

fn listen_target_to_backend(target: ListenTarget) -> BackendTarget {
    match target {
        ListenTarget::Uds(path) => BackendTarget::UnixSocket {
            path: path.to_string_lossy().to_string(),
        },
        ListenTarget::Tcp { host, port } => BackendTarget::Tcp { host, port },
    }
}

async fn pm_mark_active(pm: &ProcessManagerHandle, app_id: i64) {
    let mut pm = pm.lock().await;
    pm.mark_active(app_id);
}

// ---------------------------------------------------------------------------
// Error / routing helpers
// ---------------------------------------------------------------------------

fn accepts_html(session: &Session) -> bool {
    session
        .req_header()
        .headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"))
}

/// Wait for a managed process to become ready.
/// Browsers get an immediate 503 loading page; other clients block with polling.
async fn await_managed_ready(
    session: &mut Session,
    pm: &ProcessManagerHandle,
    app_id: i64,
    name: &str,
    root: &std::path::Path,
    kind: &str,
) -> std::result::Result<Option<BackendTarget>, Box<Error>> {
    // First attempt already returned Starting — check if browser
    if accepts_html(session) {
        write_loading_page(session, name, kind).await?;
        return Ok(None);
    }
    // Non-browser: poll until ready or timeout
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
    let deadline = tokio::time::Instant::now() + MAX_WAIT;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let status = crate::process::prepare_and_ensure_started(pm, app_id, name, root, kind)
            .await
            .map_err(|e| Error::explain(ErrorType::ConnectError, format!("{e}")))?;
        match status {
            StartStatus::Ready(listen_target) => {
                pm_mark_active(pm, app_id).await;
                return Ok(Some(listen_target_to_backend(listen_target)));
            }
            StartStatus::Starting => {
                if tokio::time::Instant::now() >= deadline {
                    write_error_page(session, 504, "managed_startup_timeout").await?;
                    return Ok(None);
                }
            }
        }
    }
}

async fn write_loading_page(session: &mut Session, app_name: &str, kind: &str) -> Result<()> {
    let accept = session
        .req_header()
        .headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let (content_type, body) = if accept.contains("application/json") {
        (
            "application/json; charset=utf-8",
            format!(
                r#"{{"error":"starting","app":"{}","retry_after":1}}"#,
                app_name.replace('"', "\\\"")
            ),
        )
    } else if accept.contains("text/html") {
        static TEMPLATE: &str = include_str!("loading.html");
        (
            "text/html; charset=utf-8",
            TEMPLATE
                .replace("{{name}}", &html_escape(app_name))
                .replace("{{kind}}", &html_escape(kind)),
        )
    } else {
        (
            "text/plain; charset=utf-8",
            format!("{app_name} is starting, retry in 1s"),
        )
    };

    let mut resp = ResponseHeader::build(503, None)?;
    resp.insert_header("content-type", content_type)?;
    resp.insert_header("content-length", body.len().to_string())?;
    resp.insert_header("retry-after", "1")?;
    resp.insert_header("cache-control", "no-cache, no-store")?;

    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await?;
    Ok(())
}

fn error_to_status_code(e: &Error) -> u16 {
    match e.etype() {
        HTTPStatus(code) => *code,
        _ => match e.esource() {
            ErrorSource::Upstream => 502,
            ErrorSource::Downstream => match e.etype() {
                WriteError | ReadError | ConnectionClosed => 0,
                _ => 400,
            },
            ErrorSource::Internal | ErrorSource::Unset => 500,
        },
    }
}

async fn write_error_page(session: &mut Session, status: u16, message: &str) -> Result<()> {
    let (title, desc, hint) = match (status, message) {
        (502, _) => (
            "Bad Gateway",
            "The upstream server is not reachable.",
            "Check that your app is running and listening on the configured port.",
        ),
        (403, "lan_access_denied") => (
            "Forbidden",
            "LAN access is not enabled for this app.",
            "Enable LAN access for this app in the dashboard or via the <code>app.update</code> API.",
        ),
        (400, "missing_host") => (
            "Bad Request",
            "The request is missing a Host header.",
            "Ensure your HTTP client sends a valid <code>Host</code> header.",
        ),
        (404, "route_not_found") => (
            "Not Found",
            "No app is registered for this domain.",
            "Register an app via the dashboard or by adding a file to your apps directory.",
        ),
        (404, _) => (
            "Not Found",
            "The requested resource was not found.",
            "Check that the file path is correct.",
        ),
        (500, "static_root_missing") => (
            "Internal Error",
            "The static file root directory is not accessible.",
            "Verify the app's <code>static_root</code> path exists and is readable.",
        ),
        (504, "managed_startup_timeout") => (
            "Gateway Timeout",
            "The managed app did not become ready in time.",
            "Check that the app starts successfully by looking at its log file.",
        ),
        (500, _) => (
            "Internal Error",
            "An unexpected error occurred while processing the request.",
            "Check the coulson logs for more details.",
        ),
        _ => (
            "Error",
            "Something went wrong.",
            "Check the coulson logs for more details.",
        ),
    };

    const TEMPLATE: &str = include_str!("error.html");
    let body = TEMPLATE
        .replace("{{status}}", &status.to_string())
        .replace("{{title}}", title)
        .replace("{{message}}", desc)
        .replace("{{hint}}", hint);

    let mut resp = ResponseHeader::build(status, None)?;
    resp.insert_header("content-type", "text/html; charset=utf-8")?;
    resp.insert_header("content-length", body.len().to_string())?;
    resp.insert_header("connection", "close")?;

    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await?;
    Ok(())
}

fn is_loopback_client(session: &Session) -> bool {
    session
        .client_addr()
        .and_then(|a| a.as_inet())
        .map(|inet| is_local_ip(inet.ip()))
        .unwrap_or(false)
}

/// Check if an IP is local (loopback or belongs to a local interface).
fn is_local_ip(ip: std::net::IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    // If we can bind to the IP, it belongs to this machine
    std::net::TcpListener::bind(std::net::SocketAddr::new(ip, 0)).is_ok()
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

    // Also try default.localhost for .localhost requests
    if domain_suffix != LOCALHOST_SUFFIX && host.ends_with(&format!(".{LOCALHOST_SUFFIX}")) {
        let default_localhost = format!("default.{LOCALHOST_SUFFIX}");
        if let Some(hit) = select_route(routes.get(&default_localhost), path) {
            return Some(hit);
        }
    }

    None
}

/// Like `resolve_target` but ignores path_prefix matching — returns any route
/// for the host. Used by embedded inspector to identify the app owning a domain
/// even when no root ("/") route exists.
fn resolve_any_route(
    routes: &HashMap<String, Vec<RouteRule>>,
    host: &str,
    domain_suffix: &str,
) -> Option<RouteRule> {
    if let Some(hit) = any_route(routes.get(host)) {
        return Some(hit);
    }

    // Wildcard host matching (e.g. *.example.com)
    if let Some(hit) = any_wildcard_route(routes, host) {
        return Some(hit);
    }

    let mut parts: Vec<&str> = host.split('.').collect();
    while parts.len() > 2 {
        parts.remove(0);
        let candidate = parts.join(".");
        if let Some(hit) = any_route(routes.get(&candidate)) {
            return Some(hit);
        }
    }

    let default_host = format!("default.{domain_suffix}");
    if let Some(hit) = any_route(routes.get(&default_host)) {
        return Some(hit);
    }

    if domain_suffix != LOCALHOST_SUFFIX && host.ends_with(&format!(".{LOCALHOST_SUFFIX}")) {
        let default_localhost = format!("default.{LOCALHOST_SUFFIX}");
        if let Some(hit) = any_route(routes.get(&default_localhost)) {
            return Some(hit);
        }
    }

    None
}

/// Like `select_wildcard_route` but ignores path_prefix matching.
fn any_wildcard_route(routes: &HashMap<String, Vec<RouteRule>>, host: &str) -> Option<RouteRule> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    for i in 1..(parts.len() - 1) {
        let suffix = parts[i..].join(".");
        let candidate = format!("*.{suffix}");
        if let Some(hit) = any_route(routes.get(&candidate)) {
            return Some(hit);
        }
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

/// Pick any route for a host, ignoring path_prefix matching.
/// Used by the embedded inspector to identify which app owns a domain.
/// Returns the shortest-prefix (most general) route as the "default" app.
fn any_route(candidates: Option<&Vec<RouteRule>>) -> Option<RouteRule> {
    candidates?.last().cloned()
}

// ---------------------------------------------------------------------------
// Request Inspector helpers (shared by BridgeProxy and DedicatedProxy)
// ---------------------------------------------------------------------------

fn inspect_capture_req_body(ctx: &mut ProxyCtx, body: &Option<Bytes>) {
    if !ctx.inspect {
        return;
    }
    if let Some(ref chunk) = body {
        let buf = ctx.inspect_req_body.get_or_insert_with(Vec::new);
        let remaining = INSPECT_BODY_MAX.saturating_sub(buf.len());
        if remaining > 0 {
            buf.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        }
    }
}

fn inspect_capture_response_meta(ctx: &mut ProxyCtx, upstream_response: &ResponseHeader) {
    if !ctx.inspect {
        return;
    }
    ctx.inspect_status = Some(upstream_response.status.as_u16());
    let headers: std::collections::HashMap<String, String> = upstream_response
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    ctx.inspect_resp_headers = serde_json::to_string(&headers).ok();
}

fn inspect_capture_resp_body(ctx: &mut ProxyCtx, body: &Option<Bytes>, end_of_stream: bool) {
    if !ctx.inspect {
        return;
    }
    if let Some(ref chunk) = body {
        let buf = ctx.inspect_resp_body.get_or_insert_with(Vec::new);
        let remaining = INSPECT_BODY_MAX.saturating_sub(buf.len());
        if remaining > 0 {
            buf.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        }
    }
    if end_of_stream {
        let elapsed = ctx.inspect_start.map(|s| s.elapsed().as_millis() as u64);
        let captured = CapturedRequest {
            id: uuid::Uuid::now_v7().to_string(),
            app_id: ctx.inspect_app_id.take().unwrap_or_default(),
            timestamp: time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000,
            method: ctx.inspect_method.take().unwrap_or_default(),
            path: ctx.inspect_path.take().unwrap_or_default(),
            query_string: ctx.inspect_query.take(),
            request_headers: ctx.inspect_req_headers.take().unwrap_or_default(),
            request_body: ctx.inspect_req_body.take(),
            status_code: ctx.inspect_status.take(),
            response_headers: ctx.inspect_resp_headers.take(),
            response_body: ctx.inspect_resp_body.take(),
            response_time_ms: elapsed,
        };
        if let Some(tx) = ctx.inspect_tx.take() {
            let event = crate::InspectEvent {
                app_id: captured.app_id,
                request_id: captured.id.clone(),
                method: captured.method.clone(),
                path: captured.path.clone(),
                query_string: captured.query_string.clone(),
                status_code: captured.status_code,
                response_time_ms: captured.response_time_ms,
                timestamp: captured.timestamp,
            };
            let _ = tx.send(event);
        }
        if let Some(store) = ctx.inspect_store.take() {
            let max = ctx.inspect_max_requests;
            tokio::spawn(async move {
                if let Err(e) = store.insert_request_log(&captured, max) {
                    tracing::warn!(error = %e, "failed to save captured request");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_is_normalized() {
        let host = extract_host(Some("MyApp.coulson.local:8080")).expect("host");
        assert_eq!(host, "myapp.coulson.local");
    }

    #[test]
    fn subdomain_falls_back_to_parent_host() {
        let mut routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        routes.insert(
            "myapp.coulson.local".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5006,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                static_root: None,
                app_id: None,
                inspect_enabled: false,
                lan_access: false,
            }],
        );
        let out = resolve_target(&routes, "www.myapp.coulson.local", "coulson.local", "/")
            .expect("fallback");
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
            "default.coulson.local".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5007,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                static_root: None,
                app_id: None,
                inspect_enabled: false,
                lan_access: false,
            }],
        );
        let out = resolve_target(
            &routes,
            "totally-unknown.coulson.local",
            "coulson.local",
            "/",
        )
        .expect("default");
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
            "myapp.coulson.local".to_string(),
            vec![
                RouteRule {
                    target: BackendTarget::Tcp {
                        host: "127.0.0.1".to_string(),
                        port: 5000,
                    },
                    path_prefix: Some("/api/v1".to_string()),
                    timeout_ms: None,
                    cors_enabled: false,
                    force_https: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    static_root: None,
                    app_id: None,
                    inspect_enabled: false,
                    lan_access: false,
                },
                RouteRule {
                    target: BackendTarget::Tcp {
                        host: "127.0.0.1".to_string(),
                        port: 4000,
                    },
                    path_prefix: Some("/api".to_string()),
                    timeout_ms: None,
                    cors_enabled: false,
                    force_https: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    static_root: None,
                    app_id: None,
                    inspect_enabled: false,
                    lan_access: false,
                },
            ],
        );
        let out = resolve_target(
            &routes,
            "myapp.coulson.local",
            "coulson.local",
            "/api/v1/users",
        )
        .expect("route");
        match out.target {
            BackendTarget::Tcp { port, .. } => assert_eq!(port, 5000),
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn wildcard_host_matches_subdomain() {
        let mut routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        routes.insert(
            "*.myapp.coulson.local".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5010,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                static_root: None,
                app_id: None,
                inspect_enabled: false,
                lan_access: false,
            }],
        );
        let out = resolve_target(&routes, "api.myapp.coulson.local", "coulson.local", "/")
            .expect("wildcard");
        match out.target {
            BackendTarget::Tcp { port, .. } => assert_eq!(port, 5010),
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn exact_host_beats_wildcard() {
        let mut routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        routes.insert(
            "api.myapp.coulson.local".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5001,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                static_root: None,
                app_id: None,
                inspect_enabled: false,
                lan_access: false,
            }],
        );
        routes.insert(
            "*.myapp.coulson.local".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5002,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                static_root: None,
                app_id: None,
                inspect_enabled: false,
                lan_access: false,
            }],
        );
        let out = resolve_target(&routes, "api.myapp.coulson.local", "coulson.local", "/")
            .expect("route");
        match out.target {
            BackendTarget::Tcp { port, .. } => assert_eq!(port, 5001),
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn wildcard_requires_subdomain() {
        let mut routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        routes.insert(
            "*.myapp.coulson.local".to_string(),
            vec![RouteRule {
                target: BackendTarget::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 5002,
                },
                path_prefix: None,
                timeout_ms: None,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                static_root: None,
                app_id: None,
                inspect_enabled: false,
                lan_access: false,
            }],
        );
        assert!(resolve_target(&routes, "myapp.coulson.local", "coulson.local", "/").is_none());
    }

    // --- New feature tests ---

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
        assert_eq!(
            percent_decode_str("/foo%20bar").decode_utf8_lossy(),
            "/foo bar"
        );
        assert_eq!(percent_decode_str("/a%2Fb").decode_utf8_lossy(), "/a/b");
    }

    #[test]
    fn format_size_units() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1048576), "1.0 MB");
        assert_eq!(format_size(1073741824), "1.0 GB");
    }

    // Helper to build a RouteRule with only the fields we care about
    fn route(target_port: u16, path_prefix: Option<&str>) -> RouteRule {
        RouteRule {
            target: BackendTarget::Tcp {
                host: "127.0.0.1".to_string(),
                port: target_port,
            },
            path_prefix: path_prefix.map(|s| s.to_string()),
            timeout_ms: None,
            cors_enabled: false,
            force_https: false,
            basic_auth_user: None,
            basic_auth_pass: None,
            spa_rewrite: false,
            listen_port: None,
            static_root: None,
            app_id: None,
            inspect_enabled: false,
            lan_access: false,
        }
    }

    fn assert_port(rule: &RouteRule, expected: u16) {
        match &rule.target {
            BackendTarget::Tcp { port, .. } => assert_eq!(*port, expected),
            _ => panic!("expected tcp target"),
        }
    }

    #[test]
    fn no_routes_returns_none() {
        let routes: HashMap<String, Vec<RouteRule>> = HashMap::new();
        assert!(resolve_target(&routes, "myapp.coulson.local", "coulson.local", "/").is_none());
    }

    #[test]
    fn path_prefix_exact_match() {
        let mut routes = HashMap::new();
        routes.insert(
            "myapp.coulson.local".to_string(),
            vec![route(5000, Some("/api")), route(4000, None)],
        );
        let out =
            resolve_target(&routes, "myapp.coulson.local", "coulson.local", "/api").expect("route");
        assert_port(&out, 5000);
    }

    #[test]
    fn path_prefix_child_path_match() {
        let mut routes = HashMap::new();
        routes.insert(
            "myapp.coulson.local".to_string(),
            vec![route(5000, Some("/api")), route(4000, None)],
        );
        let out = resolve_target(
            &routes,
            "myapp.coulson.local",
            "coulson.local",
            "/api/users/1",
        )
        .expect("route");
        assert_port(&out, 5000);
    }

    #[test]
    fn path_prefix_no_match_falls_through() {
        let mut routes = HashMap::new();
        routes.insert(
            "myapp.coulson.local".to_string(),
            vec![route(5000, Some("/api")), route(4000, None)],
        );
        let out = resolve_target(&routes, "myapp.coulson.local", "coulson.local", "/about")
            .expect("route");
        assert_port(&out, 4000);
    }

    #[test]
    fn path_prefix_partial_name_no_false_match() {
        // /api should NOT match /api-docs (no "/" separator)
        let mut routes = HashMap::new();
        routes.insert(
            "myapp.coulson.local".to_string(),
            vec![route(5000, Some("/api")), route(4000, None)],
        );
        let out = resolve_target(&routes, "myapp.coulson.local", "coulson.local", "/api-docs")
            .expect("route");
        assert_port(&out, 4000);
    }

    #[test]
    fn deep_subdomain_falls_back_progressively() {
        // a.b.myapp.coulson.local → b.myapp.coulson.local → myapp.coulson.local
        let mut routes = HashMap::new();
        routes.insert("myapp.coulson.local".to_string(), vec![route(5006, None)]);
        let out = resolve_target(&routes, "a.b.myapp.coulson.local", "coulson.local", "/")
            .expect("fallback");
        assert_port(&out, 5006);
    }

    #[test]
    fn subdomain_fallback_stops_at_mid_level() {
        // a.b.myapp.coulson.local: b.myapp.coulson.local exists → use it, not myapp.coulson.local
        let mut routes = HashMap::new();
        routes.insert("b.myapp.coulson.local".to_string(), vec![route(6000, None)]);
        routes.insert("myapp.coulson.local".to_string(), vec![route(5000, None)]);
        let out = resolve_target(&routes, "a.b.myapp.coulson.local", "coulson.local", "/")
            .expect("fallback");
        assert_port(&out, 6000);
    }

    #[test]
    fn wildcard_deeper_nesting() {
        // *.coulson.local matches foo.coulson.local
        let mut routes = HashMap::new();
        routes.insert("*.coulson.local".to_string(), vec![route(7000, None)]);
        let out = resolve_target(&routes, "anything.coulson.local", "coulson.local", "/")
            .expect("wildcard");
        assert_port(&out, 7000);
    }

    #[test]
    fn wildcard_with_path_prefix() {
        let mut routes = HashMap::new();
        routes.insert(
            "*.myapp.coulson.local".to_string(),
            vec![route(5000, Some("/api")), route(4000, None)],
        );
        let out = resolve_target(
            &routes,
            "v2.myapp.coulson.local",
            "coulson.local",
            "/api/items",
        )
        .expect("wildcard+path");
        assert_port(&out, 5000);
    }

    #[test]
    fn extract_host_none_returns_none() {
        assert!(extract_host(None).is_none());
    }

    #[test]
    fn extract_host_strips_port() {
        let host = extract_host(Some("myapp.test:8080")).expect("host");
        assert_eq!(host, "myapp.test");
    }

    #[test]
    fn extract_host_lowercases() {
        let host = extract_host(Some("MyApp.Test")).expect("host");
        assert_eq!(host, "myapp.test");
    }
}
