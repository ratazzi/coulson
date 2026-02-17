use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};

use crate::domain::{AppSpec, DomainName, TunnelMode};
use crate::scanner;
use crate::store::{StaticAppInput, StoreError};
use crate::tunnel;
use crate::SharedState;

#[derive(Debug, Deserialize)]
struct RequestEnvelope {
    request_id: String,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ResponseEnvelope {
    request_id: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Debug, Error)]
enum ControlError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("not found")]
    NotFound,
    #[error("domain conflict")]
    DomainConflict,
    #[error("detection failed: {0}")]
    DetectionFailed(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Deserialize)]
struct CreateAppParams {
    name: String,
    domain: String,
    #[serde(default)]
    path_prefix: Option<String>,
    #[serde(default = "default_target_type")]
    target_type: String,
    #[serde(default)]
    target_value: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    cors_enabled: bool,
    #[serde(default)]
    basic_auth_user: Option<String>,
    #[serde(default)]
    basic_auth_pass: Option<String>,
    #[serde(default)]
    spa_rewrite: bool,
    #[serde(default)]
    listen_port: Option<u16>,
}

fn default_target_type() -> String {
    "tcp".to_string()
}

#[derive(Debug, Deserialize)]
struct AppIdParams {
    app_id: i64,
}

#[derive(Debug, Deserialize)]
struct NamedTunnelSetupParams {
    api_token: String,
    account_id: String,
    domain: String,
    #[serde(default)]
    tunnel_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NamedTunnelTeardownParams {
    api_token: String,
}

#[derive(Debug, Deserialize)]
struct TunnelConfigureParams {
    api_token: String,
    account_id: String,
}

#[derive(Debug, Deserialize)]
struct NamedTunnelConnectParams {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AppTunnelSetupParams {
    app_id: i64,
    domain: String,
    #[serde(default)]
    auto_dns: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateSettingsParams {
    app_id: i64,
    cors_enabled: Option<bool>,
    basic_auth_user: Option<Option<String>>,
    basic_auth_pass: Option<Option<String>>,
    spa_rewrite: Option<bool>,
    listen_port: Option<Option<u16>>,
    tunnel_mode: Option<TunnelMode>,
    app_tunnel_domain: Option<String>,
    app_tunnel_token: Option<String>,
    #[serde(default)]
    app_tunnel_auto_dns: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct CreateFromFolderParams {
    path: String,
}

#[derive(Debug, Deserialize)]
struct RequestListParams {
    app_name: String,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize {
    50
}

#[derive(Debug, Deserialize)]
struct RequestGetParams {
    app_name: String,
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct RequestWatchParams {
    app_name: String,
}

#[derive(Debug, Deserialize)]
struct RequestReplayParams {
    app_name: String,
    request_id: String,
}

pub async fn run_control_server(socket_path: PathBuf, state: SharedState) -> anyhow::Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    info!(path = %socket_path.display(), "control server listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, state).await {
                let is_broken_pipe = err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe);
                if is_broken_pipe {
                    debug!(error = %err, "control client disconnected");
                } else {
                    error!(error = %err, "control client failed");
                }
            }
        });
    }
}

async fn handle_client(stream: UnixStream, state: SharedState) -> anyhow::Result<()> {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r).lines();

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<RequestEnvelope>(&line) {
            Ok(req) => dispatch_request(req, &state).await,
            Err(err) => ResponseEnvelope {
                request_id: "unknown".to_string(),
                ok: false,
                result: None,
                error: Some(ErrorBody {
                    code: "bad_request".to_string(),
                    message: err.to_string(),
                    details: None,
                }),
            },
        };

        let payload = serde_json::to_string(&response)?;
        w.write_all(payload.as_bytes()).await?;
        w.write_all(b"\n").await?;
    }

    Ok(())
}

macro_rules! find_app {
    ($state:expr, $req:ident, $app_id:expr) => {
        match $state.store.get_by_id($app_id) {
            Ok(Some(app)) => app,
            Ok(None) => return render_err($req.request_id, ControlError::NotFound),
            Err(e) => return internal_error($req.request_id, e.to_string()),
        }
    };
}

macro_rules! require_setting {
    ($state:expr, $req:ident, $key:expr, $msg:expr) => {
        match $state.store.get_setting($key) {
            Ok(Some(v)) => v,
            Ok(None) => {
                return render_err(
                    $req.request_id,
                    ControlError::InvalidParams($msg.to_string()),
                );
            }
            Err(e) => return internal_error($req.request_id, e.to_string()),
        }
    };
}

macro_rules! parse_params {
    ($req:ident) => {
        match serde_json::from_value($req.params) {
            Ok(v) => v,
            Err(e) => {
                return render_err($req.request_id, ControlError::InvalidParams(e.to_string()));
            }
        }
    };
}

async fn dispatch_request(req: RequestEnvelope, state: &SharedState) -> ResponseEnvelope {
    let result = match req.method.as_str() {
        "health.ping" => Ok(json!({
            "pong": true,
            "version": env!("CARGO_PKG_VERSION"),
            "http_port": state.listen_http.port(),
            "https_port": state.listen_https.map(|a| a.port()),
            "runtime_dir": state.runtime_dir.to_string_lossy(),
        })),
        "app.list" => {
            let apps = match state.store.list_all() {
                Ok(v) => v,
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };
            Ok(json!({ "apps": apps }))
        }
        "request.list" => {
            let params: RequestListParams = parse_params!(req);
            // Verify app exists (consistent with request.get/request.watch)
            match state.store.get_by_name(&params.app_name) {
                Ok(Some(_)) => {}
                Ok(None) => return render_err(req.request_id, ControlError::NotFound),
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
            let (requests, total) = match state.store.get_request_logs_by_app_name(
                &params.app_name,
                params.limit,
                params.offset,
            ) {
                Ok(v) => v,
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };
            Ok(json!({ "requests": requests, "total": total }))
        }
        "request.get" => {
            let params: RequestGetParams = parse_params!(req);
            // Validate app_name matches the request
            let app = match state.store.get_by_name(&params.app_name) {
                Ok(v) => v,
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };
            let app_id = match app {
                Some(a) => a.id.0,
                None => return render_err(req.request_id, ControlError::NotFound),
            };
            let captured = match state.store.get_request_log(&params.request_id) {
                Ok(v) => v,
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };
            match captured {
                Some(r) if r.app_id == app_id => Ok(json!({ "request": r })),
                Some(_) => Err(ControlError::NotFound),
                None => Err(ControlError::NotFound),
            }
        }
        "request.watch" => {
            let params: RequestWatchParams = parse_params!(req);
            // Verify app exists
            match state.store.get_by_name(&params.app_name) {
                Ok(Some(_)) => {
                    let port = state.listen_http.port();
                    Ok(json!({
                        "stream_url": format!("http://127.0.0.1:{}/apps/{}/requests/stream", port, params.app_name)
                    }))
                }
                Ok(None) => Err(ControlError::NotFound),
                Err(e) => Err(ControlError::Internal(e.to_string())),
            }
        }
        "request.replay" => {
            let params: RequestReplayParams = parse_params!(req);
            // Pre-validate app and request existence (consistent with request.get)
            let app = match state.store.get_by_name(&params.app_name) {
                Ok(Some(a)) => a,
                Ok(None) => return render_err(req.request_id, ControlError::NotFound),
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };
            match state.store.get_request_log(&params.request_id) {
                Ok(Some(r)) if r.app_id == app.id.0 => {}
                Ok(_) => return render_err(req.request_id, ControlError::NotFound),
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
            match crate::dashboard::execute_replay(
                &state.store,
                &params.app_name,
                &params.request_id,
            )
            .await
            {
                Ok(outcome) => {
                    if let Some(ref err) = outcome.error {
                        Ok(json!({ "error": err }))
                    } else {
                        Ok(json!({
                            "status_code": outcome.status_code,
                            "response_time_ms": outcome.response_time_ms,
                            "response_headers": outcome.response_headers,
                            "body": outcome.body,
                        }))
                    }
                }
                Err(e) => Err(ControlError::Internal(e.to_string())),
            }
        }
        "app.create"
        | "app.create_tcp"
        | "app.create_static"
        | "app.create_static_dir"
        | "app.create_unix_socket" => {
            let params: CreateAppParams = parse_params!(req);

            if params.name.trim().is_empty() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("name cannot be empty".to_string()),
                );
            }
            if params.target_value.is_empty() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("target_value cannot be empty".to_string()),
                );
            }

            let domain = match DomainName::parse(&params.domain, &state.domain_suffix) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            if matches!(params.timeout_ms, Some(0)) {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("timeout_ms must be > 0".to_string()),
                );
            }

            if let Some(port) = params.listen_port {
                if port == 0 {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams("listen_port must be > 0".to_string()),
                    );
                }
            }

            // Type-specific validation
            match params.target_type.as_str() {
                "tcp" => {
                    let (_, port_str) = params.target_value.rsplit_once(':').unwrap_or(("", ""));
                    match port_str.parse::<u16>() {
                        Ok(p) if p > 0 => {}
                        _ => {
                            return render_err(
                                req.request_id,
                                ControlError::InvalidParams(format!(
                                    "tcp target_value must be host:port (port > 0), got: {}",
                                    params.target_value
                                )),
                            );
                        }
                    }
                }
                "static_dir" => {
                    let root = std::path::Path::new(&params.target_value);
                    if !root.is_dir() {
                        return render_err(
                            req.request_id,
                            ControlError::InvalidParams(format!(
                                "static_dir target is not a directory: {}",
                                params.target_value
                            )),
                        );
                    }
                }
                "unix_socket" => {
                    let sock = std::path::Path::new(&params.target_value);
                    if !sock.exists() {
                        return render_err(
                            req.request_id,
                            ControlError::InvalidParams(format!(
                                "unix_socket target does not exist: {}",
                                params.target_value
                            )),
                        );
                    }
                }
                other => {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams(format!(
                            "unknown target_type: {other}, must be tcp/static_dir/unix_socket"
                        )),
                    );
                }
            }

            let path_prefix = match normalize_path_prefix(params.path_prefix.as_deref()) {
                Ok(v) => v,
                Err(msg) => {
                    return render_err(req.request_id, ControlError::InvalidParams(msg));
                }
            };

            match state.store.insert_static(&StaticAppInput {
                name: &params.name,
                domain: &domain,
                path_prefix: path_prefix.as_deref(),
                target_type: &params.target_type,
                target_value: &params.target_value,
                timeout_ms: params.timeout_ms,
                cors_enabled: params.cors_enabled,
                basic_auth_user: params.basic_auth_user.as_deref(),
                basic_auth_pass: params.basic_auth_pass.as_deref(),
                spa_rewrite: params.spa_rewrite,
                listen_port: params.listen_port,
            }) {
                Ok(app) => {
                    if let Err(e) = state.reload_routes() {
                        return internal_error(req.request_id, e.to_string());
                    }
                    Ok(json!({ "app": app }))
                }
                Err(e) => {
                    if let Some(StoreError::DomainConflict) = e.downcast_ref::<StoreError>() {
                        return render_err(req.request_id, ControlError::DomainConflict);
                    }
                    return internal_error(req.request_id, e.to_string());
                }
            }
        }
        "app.create_from_folder" => {
            let params: CreateFromFolderParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            let folder = std::path::Path::new(&params.path);
            if !folder.is_dir() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams(format!(
                        "path is not a directory: {}",
                        params.path
                    )),
                );
            }

            let folder_name = folder.file_name().and_then(|n| n.to_str()).unwrap_or("app");
            let name = scanner::sanitize_name(folder_name);
            let domain_str = format!("{}.{}", name, state.domain_suffix);
            let domain = match DomainName::parse(&domain_str, &state.domain_suffix) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            // Helper: insert app, reload routes, return response
            let insert_and_respond = |result: anyhow::Result<AppSpec>| -> ResponseEnvelope {
                match result {
                    Ok(app) => {
                        let _ = state.reload_routes();
                        ok_response(req.request_id.clone(), json!({ "app": app }))
                    }
                    Err(e) => {
                        if let Some(StoreError::DomainConflict) = e.downcast_ref::<StoreError>() {
                            render_err(req.request_id.clone(), ControlError::DomainConflict)
                        } else {
                            internal_error(req.request_id.clone(), e.to_string())
                        }
                    }
                }
            };

            let insert_tcp = |target_value: &str| -> ResponseEnvelope {
                let input = StaticAppInput {
                    name: &name,
                    domain: &domain,
                    path_prefix: None,
                    target_type: "tcp",
                    target_value,
                    timeout_ms: None,
                    cors_enabled: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                };
                insert_and_respond(state.store.insert_static(&input))
            };

            // 1. coulson.json
            let manifest_path = folder.join("coulson.json");
            if manifest_path.exists() {
                let raw = match std::fs::read_to_string(&manifest_path) {
                    Ok(v) => v,
                    Err(e) => return internal_error(req.request_id, e.to_string()),
                };
                let manifest: serde_json::Value = match serde_json::from_str(&raw) {
                    Ok(v) => v,
                    Err(e) => {
                        return internal_error(req.request_id, format!("invalid coulson.json: {e}"))
                    }
                };

                if let Some((_prov, detected)) =
                    state.provider_registry.detect(folder, Some(&manifest))
                {
                    let root_str = folder.to_string_lossy().to_string();
                    return insert_and_respond(state.store.insert_managed(
                        &name,
                        &domain,
                        &root_str,
                        &detected.kind,
                        None,
                    ));
                }

                if let Some(raw_port) = manifest.get("target_port").and_then(|v| v.as_u64()) {
                    if raw_port > u16::MAX as u64 {
                        return render_err(
                            req.request_id,
                            ControlError::InvalidParams(format!(
                                "target_port out of range: {raw_port}"
                            )),
                        );
                    }
                    let port = raw_port as u16;
                    if port > 0 {
                        let host = manifest
                            .get("target_host")
                            .and_then(|v| v.as_str())
                            .unwrap_or("127.0.0.1");
                        let target_value = format!("{host}:{port}");
                        return insert_tcp(&target_value);
                    }
                }
            }

            // 2. coulson.routes — parse first non-empty line
            let routes_path = folder.join("coulson.routes");
            if routes_path.exists() {
                let raw = match std::fs::read_to_string(&routes_path) {
                    Ok(v) => v,
                    Err(e) => return internal_error(req.request_id, e.to_string()),
                };
                if let Some(target_value) = parse_first_route_target(&raw) {
                    return insert_tcp(&target_value);
                }
            }

            // 3. Provider registry auto-detect
            if let Some((_prov, detected)) = state.provider_registry.detect(folder, None) {
                let root_str = folder.to_string_lossy().to_string();
                return insert_and_respond(state.store.insert_managed(
                    &name,
                    &domain,
                    &root_str,
                    &detected.kind,
                    None,
                ));
            }

            // 4. public/ subdirectory
            let public_dir = folder.join("public");
            if public_dir.is_dir() {
                let root_str = public_dir.to_string_lossy().to_string();
                return insert_and_respond(
                    state
                        .store
                        .insert_static_dir(&name, &domain, &root_str, None),
                );
            }

            // 5. index.html
            if folder.join("index.html").exists() {
                let root_str = folder.to_string_lossy().to_string();
                return insert_and_respond(
                    state
                        .store
                        .insert_static_dir(&name, &domain, &root_str, None),
                );
            }

            // 6. Nothing detected
            Err(ControlError::DetectionFailed(format!(
                "could not detect app type for: {}",
                params.path
            )))
        }
        "app.update" => {
            let params: UpdateSettingsParams = parse_params!(req);
            match state.store.update_settings(
                params.app_id,
                params.cors_enabled,
                params.basic_auth_user.as_ref().map(|v| v.as_deref()),
                params.basic_auth_pass.as_ref().map(|v| v.as_deref()),
                params.spa_rewrite,
                params.listen_port,
                None,
            ) {
                Ok(found) => {
                    if !found {
                        return render_err(req.request_id, ControlError::NotFound);
                    }
                    if let Err(e) = state.reload_routes() {
                        return internal_error(req.request_id, e.to_string());
                    }
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }

            // Handle tunnel_mode change
            if let Some(new_mode) = params.tunnel_mode {
                let app = find_app!(state, req, params.app_id);

                let old_mode = &app.tunnel_mode;

                // Check if named mode has required params
                if new_mode == TunnelMode::Named
                    && params.app_tunnel_domain.is_none()
                    && app.app_tunnel_domain.is_none()
                {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams(
                            "app_tunnel_domain is required for named tunnel mode".to_string(),
                        ),
                    );
                }

                // Check if named mode needs re-setup (domain changed)
                let named_domain_changed = new_mode == TunnelMode::Named
                    && *old_mode == TunnelMode::Named
                    && params.app_tunnel_domain.is_some()
                    && params.app_tunnel_domain.as_deref() != app.app_tunnel_domain.as_deref();

                if *old_mode != new_mode || named_domain_changed {
                    let routing = routing_for_app(&app, state.listen_http.port());

                    // Teardown old mode (best-effort: log errors and continue)
                    match old_mode {
                        TunnelMode::Quick => {
                            let _ = tunnel::stop_tunnel(&state.tunnels, params.app_id);
                            if let Err(e) = state.store.update_tunnel_url(params.app_id, None) {
                                tracing::warn!(error = %e, "failed to clear tunnel_url during teardown");
                            }
                            if let Err(e) =
                                state.store.set_tunnel_mode(params.app_id, TunnelMode::None)
                            {
                                tracing::warn!(error = %e, "failed to reset tunnel_mode during teardown");
                            }
                        }
                        TunnelMode::Named => {
                            // Stop the tunnel connection but preserve credentials
                            // so the tunnel can be reconnected via `start` without re-creating CF resources.
                            let _ =
                                tunnel::stop_app_named_tunnel(&state.app_tunnels, params.app_id);
                            if let Err(e) =
                                state.store.set_tunnel_mode(params.app_id, TunnelMode::None)
                            {
                                tracing::warn!(error = %e, "failed to reset tunnel_mode during teardown");
                            }
                        }
                        _ => {}
                    }

                    // Setup new mode
                    match new_mode {
                        TunnelMode::Quick => {
                            match tunnel::start_quick_tunnel(
                                state.tunnels.clone(),
                                params.app_id,
                                routing.clone(),
                            )
                            .await
                            {
                                Ok(hostname) => {
                                    let url = format!("https://{hostname}");
                                    if let Err(e) =
                                        state.store.update_tunnel_url(params.app_id, Some(&url))
                                    {
                                        return internal_error(req.request_id, e.to_string());
                                    }
                                    if let Err(e) = state
                                        .store
                                        .set_tunnel_mode(params.app_id, TunnelMode::Quick)
                                    {
                                        return internal_error(req.request_id, e.to_string());
                                    }
                                    let _ = state.reload_routes();
                                    return ok_response(
                                        req.request_id,
                                        json!({ "updated": true, "tunnel_mode": "quick", "tunnel_url": url }),
                                    );
                                }
                                Err(e) => return internal_error(req.request_id, e.to_string()),
                            }
                        }
                        TunnelMode::Named => {
                            let tunnel_domain =
                                match params
                                    .app_tunnel_domain
                                    .as_deref()
                                    .or(app.app_tunnel_domain.as_deref())
                                {
                                    Some(d) => d.to_string(),
                                    None => return render_err(
                                        req.request_id,
                                        ControlError::InvalidParams(
                                            "app_tunnel_domain is required for named tunnel mode"
                                                .to_string(),
                                        ),
                                    ),
                                };

                            // Reconnect using saved credentials if available
                            // (skip when domain changed — that requires a full rebuild)
                            if !named_domain_changed
                                && params.app_tunnel_token.is_none()
                                && app.app_tunnel_creds.is_some()
                            {
                                let creds: tunnel::TunnelCredentials = match serde_json::from_str(
                                    app.app_tunnel_creds.as_ref().unwrap(),
                                ) {
                                    Ok(v) => v,
                                    Err(e) => return internal_error(req.request_id, e.to_string()),
                                };
                                if let Err(e) = tunnel::start_app_named_tunnel(
                                    state.app_tunnels.clone(),
                                    params.app_id,
                                    creds.clone(),
                                    tunnel_domain.clone(),
                                    routing.clone(),
                                )
                                .await
                                {
                                    return internal_error(req.request_id, e.to_string());
                                }
                                if let Err(e) = state
                                    .store
                                    .set_tunnel_mode(params.app_id, TunnelMode::Named)
                                {
                                    return internal_error(req.request_id, e.to_string());
                                }
                                let _ = state.reload_routes();
                                return ok_response(
                                    req.request_id,
                                    json!({
                                        "updated": true,
                                        "tunnel_mode": "named",
                                        "tunnel_id": creds.tunnel_id,
                                        "tunnel_domain": tunnel_domain,
                                        "reconnected": true,
                                    }),
                                );
                            }

                            // Token-based: decode token and connect directly
                            if let Some(token) = &params.app_tunnel_token {
                                let credentials = match tunnel::decode_tunnel_token(token) {
                                    Ok(v) => v,
                                    Err(e) => return internal_error(req.request_id, e.to_string()),
                                };
                                let tunnel_id = credentials.tunnel_id.clone();

                                if let Err(e) = tunnel::start_app_named_tunnel(
                                    state.app_tunnels.clone(),
                                    params.app_id,
                                    credentials.clone(),
                                    tunnel_domain.clone(),
                                    routing.clone(),
                                )
                                .await
                                {
                                    return internal_error(req.request_id, e.to_string());
                                }

                                let creds_json = match serde_json::to_string(&credentials) {
                                    Ok(v) => v,
                                    Err(e) => return internal_error(req.request_id, e.to_string()),
                                };
                                if let Err(e) = state.store.set_app_tunnel_state(
                                    params.app_id,
                                    Some(&tunnel_id),
                                    Some(&tunnel_domain),
                                    None,
                                    Some(&creds_json),
                                    TunnelMode::Named,
                                ) {
                                    return internal_error(req.request_id, e.to_string());
                                }

                                let _ = state.reload_routes();
                                return ok_response(
                                    req.request_id,
                                    json!({
                                        "updated": true,
                                        "tunnel_mode": "named",
                                        "tunnel_id": tunnel_id,
                                        "tunnel_domain": tunnel_domain,
                                    }),
                                );
                            }

                            // API-based: create tunnel via CF API
                            let auto_dns = params.app_tunnel_auto_dns.unwrap_or(false);

                            let api_token = require_setting!(
                                state,
                                req,
                                "cf.api_token",
                                "CF credentials not configured, run tunnel.configure first"
                            );
                            let account_id = require_setting!(
                                state,
                                req,
                                "cf.account_id",
                                "cf.account_id not configured"
                            );

                            let tunnel_name = format!("coulson-{}", params.app_id);
                            let (credentials, tunnel_id) = match tunnel::named::create_named_tunnel(
                                &api_token,
                                &account_id,
                                &tunnel_name,
                            )
                            .await
                            {
                                Ok(v) => v,
                                Err(e) => return internal_error(req.request_id, e.to_string()),
                            };

                            let mut dns_record_id: Option<String> = None;
                            let mut zone_id_used: Option<String> = None;
                            if auto_dns {
                                match tunnel::named::find_zone_id(&api_token, &tunnel_domain).await
                                {
                                    Ok(zid) => {
                                        zone_id_used = Some(zid.clone());
                                        match tunnel::named::create_dns_cname(
                                            &api_token,
                                            &zid,
                                            &tunnel_domain,
                                            &tunnel_id,
                                        )
                                        .await
                                        {
                                            Ok(rid) => dns_record_id = Some(rid),
                                            Err(e) => {
                                                let _ = tunnel::named::delete_named_tunnel(
                                                    &api_token,
                                                    &account_id,
                                                    &tunnel_id,
                                                )
                                                .await;
                                                return internal_error(
                                                    req.request_id,
                                                    format!("failed to create DNS CNAME: {e}"),
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tunnel::named::delete_named_tunnel(
                                            &api_token,
                                            &account_id,
                                            &tunnel_id,
                                        )
                                        .await;
                                        return internal_error(
                                            req.request_id,
                                            format!("failed to find zone for domain: {e}"),
                                        );
                                    }
                                }
                            }

                            if let Err(e) = tunnel::start_app_named_tunnel(
                                state.app_tunnels.clone(),
                                params.app_id,
                                credentials.clone(),
                                tunnel_domain.clone(),
                                routing.clone(),
                            )
                            .await
                            {
                                if let (Some(rid), Some(zid)) = (&dns_record_id, &zone_id_used) {
                                    let _ = tunnel::named::delete_dns_record(&api_token, zid, rid)
                                        .await;
                                }
                                let _ = tunnel::named::delete_named_tunnel(
                                    &api_token,
                                    &account_id,
                                    &tunnel_id,
                                )
                                .await;
                                return internal_error(req.request_id, e.to_string());
                            }

                            let creds_json = match serde_json::to_string(&credentials) {
                                Ok(v) => v,
                                Err(e) => return internal_error(req.request_id, e.to_string()),
                            };
                            if let Err(e) = state.store.set_app_tunnel_state(
                                params.app_id,
                                Some(&tunnel_id),
                                Some(&tunnel_domain),
                                dns_record_id.as_deref(),
                                Some(&creds_json),
                                TunnelMode::Named,
                            ) {
                                return internal_error(req.request_id, e.to_string());
                            }

                            let _ = state.reload_routes();
                            return ok_response(
                                req.request_id,
                                json!({
                                    "updated": true,
                                    "tunnel_mode": "named",
                                    "tunnel_id": tunnel_id,
                                    "tunnel_domain": tunnel_domain,
                                    "dns_record_id": dns_record_id,
                                }),
                            );
                        }
                        // None / Global — teardown already done above, just set mode
                        _ => {
                            if let Err(e) = state.store.set_tunnel_mode(params.app_id, new_mode) {
                                return internal_error(req.request_id, e.to_string());
                            }
                            let _ = state.reload_routes();
                            return ok_response(
                                req.request_id,
                                json!({ "updated": true, "tunnel_mode": new_mode.as_str() }),
                            );
                        }
                    }
                }
            }

            Ok(json!({ "updated": true }))
        }
        "app.delete" => {
            let params: AppIdParams = parse_params!(req);
            let app = find_app!(state, req, params.app_id);
            if let Some(ref fs_entry) = app.fs_entry {
                scanner::remove_app_fs_entry(&state.apps_root, fs_entry);
            }
            match state.store.delete(params.app_id) {
                Ok(found) => {
                    if !found {
                        return render_err(req.request_id, ControlError::NotFound);
                    }
                    if let Err(e) = state.reload_routes() {
                        return internal_error(req.request_id, e.to_string());
                    }
                    Ok(json!({ "deleted": true }))
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
        }
        "app.start" => {
            let params: AppIdParams = parse_params!(req);
            match state.store.set_enabled(params.app_id, true) {
                Ok(found) => {
                    if !found {
                        return render_err(req.request_id, ControlError::NotFound);
                    }
                    if let Err(e) = state.reload_routes() {
                        return internal_error(req.request_id, e.to_string());
                    }
                    Ok(json!({ "enabled": true }))
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
        }
        "app.stop" => {
            let params: AppIdParams = parse_params!(req);
            match state.store.set_enabled(params.app_id, false) {
                Ok(found) => {
                    if !found {
                        return render_err(req.request_id, ControlError::NotFound);
                    }
                    if let Err(e) = state.reload_routes() {
                        return internal_error(req.request_id, e.to_string());
                    }
                    Ok(json!({ "enabled": false }))
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
        }
        "route.reload" => match state.reload_routes() {
            Ok(_) => Ok(json!({ "reloaded": true })),
            Err(e) => return internal_error(req.request_id, e.to_string()),
        },
        "apps.scan" => match scanner::sync_from_apps_root(state) {
            Ok(stats) => {
                if let Err(e) =
                    crate::runtime::write_scan_warnings(&state.scan_warnings_path, &stats)
                {
                    return internal_error(req.request_id, e.to_string());
                }
                if let Err(e) = state.reload_routes() {
                    return internal_error(req.request_id, e.to_string());
                }
                Ok(json!({ "scan": stats }))
            }
            Err(e) => return internal_error(req.request_id, e.to_string()),
        },
        "process.list" => {
            let mut pm = state.process_manager.lock().await;
            let infos = pm.list_status();
            Ok(json!({ "processes": infos }))
        }
        "process.restart" => {
            let params: AppIdParams = parse_params!(req);
            let app = find_app!(state, req, params.app_id);
            let (root, kind, name) = match &app.target {
                crate::domain::BackendTarget::Managed {
                    root, kind, name, ..
                } => (root.clone(), kind.clone(), name.clone()),
                _ => {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams("app is not a managed process".to_string()),
                    );
                }
            };
            let mut pm = state.process_manager.lock().await;
            pm.kill_process(params.app_id);
            match pm
                .ensure_running(params.app_id, &name, std::path::Path::new(&root), &kind)
                .await
            {
                Ok(socket_path) => Ok(json!({ "restarted": true, "socket_path": socket_path })),
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
        }
        "apps.warnings" => match crate::runtime::read_scan_warnings(&state.scan_warnings_path) {
            Ok(data) => Ok(json!({ "warnings": data })),
            Err(e) => return internal_error(req.request_id, e.to_string()),
        },
        "tunnel.start" => {
            let params: AppIdParams = parse_params!(req);

            // Look up the app to get its target port
            let app = find_app!(state, req, params.app_id);

            let routing = routing_for_app(&app, state.listen_http.port());

            match tunnel::start_quick_tunnel(state.tunnels.clone(), params.app_id, routing).await {
                Ok(hostname) => {
                    let url = format!("https://{}", hostname);
                    if let Err(e) = state.store.update_tunnel_url(params.app_id, Some(&url)) {
                        return internal_error(req.request_id, e.to_string());
                    }
                    if let Err(e) = state
                        .store
                        .set_tunnel_mode(params.app_id, TunnelMode::Quick)
                    {
                        return internal_error(req.request_id, e.to_string());
                    }
                    Ok(json!({ "tunnel_url": url, "hostname": hostname }))
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
        }
        "tunnel.stop" => {
            let params: AppIdParams = parse_params!(req);

            match tunnel::stop_tunnel(&state.tunnels, params.app_id) {
                Ok(()) => {
                    if let Err(e) = state.store.update_tunnel_url(params.app_id, None) {
                        return internal_error(req.request_id, e.to_string());
                    }
                    if let Err(e) = state.store.set_tunnel_mode(params.app_id, TunnelMode::None) {
                        return internal_error(req.request_id, e.to_string());
                    }
                    Ok(json!({ "stopped": true }))
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
        }
        "tunnel.status" => {
            let tunnels = tunnel::tunnel_status(&state.tunnels);
            Ok(json!({ "tunnels": tunnels }))
        }
        "named_tunnel.setup" => {
            let params: NamedTunnelSetupParams = parse_params!(req);

            if params.domain.trim().is_empty() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("domain cannot be empty".to_string()),
                );
            }

            // Check if already connected
            if state.named_tunnel.lock().is_some() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams(
                        "named tunnel already active, disconnect first".to_string(),
                    ),
                );
            }

            let tunnel_name = params
                .tunnel_name
                .unwrap_or_else(|| format!("coulson-{}", &params.domain));

            let (credentials, tunnel_id) = match tunnel::named::create_named_tunnel(
                &params.api_token,
                &params.account_id,
                &tunnel_name,
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };

            // Persist credentials and domain
            let creds_json = match serde_json::to_string(&credentials) {
                Ok(v) => v,
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };
            if let Err(e) = state
                .store
                .set_setting("named_tunnel.credentials", &creds_json)
            {
                return internal_error(req.request_id, e.to_string());
            }
            if let Err(e) = state
                .store
                .set_setting("named_tunnel.domain", &params.domain)
            {
                return internal_error(req.request_id, e.to_string());
            }
            if let Err(e) = state
                .store
                .set_setting("named_tunnel.account_id", &params.account_id)
            {
                return internal_error(req.request_id, e.to_string());
            }

            // Start the tunnel
            let local_proxy_port = state.listen_http.port();
            let local_suffix = state.domain_suffix.clone();
            match tunnel::start_named_tunnel(
                credentials,
                params.domain.clone(),
                local_suffix,
                local_proxy_port,
                state.store.clone(),
                Some(state.share_signer.clone()),
                state.tunnel_conns.clone(),
            )
            .await
            {
                Ok(handle) => {
                    *state.named_tunnel.lock() = Some(handle);
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }

            let cname_target = format!("{tunnel_id}.cfargotunnel.com");
            Ok(json!({
                "tunnel_id": tunnel_id,
                "cname_target": cname_target,
                "domain": params.domain,
                "hint": format!("Add DNS: *.{} CNAME {}", params.domain, cname_target),
            }))
        }
        "named_tunnel.teardown" => {
            let params: NamedTunnelTeardownParams = parse_params!(req);

            // Disconnect if active (scope the lock to avoid holding across await)
            let active_handle = state.named_tunnel.lock().take();
            if let Some(handle) = active_handle {
                handle.task.abort();
                info!("named tunnel disconnected for teardown");

                let account_id = match state.store.get_setting("named_tunnel.account_id") {
                    Ok(Some(v)) => v,
                    _ => {
                        return render_err(
                            req.request_id,
                            ControlError::Internal("account_id not found in settings".to_string()),
                        );
                    }
                };

                if let Err(e) = tunnel::named::delete_named_tunnel(
                    &params.api_token,
                    &account_id,
                    &handle.credentials.tunnel_id,
                )
                .await
                {
                    return internal_error(req.request_id, e.to_string());
                }
            } else {
                // Try to delete from stored credentials even if not connected
                let creds_json = state.store.get_setting("named_tunnel.credentials");
                let account_id = state.store.get_setting("named_tunnel.account_id");
                if let (Ok(Some(creds_str)), Ok(Some(acct))) = (creds_json, account_id) {
                    if let Ok(creds) = serde_json::from_str::<tunnel::TunnelCredentials>(&creds_str)
                    {
                        if let Err(e) = tunnel::named::delete_named_tunnel(
                            &params.api_token,
                            &acct,
                            &creds.tunnel_id,
                        )
                        .await
                        {
                            return internal_error(req.request_id, e.to_string());
                        }
                    }
                }
            }

            // Clear stored credentials (best-effort during teardown)
            for key in [
                "named_tunnel.credentials",
                "named_tunnel.domain",
                "named_tunnel.account_id",
            ] {
                if let Err(e) = state.store.delete_setting(key) {
                    tracing::warn!(error = %e, key, "failed to delete setting during teardown");
                }
            }

            Ok(json!({ "torn_down": true }))
        }
        "named_tunnel.connect" => {
            if state.named_tunnel.lock().is_some() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("named tunnel already connected".to_string()),
                );
            }

            let params: NamedTunnelConnectParams = parse_params!(req);

            // If token+domain provided, decode and persist before connecting
            if let (Some(token), Some(domain)) = (&params.token, &params.domain) {
                if token.trim().is_empty() || domain.trim().is_empty() {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams(
                            "token and domain must not be empty".to_string(),
                        ),
                    );
                }
                let credentials = match tunnel::decode_tunnel_token(token) {
                    Ok(v) => v,
                    Err(e) => return internal_error(req.request_id, e.to_string()),
                };
                let creds_json = match serde_json::to_string(&credentials) {
                    Ok(v) => v,
                    Err(e) => return internal_error(req.request_id, e.to_string()),
                };
                if let Err(e) = state
                    .store
                    .set_setting("named_tunnel.credentials", &creds_json)
                {
                    return internal_error(req.request_id, e.to_string());
                }
                if let Err(e) = state.store.set_setting("named_tunnel.domain", domain) {
                    return internal_error(req.request_id, e.to_string());
                }
            }

            // Load credentials from settings
            let creds_str = match state.store.get_setting("named_tunnel.credentials") {
                Ok(Some(v)) => v,
                Ok(None) => {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams(
                            "no saved credentials, provide token+domain or run named_tunnel.setup first".to_string(),
                        ),
                    );
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };
            let tunnel_domain = match state.store.get_setting("named_tunnel.domain") {
                Ok(Some(v)) => v,
                Ok(None) => {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams("no saved tunnel domain".to_string()),
                    );
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };
            let credentials: tunnel::TunnelCredentials = match serde_json::from_str(&creds_str) {
                Ok(v) => v,
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };

            let local_proxy_port = state.listen_http.port();
            let local_suffix = state.domain_suffix.clone();
            match tunnel::start_named_tunnel(
                credentials,
                tunnel_domain.clone(),
                local_suffix,
                local_proxy_port,
                state.store.clone(),
                Some(state.share_signer.clone()),
                state.tunnel_conns.clone(),
            )
            .await
            {
                Ok(handle) => {
                    *state.named_tunnel.lock() = Some(handle);
                    Ok(json!({ "connected": true, "domain": tunnel_domain }))
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
        }
        "named_tunnel.disconnect" => match state.named_tunnel.lock().take() {
            Some(handle) => {
                handle.task.abort();
                state.tunnel_conns.write().clear();
                info!("named tunnel disconnected");
                Ok(json!({ "disconnected": true }))
            }
            None => {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("no named tunnel connected".to_string()),
                );
            }
        },
        "named_tunnel.status" => {
            let guard = state.named_tunnel.lock();
            if let Some(handle) = guard.as_ref() {
                let domain = match state.store.get_setting("named_tunnel.domain") {
                    Ok(v) => v,
                    Err(e) => return internal_error(req.request_id, e.to_string()),
                };
                Ok(json!({
                    "connected": true,
                    "tunnel_id": handle.credentials.tunnel_id,
                    "tunnel_domain": handle.tunnel_domain,
                    "domain": domain,
                    "cname_target": format!("{}.cfargotunnel.com", handle.credentials.tunnel_id),
                }))
            } else {
                // Check if credentials are saved (disconnected but configured)
                let has_creds = matches!(
                    state.store.get_setting("named_tunnel.credentials"),
                    Ok(Some(_))
                );
                let domain = state
                    .store
                    .get_setting("named_tunnel.domain")
                    .ok()
                    .flatten();
                Ok(json!({
                    "connected": false,
                    "configured": has_creds,
                    "domain": domain,
                }))
            }
        }
        "settings.get_default_app" => match state.store.get_setting("default_app") {
            Ok(val) => Ok(json!({ "default_app": val })),
            Err(e) => return internal_error(req.request_id, e.to_string()),
        },
        "settings.set_default_app" => {
            let default_app: Option<String> = match req.params.get("default_app") {
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                Some(serde_json::Value::Null) | None => None,
                _ => {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams(
                            "default_app must be a string or null".to_string(),
                        ),
                    );
                }
            };
            match default_app {
                Some(raw) => {
                    let app_domain = raw.trim().to_ascii_lowercase();
                    if app_domain.is_empty() {
                        return render_err(
                            req.request_id,
                            ControlError::InvalidParams("default_app cannot be empty".to_string()),
                        );
                    }
                    if let Err(e) = state.store.set_setting("default_app", &app_domain) {
                        return internal_error(req.request_id, e.to_string());
                    }
                    Ok(json!({ "default_app": app_domain }))
                }
                None => {
                    if let Err(e) = state.store.delete_setting("default_app") {
                        return internal_error(req.request_id, e.to_string());
                    }
                    Ok(json!({ "default_app": null }))
                }
            }
        }
        "tunnel.configure" => {
            let params: TunnelConfigureParams = parse_params!(req);
            if params.api_token.trim().is_empty() || params.account_id.trim().is_empty() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams(
                        "api_token and account_id are required".to_string(),
                    ),
                );
            }
            if let Err(e) = state.store.set_setting("cf.api_token", &params.api_token) {
                return internal_error(req.request_id, e.to_string());
            }
            if let Err(e) = state.store.set_setting("cf.account_id", &params.account_id) {
                return internal_error(req.request_id, e.to_string());
            }
            Ok(json!({ "configured": true }))
        }
        "tunnel.configure_status" => {
            let has_token = matches!(state.store.get_setting("cf.api_token"), Ok(Some(_)));
            let has_account = matches!(state.store.get_setting("cf.account_id"), Ok(Some(_)));
            Ok(json!({ "configured": has_token && has_account }))
        }
        "tunnel.app_setup" => {
            let params: AppTunnelSetupParams = parse_params!(req);

            if params.domain.trim().is_empty() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("domain cannot be empty".to_string()),
                );
            }

            // Read CF credentials from settings
            let api_token = require_setting!(
                state,
                req,
                "cf.api_token",
                "CF credentials not configured, run tunnel.configure first"
            );
            let account_id =
                require_setting!(state, req, "cf.account_id", "cf.account_id not configured");

            // Look up app and get target port
            let app = find_app!(state, req, params.app_id);

            let routing = routing_for_app(&app, state.listen_http.port());

            // Check if app already has a tunnel
            if app.app_tunnel_id.is_some() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams(
                        "app already has a tunnel configured, teardown first".to_string(),
                    ),
                );
            }

            // Create CF named tunnel
            let tunnel_name = format!("coulson-{}", params.app_id);
            let (credentials, tunnel_id) =
                match tunnel::named::create_named_tunnel(&api_token, &account_id, &tunnel_name)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => return internal_error(req.request_id, e.to_string()),
                };

            // Auto DNS if requested
            let mut dns_record_id: Option<String> = None;
            let mut zone_id_used: Option<String> = None;
            if params.auto_dns {
                match tunnel::named::find_zone_id(&api_token, &params.domain).await {
                    Ok(zid) => {
                        zone_id_used = Some(zid.clone());
                        match tunnel::named::create_dns_cname(
                            &api_token,
                            &zid,
                            &params.domain,
                            &tunnel_id,
                        )
                        .await
                        {
                            Ok(rid) => dns_record_id = Some(rid),
                            Err(e) => {
                                // Best effort: delete the tunnel we just created
                                let _ = tunnel::named::delete_named_tunnel(
                                    &api_token,
                                    &account_id,
                                    &tunnel_id,
                                )
                                .await;
                                return internal_error(
                                    req.request_id,
                                    format!("failed to create DNS CNAME: {e}"),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        let _ =
                            tunnel::named::delete_named_tunnel(&api_token, &account_id, &tunnel_id)
                                .await;
                        return internal_error(
                            req.request_id,
                            format!("failed to find zone for domain: {e}"),
                        );
                    }
                }
            }

            // Start tunnel connection
            if let Err(e) = tunnel::start_app_named_tunnel(
                state.app_tunnels.clone(),
                params.app_id,
                credentials.clone(),
                params.domain.clone(),
                routing,
            )
            .await
            {
                // Cleanup on failure
                if let (Some(rid), Some(zid)) = (&dns_record_id, &zone_id_used) {
                    let _ = tunnel::named::delete_dns_record(&api_token, zid, rid).await;
                }
                let _ =
                    tunnel::named::delete_named_tunnel(&api_token, &account_id, &tunnel_id).await;
                return internal_error(req.request_id, e.to_string());
            }

            // Persist tunnel info
            let creds_json = match serde_json::to_string(&credentials) {
                Ok(v) => v,
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };
            if let Err(e) = state.store.set_app_tunnel_state(
                params.app_id,
                Some(&tunnel_id),
                Some(&params.domain),
                dns_record_id.as_deref(),
                Some(&creds_json),
                TunnelMode::Named,
            ) {
                return internal_error(req.request_id, e.to_string());
            }

            let cname_target = format!("{tunnel_id}.cfargotunnel.com");
            Ok(json!({
                "tunnel_id": tunnel_id,
                "domain": params.domain,
                "cname_target": cname_target,
                "dns_record_id": dns_record_id,
            }))
        }
        "tunnel.app_teardown" => {
            let params: AppIdParams = parse_params!(req);

            // Read CF credentials
            let api_token =
                require_setting!(state, req, "cf.api_token", "CF credentials not configured");
            let account_id =
                require_setting!(state, req, "cf.account_id", "cf.account_id not configured");

            // Get app info
            let app = find_app!(state, req, params.app_id);

            let tunnel_id = match &app.app_tunnel_id {
                Some(id) => id.clone(),
                None => {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams("app has no tunnel configured".to_string()),
                    );
                }
            };

            // Stop running tunnel connection (ignore if not running)
            let _ = tunnel::stop_app_named_tunnel(&state.app_tunnels, params.app_id);

            let mut warnings: Vec<String> = Vec::new();

            // Delete DNS record if auto-created
            if let Some(dns_id) = &app.app_tunnel_dns_id {
                if let Some(domain) = &app.app_tunnel_domain {
                    match tunnel::named::find_zone_id(&api_token, domain).await {
                        Ok(zone_id) => {
                            if let Err(e) =
                                tunnel::named::delete_dns_record(&api_token, &zone_id, dns_id).await
                            {
                                error!(error = %e, "failed to delete DNS record, continuing teardown");
                                warnings.push(format!("DNS record deletion failed: {e}"));
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "failed to find zone for DNS cleanup, continuing teardown");
                            warnings.push(format!("DNS zone lookup failed: {e}"));
                        }
                    }
                }
            }

            // Delete CF tunnel
            if let Err(e) =
                tunnel::named::delete_named_tunnel(&api_token, &account_id, &tunnel_id).await
            {
                error!(error = %e, "failed to delete CF tunnel, continuing teardown");
                warnings.push(format!("CF tunnel deletion failed: {e}"));
            }

            // Clear tunnel fields in DB (atomic: tunnel fields + mode in one update)
            if let Err(e) = state.store.set_app_tunnel_state(
                params.app_id,
                None,
                None,
                None,
                None,
                TunnelMode::None,
            ) {
                return internal_error(req.request_id, e.to_string());
            }

            if warnings.is_empty() {
                Ok(json!({ "torn_down": true }))
            } else {
                Ok(json!({ "torn_down": true, "partial": true, "warnings": warnings }))
            }
        }
        "tunnel.app_status" => {
            let params: AppIdParams = parse_params!(req);

            let app = find_app!(state, req, params.app_id);

            let connected = state.app_tunnels.lock().contains_key(&params.app_id);
            let configured = app.app_tunnel_id.is_some();

            Ok(json!({
                "configured": configured,
                "connected": connected,
                "tunnel_id": app.app_tunnel_id,
                "tunnel_domain": app.app_tunnel_domain,
                "dns_record_id": app.app_tunnel_dns_id,
            }))
        }
        _ => Err(ControlError::InvalidParams(format!(
            "unknown method: {}",
            req.method
        ))),
    };

    match result {
        Ok(result) => ResponseEnvelope {
            request_id: req.request_id,
            ok: true,
            result: Some(result),
            error: None,
        },
        Err(err) => render_err(req.request_id, err),
    }
}

/// Parse the first route target from a coulson.routes file content.
/// Returns `Some("host:port")` on success, `None` if nothing parseable.
fn parse_first_route_target(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let target_token = if parts[0].starts_with('/') {
            parts.get(1).copied()
        } else {
            Some(parts[0])
        };
        if let Some(token) = target_token {
            // bare port
            if let Ok(port) = token.parse::<u16>() {
                if port > 0 {
                    return Some(format!("127.0.0.1:{port}"));
                }
            }
            // host:port
            if let Some((host, port_str)) = token.rsplit_once(':') {
                let host = host
                    .strip_prefix("http://")
                    .or_else(|| host.strip_prefix("https://"))
                    .unwrap_or(host);
                if let Ok(port) = port_str.parse::<u16>() {
                    if port > 0 && !host.is_empty() {
                        return Some(format!("{host}:{port}"));
                    }
                }
            }
        }
        break; // only try the first route line
    }
    None
}

fn render_err(request_id: String, err: ControlError) -> ResponseEnvelope {
    let (code, message) = match err {
        ControlError::InvalidParams(msg) => ("invalid_params", msg),
        ControlError::NotFound => ("not_found", "resource not found".to_string()),
        ControlError::DomainConflict => ("domain_conflict", "domain already exists".to_string()),
        ControlError::DetectionFailed(msg) => ("detection_failed", msg),
        ControlError::Internal(msg) => ("internal_error", msg),
    };

    ResponseEnvelope {
        request_id,
        ok: false,
        result: None,
        error: Some(ErrorBody {
            code: code.to_string(),
            message,
            details: None,
        }),
    }
}

fn ok_response(request_id: String, result: serde_json::Value) -> ResponseEnvelope {
    ResponseEnvelope {
        request_id,
        ok: true,
        result: Some(result),
        error: None,
    }
}

fn internal_error(request_id: String, message: String) -> ResponseEnvelope {
    render_err(request_id, ControlError::Internal(message))
}

/// Build the appropriate tunnel routing for an app based on its backend type.
fn routing_for_app(
    app: &crate::domain::AppSpec,
    proxy_port: u16,
) -> tunnel::transport::TunnelRouting {
    tunnel::transport::TunnelRouting::FixedHost {
        local_host: app.domain.0.clone(),
        local_proxy_port: proxy_port,
    }
}

fn normalize_path_prefix(input: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = input else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !trimmed.starts_with('/') {
        return Err("path_prefix must start with '/'".to_string());
    }
    if trimmed.len() > 1 && trimmed.ends_with('/') {
        return Ok(Some(trimmed.trim_end_matches('/').to_string()));
    }
    Ok(Some(trimmed.to_string()))
}
