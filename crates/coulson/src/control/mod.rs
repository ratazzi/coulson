use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};

use crate::domain::TunnelMode;
use crate::service;
use crate::service::ServiceError;
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

impl From<ServiceError> for ControlError {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::InvalidParams(msg) => ControlError::InvalidParams(msg),
            ServiceError::NotFound => ControlError::NotFound,
            ServiceError::DomainConflict => ControlError::DomainConflict,
            ServiceError::DetectionFailed(msg) => ControlError::DetectionFailed(msg),
            ServiceError::Internal(msg) => ControlError::Internal(msg),
        }
    }
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
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateSettingsParams {
    app_id: i64,
    cors_enabled: Option<bool>,
    force_https: Option<bool>,
    basic_auth_user: Option<Option<String>>,
    basic_auth_pass: Option<Option<String>>,
    spa_rewrite: Option<bool>,
    listen_port: Option<Option<u16>>,
    lan_access: Option<bool>,
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
        "app.list" => service::app_list(state)
            .map(|apps| json!({ "apps": apps }))
            .map_err(ControlError::from),
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
            let params: service::CreateAppParams = parse_params!(req);
            service::app_create(state, &params)
                .map(|app| json!({ "app": app }))
                .map_err(ControlError::from)
        }
        "app.create_from_folder" => {
            let params: CreateFromFolderParams = parse_params!(req);
            service::app_create_from_folder(state, &params.path)
                .map(|app| json!({ "app": app }))
                .map_err(ControlError::from)
        }
        "app.update" => {
            let params: UpdateSettingsParams = parse_params!(req);

            // Apply non-tunnel settings
            if let Err(e) = service::app_update_settings(
                state,
                params.app_id,
                &service::UpdateSettingsParams {
                    cors_enabled: params.cors_enabled,
                    force_https: params.force_https,
                    basic_auth_user: params.basic_auth_user.clone(),
                    basic_auth_pass: params.basic_auth_pass.clone(),
                    spa_rewrite: params.spa_rewrite,
                    listen_port: params.listen_port,
                    timeout_ms: None,
                    lan_access: params.lan_access,
                },
            ) {
                return render_err(req.request_id, ControlError::from(e));
            }

            // Handle tunnel_mode change
            if let Some(new_mode) = params.tunnel_mode {
                match service::app_set_tunnel_mode(
                    state,
                    params.app_id,
                    new_mode,
                    params.app_tunnel_domain.as_deref(),
                    params.app_tunnel_token.as_deref(),
                    params.app_tunnel_auto_dns.unwrap_or(false),
                )
                .await
                {
                    Ok(result) => {
                        let mut resp =
                            json!({ "updated": true, "tunnel_mode": result.tunnel_mode.as_str() });
                        if let Some(url) = &result.tunnel_url {
                            resp["tunnel_url"] = json!(url);
                        }
                        if let Some(tid) = &result.tunnel_id {
                            resp["tunnel_id"] = json!(tid);
                        }
                        if let Some(td) = &result.tunnel_domain {
                            resp["tunnel_domain"] = json!(td);
                        }
                        if result.reconnected {
                            resp["reconnected"] = json!(true);
                        }
                        return ok_response(req.request_id, resp);
                    }
                    Err(e) => return render_err(req.request_id, ControlError::from(e)),
                }
            }

            Ok(json!({ "updated": true }))
        }
        "app.delete" => {
            let params: AppIdParams = parse_params!(req);
            service::app_delete(state, params.app_id)
                .map(|_| json!({ "deleted": true }))
                .map_err(ControlError::from)
        }
        "app.start" => {
            let params: AppIdParams = parse_params!(req);
            service::app_set_enabled(state, params.app_id, true)
                .map(|_| json!({ "enabled": true }))
                .map_err(ControlError::from)
        }
        "app.stop" => {
            let params: AppIdParams = parse_params!(req);
            service::app_set_enabled(state, params.app_id, false)
                .map(|_| json!({ "enabled": false }))
                .map_err(ControlError::from)
        }
        "route.reload" => match state.reload_routes() {
            Ok(_) => Ok(json!({ "reloaded": true })),
            Err(e) => return internal_error(req.request_id, e.to_string()),
        },
        "network.changed" => {
            let _ = state.network_change_tx.send(());
            Ok(json!({ "notified": true }))
        }
        "apps.scan" => service::apps_scan(state)
            .map(|stats| json!({ "scan": stats }))
            .map_err(ControlError::from),
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
            pm.kill_process(params.app_id).await;
            match pm
                .ensure_running(params.app_id, &name, std::path::Path::new(&root), &kind)
                .await
            {
                Ok(listen_target) => {
                    let listen_json = match listen_target {
                        crate::process::ListenTarget::Uds(path) => {
                            json!({ "type": "uds", "path": path.to_string_lossy() })
                        }
                        crate::process::ListenTarget::Tcp { host, port } => {
                            json!({ "type": "tcp", "host": host, "port": port })
                        }
                    };
                    Ok(json!({ "restarted": true, "listen": listen_json }))
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
        }
        "apps.warnings" => service::apps_warnings(state)
            .map(|data| json!({ "warnings": data }))
            .map_err(ControlError::from),
        "tunnel.start" => {
            let params: AppIdParams = parse_params!(req);
            match service::app_set_tunnel_mode(
                state,
                params.app_id,
                TunnelMode::Quick,
                None,
                None,
                false,
            )
            .await
            {
                Ok(result) => {
                    let hostname = result
                        .tunnel_url
                        .as_deref()
                        .and_then(|u| u.strip_prefix("https://"))
                        .unwrap_or("");
                    Ok(json!({ "tunnel_url": result.tunnel_url, "hostname": hostname }))
                }
                Err(e) => Err(ControlError::from(e)),
            }
        }
        "tunnel.stop" => {
            let params: AppIdParams = parse_params!(req);
            service::app_set_tunnel_mode(state, params.app_id, TunnelMode::None, None, None, false)
                .await
                .map(|_| json!({ "stopped": true }))
                .map_err(ControlError::from)
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
            if let Err(e) = service::set_default_app(state, default_app.as_deref()) {
                return render_err(req.request_id, ControlError::from(e));
            }
            Ok(json!({ "default_app": default_app }))
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

            // Check if app already has a tunnel
            let app = find_app!(state, req, params.app_id);
            if app.app_tunnel_id.is_some() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams(
                        "app already has a tunnel configured, teardown first".to_string(),
                    ),
                );
            }

            match service::app_set_tunnel_mode(
                state,
                params.app_id,
                TunnelMode::Named,
                Some(&params.domain),
                params.token.as_deref(),
                false,
            )
            .await
            {
                Ok(result) => {
                    let cname_target = result
                        .tunnel_id
                        .as_deref()
                        .map(|tid| format!("{tid}.cfargotunnel.com"));
                    Ok(json!({
                        "tunnel_id": result.tunnel_id,
                        "domain": result.tunnel_domain,
                        "cname_target": cname_target,
                        "dns_record_id": result.dns_record_id,
                    }))
                }
                Err(e) => Err(ControlError::from(e)),
            }
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
