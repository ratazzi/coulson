use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info};

use crate::domain::DomainName;
use crate::scanner;
use crate::store::StoreError;
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
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Deserialize)]
struct CreateStaticParams {
    name: String,
    domain: String,
    #[serde(default)]
    path_prefix: Option<String>,
    target_host: String,
    target_port: u16,
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

#[derive(Debug, Deserialize)]
struct CreateStaticDirParams {
    name: String,
    domain: String,
    static_root: String,
    #[serde(default)]
    listen_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct CreateUnixSocketParams {
    name: String,
    domain: String,
    #[serde(default)]
    path_prefix: Option<String>,
    socket_path: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    listen_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct AppIdParams {
    app_id: String,
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
struct UpdateSettingsParams {
    app_id: String,
    cors_enabled: Option<bool>,
    basic_auth_user: Option<Option<String>>,
    basic_auth_pass: Option<Option<String>>,
    spa_rewrite: Option<bool>,
    listen_port: Option<Option<u16>>,
    tunnel_exposed: Option<bool>,
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
                error!(error = %err, "control client failed");
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

async fn dispatch_request(req: RequestEnvelope, state: &SharedState) -> ResponseEnvelope {
    let result = match req.method.as_str() {
        "health.ping" => Ok(json!({ "pong": true })),
        "app.list" => {
            let apps = match state.store.list_all() {
                Ok(v) => v,
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };
            Ok(json!({ "apps": apps }))
        }
        "app.create_static" => {
            let params: CreateStaticParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            if params.name.trim().is_empty() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("name cannot be empty".to_string()),
                );
            }

            let domain = match DomainName::parse(&params.domain, &state.domain_suffix) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            if params.target_port == 0 {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("target_port out of range".to_string()),
                );
            }
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

            let path_prefix = match normalize_path_prefix(params.path_prefix.as_deref()) {
                Ok(v) => v,
                Err(msg) => {
                    return render_err(req.request_id, ControlError::InvalidParams(msg));
                }
            };

            match state.store.insert_static(
                &params.name,
                &domain,
                path_prefix.as_deref(),
                &params.target_host,
                params.target_port,
                params.timeout_ms,
                params.cors_enabled,
                params.basic_auth_user.as_deref(),
                params.basic_auth_pass.as_deref(),
                params.spa_rewrite,
                params.listen_port,
            ) {
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
        "app.create_static_dir" => {
            let params: CreateStaticDirParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            if params.name.trim().is_empty() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("name cannot be empty".to_string()),
                );
            }

            let domain = match DomainName::parse(&params.domain, &state.domain_suffix) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            let root = std::path::Path::new(&params.static_root);
            if !root.is_dir() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams(format!(
                        "static_root is not a directory: {}",
                        params.static_root
                    )),
                );
            }

            match state.store.insert_static_dir(&params.name, &domain, &params.static_root, params.listen_port) {
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
        "app.create_unix_socket" => {
            let params: CreateUnixSocketParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            if params.name.trim().is_empty() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("name cannot be empty".to_string()),
                );
            }

            let domain = match DomainName::parse(&params.domain, &state.domain_suffix) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            let sock = std::path::Path::new(&params.socket_path);
            if !sock.exists() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams(format!(
                        "socket_path does not exist: {}",
                        params.socket_path
                    )),
                );
            }

            let path_prefix = match normalize_path_prefix(params.path_prefix.as_deref()) {
                Ok(v) => v,
                Err(msg) => {
                    return render_err(req.request_id, ControlError::InvalidParams(msg));
                }
            };

            match state.store.insert_unix_socket(
                &params.name,
                &domain,
                path_prefix.as_deref(),
                &params.socket_path,
                params.timeout_ms,
                params.listen_port,
            ) {
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
        "app.update" => {
            let params: UpdateSettingsParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };
            match state.store.update_settings(
                &params.app_id,
                params.cors_enabled,
                params.basic_auth_user.as_ref().map(|v| v.as_deref()),
                params.basic_auth_pass.as_ref().map(|v| v.as_deref()),
                params.spa_rewrite,
                params.listen_port,
                params.tunnel_exposed,
            ) {
                Ok(found) => {
                    if !found {
                        return render_err(req.request_id, ControlError::NotFound);
                    }
                    if let Err(e) = state.reload_routes() {
                        return internal_error(req.request_id, e.to_string());
                    }
                    Ok(json!({ "updated": true }))
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
        }
        "app.delete" => {
            let params: AppIdParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };
            match state.store.delete(&params.app_id) {
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
            let params: AppIdParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };
            match state.store.set_enabled(&params.app_id, true) {
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
            let params: AppIdParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };
            match state.store.set_enabled(&params.app_id, false) {
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
        "apps.warnings" => match crate::runtime::read_scan_warnings(&state.scan_warnings_path) {
            Ok(data) => Ok(json!({ "warnings": data })),
            Err(e) => return internal_error(req.request_id, e.to_string()),
        },
        "tunnel.start" => {
            let params: AppIdParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            // Look up the app to get its target port
            let app = match state.store.get_by_id(&params.app_id) {
                Ok(Some(app)) => app,
                Ok(None) => {
                    return render_err(req.request_id, ControlError::NotFound);
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            };

            let local_port = match &app.target {
                crate::domain::BackendTarget::Tcp { port, .. } => *port,
                _ => {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams(
                            "tunnel only supports TCP backend targets".to_string(),
                        ),
                    );
                }
            };

            match tunnel::start_quick_tunnel(
                state.tunnels.clone(),
                params.app_id.clone(),
                local_port,
            )
            .await
            {
                Ok(hostname) => {
                    let url = format!("https://{}", hostname);
                    if let Err(e) = state.store.update_tunnel_url(&params.app_id, Some(&url)) {
                        return internal_error(req.request_id, e.to_string());
                    }
                    Ok(json!({ "tunnel_url": url, "hostname": hostname }))
                }
                Err(e) => return internal_error(req.request_id, e.to_string()),
            }
        }
        "tunnel.stop" => {
            let params: AppIdParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

            match tunnel::stop_tunnel(&state.tunnels, &params.app_id) {
                Ok(()) => {
                    if let Err(e) = state.store.update_tunnel_url(&params.app_id, None) {
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
            let params: NamedTunnelSetupParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

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
                .unwrap_or_else(|| format!("bridgehead-{}", &params.domain));

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
            if let Err(e) = state.store.set_setting("named_tunnel.credentials", &creds_json) {
                return internal_error(req.request_id, e.to_string());
            }
            if let Err(e) = state.store.set_setting("named_tunnel.domain", &params.domain) {
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
            let params: NamedTunnelTeardownParams = match serde_json::from_value(req.params) {
                Ok(v) => v,
                Err(e) => {
                    return render_err(req.request_id, ControlError::InvalidParams(e.to_string()));
                }
            };

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
                            ControlError::Internal(
                                "account_id not found in settings".to_string(),
                            ),
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

            // Clear stored credentials
            let _ = state.store.delete_setting("named_tunnel.credentials");
            let _ = state.store.delete_setting("named_tunnel.domain");
            let _ = state.store.delete_setting("named_tunnel.account_id");

            Ok(json!({ "torn_down": true }))
        }
        "named_tunnel.connect" => {
            if state.named_tunnel.lock().is_some() {
                return render_err(
                    req.request_id,
                    ControlError::InvalidParams("named tunnel already connected".to_string()),
                );
            }

            let creds_str = match state.store.get_setting("named_tunnel.credentials") {
                Ok(Some(v)) => v,
                Ok(None) => {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams(
                            "no saved credentials, run named_tunnel.setup first".to_string(),
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
        "named_tunnel.disconnect" => {
            match state.named_tunnel.lock().take() {
                Some(handle) => {
                    handle.task.abort();
                    info!("named tunnel disconnected");
                    Ok(json!({ "disconnected": true }))
                }
                None => {
                    return render_err(
                        req.request_id,
                        ControlError::InvalidParams("no named tunnel connected".to_string()),
                    );
                }
            }
        }
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

fn internal_error(request_id: String, message: String) -> ResponseEnvelope {
    render_err(request_id, ControlError::Internal(message))
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
