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
struct UpdateSettingsParams {
    app_id: String,
    cors_enabled: Option<bool>,
    basic_auth_user: Option<Option<String>>,
    basic_auth_pass: Option<Option<String>>,
    spa_rewrite: Option<bool>,
    listen_port: Option<Option<u16>>,
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
