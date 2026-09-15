use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::app_status::{AppState, AppStatus};
use crate::rpc_client::RpcClient;

#[cfg(test)]
mod tests;

#[derive(Debug, Serialize)]
pub struct WaitReport {
    pub ready: bool,
    pub app: Option<AppStatus>,
    pub error: Option<WaitError>,
}

#[derive(Debug, Serialize)]
pub struct WaitError {
    pub code: &'static str,
    pub message: String,
}

impl WaitReport {
    pub fn exit_code(&self) -> u8 {
        if self.ready {
            0
        } else if self.error.as_ref().is_some_and(|e| e.code == "timeout") {
            124
        } else {
            1
        }
    }

    fn error(app: Option<AppStatus>, code: &'static str, message: String) -> Self {
        Self {
            ready: false,
            app,
            error: Some(WaitError { code, message }),
        }
    }
}

/// Waits only on lifecycle snapshots; never starts an app or sends it traffic.
pub async fn wait_for_app(client: &RpcClient, name: &str, timeout: Duration) -> WaitReport {
    #[derive(Deserialize)]
    struct StatusResponse {
        apps: Vec<AppStatus>,
    }

    let mut last_status: Option<AppStatus> = None;
    let poll = async {
        loop {
            let response = match client
                .call_async("app.status", json!({ "name": name }))
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    return WaitReport::error(
                        last_status.clone(),
                        "query_failed",
                        error.to_string(),
                    )
                }
            };
            let mut statuses = match serde_json::from_value::<StatusResponse>(response) {
                Ok(response) if response.apps.len() == 1 => response.apps,
                _ => {
                    return WaitReport::error(
                        last_status.clone(),
                        "invalid_response",
                        "Expected status for exactly one application".into(),
                    )
                }
            };
            let app = statuses.remove(0);
            if last_status
                .as_ref()
                .is_some_and(|previous| previous.app_id != app.app_id)
            {
                return WaitReport::error(
                    Some(app),
                    "app_replaced",
                    format!("{name} was replaced while waiting"),
                );
            }
            let state = app.state;
            last_status = Some(app);
            match state {
                AppState::Ready => {
                    return WaitReport {
                        ready: true,
                        app: last_status.clone(),
                        error: None,
                    }
                }
                AppState::Failed => {
                    let detail = last_status
                        .as_ref()
                        .and_then(|a| a.last_error.as_ref())
                        .map(|e| match e.exit_code {
                            Some(code) => format!("{} (exit {code})", e.message),
                            None => e.message.clone(),
                        })
                        .unwrap_or_else(|| "Application failed".into());
                    return WaitReport::error(last_status.clone(), "app_failed", detail);
                }
                AppState::Disabled => {
                    return WaitReport::error(
                        last_status.clone(),
                        "app_disabled",
                        format!("{name} is disabled"),
                    )
                }
                AppState::Unknown => {
                    return WaitReport::error(
                        last_status.clone(),
                        "status_unknown",
                        format!("Cannot determine readiness for {name}"),
                    )
                }
                AppState::Sleeping | AppState::Starting => {}
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };

    match tokio::time::timeout(timeout, poll).await {
        Ok(report) => report,
        Err(_) => WaitReport::error(
            last_status,
            "timeout",
            format!("Timed out waiting for {name} after {timeout:?}"),
        ),
    }
}

pub fn parse_timeout(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    let (number, multiplier) = if let Some(n) = value.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = value.strip_suffix('s') {
        (n, 1000)
    } else if let Some(n) = value.strip_suffix('m') {
        (n, 60_000)
    } else if let Some(n) = value.strip_suffix('h') {
        (n, 3_600_000)
    } else {
        (value, 1000)
    };
    let millis = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|n| *n > 0)
        .ok_or_else(|| "Use a positive duration such as 30s, 2m, or 500ms".to_string())?;
    let duration = Duration::from_millis(millis);
    if std::time::Instant::now().checked_add(duration).is_none() {
        return Err("Timeout is too large".into());
    }
    Ok(duration)
}
