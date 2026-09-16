use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::domain::{AppSpec, BackendTarget};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppState {
    Sleeping,
    Starting,
    Ready,
    Failed,
    Disabled,
    Unknown,
}

impl AppState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Sleeping => "sleeping",
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Disabled => "disabled",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppFailure {
    pub code: String,
    pub message: String,
    pub occurred_at: i64,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStatus {
    pub app_id: i64,
    pub name: String,
    pub domain: String,
    pub state: AppState,
    pub since: Option<i64>,
    pub started_at: Option<i64>,
    pub ready_at: Option<i64>,
    pub last_error: Option<AppFailure>,
    pub keep_awake: Option<KeepAwake>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KeepAwake {
    /// Unix seconds; null means until explicitly cleared in this daemon session.
    pub expires_at: Option<i64>,
}

impl KeepAwake {
    pub fn active_at(self, timestamp: i64) -> bool {
        self.expires_at.is_none_or(|expires| expires > timestamp)
    }
}

#[derive(Clone)]
struct RuntimeRecord {
    // Identity prevents an in-place scanner rewrite inheriting an old process's status.
    identity: (String, String, String),
    state: AppState,
    since: i64,
    started_at: Option<i64>,
    ready_at: Option<i64>,
    last_error: Option<AppFailure>,
    keep_awake: Option<KeepAwake>,
}

/// Lifecycle snapshots can be read even while a slow startup holds the process-manager lock.
/// Records are in memory and reset when the daemon restarts.
#[derive(Clone, Default)]
pub struct AppStatusStore(Arc<RwLock<HashMap<i64, RuntimeRecord>>>);

fn identity(app: &AppSpec) -> Option<(String, String, String)> {
    match &app.target {
        BackendTarget::Managed {
            root, name, kind, ..
        } => Some((name.clone(), root.clone(), kind.clone())),
        _ => None,
    }
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl AppStatusStore {
    pub fn snapshot(&self, app: &AppSpec) -> AppStatus {
        let records = self.0.read();
        let record = records
            .get(&app.id.0)
            .filter(|r| Some(r.identity.clone()) == identity(app));
        let state = if !app.enabled {
            AppState::Disabled
        } else {
            match &app.target {
                BackendTarget::Managed { .. } => record.map_or(AppState::Sleeping, |r| r.state),
                BackendTarget::StaticDir { root } => {
                    if std::path::Path::new(root).is_dir() {
                        AppState::Ready
                    } else {
                        AppState::Failed
                    }
                }
                _ => AppState::Unknown,
            }
        };
        let mut result = AppStatus {
            app_id: app.id.0,
            name: app.name.clone(),
            domain: app.domain.0.clone(),
            state,
            since: record.filter(|r| r.state == state).map(|r| r.since),
            started_at: record.and_then(|r| r.started_at),
            ready_at: record.and_then(|r| r.ready_at),
            last_error: record.and_then(|r| r.last_error.clone()),
            keep_awake: record
                .and_then(|r| r.keep_awake)
                .filter(|policy| app.enabled && policy.active_at(now())),
        };
        if state == AppState::Failed && matches!(app.target, BackendTarget::StaticDir { .. }) {
            result.last_error = Some(AppFailure {
                code: "static_root_missing".into(),
                message: "Static directory is missing or inaccessible".into(),
                occurred_at: now(),
                exit_code: None,
            });
        }
        result
    }

    pub fn starting(&self, app: &AppSpec) {
        self.transition(app, AppState::Starting, None);
    }

    pub fn ready(&self, app: &AppSpec) {
        self.transition(app, AppState::Ready, None);
    }

    pub fn failed(&self, app: &AppSpec, code: &str, message: &str, exit_code: Option<i32>) {
        self.transition(
            app,
            AppState::Failed,
            Some(AppFailure {
                code: code.into(),
                message: message.into(),
                occurred_at: now(),
                exit_code,
            }),
        );
    }

    pub fn sleeping(&self, app_id: i64) {
        if let Some(record) = self.0.write().get_mut(&app_id) {
            record.state = AppState::Sleeping;
            record.since = now();
            record.last_error = None;
        }
    }

    pub fn set_keep_awake(&self, app: &AppSpec, policy: KeepAwake) {
        let Some(identity) = identity(app) else {
            return;
        };
        let mut records = self.0.write();
        let record = records.entry(app.id.0).or_insert_with(|| RuntimeRecord {
            identity: identity.clone(),
            state: AppState::Sleeping,
            since: now(),
            started_at: None,
            ready_at: None,
            last_error: None,
            keep_awake: None,
        });
        if record.identity != identity {
            *record = RuntimeRecord {
                identity,
                state: AppState::Sleeping,
                since: now(),
                started_at: None,
                ready_at: None,
                last_error: None,
                keep_awake: None,
            };
        }
        record.keep_awake = Some(policy);
    }

    pub fn clear_keep_awake(&self, app_id: i64) {
        if let Some(record) = self.0.write().get_mut(&app_id) {
            record.keep_awake = None;
        }
    }

    pub fn is_kept_awake(&self, app: &AppSpec) -> bool {
        // Process groups retain their spawn-time enabled flag. The active policy
        // is current desired state; disable clears it separately.
        self.0
            .read()
            .get(&app.id.0)
            .filter(|record| Some(record.identity.clone()) == identity(app))
            .and_then(|record| record.keep_awake)
            .is_some_and(|policy| policy.active_at(now()))
    }

    pub fn retain_apps(&self, apps: &[AppSpec]) {
        let identities: HashMap<_, _> = apps
            .iter()
            .filter_map(|a| identity(a).map(|i| (a.id.0, i)))
            .collect();
        self.0
            .write()
            .retain(|id, r| identities.get(id) == Some(&r.identity));
        for app in apps.iter().filter(|a| !a.enabled) {
            self.clear_keep_awake(app.id.0);
        }
    }

    fn transition(&self, app: &AppSpec, state: AppState, failure: Option<AppFailure>) {
        let Some(identity) = identity(app) else {
            return;
        };
        let mut records = self.0.write();
        let timestamp = now();
        let entry = records.entry(app.id.0).or_insert_with(|| RuntimeRecord {
            identity: identity.clone(),
            state,
            since: timestamp,
            started_at: None,
            ready_at: None,
            last_error: None,
            keep_awake: None,
        });
        if entry.identity != identity {
            *entry = RuntimeRecord {
                identity,
                state,
                since: timestamp,
                started_at: None,
                ready_at: None,
                last_error: None,
                keep_awake: None,
            };
        }
        let new_start = entry.state != AppState::Starting || entry.started_at.is_none();
        if entry.state != state {
            entry.since = timestamp;
        }
        entry.state = state;
        match state {
            AppState::Starting if new_start => {
                entry.started_at = Some(timestamp);
                entry.ready_at = None;
            }
            AppState::Ready => {
                entry.ready_at.get_or_insert(timestamp);
            }
            AppState::Failed => {
                entry.last_error = failure;
            }
            _ => {}
        }
    }
}

/// Safe diagnostic context: raw commands, environment values and subprocess stderr
/// remain in existing logs/errors and are never copied into status responses.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct StartFailure {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("Primary process exited unexpectedly")]
pub struct ProcessExit {
    pub exit_code: Option<i32>,
}

impl StartFailure {
    pub fn timeout(seconds: u64) -> Self {
        Self {
            code: "readiness_timeout",
            message: format!("Service did not listen within {seconds}s"),
        }
    }
}
