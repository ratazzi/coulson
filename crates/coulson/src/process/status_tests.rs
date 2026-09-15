use super::*;
use crate::app_status::{AppState, AppStatus};
use crate::domain::{AppSpec, BackendTarget, DomainName};

struct Fixture {
    dir: PathBuf,
    app: AppSpec,
    pm: ProcessManager,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("cs-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let store =
            Arc::new(crate::store::AppRepository::new(&dir.join("db"), "coulson.local").unwrap());
        store.init_schema().unwrap();
        let (app, _) = store
            .upsert_scanned_managed(
                "demo",
                &DomainName("demo.coulson.local".into()),
                dir.to_str().unwrap(),
                "procfile",
                true,
                "fs",
                "entry",
                None,
            )
            .unwrap();
        let (log_tx, _) = broadcast::channel(8);
        let pm = ProcessManager::new(ProcessManagerConfig {
            app_statuses: AppStatusStore::default(),
            idle_timeout: Duration::from_secs(900),
            registry: Arc::new(ProviderRegistry::new()),
            runtime_dir: dir.clone(),
            backend: ProcessBackend::Direct,
            hook_manager: Arc::new(HookManager::new(dir.join("hooks"), 1)),
            hook_factory: HookContextFactory::new(80, None, true, false, "coulson.local".into()),
            log_tx,
            store,
        });
        Self { dir, app, pm }
    }

    fn status(&self) -> AppStatus {
        self.pm.app_statuses.snapshot(&self.app)
    }

    fn group(&mut self) -> &mut ProcessGroup {
        self.pm.processes.get_mut(&self.app.id.0).unwrap()
    }

    fn insert_child(&mut self, child: Child, ready: bool) {
        self.pm.app_statuses.starting(&self.app);
        if ready {
            self.pm.app_statuses.ready(&self.app);
        }
        self.pm.processes.insert(
            self.app.id.0,
            ProcessGroup {
                primary: ManagedProcess {
                    handle: ProcessHandle::Direct { child },
                    listen_target: ListenTarget::Uds(self.dir.join("web.sock")),
                    started_at: Instant::now(),
                    last_active: Instant::now(),
                    kind: "procfile".into(),
                    ready,
                    resolved_env: vec![],
                },
                companions: vec![],
                name: "demo".into(),
                root: self.dir.clone(),
                idle_timeout: None,
                app_snapshot: self.app.clone(),
            },
        );
    }

    fn sleeping_child(&mut self, ready: bool) {
        self.insert_child(sleeping_child(), ready);
    }
}

fn sleeping_child() -> Child {
    Command::new("/bin/sleep")
        .arg("60")
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

#[tokio::test]
async fn status_readiness_does_not_start_apps_or_extend_idle_time() {
    let mut f = Fixture::new();
    f.pm.refresh_runtime_states().await;
    assert_eq!(f.status().state, AppState::Sleeping);
    assert!(f.pm.processes.is_empty());
    f.sleeping_child(false);
    let last_active = f.group().primary.last_active;
    let start =
        f.pm.ensure_started(f.app.id.0, "demo", &f.dir, "procfile", None)
            .await
            .unwrap();
    assert!(matches!(
        start,
        EnsureStarted::Status(StartStatus::Starting)
    ));
    f.pm.refresh_runtime_states().await;
    assert_eq!(f.status().state, AppState::Starting);
    let _listener = tokio::net::UnixListener::bind(f.dir.join("web.sock")).unwrap();
    f.pm.refresh_runtime_states().await;
    let ready = f.status();
    assert_eq!(ready.state, AppState::Ready);
    assert!(ready.started_at.is_some() && ready.ready_at.is_some());
    assert_eq!(f.group().primary.last_active, last_active);
    f.group().primary.last_active = Instant::now() - Duration::from_secs(901);
    assert_eq!(f.pm.reap_idle().await, 1);
    assert_eq!(f.status().state, AppState::Sleeping);
    assert!(f.status().last_error.is_none());
}

#[tokio::test]
async fn status_timeout_is_retained_until_retry_or_stop() {
    let mut f = Fixture::new();
    f.sleeping_child(false);
    f.group().primary.started_at = Instant::now() - Duration::from_secs(31);
    f.pm.refresh_runtime_states().await;
    let failed = f.status();
    assert_eq!(failed.state, AppState::Failed);
    assert_eq!(failed.last_error.unwrap().code, "readiness_timeout");
    assert!(failed.started_at.is_some());
    f.pm.refresh_runtime_states().await;
    assert_eq!(f.status().state, AppState::Failed);
    f.pm.kill_process(f.app.id.0).await;
    assert_eq!(f.status().state, AppState::Sleeping);
}

#[tokio::test]
async fn status_unexpected_exit_preserves_code_and_cleans_companions() {
    let mut f = Fixture::new();
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child.wait().await.unwrap();
    f.insert_child(child, true);
    f.group().companions.push(CompanionProcess {
        process_type: "worker".into(),
        handle: ProcessHandle::Direct {
            child: sleeping_child(),
        },
    });
    f.pm.refresh_runtime_states().await;
    let status = f.status();
    assert_eq!(status.state, AppState::Failed);
    assert_eq!(status.last_error.unwrap().exit_code, Some(7));
    assert!(status.ready_at.is_some());
    assert!(f.pm.processes.is_empty());
}

#[tokio::test]
async fn status_records_preparation_failure_for_both_start_paths() {
    let mut f = Fixture::new();
    let start =
        f.pm.ensure_started(f.app.id.0, "demo", &f.dir, "procfile", None)
            .await;
    assert!(start.is_err());
    assert_eq!(f.status().last_error.unwrap().code, "prepare_failed");
    f.pm.kill_process(f.app.id.0).await;
    let start =
        f.pm.ensure_running(f.app.id.0, "demo", &f.dir, "procfile", None)
            .await;
    assert!(start.is_err());
    assert_eq!(f.status().state, AppState::Failed);
    let mut disabled = f.app.clone();
    disabled.enabled = false;
    assert_eq!(
        f.pm.app_statuses.snapshot(&disabled).state,
        AppState::Disabled
    );
    let mut changed = f.app.clone();
    if let BackendTarget::Managed { root, .. } = &mut changed.target {
        root.push_str("-changed");
    }
    assert_eq!(
        f.pm.app_statuses.snapshot(&changed).state,
        AppState::Sleeping
    );
    f.pm.app_statuses.retain_apps(&[]);
    assert_eq!(f.status().state, AppState::Sleeping);
}

#[tokio::test]
async fn status_snapshot_remains_readable_during_explicit_start() {
    let mut f = Fixture::new();
    f.sleeping_child(false);
    let statuses = f.pm.app_statuses.clone();
    let start =
        f.pm.ensure_running(f.app.id.0, "demo", &f.dir, "procfile", None);
    tokio::pin!(start);
    let pending = tokio::time::timeout(Duration::from_millis(20), &mut start).await;
    assert!(pending.is_err());
    assert_eq!(statuses.snapshot(&f.app).state, AppState::Starting);
    let _listener = tokio::net::UnixListener::bind(f.dir.join("web.sock")).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), &mut start).await;
    assert!(result.unwrap().is_ok());
    assert_eq!(statuses.snapshot(&f.app).state, AppState::Ready);
}

#[tokio::test]
async fn status_environment_failure_cannot_overwrite_competing_live_start() {
    let mut f = Fixture::new();
    f.sleeping_child(false);
    let error = anyhow::anyhow!("secret fixture value").context(StartFailure {
        code: "environment_failed",
        message: "Could not prepare startup environment".into(),
    });
    f.pm.record_start_failure(f.app.id.0, "demo", &f.dir, "procfile", &error);
    assert_eq!(f.status().state, AppState::Starting);
    f.pm.kill_process(f.app.id.0).await;
    f.pm.record_start_failure(f.app.id.0, "demo", &f.dir, "procfile", &error);
    assert_eq!(f.status().state, AppState::Failed);
    let json = serde_json::to_string(&f.status()).unwrap();
    assert!(!json.contains("secret fixture value"));
}

#[test]
fn status_static_and_external_backends_are_distinguished() {
    let f = Fixture::new();
    let mut app = f.app.clone();
    app.target = BackendTarget::StaticDir {
        root: f.dir.to_string_lossy().into_owned(),
    };
    assert_eq!(f.pm.app_statuses.snapshot(&app).state, AppState::Ready);
    app.target = BackendTarget::StaticDir {
        root: f.dir.join("missing").to_string_lossy().into_owned(),
    };
    assert_eq!(f.pm.app_statuses.snapshot(&app).state, AppState::Failed);
    app.target = BackendTarget::Tcp {
        host: "127.0.0.1".into(),
        port: 3000,
    };
    assert_eq!(f.pm.app_statuses.snapshot(&app).state, AppState::Unknown);
    app.enabled = false;
    assert_eq!(f.pm.app_statuses.snapshot(&app).state, AppState::Disabled);
}

#[tokio::test]
async fn status_explicit_start_reports_exit_before_readiness_timeout() {
    let mut f = Fixture::new();
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 9"])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child.wait().await.unwrap();
    let mut handle = ProcessHandle::Direct { child };
    let target = ListenTarget::Uds(f.dir.join("web.sock"));
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        wait_for_process_ready(&mut handle, &target, Duration::from_secs(30)),
    )
    .await
    .unwrap();
    let error = result.unwrap_err();
    f.pm.record_start_failure(f.app.id.0, "demo", &f.dir, "procfile", &error);
    let failure = f.status().last_error.unwrap();
    assert_eq!(failure.code, "process_exited");
    assert_eq!(failure.exit_code, Some(9));
}
