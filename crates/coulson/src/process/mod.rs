pub mod provider;

mod asgi;
mod docker;
mod node;
mod rack;

pub use provider::ProviderRegistry;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::process::{Child, Command};
use tracing::info;

use provider::{ManagedApp, ProcessSpec};

pub type ProcessManagerHandle = Arc<tokio::sync::Mutex<ProcessManager>>;

pub fn new_process_manager(
    idle_timeout: Duration,
    registry: Arc<ProviderRegistry>,
    runtime_dir: PathBuf,
) -> ProcessManagerHandle {
    Arc::new(tokio::sync::Mutex::new(ProcessManager::new(
        idle_timeout,
        registry,
        runtime_dir,
    )))
}

/// Create the default provider registry with all built-in providers.
///
/// Registration order determines auto-detection priority.
/// Only register providers whose resolve() is implemented.
/// Rack, Node, Docker are detected but not yet runnable — keep them
/// out of the registry so they don't preempt static `public/` fallback.
pub fn default_registry() -> ProviderRegistry {
    let mut reg = ProviderRegistry::new();
    reg.register(asgi::AsgiProvider);
    reg
}

pub struct ProcessManager {
    processes: HashMap<i64, ManagedProcess>,
    idle_timeout: Duration,
    registry: Arc<ProviderRegistry>,
    runtime_dir: PathBuf,
}

struct ManagedProcess {
    child: Child,
    socket_path: PathBuf,
    started_at: Instant,
    last_active: Instant,
    #[allow(dead_code)]
    kind: String,
    ready: bool,
}

pub enum StartStatus {
    /// Process is running and UDS is connectable.
    Ready(String),
    /// Process has been spawned but UDS is not yet ready.
    Starting,
}

#[derive(serde::Serialize)]
pub struct ProcessInfo {
    pub app_id: i64,
    pub pid: u32,
    pub kind: String,
    pub socket_path: String,
    pub uptime_secs: u64,
    pub idle_secs: u64,
    pub alive: bool,
}

impl ProcessManager {
    pub fn new(
        idle_timeout: Duration,
        registry: Arc<ProviderRegistry>,
        runtime_dir: PathBuf,
    ) -> Self {
        Self {
            processes: HashMap::new(),
            idle_timeout,
            registry,
            runtime_dir,
        }
    }

    pub fn list_status(&mut self) -> Vec<ProcessInfo> {
        let now = Instant::now();
        self.processes
            .iter_mut()
            .map(|(app_id, proc)| {
                let alive = matches!(proc.child.try_wait(), Ok(None));
                ProcessInfo {
                    app_id: *app_id,
                    pid: proc.child.id().unwrap_or(0),
                    kind: proc.kind.clone(),
                    socket_path: proc.socket_path.to_string_lossy().to_string(),
                    uptime_secs: now.duration_since(proc.started_at).as_secs(),
                    idle_secs: now.duration_since(proc.last_active).as_secs(),
                    alive,
                }
            })
            .collect()
    }

    /// Returns the UDS path for the managed app, starting the process if needed.
    ///
    /// The `kind` parameter selects the provider (e.g. "asgi", "rack", "node").
    pub async fn ensure_running(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
    ) -> anyhow::Result<String> {
        // Check if already running and alive
        if let Some(proc) = self.processes.get_mut(&app_id) {
            match proc.child.try_wait() {
                Ok(None) => {
                    proc.last_active = Instant::now();
                    return Ok(proc.socket_path.to_string_lossy().to_string());
                }
                _ => {
                    info!(app_id, "managed process exited, will restart");
                    let removed = self.processes.remove(&app_id).unwrap();
                    cleanup_socket(&removed.socket_path);
                }
            }
        }

        // Resolve the provider
        let prov = self
            .registry
            .get(kind)
            .ok_or_else(|| anyhow::anyhow!("no process provider for kind: {kind}"))?;

        let managed_dir = self.runtime_dir.join("managed");
        std::fs::create_dir_all(&managed_dir)
            .with_context(|| format!("failed to create {}", managed_dir.display()))?;
        // On macOS /tmp → /private/tmp; canonicalize so pingora's peer address matches.
        let sockets_dir = std::fs::canonicalize(&managed_dir).unwrap_or(managed_dir);

        let managed_app = ManagedApp {
            name: name.to_string(),
            root: root.to_path_buf(),
            kind: kind.to_string(),
            manifest: None,
            env_overrides: HashMap::new(),
            socket_dir: sockets_dir.clone(),
        };

        let spec: ProcessSpec = prov.resolve(&managed_app)?;

        info!(
            app_id,
            kind,
            socket = %spec.socket_path.display(),
            command = %spec.command.display(),
            root = %root.display(),
            "starting managed process via {} provider",
            prov.display_name()
        );

        cleanup_socket(&spec.socket_path);

        let log_path = sockets_dir.join(format!("{name}.log"));
        let log_file = std::fs::File::create(&log_path)
            .with_context(|| format!("failed to create log file {}", log_path.display()))?;
        let stderr_file = log_file
            .try_clone()
            .with_context(|| "failed to clone log file handle")?;

        let mut cmd = Command::new(&spec.command);
        cmd.args(&spec.args);
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        let child = cmd
            .current_dir(&spec.working_dir)
            .kill_on_drop(true)
            .stdout(stderr_file)
            .stderr(log_file)
            .spawn()
            .with_context(|| format!("failed to spawn {} for {app_id}", spec.command.display()))?;

        const UDS_READY_TIMEOUT_SECS: u64 = 30;
        provider::wait_for_uds_ready(
            &spec.socket_path,
            Duration::from_secs(UDS_READY_TIMEOUT_SECS),
        )
        .await?;

        let path_str = spec.socket_path.to_string_lossy().to_string();
        let now = Instant::now();
        self.processes.insert(
            app_id,
            ManagedProcess {
                child,
                socket_path: spec.socket_path,
                started_at: now,
                last_active: now,
                kind: kind.to_string(),
                ready: true,
            },
        );

        Ok(path_str)
    }

    /// Non-blocking variant: spawns the process if needed but does NOT wait for UDS readiness.
    /// Returns `StartStatus::Ready` if the process is running and connectable,
    /// or `StartStatus::Starting` if the process has been spawned but isn't ready yet.
    pub async fn ensure_started(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
    ) -> anyhow::Result<StartStatus> {
        if let Some(proc) = self.processes.get_mut(&app_id) {
            match proc.child.try_wait() {
                Ok(None) => {
                    if proc.ready {
                        proc.last_active = Instant::now();
                        return Ok(StartStatus::Ready(
                            proc.socket_path.to_string_lossy().to_string(),
                        ));
                    }
                    // Not yet marked ready — probe the UDS
                    if quick_uds_check(&proc.socket_path).await {
                        proc.ready = true;
                        proc.last_active = Instant::now();
                        return Ok(StartStatus::Ready(
                            proc.socket_path.to_string_lossy().to_string(),
                        ));
                    }
                    // Still not ready — check startup timeout
                    const STARTUP_TIMEOUT_SECS: u64 = 30;
                    if proc.started_at.elapsed() > Duration::from_secs(STARTUP_TIMEOUT_SECS) {
                        let _ = proc.child.start_kill();
                        let removed = self.processes.remove(&app_id).unwrap();
                        cleanup_socket(&removed.socket_path);
                        anyhow::bail!(
                            "managed process for {name} (app_id={app_id}) failed to become ready within {STARTUP_TIMEOUT_SECS}s"
                        );
                    }
                    return Ok(StartStatus::Starting);
                }
                _ => {
                    info!(app_id, "managed process exited, will restart");
                    let removed = self.processes.remove(&app_id).unwrap();
                    cleanup_socket(&removed.socket_path);
                }
            }
        }

        // Spawn a new process (same as ensure_running but skip wait_for_uds_ready)
        let prov = self
            .registry
            .get(kind)
            .ok_or_else(|| anyhow::anyhow!("no process provider for kind: {kind}"))?;

        let managed_dir = self.runtime_dir.join("managed");
        std::fs::create_dir_all(&managed_dir)
            .with_context(|| format!("failed to create {}", managed_dir.display()))?;
        let sockets_dir = std::fs::canonicalize(&managed_dir).unwrap_or(managed_dir);

        let managed_app = ManagedApp {
            name: name.to_string(),
            root: root.to_path_buf(),
            kind: kind.to_string(),
            manifest: None,
            env_overrides: HashMap::new(),
            socket_dir: sockets_dir.clone(),
        };

        let spec: ProcessSpec = prov.resolve(&managed_app)?;

        info!(
            app_id,
            kind,
            socket = %spec.socket_path.display(),
            command = %spec.command.display(),
            root = %root.display(),
            "starting managed process via {} provider (non-blocking)",
            prov.display_name()
        );

        cleanup_socket(&spec.socket_path);

        let log_path = sockets_dir.join(format!("{name}.log"));
        let log_file = std::fs::File::create(&log_path)
            .with_context(|| format!("failed to create log file {}", log_path.display()))?;
        let stderr_file = log_file
            .try_clone()
            .with_context(|| "failed to clone log file handle")?;

        let mut cmd = Command::new(&spec.command);
        cmd.args(&spec.args);
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        let child = cmd
            .current_dir(&spec.working_dir)
            .kill_on_drop(true)
            .stdout(stderr_file)
            .stderr(log_file)
            .spawn()
            .with_context(|| format!("failed to spawn {} for {app_id}", spec.command.display()))?;

        let now = Instant::now();
        self.processes.insert(
            app_id,
            ManagedProcess {
                child,
                socket_path: spec.socket_path,
                started_at: now,
                last_active: now,
                kind: kind.to_string(),
                ready: false,
            },
        );

        Ok(StartStatus::Starting)
    }

    /// Kill a specific managed process. Returns true if it was found and killed.
    pub fn kill_process(&mut self, app_id: i64) -> bool {
        if let Some(mut proc) = self.processes.remove(&app_id) {
            info!(app_id, "killing managed process");
            let _ = proc.child.start_kill();
            cleanup_socket(&proc.socket_path);
            true
        } else {
            false
        }
    }

    pub fn mark_active(&mut self, app_id: i64) {
        if let Some(proc) = self.processes.get_mut(&app_id) {
            proc.last_active = Instant::now();
        }
    }

    /// Kill processes idle longer than the configured timeout. Returns count reaped.
    pub fn reap_idle(&mut self) -> usize {
        let now = Instant::now();
        let timeout = self.idle_timeout;
        let mut to_remove = Vec::new();

        for (app_id, proc) in &self.processes {
            if now.duration_since(proc.last_active) > timeout {
                to_remove.push(*app_id);
            }
        }

        for app_id in &to_remove {
            if let Some(mut proc) = self.processes.remove(app_id) {
                info!(
                    app_id,
                    socket = %proc.socket_path.display(),
                    "reaping idle managed process"
                );
                let _ = proc.child.start_kill();
                cleanup_socket(&proc.socket_path);
            }
        }

        to_remove.len()
    }

    /// Kill all managed processes (called on daemon shutdown).
    pub fn shutdown_all(&mut self) {
        for (app_id, mut proc) in self.processes.drain() {
            info!(
                app_id,
                socket = %proc.socket_path.display(),
                "shutting down managed process"
            );
            let _ = proc.child.start_kill();
            cleanup_socket(&proc.socket_path);
        }
    }
}

fn cleanup_socket(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Single-shot UDS probe with a short timeout.
async fn quick_uds_check(path: &Path) -> bool {
    const PROBE_TIMEOUT_MS: u64 = 200;
    tokio::time::timeout(
        Duration::from_millis(PROBE_TIMEOUT_MS),
        tokio::net::UnixStream::connect(path),
    )
    .await
    .is_ok_and(|r| r.is_ok())
}
