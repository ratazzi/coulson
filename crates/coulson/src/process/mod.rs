pub mod provider;

mod asgi;
mod docker;
mod node;
mod rack;

pub use provider::{ListenTarget, ProviderRegistry};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::process::{Child, Command};
use tracing::{info, warn};

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
pub fn default_registry() -> ProviderRegistry {
    let mut reg = ProviderRegistry::new();
    reg.register(asgi::AsgiProvider);
    reg.register(node::NodeProvider);
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
    listen_target: ListenTarget,
    started_at: Instant,
    last_active: Instant,
    #[allow(dead_code)]
    kind: String,
    ready: bool,
}

pub enum StartStatus {
    /// Process is running and ready to accept connections.
    Ready(ListenTarget),
    /// Process has been spawned but is not yet ready.
    Starting,
}

#[derive(serde::Serialize)]
pub struct ProcessInfo {
    pub app_id: i64,
    pub pid: u32,
    pub kind: String,
    pub listen_address: String,
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
                    listen_address: listen_target_display(&proc.listen_target),
                    uptime_secs: now.duration_since(proc.started_at).as_secs(),
                    idle_secs: now.duration_since(proc.last_active).as_secs(),
                    alive,
                }
            })
            .collect()
    }

    /// Returns the listen target for the managed app, starting the process if needed.
    ///
    /// The `kind` parameter selects the provider (e.g. "asgi", "rack", "node").
    pub async fn ensure_running(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
    ) -> anyhow::Result<ListenTarget> {
        // Check if already running and alive
        if let Some(proc) = self.processes.get_mut(&app_id) {
            match proc.child.try_wait() {
                Ok(None) => {
                    proc.last_active = Instant::now();
                    return Ok(proc.listen_target.clone());
                }
                _ => {
                    info!(app_id, "managed process exited, will restart");
                    let removed = self.processes.remove(&app_id).unwrap();
                    cleanup_listen_target(&removed.listen_target);
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
            listen = %listen_target_display(&spec.listen_target),
            command = %spec.command.display(),
            root = %root.display(),
            "starting managed process via {} provider",
            prov.display_name()
        );

        cleanup_listen_target(&spec.listen_target);

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
        // SAFETY: process_group(0) places the child in a new process group (PGID = child PID).
        // This lets us kill the entire tree (including grandchildren from dev servers).
        cmd.process_group(0);

        let child = cmd
            .current_dir(&spec.working_dir)
            .kill_on_drop(true)
            .stdout(stderr_file)
            .stderr(log_file)
            .spawn()
            .with_context(|| format!("failed to spawn {} for {app_id}", spec.command.display()))?;

        const READY_TIMEOUT_SECS: u64 = 30;
        wait_for_ready(&spec.listen_target, Duration::from_secs(READY_TIMEOUT_SECS)).await?;

        let now = Instant::now();
        self.processes.insert(
            app_id,
            ManagedProcess {
                child,
                listen_target: spec.listen_target.clone(),
                started_at: now,
                last_active: now,
                kind: kind.to_string(),
                ready: true,
            },
        );

        Ok(spec.listen_target)
    }

    /// Non-blocking variant: spawns the process if needed but does NOT wait for readiness.
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
                        return Ok(StartStatus::Ready(proc.listen_target.clone()));
                    }
                    // Not yet marked ready — probe
                    if quick_ready_check(&proc.listen_target).await {
                        proc.ready = true;
                        proc.last_active = Instant::now();
                        return Ok(StartStatus::Ready(proc.listen_target.clone()));
                    }
                    // Still not ready — check startup timeout
                    const STARTUP_TIMEOUT_SECS: u64 = 30;
                    if proc.started_at.elapsed() > Duration::from_secs(STARTUP_TIMEOUT_SECS) {
                        kill_process_group(&mut proc.child).await;
                        let removed = self.processes.remove(&app_id).unwrap();
                        cleanup_listen_target(&removed.listen_target);
                        anyhow::bail!(
                            "managed process for {name} (app_id={app_id}) failed to become ready within {STARTUP_TIMEOUT_SECS}s"
                        );
                    }
                    return Ok(StartStatus::Starting);
                }
                _ => {
                    info!(app_id, "managed process exited, will restart");
                    let removed = self.processes.remove(&app_id).unwrap();
                    cleanup_listen_target(&removed.listen_target);
                }
            }
        }

        // Spawn a new process (same as ensure_running but skip readiness wait)
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
            listen = %listen_target_display(&spec.listen_target),
            command = %spec.command.display(),
            root = %root.display(),
            "starting managed process via {} provider (non-blocking)",
            prov.display_name()
        );

        cleanup_listen_target(&spec.listen_target);

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
        cmd.process_group(0);

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
                listen_target: spec.listen_target,
                started_at: now,
                last_active: now,
                kind: kind.to_string(),
                ready: false,
            },
        );

        Ok(StartStatus::Starting)
    }

    /// Kill a specific managed process. Returns true if it was found and killed.
    pub async fn kill_process(&mut self, app_id: i64) -> bool {
        if let Some(mut proc) = self.processes.remove(&app_id) {
            info!(app_id, "killing managed process");
            kill_process_group(&mut proc.child).await;
            cleanup_listen_target(&proc.listen_target);
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
    pub async fn reap_idle(&mut self) -> usize {
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
                    listen = %listen_target_display(&proc.listen_target),
                    "reaping idle managed process"
                );
                kill_process_group(&mut proc.child).await;
                cleanup_listen_target(&proc.listen_target);
            }
        }

        to_remove.len()
    }

    /// Kill all managed processes (called on daemon shutdown).
    pub async fn shutdown_all(&mut self) {
        for (app_id, mut proc) in self.processes.drain() {
            info!(
                app_id,
                listen = %listen_target_display(&proc.listen_target),
                "shutting down managed process"
            );
            kill_process_group(&mut proc.child).await;
            cleanup_listen_target(&proc.listen_target);
        }
    }
}

/// Clean up resources associated with a listen target.
/// Only UDS targets have socket files to remove.
fn cleanup_listen_target(target: &ListenTarget) {
    if let ListenTarget::Uds(path) = target {
        let _ = std::fs::remove_file(path);
    }
}

/// Wait for a listen target to become ready (UDS or TCP).
async fn wait_for_ready(target: &ListenTarget, timeout: Duration) -> anyhow::Result<()> {
    match target {
        ListenTarget::Uds(path) => provider::wait_for_uds_ready(path, timeout).await,
        ListenTarget::Tcp { host, port } => {
            provider::wait_for_tcp_ready(host, *port, timeout).await
        }
    }
}

/// Single-shot readiness probe with a short timeout.
async fn quick_ready_check(target: &ListenTarget) -> bool {
    const PROBE_TIMEOUT_MS: u64 = 200;
    let timeout = Duration::from_millis(PROBE_TIMEOUT_MS);
    match target {
        ListenTarget::Uds(path) => {
            tokio::time::timeout(timeout, tokio::net::UnixStream::connect(path))
                .await
                .is_ok_and(|r| r.is_ok())
        }
        ListenTarget::Tcp { host, port } => {
            let addr = format!("{host}:{port}");
            tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
                .await
                .is_ok_and(|r| r.is_ok())
        }
    }
}

/// Human-readable display of a listen target.
fn listen_target_display(target: &ListenTarget) -> String {
    match target {
        ListenTarget::Uds(path) => path.to_string_lossy().to_string(),
        ListenTarget::Tcp { host, port } => format!("{host}:{port}"),
    }
}

/// Kill an entire process group: SIGTERM first, then SIGKILL after a grace period.
///
/// Dev-mode processes (e.g. `bun run dev`, `npm run dev`) typically spawn child
/// processes. Using `process_group(0)` when spawning places the entire tree in a
/// new process group whose PGID equals the child PID. This function sends signals
/// to the negative PGID, reaching all descendants.
async fn kill_process_group(child: &mut Child) {
    let Some(pid) = child.id() else {
        // Already exited.
        return;
    };
    let pgid = pid as i32;

    // SIGTERM the whole group for graceful shutdown.
    let ret = unsafe { libc::kill(-pgid, libc::SIGTERM) };
    if ret != 0 {
        // Process (group) may already be gone — fall back to direct kill.
        let _ = child.start_kill();
        return;
    }

    // Give a short grace period, then SIGKILL if still alive.
    const GRACE_MS: u64 = 500;
    tokio::time::sleep(Duration::from_millis(GRACE_MS)).await;

    match child.try_wait() {
        Ok(None) => {
            // Still running — force kill the group.
            let ret = unsafe { libc::kill(-pgid, libc::SIGKILL) };
            if ret != 0 {
                warn!(pid, "SIGKILL to process group failed, trying direct kill");
                let _ = child.start_kill();
            }
        }
        Ok(Some(_)) => {
            // Leader exited but grandchildren may remain in the process group.
            // PGID stays valid while any member is alive; if all exited,
            // kill() harmlessly returns ESRCH.
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
        Err(e) => {
            // Cannot determine process state — skip group signal to avoid
            // potential misfire on a recycled PGID.
            warn!(pid, error = %e, "failed to check process status, skipping group kill");
        }
    }
}
