pub mod provider;

mod asgi;
mod docker;
mod node;
mod procfile;
mod rack;

pub use provider::{ListenTarget, ProviderRegistry};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::process::{Child, Command};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use std::process::Stdio;

use crate::config::ProcessBackend;
use crate::hooks::{HookContextFactory, HookEvent, HookManager};
use provider::{ManagedApp, ProcessSpec};

/// Dedicated tmux socket name — isolates coulson sessions from user's own tmux.
const TMUX_SOCKET: &str = "coulson";

/// A single log line emitted by a managed process.
#[derive(Clone, Debug)]
pub struct LogLine {
    pub app_id: i64,
    pub process_type: String,
    pub line: String,
}

pub type ProcessManagerHandle = Arc<tokio::sync::Mutex<ProcessManager>>;

pub struct ProcessManagerConfig {
    pub idle_timeout: Duration,
    pub registry: Arc<ProviderRegistry>,
    pub runtime_dir: PathBuf,
    pub backend: ProcessBackend,
    pub hook_manager: Arc<HookManager>,
    pub hook_factory: HookContextFactory,
    pub log_tx: broadcast::Sender<LogLine>,
}

pub fn new_process_manager(cfg: ProcessManagerConfig) -> ProcessManagerHandle {
    Arc::new(tokio::sync::Mutex::new(ProcessManager::new(cfg)))
}

/// Create the default provider registry with all built-in providers.
///
/// Registration order determines auto-detection priority.
pub fn default_registry() -> ProviderRegistry {
    let mut reg = ProviderRegistry::new();
    reg.register(asgi::AsgiProvider);
    reg.register(node::NodeProvider);
    reg.register(procfile::ProcfileProvider);
    reg.register(docker::DockerProvider);
    reg
}

enum ProcessHandle {
    Direct {
        child: Child,
    },
    Tmux {
        session_name: String,
    },
    Compose {
        project_dir: PathBuf,
        project_name: String,
        compose_file: String,
        /// Background `docker compose logs -f` process for continuous log capture.
        log_follower: Option<Child>,
    },
}

struct ManagedProcess {
    handle: ProcessHandle,
    listen_target: ListenTarget,
    started_at: Instant,
    last_active: Instant,
    kind: String,
    ready: bool,
    /// The environment this process was started with (merged, with provenance),
    /// captured at spawn so `coulson env` can show the live values.
    resolved_env: Vec<EnvEntry>,
}

#[allow(dead_code)]
struct CompanionProcess {
    process_type: String,
    handle: ProcessHandle,
    /// Companion's own spawn time — it can be restarted independently of the
    /// primary, so its uptime is not the group's.
    started_at: Instant,
}

struct ProcessGroup {
    primary: ManagedProcess,
    companions: Vec<CompanionProcess>,
    /// App name, preserved for hook context on stop/idle events.
    name: String,
    /// App root directory, preserved for hook context on stop/idle events.
    root: PathBuf,
    /// Per-app idle timeout override from `.coulson.toml`.
    idle_timeout: Option<Duration>,
}

pub struct ProcessManager {
    processes: HashMap<i64, ProcessGroup>,
    idle_timeout: Duration,
    registry: Arc<ProviderRegistry>,
    runtime_dir: PathBuf,
    use_tmux: bool,
    hook_manager: Arc<HookManager>,
    hook_factory: HookContextFactory,
    log_tx: broadcast::Sender<LogLine>,
}

pub enum StartStatus {
    /// Process is running and ready to accept connections.
    Ready(ListenTarget),
    /// Process has been spawned but is not yet ready.
    Starting,
}

/// Outcome of [`ProcessManager::ensure_started`]. Distinguishes a real start
/// result from the control signal that the caller must prefetch `env_url`
/// off-lock and retry (see [`prepare_and_ensure_started`]).
pub(crate) enum EnsureStarted {
    Status(StartStatus),
    /// About to cold-start, but `env_url` is configured and no prefetched env
    /// was supplied (the process looked alive when the prefetch was skipped but
    /// has since exited). The caller must prefetch and call again.
    NeedsEnvUrl,
}

#[derive(serde::Serialize)]
pub struct ProcessInfo {
    pub app_id: i64,
    pub pid: u32,
    pub kind: String,
    pub process_type: String,
    pub listen_address: String,
    pub uptime_secs: u64,
    pub idle_secs: u64,
    pub alive: bool,
    pub backend: String,
}

/// Which layer a resolved env var's winning value came from. Mirrors the
/// precedence in [`LayeredEnv`]. `Dotenv` carries the file path because there
/// can be more than one dotenv file (today `.coulsonrc`; future `.env`, etc.),
/// each its own layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvSource {
    Provider,
    TomlEnv,
    EnvUrl,
    Dotenv(PathBuf),
}

impl EnvSource {
    /// Stable machine label for the source kind (used for grouping/coloring).
    pub fn kind(&self) -> &'static str {
        match self {
            EnvSource::Provider => "provider",
            EnvSource::TomlEnv => "toml",
            EnvSource::EnvUrl => "env_url",
            EnvSource::Dotenv(_) => "dotenv",
        }
    }

    /// Human-readable label: the concrete file for dotenv, else the kind.
    pub fn label(&self) -> String {
        match self {
            EnvSource::Provider => "provider".to_string(),
            EnvSource::TomlEnv => ".coulson.toml".to_string(),
            EnvSource::EnvUrl => "env_url".to_string(),
            EnvSource::Dotenv(path) => path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string_lossy().into_owned()),
        }
    }

    /// Precedence rank (low → high). Used to order resolved entries so the
    /// highest-priority overrides sort last.
    fn rank(&self) -> u8 {
        match self {
            EnvSource::Provider => 0,
            EnvSource::TomlEnv => 1,
            EnvSource::EnvUrl => 2,
            EnvSource::Dotenv(_) => 3,
        }
    }
}

impl serde::Serialize for EnvSource {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("EnvSource", 2)?;
        st.serialize_field("kind", self.kind())?;
        st.serialize_field("label", &self.label())?;
        st.end()
    }
}

/// One resolved environment variable with the source that won it. Produced by
/// [`LayeredEnv::resolve`] and surfaced by the `coulson env` command.
#[derive(Clone, serde::Serialize)]
pub struct EnvEntry {
    pub key: String,
    pub value: String,
    pub source: EnvSource,
}

/// An ordered stack of named environment layers, lowest precedence first. Both
/// the merged environment and the per-variable provenance derive from the same
/// fold, so they cannot disagree — no double application, no reverse lookup.
///
/// Precedence (low → high): `Provider < TomlEnv < EnvUrl < Dotenv(.coulsonrc)`.
#[derive(Default)]
pub(crate) struct LayeredEnv {
    layers: Vec<(EnvSource, HashMap<String, String>)>,
}

impl LayeredEnv {
    /// Add a layer. Empty layers are dropped (they cannot affect the result).
    fn push(&mut self, source: EnvSource, vars: HashMap<String, String>) {
        if !vars.is_empty() {
            self.layers.push((source, vars));
        }
    }

    /// Winning value for a single key: the highest layer that sets it.
    fn get(&self, key: &str) -> Option<&str> {
        self.layers
            .iter()
            .rev()
            .find_map(|(_src, vars)| vars.get(key))
            .map(String::as_str)
    }

    /// The final merged environment; higher layers win.
    fn merge(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        for (_src, vars) in &self.layers {
            for (k, v) in vars {
                out.insert(k.clone(), v.clone());
            }
        }
        out
    }

    /// Every key with its winning value and the layer that set it, ordered by
    /// source precedence (low → high) then key — so the highest-priority
    /// overrides (`.coulsonrc`) sort last.
    fn resolve(&self) -> Vec<EnvEntry> {
        let mut map: std::collections::BTreeMap<String, (String, EnvSource)> =
            std::collections::BTreeMap::new();
        for (src, vars) in &self.layers {
            for (k, v) in vars {
                map.insert(k.clone(), (v.clone(), src.clone()));
            }
        }
        // BTreeMap gives key order; stable-sort by rank preserves key order
        // within each precedence tier.
        let mut entries: Vec<EnvEntry> = map
            .into_iter()
            .map(|(key, (value, source))| EnvEntry { key, value, source })
            .collect();
        entries.sort_by_key(|e| e.source.rank());
        entries
    }
}

impl ProcessManager {
    fn new(cfg: ProcessManagerConfig) -> Self {
        let use_tmux = match cfg.backend {
            ProcessBackend::Tmux => {
                if !tmux_available() {
                    warn!("COULSON_PROCESS_BACKEND=tmux but tmux not found in PATH");
                }
                true
            }
            ProcessBackend::Direct => false,
            ProcessBackend::Auto => {
                let available = tmux_available();
                if available {
                    info!("tmux found, using tmux process backend");
                } else {
                    info!("tmux not found, using direct process backend");
                }
                available
            }
        };

        Self {
            processes: HashMap::new(),
            idle_timeout: cfg.idle_timeout,
            registry: cfg.registry,
            runtime_dir: cfg.runtime_dir,
            use_tmux,
            hook_manager: cfg.hook_manager,
            hook_factory: cfg.hook_factory,
            log_tx: cfg.log_tx,
        }
    }

    fn fire_hook(&self, event: HookEvent, app_id: i64, name: &str, root: &Path, kind: &str) {
        let ctx = self
            .hook_factory
            .context_for_process(event, app_id, name, root, kind);
        let hm = self.hook_manager.clone();
        tokio::spawn(async move { hm.fire(&ctx).await });
    }

    /// Whether the tmux backend is active.
    pub fn uses_tmux(&self) -> bool {
        self.use_tmux
    }

    /// List process types for a managed app (e.g. `["web", "worker"]`).
    pub fn process_types(&self, app_id: i64) -> Vec<String> {
        let Some(group) = self.processes.get(&app_id) else {
            return vec![];
        };
        let mut types = vec!["web".to_string()];
        for c in &group.companions {
            types.push(c.process_type.clone());
        }
        types
    }

    /// The resolved environment (with provenance) the running web process was
    /// started with. `None` if no process is tracked for this app, or the
    /// tracked process has already exited (so callers report "not running"
    /// instead of stale env for a dead handle).
    pub fn process_env(&mut self, app_id: i64) -> Option<&[EnvEntry]> {
        let group = self.processes.get_mut(&app_id)?;
        if !is_alive(&mut group.primary.handle) {
            return None;
        }
        Some(group.primary.resolved_env.as_slice())
    }

    /// Whether log broadcast is available (direct/compose backends).
    /// Tmux uses `pipe-pane` to file, so no broadcast channel.
    pub fn has_log_broadcast(&self) -> bool {
        !self.use_tmux
    }

    /// Quick check: is there a live process for this app_id (ready or starting)?
    /// Used by proxy to skip env_url prefetch when process already exists.
    pub fn has_live_process(&mut self, app_id: i64) -> bool {
        if let Some(group) = self.processes.get_mut(&app_id) {
            is_alive(&mut group.primary.handle)
        } else {
            false
        }
    }

    pub fn list_status(&mut self) -> Vec<ProcessInfo> {
        let now = Instant::now();
        let mut result = Vec::new();
        for (app_id, group) in &mut self.processes {
            let proc = &mut group.primary;
            let (pid, alive, backend) = handle_status(&mut proc.handle);
            result.push(ProcessInfo {
                app_id: *app_id,
                pid,
                kind: proc.kind.clone(),
                process_type: "web".to_string(),
                listen_address: listen_target_display(&proc.listen_target),
                uptime_secs: now.duration_since(proc.started_at).as_secs(),
                idle_secs: now.duration_since(proc.last_active).as_secs(),
                alive,
                backend: backend.to_string(),
            });
            for companion in &mut group.companions {
                let (c_pid, c_alive, c_backend) = handle_status(&mut companion.handle);
                result.push(ProcessInfo {
                    app_id: *app_id,
                    pid: c_pid,
                    kind: proc.kind.clone(),
                    process_type: companion.process_type.clone(),
                    listen_address: String::new(),
                    uptime_secs: now.duration_since(companion.started_at).as_secs(),
                    idle_secs: now.duration_since(proc.last_active).as_secs(),
                    alive: c_alive,
                    backend: c_backend.to_string(),
                });
            }
        }
        result
    }

    /// Returns the listen target for the managed app, starting the process if needed.
    /// `env_url_env` should be pre-fetched outside the lock via `prefetch_env_url()`.
    pub async fn ensure_running(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
        env_url_env: Option<HashMap<String, String>>,
    ) -> anyhow::Result<ListenTarget> {
        // Check if already running and alive
        if let Some(group) = self.processes.get_mut(&app_id) {
            if is_alive(&mut group.primary.handle) {
                group.primary.last_active = Instant::now();
                return Ok(group.primary.listen_target.clone());
            }
            info!(app_id, "managed process exited, will restart");
            let removed = self.processes.remove(&app_id).unwrap();
            for companion in removed.companions {
                kill_handle(companion.handle).await;
            }
            kill_handle(removed.primary.handle).await;
            cleanup_listen_target(&removed.primary.listen_target);
        }

        let (mut spec, app_dir, prov_name, companion_types, manifest, coulsonrc) =
            self.resolve_spec(app_id, name, root, kind)?;

        let resolved_env =
            apply_and_capture_env(&mut spec, &manifest, env_url_env.as_ref(), &coulsonrc, root);

        let log_dir = resolve_log_dir(&manifest, root, &app_dir);
        std::fs::create_dir_all(&log_dir).ok();
        let log_path = process_log_path(&log_dir, "web");

        info!(
            app_id,
            kind,
            listen = %listen_target_display(&spec.listen_target),
            root = %root.display(),
            "starting managed process via {prov_name} provider",
        );

        self.fire_hook(HookEvent::AppStart, app_id, name, root, kind);

        cleanup_listen_target(&spec.listen_target);

        let log_tx = &self.log_tx;

        let handle = if kind == "docker" {
            // Docker Compose: run `docker compose up -d --build` synchronously,
            // since it exits immediately after starting containers in the background.
            let project_name = name.to_string();
            // Extract compose file from args: ["compose", "-f", <file>, "-p", ...]
            let compose_file = spec.args.get(2).cloned().unwrap_or_default();
            let working_dir = spec.working_dir.clone();
            let cmd = spec.command.clone();
            let args = spec.args.clone();
            let env = spec.env.clone();

            let result = tokio::task::spawn_blocking(move || {
                let mut command = std::process::Command::new(&cmd);
                command
                    .args(&args)
                    .envs(&env)
                    .current_dir(&working_dir)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                command.output()
            })
            .await
            .map_err(|e| anyhow::anyhow!("docker compose task panicked: {e}"))?
            .with_context(|| "failed to run docker compose up")?;

            if !result.status.success() {
                let stderr = String::from_utf8_lossy(&result.stderr);
                anyhow::bail!(
                    "docker compose up failed (exit {}): {stderr}",
                    result.status
                );
            }

            let log_follower = spawn_compose_log_follower(
                root,
                &project_name,
                &compose_file,
                &log_path,
                log_tx,
                app_id,
            );

            ProcessHandle::Compose {
                project_dir: root.to_path_buf(),
                project_name,
                compose_file,
                log_follower,
            }
        } else {
            self.spawn_process(name, &spec, &log_path, &app_dir, log_tx, app_id, "web")?
        };

        // Docker builds can be slow — use a longer readiness timeout.
        let ready_timeout_secs: u64 = if kind == "docker" { 120 } else { 30 };
        if let Err(e) =
            wait_for_ready(&spec.listen_target, Duration::from_secs(ready_timeout_secs)).await
        {
            log_tail(&log_path, name);
            // Clean up the started process/containers to avoid leaking resources
            kill_handle(handle).await;
            return Err(e);
        }

        self.fire_hook(HookEvent::AppReady, app_id, name, root, kind);

        let companions = self.spawn_companions(
            app_id,
            name,
            root,
            kind,
            &companion_types,
            &app_dir,
            &manifest,
            env_url_env.as_ref(),
            &log_dir,
            log_tx,
            &coulsonrc,
        );

        let app_idle_timeout = manifest_idle_timeout(&manifest);
        let now = Instant::now();
        self.processes.insert(
            app_id,
            ProcessGroup {
                primary: ManagedProcess {
                    handle,
                    listen_target: spec.listen_target.clone(),
                    started_at: now,
                    last_active: now,
                    kind: kind.to_string(),
                    ready: true,
                    resolved_env,
                },
                companions,
                name: name.to_string(),
                root: root.to_path_buf(),
                idle_timeout: app_idle_timeout,
            },
        );

        Ok(spec.listen_target)
    }

    /// Non-blocking variant: spawns the process if needed but does NOT wait for readiness.
    /// `env_url_env` should be pre-fetched outside the lock via `prefetch_env_url()`.
    pub(crate) async fn ensure_started(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
        env_url_env: Option<HashMap<String, String>>,
    ) -> anyhow::Result<EnsureStarted> {
        // Check existing process state in a limited scope to avoid borrow conflicts
        enum ExistingState {
            AlreadyReady(ListenTarget),
            JustBecameReady(ListenTarget),
            StillStarting,
            TimedOut,
            Exited,
        }
        let existing = if let Some(group) = self.processes.get_mut(&app_id) {
            if is_alive(&mut group.primary.handle) {
                if group.primary.ready {
                    group.primary.last_active = Instant::now();
                    Some(ExistingState::AlreadyReady(
                        group.primary.listen_target.clone(),
                    ))
                } else if quick_ready_check(&group.primary.listen_target).await {
                    group.primary.ready = true;
                    group.primary.last_active = Instant::now();
                    Some(ExistingState::JustBecameReady(
                        group.primary.listen_target.clone(),
                    ))
                } else {
                    let startup_timeout = if group.primary.kind == "docker" {
                        120
                    } else {
                        30
                    };
                    if group.primary.started_at.elapsed() > Duration::from_secs(startup_timeout) {
                        Some(ExistingState::TimedOut)
                    } else {
                        Some(ExistingState::StillStarting)
                    }
                }
            } else {
                Some(ExistingState::Exited)
            }
        } else {
            None
        };

        match existing {
            Some(ExistingState::AlreadyReady(target)) => {
                return Ok(EnsureStarted::Status(StartStatus::Ready(target)));
            }
            Some(ExistingState::JustBecameReady(target)) => {
                self.fire_hook(HookEvent::AppReady, app_id, name, root, kind);
                return Ok(EnsureStarted::Status(StartStatus::Ready(target)));
            }
            Some(ExistingState::StillStarting) => {
                return Ok(EnsureStarted::Status(StartStatus::Starting));
            }
            Some(ExistingState::TimedOut) => {
                let removed = self.processes.remove(&app_id).unwrap();
                let startup_timeout = if removed.primary.kind == "docker" {
                    120
                } else {
                    30
                };
                for companion in removed.companions {
                    kill_handle(companion.handle).await;
                }
                let manifest = load_coulson_toml_manifest(root);
                let app_dir = self.runtime_dir.join("managed").join(name);
                let log_dir = resolve_log_dir(&manifest, root, &app_dir);
                let timed_out_log = process_log_path(&log_dir, "web");
                log_tail(&timed_out_log, name);
                kill_handle(removed.primary.handle).await;
                cleanup_listen_target(&removed.primary.listen_target);
                anyhow::bail!(
                    "managed process for {name} (app_id={app_id}) failed to become ready within {startup_timeout}s"
                );
            }
            Some(ExistingState::Exited) => {
                info!(app_id, "managed process exited, will restart");
                let removed = self.processes.remove(&app_id).unwrap();
                for companion in removed.companions {
                    kill_handle(companion.handle).await;
                }
                kill_handle(removed.primary.handle).await;
                cleanup_listen_target(&removed.primary.listen_target);
            }
            None => {} // No existing process, proceed to spawn
        }

        // We are about to cold-start. If `env_url` is configured but we have no
        // prefetched env (the process looked alive when the prefetch was skipped
        // but has since exited), bail to the caller to prefetch off-lock and
        // retry — otherwise the new child would miss the remote env layer. This
        // closes the exit-race window the held lock cannot: the lock guards the
        // `processes` map, not the OS process's liveness.
        if env_url_env.is_none() && env_url_configured(root) {
            return Ok(EnsureStarted::NeedsEnvUrl);
        }

        let (mut spec, app_dir, prov_name, companion_types, manifest, coulsonrc) =
            self.resolve_spec(app_id, name, root, kind)?;

        let resolved_env =
            apply_and_capture_env(&mut spec, &manifest, env_url_env.as_ref(), &coulsonrc, root);

        let log_dir = resolve_log_dir(&manifest, root, &app_dir);
        std::fs::create_dir_all(&log_dir).ok();
        let log_path = process_log_path(&log_dir, "web");

        info!(
            app_id,
            kind,
            listen = %listen_target_display(&spec.listen_target),
            root = %root.display(),
            "starting managed process via {prov_name} provider (non-blocking)",
        );

        self.fire_hook(HookEvent::AppStart, app_id, name, root, kind);

        cleanup_listen_target(&spec.listen_target);

        let log_tx = &self.log_tx;

        let handle = if kind == "docker" {
            let project_name = name.to_string();
            let compose_file = spec.args.get(2).cloned().unwrap_or_default();
            let working_dir = spec.working_dir.clone();
            let cmd = spec.command.clone();
            let args = spec.args.clone();
            let env = spec.env.clone();

            let result = tokio::task::spawn_blocking(move || {
                let mut command = std::process::Command::new(&cmd);
                command
                    .args(&args)
                    .envs(&env)
                    .current_dir(&working_dir)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                command.output()
            })
            .await
            .map_err(|e| anyhow::anyhow!("docker compose task panicked: {e}"))?
            .with_context(|| "failed to run docker compose up")?;

            if !result.status.success() {
                let stderr = String::from_utf8_lossy(&result.stderr);
                anyhow::bail!(
                    "docker compose up failed (exit {}): {stderr}",
                    result.status
                );
            }

            let log_follower = spawn_compose_log_follower(
                root,
                &project_name,
                &compose_file,
                &log_path,
                log_tx,
                app_id,
            );

            ProcessHandle::Compose {
                project_dir: root.to_path_buf(),
                project_name,
                compose_file,
                log_follower,
            }
        } else {
            self.spawn_process(name, &spec, &log_path, &app_dir, log_tx, app_id, "web")?
        };

        let companions = self.spawn_companions(
            app_id,
            name,
            root,
            kind,
            &companion_types,
            &app_dir,
            &manifest,
            env_url_env.as_ref(),
            &log_dir,
            log_tx,
            &coulsonrc,
        );

        let app_idle_timeout = manifest_idle_timeout(&manifest);
        let now = Instant::now();
        self.processes.insert(
            app_id,
            ProcessGroup {
                primary: ManagedProcess {
                    handle,
                    listen_target: spec.listen_target,
                    started_at: now,
                    last_active: now,
                    kind: kind.to_string(),
                    ready: false,
                    resolved_env,
                },
                companions,
                name: name.to_string(),
                root: root.to_path_buf(),
                idle_timeout: app_idle_timeout,
            },
        );

        Ok(EnsureStarted::Status(StartStatus::Starting))
    }

    /// Kill a specific managed process. Returns true if it was found and killed.
    pub async fn kill_process(&mut self, app_id: i64) -> bool {
        if let Some(group) = self.processes.remove(&app_id) {
            info!(app_id, "killing managed process");
            for companion in group.companions {
                kill_handle(companion.handle).await;
            }
            kill_handle(group.primary.handle).await;
            cleanup_listen_target(&group.primary.listen_target);
            self.fire_hook(
                HookEvent::AppStop,
                app_id,
                &group.name,
                &group.root,
                &group.primary.kind,
            );
            true
        } else {
            false
        }
    }

    /// Restart a single process type of a running app group: `"web"` restarts
    /// the primary while companions keep running; any other type restarts that
    /// companion alone. The group must already be running — starting a lone
    /// member of a stopped app is not meaningful.
    /// Returns the (possibly re-resolved) listen target of the primary.
    pub async fn restart_process_type(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
        process_type: &str,
        env_url_env: Option<HashMap<String, String>>,
    ) -> anyhow::Result<ListenTarget> {
        if !self.processes.contains_key(&app_id) {
            anyhow::bail!("{name} is not running; use `coulson restart {name}` to start it");
        }
        if process_type == "web" {
            if self
                .processes
                .get(&app_id)
                .is_some_and(|g| g.companions.is_empty())
            {
                // No companions to preserve — identical to a group restart.
                self.kill_process(app_id).await;
                return self
                    .ensure_running(app_id, name, root, kind, env_url_env)
                    .await;
            }
            self.restart_primary(app_id, name, root, kind, env_url_env)
                .await
        } else {
            self.restart_companion(app_id, name, root, kind, process_type, env_url_env)
                .await?;
            Ok(self
                .processes
                .get(&app_id)
                .expect("group checked above")
                .primary
                .listen_target
                .clone())
        }
    }

    /// Kill and respawn one companion, re-resolving its Procfile entry and env
    /// so config edits take effect. Also (re)starts a configured companion that
    /// died or failed to spawn with the group.
    async fn restart_companion(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
        process_type: &str,
        env_url_env: Option<HashMap<String, String>>,
    ) -> anyhow::Result<()> {
        let (_spec, app_dir, _prov_name, companion_types, manifest, coulsonrc) =
            self.resolve_spec(app_id, name, root, kind)?;

        let running = self
            .processes
            .get(&app_id)
            .is_some_and(|g| g.companions.iter().any(|c| c.process_type == process_type));
        if !running && !companion_types.iter().any(|t| t == process_type) {
            let mut available = vec!["web".to_string()];
            available.extend(companion_types);
            anyhow::bail!(
                "unknown process type '{process_type}' for {name}; available: {}",
                available.join(", ")
            );
        }

        if let Some(group) = self.processes.get_mut(&app_id) {
            if let Some(pos) = group
                .companions
                .iter()
                .position(|c| c.process_type == process_type)
            {
                info!(app_id, process_type, "restarting companion process");
                let old = group.companions.remove(pos);
                kill_handle(old.handle).await;
            }
        }

        let log_dir = resolve_log_dir(&manifest, root, &app_dir);
        std::fs::create_dir_all(&log_dir).ok();
        let log_tx = self.log_tx.clone();
        let types = [process_type.to_string()];
        let spawned = self.spawn_companions(
            app_id,
            name,
            root,
            kind,
            &types,
            &app_dir,
            &manifest,
            env_url_env.as_ref(),
            &log_dir,
            &log_tx,
            &coulsonrc,
        );
        if spawned.is_empty() {
            anyhow::bail!(
                "failed to start {process_type} for {name} (see {})",
                process_log_path(&log_dir, process_type).display()
            );
        }
        self.processes
            .get_mut(&app_id)
            .expect("group checked by caller")
            .companions
            .extend(spawned);
        Ok(())
    }

    /// Kill and respawn only the primary, keeping companions running. Only
    /// reached for groups that have companions (procfile — never docker). If
    /// the respawn fails the group is gone, so the orphaned companions are
    /// killed too rather than leaked.
    async fn restart_primary(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
        env_url_env: Option<HashMap<String, String>>,
    ) -> anyhow::Result<ListenTarget> {
        let group = self
            .processes
            .remove(&app_id)
            .expect("group checked by caller");
        info!(app_id, "restarting primary process, keeping companions");
        kill_handle(group.primary.handle).await;
        cleanup_listen_target(&group.primary.listen_target);
        self.fire_hook(HookEvent::AppStop, app_id, &group.name, &group.root, kind);

        match self
            .spawn_primary(app_id, name, root, kind, env_url_env)
            .await
        {
            Ok((primary, idle_timeout)) => {
                let listen_target = primary.listen_target.clone();
                self.processes.insert(
                    app_id,
                    ProcessGroup {
                        primary,
                        companions: group.companions,
                        name: name.to_string(),
                        root: root.to_path_buf(),
                        idle_timeout,
                    },
                );
                Ok(listen_target)
            }
            Err(e) => {
                for companion in group.companions {
                    kill_handle(companion.handle).await;
                }
                Err(e)
            }
        }
    }

    /// Resolve and spawn the primary (non-docker), waiting for readiness.
    /// The spawn half of `ensure_running`, minus companions and group insert.
    async fn spawn_primary(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
        env_url_env: Option<HashMap<String, String>>,
    ) -> anyhow::Result<(ManagedProcess, Option<Duration>)> {
        let (mut spec, app_dir, prov_name, _companion_types, manifest, coulsonrc) =
            self.resolve_spec(app_id, name, root, kind)?;
        let resolved_env =
            apply_and_capture_env(&mut spec, &manifest, env_url_env.as_ref(), &coulsonrc, root);

        let log_dir = resolve_log_dir(&manifest, root, &app_dir);
        std::fs::create_dir_all(&log_dir).ok();
        let log_path = process_log_path(&log_dir, "web");

        info!(
            app_id,
            kind,
            listen = %listen_target_display(&spec.listen_target),
            root = %root.display(),
            "starting managed process via {prov_name} provider",
        );
        self.fire_hook(HookEvent::AppStart, app_id, name, root, kind);
        cleanup_listen_target(&spec.listen_target);

        let handle = self.spawn_process(
            name,
            &spec,
            &log_path,
            &app_dir,
            &self.log_tx.clone(),
            app_id,
            "web",
        )?;

        if let Err(e) = wait_for_ready(&spec.listen_target, Duration::from_secs(30)).await {
            log_tail(&log_path, name);
            kill_handle(handle).await;
            return Err(e);
        }
        self.fire_hook(HookEvent::AppReady, app_id, name, root, kind);

        let now = Instant::now();
        Ok((
            ManagedProcess {
                handle,
                listen_target: spec.listen_target.clone(),
                started_at: now,
                last_active: now,
                kind: kind.to_string(),
                ready: true,
                resolved_env,
            },
            manifest_idle_timeout(&manifest),
        ))
    }

    pub fn mark_active(&mut self, app_id: i64) {
        if let Some(group) = self.processes.get_mut(&app_id) {
            group.primary.last_active = Instant::now();
        }
    }

    /// Kill processes idle longer than the configured timeout. Returns count reaped.
    pub async fn reap_idle(&mut self) -> usize {
        let now = Instant::now();
        let global_timeout = self.idle_timeout;
        let mut to_remove = Vec::new();

        for (app_id, group) in &self.processes {
            let timeout = group.idle_timeout.unwrap_or(global_timeout);
            if now.duration_since(group.primary.last_active) > timeout {
                to_remove.push(*app_id);
            }
        }

        for app_id in &to_remove {
            if let Some(group) = self.processes.remove(app_id) {
                info!(
                    app_id,
                    listen = %listen_target_display(&group.primary.listen_target),
                    "reaping idle managed process"
                );
                // Fire AppIdle before reaping
                let idle_ctx = self.hook_factory.context_for_process(
                    HookEvent::AppIdle,
                    *app_id,
                    &group.name,
                    &group.root,
                    &group.primary.kind,
                );
                self.hook_manager.fire(&idle_ctx).await;
                for companion in group.companions {
                    kill_handle(companion.handle).await;
                }
                kill_handle(group.primary.handle).await;
                cleanup_listen_target(&group.primary.listen_target);
                // Fire AppStop after kill
                self.fire_hook(
                    HookEvent::AppStop,
                    *app_id,
                    &group.name,
                    &group.root,
                    &group.primary.kind,
                );
            }
        }

        to_remove.len()
    }

    /// Kill all managed processes (called on daemon shutdown).
    pub async fn shutdown_all(&mut self) {
        for (app_id, group) in self.processes.drain() {
            info!(
                app_id,
                listen = %listen_target_display(&group.primary.listen_target),
                "shutting down managed process"
            );
            for companion in group.companions {
                kill_handle(companion.handle).await;
            }
            kill_handle(group.primary.handle).await;
            cleanup_listen_target(&group.primary.listen_target);
        }
        // If using tmux, kill the dedicated server to clean up.
        if self.use_tmux {
            let _ = tmux_cmd().args(["kill-server"]).output();
        }
    }

    /// Resolve a ProcessSpec from the provider registry.
    /// Returns the spec, the per-app runtime directory (`$RUNTIME/managed/{name}/`),
    /// provider name, companion types, the loaded `.coulson.toml` manifest (if any),
    /// and the parsed `.coulsonrc` snapshot so the caller can finalize the env from
    /// the same single read (no re-parse, no TOCTOU).
    #[allow(clippy::type_complexity)]
    fn resolve_spec(
        &self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
    ) -> anyhow::Result<(
        ProcessSpec,
        PathBuf,
        String,
        Vec<String>,
        Option<serde_json::Value>,
        HashMap<String, String>,
    )> {
        let prov = self
            .registry
            .get(kind)
            .ok_or_else(|| anyhow::anyhow!("no process provider for kind: {kind}"))?;

        // Each app gets its own runtime directory `$RUNTIME/managed/{name}/`.
        // The app name lives in the directory, so socket/log files inside are
        // named purely by process type (`web.sock`, `web.log`, `worker.log`),
        // which also makes cross-app filename collisions structurally
        // impossible.
        let app_dir = self.runtime_dir.join("managed").join(name);
        std::fs::create_dir_all(&app_dir)
            .with_context(|| format!("failed to create {}", app_dir.display()))?;
        let app_dir = std::fs::canonicalize(&app_dir).unwrap_or(app_dir);

        let env_overrides = crate::process::provider::load_coulsonrc(root);

        // Load .coulson.toml manifest if present (needed so its [env] block can
        // also supply COULSON_MANAGED_SERVICES, not only .coulsonrc).
        let manifest = load_coulson_toml_manifest(root);

        let managed_services_value = lookup_managed_services(&env_overrides, manifest.as_ref());
        let companion_types = parse_managed_services(managed_services_value.as_deref());

        if !companion_types.is_empty() && kind != "procfile" {
            warn!(
                app_id,
                kind, "COULSON_MANAGED_SERVICES is only supported for procfile apps, ignoring"
            );
        }

        let managed_app = ManagedApp {
            name: name.to_string(),
            root: root.to_path_buf(),
            kind: kind.to_string(),
            manifest,
            env_overrides: env_overrides.clone(),
            socket_dir: app_dir.clone(),
        };

        // Provider seeds `spec.env` with its framework defaults only. The
        // authoritative env layering (`.coulson.toml [env]` < env_url <
        // `.coulsonrc`) and the `COULSON_MANAGED_SERVICES` strip are applied
        // later by `apply_and_capture_env`, once env_url has been fetched.
        let spec = prov.resolve(&managed_app)?;

        let _ = app_id; // used in caller for logging
        Ok((
            spec,
            app_dir,
            prov.display_name().to_string(),
            companion_types,
            managed_app.manifest,
            env_overrides,
        ))
    }

    /// Resolve the environment a managed app's **web** process would receive,
    /// annotating each variable with the source that won it — WITHOUT spawning.
    ///
    /// Reuses the real spawn path (`resolve_spec` + `finalize_managed_env`) so
    /// the result matches what the child would actually get. Resolving the
    /// provider spec has the same side effects as a real start (binary
    /// detection, and a transient free-port probe for TCP providers). When
    /// `fetch_remote` is true, `env_url` is fetched. Used by `coulson env`.
    pub async fn inspect_env(
        &self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
        fetch_remote: bool,
    ) -> anyhow::Result<Vec<EnvEntry>> {
        let (spec, _sockets_dir, _prov_name, _companion_types, manifest, coulsonrc) =
            self.resolve_spec(app_id, name, root, kind)?;

        let env_url_env = if fetch_remote {
            prefetch_env_url(root).await?
        } else {
            None
        };

        // Provenance falls straight out of the layered fold — no reverse lookup.
        let layered =
            build_layered_env(spec.env, &manifest, env_url_env.as_ref(), &coulsonrc, root);
        let mut entries = layered.resolve();
        entries.retain(|e| e.key != "COULSON_MANAGED_SERVICES");
        Ok(entries)
    }

    /// Spawn a process using the current backend (direct or tmux).
    #[allow(clippy::too_many_arguments)]
    fn spawn_process(
        &self,
        name: &str,
        spec: &ProcessSpec,
        log_path: &Path,
        managed_dir: &Path,
        log_tx: &broadcast::Sender<LogLine>,
        app_id: i64,
        process_type: &str,
    ) -> anyhow::Result<ProcessHandle> {
        if self.use_tmux {
            self.spawn_tmux(name, spec, log_path, managed_dir, process_type)
        } else {
            Self::spawn_direct(name, spec, log_path, log_tx, app_id, process_type)
        }
    }

    /// Spawn companion processes for a Procfile app.
    ///
    /// `manifest` and `remote_env` are passed through so companion specs receive
    /// the same layered env as the web process (provider defaults < `.coulson.toml
    /// [env]` < `env_url` < `.coulsonrc`). Without this, workers/schedulers would
    /// see only `.coulsonrc` and miss secrets like `DATABASE_URL`.
    #[allow(clippy::too_many_arguments)]
    fn spawn_companions(
        &self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
        companion_types: &[String],
        app_dir: &Path,
        manifest: &Option<serde_json::Value>,
        remote_env: Option<&HashMap<String, String>>,
        log_dir: &Path,
        log_tx: &broadcast::Sender<LogLine>,
        coulsonrc: &HashMap<String, String>,
    ) -> Vec<CompanionProcess> {
        if companion_types.is_empty() || kind != "procfile" {
            return vec![];
        }

        let managed_app = ManagedApp {
            name: name.to_string(),
            root: root.to_path_buf(),
            kind: kind.to_string(),
            manifest: manifest.clone(),
            env_overrides: coulsonrc.clone(),
            socket_dir: app_dir.to_path_buf(),
        };

        let provider = procfile::ProcfileProvider;
        let mut companions = Vec::new();

        for ptype in companion_types {
            match provider.resolve_companion(&managed_app, ptype) {
                Ok(cspec) => {
                    let mut spec = ProcessSpec {
                        command: cspec.command,
                        args: cspec.args,
                        env: cspec.env,
                        working_dir: cspec.working_dir,
                        listen_target: ListenTarget::Tcp {
                            host: String::new(),
                            port: 0,
                        },
                    };
                    // Same env precedence as the web process (companion env is
                    // applied but not stored for inspection this pass).
                    let _ = apply_and_capture_env(&mut spec, manifest, remote_env, coulsonrc, root);
                    let log_path = process_log_path(log_dir, ptype);
                    match self.spawn_process(
                        &format!("{name}-{ptype}"),
                        &spec,
                        &log_path,
                        app_dir,
                        log_tx,
                        app_id,
                        ptype,
                    ) {
                        Ok(handle) => {
                            info!(
                                app_id,
                                process_type = %ptype,
                                "spawned companion process"
                            );
                            companions.push(CompanionProcess {
                                process_type: ptype.clone(),
                                handle,
                                started_at: Instant::now(),
                            });
                        }
                        Err(e) => {
                            warn!(
                                app_id,
                                process_type = %ptype,
                                error = %e,
                                "failed to spawn companion process"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        app_id,
                        process_type = %ptype,
                        error = %e,
                        "failed to resolve companion process"
                    );
                }
            }
        }

        companions
    }

    /// Spawn via direct child process.
    ///
    /// stdout/stderr are piped through a tee task that writes to the log file
    /// and broadcasts each line to `log_tx` for live SSE streaming.
    fn spawn_direct(
        name: &str,
        spec: &ProcessSpec,
        log_path: &Path,
        log_tx: &broadcast::Sender<LogLine>,
        app_id: i64,
        process_type: &str,
    ) -> anyhow::Result<ProcessHandle> {
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("failed to open log file {}", log_path.display()))?;

        // All specs go through login shell for user env loading
        let full_cmd = build_full_command(spec);
        let shell = user_shell();
        let args = login_shell_args(&shell, &full_cmd, &spec.env);

        let mut cmd = Command::new(&shell);
        cmd.args(&args);
        for (k, v) in &spec.env {
            // `Command::env` panics on keys containing '=' or NUL. These keys
            // are also skipped by the inner `env(1)` prefix (see
            // `build_env_command_prefix`), so the final process env stays
            // consistent across direct and tmux backends.
            if !is_env_command_key(k) {
                continue;
            }
            cmd.env(k, v);
        }
        cmd.process_group(0);

        let mut child = cmd
            .current_dir(&spec.working_dir)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn {} for {name}", shell.display()))?;

        // Tee stdout + stderr → log file + broadcast channel
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        spawn_tee_task(
            stdout,
            stderr,
            log_file,
            log_tx.clone(),
            app_id,
            process_type,
        );

        Ok(ProcessHandle::Direct { child })
    }

    /// Spawn via tmux session.
    fn spawn_tmux(
        &self,
        name: &str,
        spec: &ProcessSpec,
        log_path: &Path,
        app_dir: &Path,
        process_type: &str,
    ) -> anyhow::Result<ProcessHandle> {
        let session_name = name.to_string();

        // Kill any existing session with this name
        if tmux_has_session(&session_name) {
            tmux_kill_session(&session_name);
        }

        // Generate wrapper script — named by process type within the per-app
        // directory (the app name is already in `app_dir`).
        let script_path = app_dir.join(format!("{process_type}.sh"));
        let script_content = generate_wrapper_script(&user_shell(), spec);
        std::fs::write(&script_path, &script_content)
            .with_context(|| format!("failed to write wrapper script {}", script_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))?;
        }

        // Create tmux session
        let output = tmux_cmd()
            .args([
                "new-session",
                "-d",
                "-s",
                &session_name,
                "-c",
                &spec.working_dir.to_string_lossy(),
                &script_path.to_string_lossy(),
            ])
            .output()
            .with_context(|| format!("failed to spawn tmux session for {name}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("tmux new-session failed: {stderr}");
        }

        // Set remain-on-exit so session stays for inspection after crash
        let _ = tmux_cmd()
            .args(["set-option", "-t", &session_name, "remain-on-exit", "on"])
            .output();

        // Pipe pane output to log file
        let _ = tmux_cmd()
            .args([
                "pipe-pane",
                "-t",
                &session_name,
                "-o",
                &format!("cat >> {}", log_path.display()),
            ])
            .output();

        debug!(session = %session_name, "spawned tmux session");

        Ok(ProcessHandle::Tmux { session_name })
    }
}

/// Spawn a background task that reads from stdout + stderr pipes, writes each
/// line to a log file, and broadcasts it through `log_tx`.
///
/// Bytes are split on `\n` manually and decoded with lossy UTF-8 so non-UTF-8
/// output (terminal escapes, panic traces with binary bytes) does not
/// terminate the tee. Any trailing bytes not followed by a newline are
/// flushed on EOF so a crash without a final newline does not swallow the
/// last message.
fn spawn_tee_task(
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    log_file: std::fs::File,
    log_tx: broadcast::Sender<LogLine>,
    app_id: i64,
    process_type: &str,
) {
    use std::io::Write;
    use tokio::io::{AsyncRead, AsyncReadExt};

    fn tee_reader<R: AsyncRead + Unpin + Send + 'static>(
        mut reader: R,
        log_file: Arc<std::sync::Mutex<std::fs::File>>,
        log_tx: broadcast::Sender<LogLine>,
        app_id: i64,
        process_type: String,
    ) {
        tokio::spawn(async move {
            // Cap how much un-newline-terminated output we will buffer before
            // forcibly flushing as a synthetic line. Without this a process
            // that emits a very long single line, a `\r`-driven progress bar,
            // or a streaming binary blob would grow `pending` unboundedly and
            // expose Coulson to OOM on noisy child output.
            const PENDING_CAP: usize = 1024 * 1024;

            let mut buf = [0u8; 4096];
            let mut pending: Vec<u8> = Vec::with_capacity(512);
            let emit = |bytes: &[u8],
                        log_file: &Arc<std::sync::Mutex<std::fs::File>>,
                        log_tx: &broadcast::Sender<LogLine>,
                        process_type: &str| {
                let line = String::from_utf8_lossy(bytes).into_owned();
                if let Ok(mut f) = log_file.lock() {
                    let _ = writeln!(f, "{line}");
                }
                let _ = log_tx.send(LogLine {
                    app_id,
                    process_type: process_type.to_string(),
                    line,
                });
            };
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut start = 0;
                        for (i, b) in buf[..n].iter().enumerate() {
                            if *b == b'\n' {
                                let mut chunk = std::mem::take(&mut pending);
                                chunk.extend_from_slice(&buf[start..i]);
                                // Strip trailing CR so CRLF output is clean.
                                if chunk.last() == Some(&b'\r') {
                                    chunk.pop();
                                }
                                emit(&chunk, &log_file, &log_tx, &process_type);
                                start = i + 1;
                            }
                        }
                        if start < n {
                            pending.extend_from_slice(&buf[start..n]);
                        }
                        // If the buffered fragment is already past the cap,
                        // flush it now to bound memory. The synthetic line
                        // may split a "real" line in two, but that is
                        // strictly better than unbounded growth.
                        while pending.len() >= PENDING_CAP {
                            let rest = pending.split_off(PENDING_CAP);
                            emit(&pending, &log_file, &log_tx, &process_type);
                            pending = rest;
                        }
                    }
                    Err(_) => break,
                }
            }
            // Flush any trailing partial line (no terminating newline) so
            // crash tails are preserved.
            if !pending.is_empty() {
                if pending.last() == Some(&b'\r') {
                    pending.pop();
                }
                emit(&pending, &log_file, &log_tx, &process_type);
            }
        });
    }

    let file = Arc::new(std::sync::Mutex::new(log_file));
    let ptype = process_type.to_string();

    if let Some(stdout) = stdout {
        tee_reader(stdout, file.clone(), log_tx.clone(), app_id, ptype.clone());
    }
    if let Some(stderr) = stderr {
        tee_reader(stderr, file, log_tx, app_id, ptype);
    }
}

/// Extract `idle_timeout_secs` from a `.coulson.toml` manifest JSON value.
/// Resolve the directory where a managed app's process logs live.
///
/// Each process writes to `{log_dir}/{process_type}.log` (see
/// [`process_log_path`]). The directory namespaces an app's logs, so the file
/// names carry only the process type — never the app name.
///
/// Priority:
/// 1. manifest `log_dir` — explicit directory (relative paths join the app root)
/// 2. manifest `log_path` — **deprecated**; the parent directory of the given
///    file path is used (a warning is emitted)
/// 3. default `{app_runtime_dir}` (`$RUNTIME/managed/{name}/`)
pub(crate) fn resolve_log_dir(
    manifest: &Option<serde_json::Value>,
    root: &Path,
    app_runtime_dir: &Path,
) -> PathBuf {
    let manifest = manifest.as_ref();
    let resolve_relative = |raw: &str| -> PathBuf {
        let p = Path::new(raw);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            root.join(p)
        }
    };

    if let Some(raw) = manifest
        .and_then(|m| m.get("log_dir"))
        .and_then(|v| v.as_str())
    {
        return resolve_relative(raw);
    }

    if let Some(raw) = manifest
        .and_then(|m| m.get("log_path"))
        .and_then(|v| v.as_str())
    {
        warn!(
            log_path = raw,
            "`log_path` in .coulson.toml is deprecated; use `log_dir` (a directory). \
             Treating the parent directory as the log directory."
        );
        let p = resolve_relative(raw);
        return p.parent().map(Path::to_path_buf).unwrap_or(p);
    }

    app_runtime_dir.to_path_buf()
}

/// Build the log file path for a single process within an app's log directory.
/// The app name lives in `log_dir`, so the file is named purely by process type
/// (`web.log`, `worker.log`, …).
pub(crate) fn process_log_path(log_dir: &Path, process_type: &str) -> PathBuf {
    log_dir.join(format!("{process_type}.log"))
}

fn manifest_idle_timeout(manifest: &Option<serde_json::Value>) -> Option<Duration> {
    manifest
        .as_ref()?
        .get("idle_timeout_secs")?
        .as_u64()
        .map(Duration::from_secs)
}

/// Load `.coulson.toml` from app root and convert to serde_json::Value for providers.
/// Logs errors instead of silently ignoring them.
pub(crate) fn load_coulson_toml_manifest(root: &Path) -> Option<serde_json::Value> {
    let toml_path = root.join(".coulson.toml");
    let raw = match std::fs::read_to_string(&toml_path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::error!(path = %toml_path.display(), %e, "failed to read .coulson.toml");
            return None;
        }
    };
    let table: toml::Value = match toml::from_str(&raw) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(path = %toml_path.display(), %e, "failed to parse .coulson.toml");
            return None;
        }
    };
    match serde_json::to_value(table) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!(path = %toml_path.display(), %e, "failed to convert .coulson.toml to JSON");
            None
        }
    }
}

/// Extract the `[env]` table of a `.coulson.toml` manifest as a map.
fn manifest_env_map(manifest: Option<&serde_json::Value>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(obj) = manifest
        .and_then(|m| m.get("env"))
        .and_then(|v| v.as_object())
    {
        for (k, v) in obj {
            if let Some(val) = v.as_str() {
                out.insert(k.clone(), val.to_string());
            }
        }
    }
    out
}

/// Build the [`LayeredEnv`] for a managed process from all sources, lowest
/// precedence first. `provider_defaults` is the provider's framework env (PORT,
/// PYTHONUNBUFFERED, …) with no user config mixed in.
///
/// Precedence: `provider defaults < .coulson.toml [env] < env_url < .coulsonrc`.
/// `coulsonrc` is the snapshot parsed once at the start of the spawn, passed in
/// so selection decisions and the final env agree on one file read.
///
/// `PORT` is special: it is the contract between the child (bind address) and
/// the port Coulson proxies to (`listen_target`), which the provider chose via
/// `resolve_port` (reading the manifest `port` / `.coulsonrc` / allocation).
/// `resolve_port` never consults `.coulson.toml [env]` or `env_url`, so a `PORT`
/// in those layers would desync the child's `$PORT` from `listen_target` and
/// break routing. It is therefore stripped from those overlay layers; the
/// provider-chosen value (echoed by `.coulsonrc` when set there) stands.
fn build_layered_env(
    provider_defaults: HashMap<String, String>,
    manifest: &Option<serde_json::Value>,
    env_url_env: Option<&HashMap<String, String>>,
    coulsonrc: &HashMap<String, String>,
    root: &Path,
) -> LayeredEnv {
    let mut env = LayeredEnv::default();
    env.push(EnvSource::Provider, provider_defaults);

    let mut toml = manifest_env_map(manifest.as_ref());
    if toml.remove("PORT").is_some() {
        debug!("ignoring PORT in .coulson.toml [env]; PORT is managed by the provider");
    }
    env.push(EnvSource::TomlEnv, toml);

    if let Some(remote) = env_url_env {
        let mut remote = remote.clone();
        if remote.remove("PORT").is_some() {
            debug!("ignoring PORT from env_url; PORT is managed by the provider");
        }
        env.push(EnvSource::EnvUrl, remote);
    }

    env.push(
        EnvSource::Dotenv(root.join(".coulsonrc")),
        coulsonrc.clone(),
    );
    env
}

/// Apply the layered environment onto `spec.env` (merged, with the
/// `COULSON_MANAGED_SERVICES` meta-var stripped) and return the resolved entries
/// (with provenance, meta-var stripped) for storage / inspection. The meta-var
/// selects companion processes and must never reach the child environment.
fn apply_and_capture_env(
    spec: &mut ProcessSpec,
    manifest: &Option<serde_json::Value>,
    env_url_env: Option<&HashMap<String, String>>,
    coulsonrc: &HashMap<String, String>,
    root: &Path,
) -> Vec<EnvEntry> {
    let layered = build_layered_env(
        std::mem::take(&mut spec.env),
        manifest,
        env_url_env,
        coulsonrc,
        root,
    );
    let mut merged = layered.merge();
    merged.remove("COULSON_MANAGED_SERVICES");
    spec.env = merged;

    let mut entries = layered.resolve();
    entries.retain(|e| e.key != "COULSON_MANAGED_SERVICES");
    entries
}

/// Parse environment variables from a response body.
/// JSON (`content_type` contains "json"): `{"KEY": "value", ...}`
/// Otherwise dotenv format: `KEY=value` per line.
fn parse_env_body(body: &str, content_type: &str) -> anyhow::Result<HashMap<String, String>> {
    let mut env = HashMap::new();
    if content_type.contains("json") {
        let obj: serde_json::Value =
            serde_json::from_str(body).context("env_url returned invalid JSON")?;
        if let Some(map) = obj.as_object() {
            for (k, v) in map {
                match v {
                    serde_json::Value::String(s) => {
                        env.insert(k.clone(), s.clone());
                    }
                    other => {
                        env.insert(k.clone(), other.to_string());
                    }
                }
            }
        }
    } else {
        // dotenv body: parse with dotenvy (same engine as `.coulsonrc`).
        for item in dotenvy::from_read_iter(body.as_bytes()) {
            match item {
                Ok((k, v)) => {
                    env.insert(k, v);
                }
                Err(e) => {
                    debug!(error = %e, "skipping invalid dotenv line from env_url");
                }
            }
        }
    }
    Ok(env)
}

/// Fetch environment variables from a remote URL (env_url in .coulson.toml).
/// Supports JSON object `{"KEY": "value"}` and dotenv `KEY=value` formats,
/// auto-detected by Content-Type header.
async fn fetch_env_url(
    url: &str,
    headers: Option<&serde_json::Value>,
) -> anyhow::Result<HashMap<String, String>> {
    let parsed = reqwest::Url::parse(url).context("invalid env_url")?;
    let basic_auth = if !parsed.username().is_empty() || parsed.password().is_some() {
        let user = parsed.username().to_string();
        let pass = parsed.password().map(|p| p.to_string());
        let mut clean = parsed.clone();
        clean.set_username("").ok();
        clean.set_password(None).ok();
        Some((clean, user, pass))
    } else {
        None
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let mut req = if let Some((ref clean_url, ref user, ref pass)) = basic_auth {
        client
            .get(clean_url.as_str())
            .basic_auth(user, pass.as_deref())
    } else {
        client.get(url)
    };
    if let Some(hdrs) = headers.and_then(|v| v.as_object()) {
        for (k, v) in hdrs {
            if let Some(val) = v.as_str() {
                req = req.header(k.as_str(), val);
            }
        }
    }
    let resp = req.send().await.context("failed to fetch env_url")?;
    if !resp.status().is_success() {
        anyhow::bail!("env_url returned {}", resp.status());
    }
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.text().await.context("failed to read env_url body")?;

    parse_env_body(&body, &content_type)
}

/// Strip userinfo (user:pass@) from a URL for safe logging.
fn redact_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut parsed) => {
            if !parsed.username().is_empty() || parsed.password().is_some() {
                parsed.set_username("").ok();
                parsed.set_password(None).ok();
            }
            parsed.to_string()
        }
        Err(_) => {
            // Conservatively strip userinfo even from unparseable URLs
            if let Some(at) = url.find('@') {
                if let Some(scheme_end) = url.find("://") {
                    return format!("{}{}", &url[..scheme_end + 3], &url[at + 1..]);
                }
            }
            url.to_string()
        }
    }
}

/// Pre-fetch environment variables from `env_url` in `.coulson.toml`.
/// Call this OUTSIDE the ProcessManager lock to avoid blocking other operations.
/// Returns `Ok(None)` if no `env_url` is configured, `Ok(Some(...))` on success,
/// or `Err` if `env_url` is configured but the fetch failed.
pub async fn prefetch_env_url(root: &Path) -> anyhow::Result<Option<HashMap<String, String>>> {
    let manifest = match load_coulson_toml_manifest(root) {
        Some(m) => m,
        None => return Ok(None),
    };
    let url = match manifest.get("env_url").and_then(|v| v.as_str()) {
        Some(u) => u,
        None => return Ok(None),
    };
    let safe_url = redact_url(url);
    let env = fetch_env_url(url, manifest.get("env_url_headers"))
        .await
        .with_context(|| format!("failed to fetch env_url {safe_url}"))?;
    debug!(url = %safe_url, count = env.len(), "pre-fetched env from env_url");
    Ok(Some(env))
}

/// True if the app's `.coulson.toml` configures an `env_url`. Cheap manifest
/// read used to decide whether a cold-start without prefetched env must fetch.
fn env_url_configured(root: &Path) -> bool {
    load_coulson_toml_manifest(root)
        .and_then(|m| {
            m.get("env_url")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
        })
        .unwrap_or(false)
}

/// Encapsulates the lock-drop-prefetch-relock dance for starting a managed process.
///
/// If the process is already alive, skips the `env_url` prefetch entirely (hot
/// path). Otherwise drops the PM lock, fetches `env_url`, re-acquires the lock,
/// and calls `ensure_started`.
///
/// The held lock guards the `processes` map but cannot keep the OS process
/// alive, so a process that looked alive when the prefetch was skipped can still
/// exit before `ensure_started` spawns. `ensure_started` therefore signals
/// [`EnsureStarted::NeedsEnvUrl`] instead of cold-starting with `None` when an
/// `env_url` is configured; we then prefetch off-lock and retry. This fully
/// closes the exit race (not just narrows it). Converges in at most two
/// iterations: the signal path leaves no live process, so the retry takes the
/// prefetch branch and `ensure_started` spawns with the remote env.
pub async fn prepare_and_ensure_started(
    pm: &ProcessManagerHandle,
    app_id: i64,
    name: &str,
    root: &Path,
    kind: &str,
) -> anyhow::Result<StartStatus> {
    loop {
        let need_prefetch = {
            let mut guard = pm.lock().await;
            !guard.has_live_process(app_id)
        };
        let env_url_env = if need_prefetch {
            prefetch_env_url(root).await?
        } else {
            None
        };
        let mut guard = pm.lock().await;
        match guard
            .ensure_started(app_id, name, root, kind, env_url_env)
            .await?
        {
            EnsureStarted::Status(status) => return Ok(status),
            EnsureStarted::NeedsEnvUrl => {
                // Process exited after the prefetch was skipped; loop to prefetch
                // env_url off-lock before the cold-start.
                drop(guard);
            }
        }
    }
}

/// Build the full shell command string from a ProcessSpec.
/// Procfile specs have an empty command and a single args element (the raw shell command).
/// ASGI/Node specs have a binary command and separate args.
fn build_full_command(spec: &ProcessSpec) -> String {
    if spec.command.as_os_str().is_empty() {
        // Procfile-style: args[0] is the complete shell command string
        spec.args[0].clone()
    } else {
        // Binary + args: join into a single command line
        let mut parts = vec![shell_escape_path(&spec.command)];
        parts.extend(spec.args.iter().map(|a| shell_escape(a)));
        parts.join(" ")
    }
}

/// Generate a wrapper script for the process. The user shell is taken as an
/// explicit argument so tests can inject a deterministic value without mutating
/// the global `$SHELL` environment variable.
///
/// Env vars are delivered twice: once as outer `export` lines for POSIX-valid
/// keys (inherited by the inner login shell at startup) and once via an
/// `env 'K=V' ...` prefix on the exec'd command. The `env(1)` prefix is what
/// guarantees Coulson-managed values win over rc-file dotenv/mise/direnv
/// overrides, and it works uniformly on fish/tcsh/… as well as bash/zsh. It
/// also carries keys that aren't valid POSIX identifiers, keeping the tmux
/// backend's env set identical to the direct backend (which uses
/// `Command::env()`).
///
/// Note on what the inner shell does **not** preserve: shell functions,
/// aliases, and `setopt`/`shopt` state defined in the user's rc file live in
/// the outer shell process and are lost when we `exec` into a fresh
/// `$SHELL -c '…'`. Only environment variables (set via `env(1)` and the rc
/// file's `export`) and shell **syntax** survive into the final command.
fn generate_wrapper_script(shell: &Path, spec: &ProcessSpec) -> String {
    let mut lines = vec!["#!/usr/bin/env sh".to_string()];

    // Outer-script exports for inheritance into the inner login shell. The
    // outer script is `#!/usr/bin/env sh` (POSIX), so we must skip keys that
    // aren't valid POSIX identifiers or sh would fail to parse the script.
    // Non-POSIX keys are still delivered to the final process via the inner
    // `env(1)` prefix below.
    for (k, v) in &spec.env {
        if !is_valid_env_key(k) {
            continue;
        }
        let escaped = v.replace('\'', "'\\''");
        lines.push(format!("export {k}='{escaped}'"));
    }

    let shell_arg = shell_escape_path(shell);
    let cmd = build_full_command(spec);
    // Inner structure: outer login interactive shell sources rc files, then
    // `env(1)` re-applies Coulson-managed env vars (overriding any rc clobbering),
    // then **exec the same user shell again in `-c` mode** to run the actual
    // command. Routing through the user shell (instead of `sh -c`) preserves
    // bash/zsh/fish-specific *syntax* for Procfile commands (`[[ … ]]`, brace
    // expansion, etc.).
    //
    // The inner shell is invoked with shell-specific "no startup file" flags
    // (zsh `-f`, bash `--noprofile --norc`, etc.) so that startup files like
    // `~/.zshenv` cannot reverse the env vars `env(1)` just injected. For
    // bash specifically, `BASH_ENV` is stripped via `env -u BASH_ENV` because
    // non-interactive bash sources it regardless of `--norc`. As a side
    // effect, shell functions/aliases defined only in the rc file are **not**
    // available inside the final command.
    let inner = build_inner_command(shell, &cmd, &spec.env);
    let escaped_inner = inner.replace('\'', "'\\''");
    lines.push(format!("exec {shell_arg} -li -c '{escaped_inner}'"));

    lines.push(String::new()); // trailing newline
    lines.join("\n")
}

/// Shell-escape a string with single quotes.
fn shell_escape(s: &str) -> String {
    if s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/' || c == ':'
    }) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn shell_escape_path(p: &Path) -> String {
    shell_escape(&p.to_string_lossy())
}

/// Get the user's login shell from `$SHELL`, falling back to `/bin/sh`.
fn user_shell() -> PathBuf {
    std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/bin/sh"))
}

/// Is `key` a valid POSIX environment variable identifier
/// (`[A-Za-z_][A-Za-z0-9_]*`)? Used only to gate outer-script `export` lines,
/// which must follow POSIX shell syntax. Inner env injection uses `env(1)`
/// directly and can carry keys with dashes, dots, etc.
fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Is `key` safe to pass to `env(1)` as part of a `KEY=VAL` argv element?
///
/// Rejected:
/// - empty
/// - contains `=` (would split name/value incorrectly)
/// - contains NUL (invalid in argv)
/// - starts with `-` — `env(1)` parses leading-dash operands as options. On
///   macOS BSD env, `env '-BAD=1' …` errors with `illegal option -- B`. There
///   is no portable end-of-options sentinel (`--` is not in POSIX env), so the
///   only safe rule is to refuse keys that begin with a hyphen.
fn is_env_command_key(key: &str) -> bool {
    !key.is_empty() && !key.contains('=') && !key.contains('\0') && !key.starts_with('-')
}

/// Build an `env [-u BAD ...] 'K1=V1' 'K2=V2' ... ` prefix that sets (and
/// optionally unsets) environment variables for the next exec'd command via
/// the external `env(1)` program. This is the mechanism we use to re-apply
/// Coulson-managed env vars **after** the user's login shell sources its rc
/// files (dotenv, mise, direnv), ensuring our values win regardless of what
/// the rc file did.
///
/// Why `env(1)` instead of POSIX `export KEY='val'`:
/// 1. Works uniformly across shells (bash/zsh/fish/tcsh/…). Non-POSIX shells
///    can't parse `export KEY='val';` but they can all invoke external `env`.
/// 2. Accepts keys that aren't valid POSIX identifiers (e.g. `MY-KEY`), so the
///    tmux wrapper path can transport env keys identically to the direct path,
///    which uses Rust `Command::env()` (which also accepts non-POSIX keys).
/// 3. Supports `-u NAME` to remove inherited variables (used to strip
///    `BASH_ENV` before `bash -c`, since non-interactive bash sources it
///    regardless of `--norc`).
///
/// Keys containing `=`, NUL, or a leading `-` are skipped (those would break
/// `env`'s argv parsing). Returns an empty string when no usable keys remain
/// AND no unset names were requested.
fn build_env_command_prefix(env: &HashMap<String, String>, unset: &[&str]) -> String {
    if env.is_empty() && unset.is_empty() {
        return String::new();
    }
    let mut out = String::from("env");
    let mut produced_anything = false;
    for key in unset {
        out.push_str(&format!(" -u {key}"));
        produced_anything = true;
    }
    for (k, v) in env {
        if !is_env_command_key(k) {
            tracing::warn!(
                key = %k,
                "skipping env key (empty, contains '='/NUL, or leads with '-')"
            );
            continue;
        }
        let kv = format!("{k}={v}");
        let escaped = kv.replace('\'', "'\\''");
        out.push_str(&format!(" '{escaped}'"));
        produced_anything = true;
    }
    if produced_anything {
        out.push(' ');
        out
    } else {
        String::new()
    }
}

/// Returns the per-shell flags that follow the shell binary (before `-c`) to
/// skip startup-file sourcing on the inner non-interactive invocation. The
/// outer login shell already sourced rc files; the inner shell must NOT
/// re-read them, otherwise startup files like `~/.zshenv` (zsh) or
/// `$BASH_ENV` (bash) could re-clobber the env vars `env(1)` just injected.
///
/// - zsh: `-f` (NO_RCS) skips `/etc/zshenv`, `~/.zshenv`, `~/.zshrc`, etc.
/// - bash: `--noprofile --norc` skips `/etc/profile`, `~/.bashrc`, etc.
///   For non-interactive bash, `BASH_ENV` is sourced regardless of `--norc`,
///   so it must additionally be removed via `env -u BASH_ENV` (see
///   `inner_shell_unset_keys`).
/// - csh/tcsh: `-f` skips `~/.cshrc`/`~/.tcshrc`.
/// - fish: `--no-config` skips `config.fish` (fish -c still sources it).
/// - sh/dash/ksh/…: non-interactive `-c` mode does not source per-user
///   files by default, so no flags are needed.
fn inner_shell_no_startup_flags(shell: &Path) -> &'static [&'static str] {
    let name = shell.file_name().and_then(|n| n.to_str()).unwrap_or("");
    match name {
        "zsh" => &["-f"],
        "bash" => &["--noprofile", "--norc"],
        "csh" | "tcsh" => &["-f"],
        "fish" => &["--no-config"],
        _ => &[],
    }
}

/// Returns the env var names that must be removed from the inherited
/// environment before launching the inner shell, to prevent late-stage
/// startup-file sourcing from clobbering Coulson-managed env vars.
///
/// Currently only `bash` needs this: non-interactive bash sources `$BASH_ENV`
/// even when invoked with `--noprofile --norc`, so the variable must be
/// stripped via `env -u BASH_ENV`.
fn inner_shell_unset_keys(shell: &Path) -> &'static [&'static str] {
    let name = shell.file_name().and_then(|n| n.to_str()).unwrap_or("");
    match name {
        "bash" => &["BASH_ENV"],
        _ => &[],
    }
}

/// Build the `exec [env -u BAD ... 'K=V' ...] {shell} [--no-startup-flags] -c '{cmd}'`
/// inner-command string used by both the wrapper-script (tmux) path and the
/// direct-spawn (login_shell_args) path. The result is **the** point where
/// Coulson-managed env vars are re-asserted and the inner shell is locked
/// down so its own startup files cannot reverse the assertion.
fn build_inner_command(shell: &Path, cmd: &str, env: &HashMap<String, String>) -> String {
    let shell_arg = shell_escape_path(shell);
    let escaped_cmd = cmd.replace('\'', "'\\''");
    let unset = inner_shell_unset_keys(shell);
    let env_prefix = build_env_command_prefix(env, unset);
    let no_startup = inner_shell_no_startup_flags(shell);

    let mut head = format!("exec {env_prefix}{shell_arg}");
    for flag in no_startup {
        head.push(' ');
        head.push_str(flag);
    }
    format!("{head} -c '{escaped_cmd}'")
}

/// Build login-shell arguments that source the interactive RC file, then
/// use `env(1)` to re-apply Coulson-managed env vars and execute `cmd` via
/// the **same user shell** in non-interactive mode. Used by the Direct backend.
/// The shell is taken as an explicit argument so tests can inject a value
/// without mutating the global `$SHELL` env var.
///
/// Why two layers of the user shell:
/// - Outer `$SHELL -l -c` is a login shell that sources the user's rc file
///   (mise/direnv/dotenv), which is necessary for tooling that depends on
///   PATH munging or venv activation.
/// - The inner `$SHELL [--no-startup-flags] -c` runs the actual command with
///   full user-shell *syntax* (bash/zsh/fish features like `[[ … ]]`, brace
///   expansion). Routing the final command through `sh -c` would silently
///   downgrade Procfile commands to POSIX-only semantics.
/// - Between the two layers, `env(1)` re-asserts Coulson-managed env vars so
///   they win against rc-file overrides. The inner shell is launched with
///   shell-specific "no startup file" flags (e.g. `zsh -f`,
///   `bash --noprofile --norc`) so that startup files such as `~/.zshenv`
///   or `$BASH_ENV` cannot run a second time and reverse the env injection.
///
/// Caveat: shell functions and aliases defined only in the user's rc file
/// live in the outer shell process and are **not** available inside the final
/// command, since the inner `$SHELL -c` is a fresh shell process.
fn login_shell_args(shell: &Path, cmd: &str, env: &HashMap<String, String>) -> Vec<String> {
    let name = shell.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let inner = build_inner_command(shell, cmd, env);
    let full_cmd = match name {
        "zsh" => format!(". ~/.zshrc 2>/dev/null; {inner}"),
        "bash" => format!(". ~/.bashrc 2>/dev/null; {inner}"),
        _ => inner,
    };
    vec!["-l".to_string(), "-c".to_string(), full_cmd]
}

/// Extract pid, alive status, and backend name from a process handle.
fn handle_status(handle: &mut ProcessHandle) -> (u32, bool, &'static str) {
    match handle {
        ProcessHandle::Direct { child } => {
            let pid = child.id().unwrap_or(0);
            let alive = matches!(child.try_wait(), Ok(None));
            (pid, alive, "direct")
        }
        ProcessHandle::Tmux { session_name } => {
            let pid = tmux_pane_pid(session_name).unwrap_or(0);
            let alive = if pid != 0 {
                tmux_pane_alive(session_name)
            } else {
                false
            };
            (pid, alive, "tmux")
        }
        ProcessHandle::Compose {
            project_dir,
            project_name,
            compose_file,
            ..
        } => {
            let pid = compose_leader_pid(project_dir, project_name, compose_file).unwrap_or(0);
            let alive = if pid != 0 {
                compose_is_running(project_dir, project_name, compose_file)
            } else {
                false
            };
            (pid, alive, "compose")
        }
    }
}

/// Check whether the process handle is still alive.
fn is_alive(handle: &mut ProcessHandle) -> bool {
    match handle {
        ProcessHandle::Direct { child } => matches!(child.try_wait(), Ok(None)),
        ProcessHandle::Tmux { session_name } => {
            tmux_has_session(session_name) && tmux_pane_alive(session_name)
        }
        ProcessHandle::Compose {
            project_dir,
            project_name,
            compose_file,
            ..
        } => compose_is_running(project_dir, project_name, compose_file),
    }
}

/// Kill a process handle.
async fn kill_handle(handle: ProcessHandle) {
    match handle {
        ProcessHandle::Direct { mut child } => {
            kill_process_group(&mut child).await;
        }
        ProcessHandle::Tmux { session_name } => {
            // SIGTERM the pane process first, then kill the session
            if let Some(pid) = tmux_pane_pid(&session_name) {
                let pgid = pid as i32;
                unsafe { libc::kill(-pgid, libc::SIGTERM) };
                const GRACE_MS: u64 = 500;
                tokio::time::sleep(Duration::from_millis(GRACE_MS)).await;
                // Force kill if still alive
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
            }
            tmux_kill_session(&session_name);
        }
        ProcessHandle::Compose {
            project_dir,
            project_name,
            compose_file,
            mut log_follower,
        } => {
            // Kill the log follower first
            if let Some(ref mut child) = log_follower {
                let _ = child.kill().await;
            }
            compose_down(&project_dir, &project_name, &compose_file).await;
        }
    }
}

// Docker Compose helper functions

/// Build the common prefix args for all `docker compose` invocations.
fn compose_base_args<'a>(project_name: &'a str, compose_file: &'a str) -> Vec<&'a str> {
    vec!["compose", "-f", compose_file, "-p", project_name]
}

/// Check if any compose service containers are running.
fn compose_is_running(project_dir: &Path, project_name: &str, compose_file: &str) -> bool {
    let mut args = compose_base_args(project_name, compose_file);
    args.extend(["ps", "--format", "json", "--status", "running"]);
    let output = std::process::Command::new("docker")
        .args(&args)
        .current_dir(project_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            !text.trim().is_empty()
        }
        Err(_) => false,
    }
}

/// Spawn a `docker compose logs -f` process that tees output to a log file
/// and broadcasts lines through `log_tx`.
fn spawn_compose_log_follower(
    project_dir: &Path,
    project_name: &str,
    compose_file: &str,
    log_path: &Path,
    log_tx: &broadcast::Sender<LogLine>,
    app_id: i64,
) -> Option<Child> {
    let log_file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        Ok(f) => f,
        Err(e) => {
            warn!(path = %log_path.display(), error = %e, "failed to open compose log file");
            return None;
        }
    };

    let mut args = compose_base_args(project_name, compose_file);
    args.extend(["logs", "-f", "--no-color"]);
    match Command::new("docker")
        .args(&args)
        .current_dir(project_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(mut child) => {
            debug!(project = project_name, "spawned compose log follower");
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            spawn_tee_task(stdout, stderr, log_file, log_tx.clone(), app_id, "web");
            Some(child)
        }
        Err(e) => {
            warn!(project = project_name, error = %e, "failed to spawn compose log follower");
            None
        }
    }
}

/// Get the PID of the first running container's leader process.
fn compose_leader_pid(project_dir: &Path, project_name: &str, compose_file: &str) -> Option<u32> {
    let mut args = compose_base_args(project_name, compose_file);
    args.extend(["ps", "--format", "json", "--status", "running"]);
    let output = std::process::Command::new("docker")
        .args(&args)
        .current_dir(project_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    // `docker compose ps --format json` outputs one JSON object per line
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) {
            // The "ID" field is the container ID; get PID via `docker inspect`
            if let Some(container_id) = obj.get("ID").and_then(|v| v.as_str()) {
                if let Ok(inspect_out) = std::process::Command::new("docker")
                    .args(["inspect", "--format", "{{.State.Pid}}", container_id])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .output()
                {
                    if let Ok(pid) = String::from_utf8_lossy(&inspect_out.stdout)
                        .trim()
                        .parse::<u32>()
                    {
                        if pid > 0 {
                            return Some(pid);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Run `docker compose down` to stop and remove containers.
async fn compose_down(project_dir: &Path, project_name: &str, compose_file: &str) {
    let dir = project_dir.to_path_buf();
    let name = project_name.to_string();
    let cf = compose_file.to_string();
    let result = tokio::task::spawn_blocking(move || {
        let mut args = compose_base_args(&name, &cf);
        args.push("down");
        std::process::Command::new("docker")
            .args(&args)
            .current_dir(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
    })
    .await;
    match result {
        Ok(Ok(output)) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("docker compose down failed: {stderr}");
            }
        }
        Ok(Err(e)) => warn!("failed to run docker compose down: {e}"),
        Err(e) => warn!("docker compose down task panicked: {e}"),
    }
}

// tmux helper functions

/// Check if tmux is available in PATH.
pub fn tmux_available() -> bool {
    std::process::Command::new("tmux")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Build a tmux command with the dedicated socket.
fn tmux_cmd() -> std::process::Command {
    let mut cmd = std::process::Command::new("tmux");
    cmd.args(["-L", TMUX_SOCKET]);
    cmd
}

/// Check if a tmux session exists.
fn tmux_has_session(name: &str) -> bool {
    tmux_cmd()
        .args(["has-session", "-t", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Check if the pane process in a tmux session is still alive.
/// With `remain-on-exit on`, the session persists after the pane process exits.
fn tmux_pane_alive(name: &str) -> bool {
    let output = tmux_cmd()
        .args(["list-panes", "-t", name, "-F", "#{pane_dead}"])
        .output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            // pane_dead is "0" if alive, "1" if dead
            text.trim() == "0"
        }
        Err(_) => false,
    }
}

/// Get the PID of the process running in a tmux session's pane.
fn tmux_pane_pid(name: &str) -> Option<u32> {
    let output = tmux_cmd()
        .args(["list-panes", "-t", name, "-F", "#{pane_pid}"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.trim().parse().ok()
}

/// Kill a tmux session.
fn tmux_kill_session(name: &str) {
    let _ = tmux_cmd()
        .args(["kill-session", "-t", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Log the last few lines of a managed process log file on startup failure.
fn log_tail(log_path: &Path, name: &str) {
    const TAIL_LINES: usize = 10;
    if let Ok(content) = std::fs::read_to_string(log_path) {
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(TAIL_LINES);
        let tail = lines[start..].join("\n");
        if !tail.trim().is_empty() {
            warn!(
                app = name,
                log = %log_path.display(),
                "\n--- process log tail ---\n{tail}\n---"
            );
        }
    }
}

/// Clean up resources associated with a listen target.
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
/// Whether `s` is a safe process_type token.
///
/// process_type flows into several sensitive contexts: the log file path
/// (`{ptype}.log`), the Procfile lookup key, and URL path segments in
/// the log streaming endpoints. Restricting it to `[A-Za-z0-9_-]+` (the
/// de-facto Procfile convention) closes off path-traversal, URL-reserved
/// characters, and shell metacharacter surprises in one pass.
pub(crate) fn is_valid_process_type(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Look up `COULSON_MANAGED_SERVICES` (the companion-process selector) with
/// the same layer stack as the child env, so `.coulsonrc` overrides
/// `.coulson.toml [env]` here exactly as it does for every other variable.
/// `env_url` is not a layer: companions are selected before the remote env is
/// fetched.
fn lookup_managed_services(
    env_overrides: &HashMap<String, String>,
    manifest: Option<&serde_json::Value>,
) -> Option<String> {
    let mut env = LayeredEnv::default();
    env.push(EnvSource::TomlEnv, manifest_env_map(manifest));
    env.push(
        EnvSource::Dotenv(PathBuf::from(".coulsonrc")),
        env_overrides.clone(),
    );
    env.get("COULSON_MANAGED_SERVICES").map(str::to_string)
}

/// Parse `COULSON_MANAGED_SERVICES` value into companion process types (excluding "web").
fn parse_managed_services(value: Option<&str>) -> Vec<String> {
    value
        .map(|s| {
            s.split(',')
                .filter_map(|t| {
                    let t = t.trim();
                    if t.is_empty() || t == "web" {
                        return None;
                    }
                    if !is_valid_process_type(t) {
                        tracing::warn!(
                            process_type = %t,
                            "COULSON_MANAGED_SERVICES token rejected: must match [A-Za-z0-9_-]+"
                        );
                        return None;
                    }
                    Some(t.to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

fn listen_target_display(target: &ListenTarget) -> String {
    match target {
        ListenTarget::Uds(path) => path.to_string_lossy().to_string(),
        ListenTarget::Tcp { host, port } => format!("{host}:{port}"),
    }
}

/// Kill an entire process group: SIGTERM first, then SIGKILL after a grace period.
async fn kill_process_group(child: &mut Child) {
    let Some(pid) = child.id() else {
        return;
    };
    let pgid = pid as i32;

    let ret = unsafe { libc::kill(-pgid, libc::SIGTERM) };
    if ret != 0 {
        let _ = child.start_kill();
        return;
    }

    const GRACE_MS: u64 = 500;
    tokio::time::sleep(Duration::from_millis(GRACE_MS)).await;

    match child.try_wait() {
        Ok(None) => {
            let ret = unsafe { libc::kill(-pgid, libc::SIGKILL) };
            if ret != 0 {
                warn!(pid, "SIGKILL to process group failed, trying direct kill");
                let _ = child.start_kill();
            }
        }
        Ok(Some(_)) => {
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
        Err(e) => {
            warn!(pid, error = %e, "failed to check process status, skipping group kill");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_managed_services_with_companions() {
        let result = parse_managed_services(Some("web,worker, release "));
        assert_eq!(result, vec!["worker", "release"]);
    }

    #[test]
    fn parse_managed_services_web_only() {
        let result = parse_managed_services(Some("web"));
        assert!(result.is_empty());
    }

    #[test]
    fn parse_managed_services_empty_string() {
        let result = parse_managed_services(Some(""));
        assert!(result.is_empty());
    }

    #[test]
    fn parse_managed_services_none() {
        let result = parse_managed_services(None);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_managed_services_no_web() {
        let result = parse_managed_services(Some("worker,scheduler"));
        assert_eq!(result, vec!["worker", "scheduler"]);
    }

    // -- lookup_managed_services (env source resolution) --

    #[test]
    fn lookup_managed_services_coulsonrc_wins_over_toml() {
        let mut dotenv = HashMap::new();
        dotenv.insert("COULSON_MANAGED_SERVICES".to_string(), "worker".to_string());
        let manifest = serde_json::json!({
            "env": { "COULSON_MANAGED_SERVICES": "worker,scheduler" }
        });
        let got = lookup_managed_services(&dotenv, Some(&manifest));
        assert_eq!(got.as_deref(), Some("worker"));
    }

    #[test]
    fn lookup_managed_services_falls_back_to_dotenv_when_toml_absent() {
        let mut dotenv = HashMap::new();
        dotenv.insert("COULSON_MANAGED_SERVICES".to_string(), "worker".to_string());
        let manifest = serde_json::json!({ "kind": "procfile" });
        let got = lookup_managed_services(&dotenv, Some(&manifest));
        assert_eq!(got.as_deref(), Some("worker"));
    }

    #[test]
    fn lookup_managed_services_reads_toml_only() {
        let manifest = serde_json::json!({
            "env": { "COULSON_MANAGED_SERVICES": "worker" }
        });
        let got = lookup_managed_services(&HashMap::new(), Some(&manifest));
        assert_eq!(got.as_deref(), Some("worker"));
    }

    #[test]
    fn lookup_managed_services_none_when_unset() {
        assert!(lookup_managed_services(&HashMap::new(), None).is_none());
    }

    // -- env body parsing --

    #[test]
    fn parse_env_body_json() {
        let body = r#"{"DB_URL": "postgres://localhost/db", "PORT": "5000"}"#;
        let env = parse_env_body(body, "application/json").unwrap();
        assert_eq!(env.get("DB_URL").unwrap(), "postgres://localhost/db");
        assert_eq!(env.get("PORT").unwrap(), "5000");
    }

    #[test]
    fn parse_env_body_json_non_string_values() {
        let body = r#"{"COUNT": 42, "ENABLED": true}"#;
        let env = parse_env_body(body, "application/json").unwrap();
        assert_eq!(env.get("COUNT").unwrap(), "42");
        assert_eq!(env.get("ENABLED").unwrap(), "true");
    }

    #[test]
    fn parse_env_body_json_empty_object() {
        let env = parse_env_body("{}", "application/json").unwrap();
        assert!(env.is_empty());
    }

    #[test]
    fn parse_env_body_json_invalid() {
        let result = parse_env_body("not json", "application/json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_env_body_dotenv() {
        let body = "DB_URL=postgres://localhost/db\nPORT=5000\n";
        let env = parse_env_body(body, "text/plain").unwrap();
        assert_eq!(env.get("DB_URL").unwrap(), "postgres://localhost/db");
        assert_eq!(env.get("PORT").unwrap(), "5000");
    }

    #[test]
    fn parse_env_body_dotenv_with_quotes() {
        let body = "SECRET=\"my secret\"\nKEY='value'\n";
        let env = parse_env_body(body, "text/plain").unwrap();
        assert_eq!(env.get("SECRET").unwrap(), "my secret");
        assert_eq!(env.get("KEY").unwrap(), "value");
    }

    #[test]
    fn parse_env_body_dotenv_with_export() {
        let body = "export DB=postgres\nexport PORT=3000\n";
        let env = parse_env_body(body, "text/plain").unwrap();
        assert_eq!(env.get("DB").unwrap(), "postgres");
        assert_eq!(env.get("PORT").unwrap(), "3000");
    }

    #[test]
    fn parse_env_body_dotenv_comments_and_blanks() {
        let body = "# comment\n\nKEY=value\n  # another comment\n";
        let env = parse_env_body(body, "text/plain").unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env.get("KEY").unwrap(), "value");
    }

    #[test]
    fn parse_env_body_dotenv_empty() {
        let env = parse_env_body("", "text/plain").unwrap();
        assert!(env.is_empty());
    }

    // -- env key validation and env(1) prefix safety --

    #[test]
    fn is_valid_env_key_accepts_posix_identifiers() {
        assert!(is_valid_env_key("PATH"));
        assert!(is_valid_env_key("DB_URL"));
        assert!(is_valid_env_key("_PRIVATE"));
        assert!(is_valid_env_key("A1_B2"));
    }

    #[test]
    fn is_valid_env_key_rejects_bad_keys() {
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("1LEADING_DIGIT"));
        assert!(!is_valid_env_key("MY-KEY"));
        assert!(!is_valid_env_key("MY.KEY"));
        assert!(!is_valid_env_key("KEY WITH SPACE"));
        assert!(!is_valid_env_key("K$(whoami)"));
        assert!(!is_valid_env_key("K;rm -rf /"));
    }

    #[test]
    fn is_env_command_key_accepts_non_posix_but_argv_safe() {
        // Anything that `env(1)` and Rust `Command::env` will accept:
        // no `=`, no NUL, no leading `-`, non-empty.
        assert!(is_env_command_key("PATH"));
        assert!(is_env_command_key("MY-KEY"));
        assert!(is_env_command_key("MY.KEY"));
        assert!(is_env_command_key("1STARTS_WITH_DIGIT"));
        assert!(is_env_command_key("key with space"));
    }

    #[test]
    fn is_env_command_key_rejects_unsafe() {
        assert!(!is_env_command_key(""));
        assert!(!is_env_command_key("BAD=KEY"));
        assert!(!is_env_command_key("FOO\0BAR"));
        // Leading `-` is parsed by `env(1)` as an option (BSD env on macOS:
        // `illegal option -- B` for `-BAD=1`).
        assert!(!is_env_command_key("-BAD"));
        assert!(!is_env_command_key("-i"));
        assert!(!is_env_command_key("--long"));
    }

    #[test]
    fn build_env_command_prefix_carries_non_posix_keys() {
        let mut env = HashMap::new();
        env.insert("GOOD".to_string(), "value".to_string());
        env.insert("MY-KEY".to_string(), "dash-ok".to_string());
        let out = build_env_command_prefix(&env, &[]);
        assert!(out.starts_with("env "));
        assert!(out.contains("'GOOD=value'"));
        assert!(out.contains("'MY-KEY=dash-ok'"));
    }

    #[test]
    fn build_env_command_prefix_skips_unsafe_keys() {
        let mut env = HashMap::new();
        env.insert("GOOD".to_string(), "ok".to_string());
        env.insert("BAD=KEY".to_string(), "evil".to_string());
        env.insert("NUL\0KEY".to_string(), "evil".to_string());
        env.insert("-DASH".to_string(), "evil".to_string());
        let out = build_env_command_prefix(&env, &[]);
        assert!(out.contains("'GOOD=ok'"));
        assert!(!out.contains("BAD=KEY"));
        assert!(!out.contains("NUL"));
        // Leading-dash key would make `env(1)` exit with `illegal option`.
        assert!(!out.contains("-DASH"));
    }

    #[test]
    fn build_env_command_prefix_escapes_single_quotes_in_value() {
        let mut env = HashMap::new();
        env.insert("K".to_string(), "it's".to_string());
        let out = build_env_command_prefix(&env, &[]);
        // Single quote in value is escaped via '\'' (close, literal-quote, reopen).
        assert_eq!(out, "env 'K=it'\\''s' ");
    }

    #[test]
    fn build_env_command_prefix_empty_input() {
        let env = HashMap::new();
        assert_eq!(build_env_command_prefix(&env, &[]), "");
    }

    #[test]
    fn build_env_command_prefix_all_keys_unsafe_returns_empty() {
        let mut env = HashMap::new();
        env.insert("BAD=KEY".to_string(), "x".to_string());
        env.insert("-DASH".to_string(), "x".to_string());
        assert_eq!(build_env_command_prefix(&env, &[]), "");
    }

    #[test]
    fn build_env_command_prefix_emits_unset_only() {
        // When no env vars are passed but unset names are, we still need to
        // emit `env -u NAME ` so callers (e.g. bash path) can strip BASH_ENV.
        let env = HashMap::new();
        let out = build_env_command_prefix(&env, &["BASH_ENV"]);
        assert_eq!(out, "env -u BASH_ENV ");
    }

    #[test]
    fn build_env_command_prefix_combines_unset_and_set() {
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "5000".to_string());
        let out = build_env_command_prefix(&env, &["BASH_ENV"]);
        // `-u` flags must precede `KEY=VAL` operands so env(1) parses them
        // as options before walking the operand list.
        assert!(out.starts_with("env -u BASH_ENV "));
        assert!(out.contains("'PORT=5000'"));
        assert!(out.ends_with(' '));
    }

    // -- per-shell startup-file lockdown --

    #[test]
    fn inner_shell_no_startup_flags_zsh_uses_no_rcs() {
        // `zsh -f` sets NO_RCS, which skips /etc/zshenv, ~/.zshenv, ~/.zshrc.
        // This is the only way to prevent ~/.zshenv from re-clobbering env vars
        // that env(1) just injected, since .zshenv is read on every zsh start.
        assert_eq!(
            inner_shell_no_startup_flags(&PathBuf::from("/bin/zsh")),
            &["-f"]
        );
        assert_eq!(
            inner_shell_unset_keys(&PathBuf::from("/bin/zsh")),
            &[] as &[&str]
        );
    }

    #[test]
    fn inner_shell_no_startup_flags_bash_uses_norc_and_unsets_bash_env() {
        // bash --noprofile --norc skips per-user rc files, but non-interactive
        // bash *still* sources $BASH_ENV regardless of --norc. The only way to
        // prevent that is to remove BASH_ENV from the environment via
        // `env -u BASH_ENV` before invoking bash.
        assert_eq!(
            inner_shell_no_startup_flags(&PathBuf::from("/bin/bash")),
            &["--noprofile", "--norc"]
        );
        assert_eq!(
            inner_shell_unset_keys(&PathBuf::from("/bin/bash")),
            &["BASH_ENV"]
        );
    }

    #[test]
    fn inner_shell_no_startup_flags_csh_family_uses_dash_f() {
        assert_eq!(
            inner_shell_no_startup_flags(&PathBuf::from("/bin/tcsh")),
            &["-f"]
        );
        assert_eq!(
            inner_shell_no_startup_flags(&PathBuf::from("/bin/csh")),
            &["-f"]
        );
    }

    #[test]
    fn inner_shell_no_startup_flags_default_shells_get_no_flags() {
        // sh/dash/ksh in non-interactive `-c` mode do not source per-user
        // startup files by default, so no extra flags are needed.
        let no_flags: &[&str] = &[];
        assert_eq!(
            inner_shell_no_startup_flags(&PathBuf::from("/bin/sh")),
            no_flags
        );
        assert_eq!(
            inner_shell_no_startup_flags(&PathBuf::from("/bin/dash")),
            no_flags
        );
    }

    #[test]
    fn inner_shell_no_startup_flags_fish_uses_no_config() {
        // fish -c *does* source config.fish, so --no-config is needed to
        // prevent user config from clobbering Coulson-injected env vars.
        assert_eq!(
            inner_shell_no_startup_flags(&PathBuf::from("/usr/local/bin/fish")),
            &["--no-config"]
        );
    }

    #[test]
    fn build_inner_command_zsh_skips_zshenv() {
        // zsh inner must use `-f` so .zshenv cannot re-export PORT=9999
        // and clobber the env-injected PORT=5000.
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "5000".to_string());
        let inner = build_inner_command(&PathBuf::from("/bin/zsh"), "echo $PORT", &env);
        assert!(
            inner.contains("/bin/zsh -f -c"),
            "zsh inner must use -f flag, got: {inner}"
        );
        assert!(
            inner.contains("'PORT=5000'"),
            "Coulson env must still be re-applied via env(1), got: {inner}"
        );
        assert!(inner.starts_with("exec env "));
    }

    #[test]
    fn build_inner_command_bash_unsets_bash_env_and_uses_norc() {
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "5000".to_string());
        let inner = build_inner_command(&PathBuf::from("/bin/bash"), "echo $PORT", &env);
        // env -u BASH_ENV must come BEFORE the KEY=VAL operands.
        assert!(
            inner.starts_with("exec env -u BASH_ENV "),
            "bash inner must strip BASH_ENV first, got: {inner}"
        );
        assert!(
            inner.contains("/bin/bash --noprofile --norc -c"),
            "bash inner must use --noprofile --norc, got: {inner}"
        );
        assert!(inner.contains("'PORT=5000'"));
    }

    #[test]
    fn build_inner_command_bash_strips_bash_env_even_without_coulson_env() {
        // Even when there's no Coulson env to inject, we still need to
        // remove BASH_ENV so the inner bash cannot source an attacker-pointed
        // file. The env(1) call must remain.
        let env = HashMap::new();
        let inner = build_inner_command(&PathBuf::from("/bin/bash"), "echo hi", &env);
        assert!(
            inner.starts_with("exec env -u BASH_ENV /bin/bash --noprofile --norc -c"),
            "bash with no env must still env -u BASH_ENV, got: {inner}"
        );
    }

    #[test]
    fn build_inner_command_sh_no_env_no_extra_invocation() {
        // For sh / dash / unknown shells with no env, the inner reduces to
        // a plain `exec {shell} -c '{cmd}'` — no env(1), no extra flags,
        // and no spurious double spaces.
        let env = HashMap::new();
        let inner = build_inner_command(&PathBuf::from("/bin/sh"), "echo hi", &env);
        assert_eq!(inner, "exec /bin/sh -c 'echo hi'");
    }

    #[test]
    fn build_inner_command_fish_uses_no_config() {
        // fish -c reads config.fish which can clobber env vars, so
        // --no-config is required to lock down the inner shell.
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "5000".to_string());
        let inner = build_inner_command(&PathBuf::from("/usr/local/bin/fish"), "echo $PORT", &env);
        assert!(
            inner.contains("/usr/local/bin/fish --no-config -c"),
            "fish inner must use --no-config flag, got: {inner}"
        );
        assert!(inner.contains("'PORT=5000'"));
    }

    // -- wrapper script: must run final command via user shell, not /bin/sh --

    #[test]
    fn wrapper_script_runs_final_command_via_user_shell() {
        use crate::process::provider::ListenTarget;
        // Inject the shell explicitly — no global env mutation, so the test
        // is safe to run in parallel with anything that touches `$SHELL`.
        let shell = PathBuf::from("/bin/zsh");
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "5000".to_string());
        let spec = ProcessSpec {
            command: PathBuf::new(), // Procfile-style: empty command
            args: vec!["bundle exec rails server -p $PORT".to_string()],
            env,
            working_dir: PathBuf::from("/tmp"),
            listen_target: ListenTarget::Tcp {
                host: "127.0.0.1".to_string(),
                port: 5000,
            },
        };
        let script = generate_wrapper_script(&shell, &spec);

        // The inner command must be exec'd through the user shell
        // (`/bin/zsh -f -c '…'`), NOT through `sh -c '…'` — otherwise
        // bash/zsh-only syntax in Procfile commands would silently break.
        // The `-f` flag is required so .zshenv cannot reverse env injection.
        assert!(
            script.contains("/bin/zsh -f -c"),
            "wrapper should exec via user shell with -f, got:\n{script}"
        );
        assert!(
            !script.contains(" sh -c "),
            "wrapper must not downgrade to sh -c, got:\n{script}"
        );
        // env(1) prefix must still be present so the login shell's rc files
        // (~/.zshrc etc.) cannot override the injected spec env. (This is the
        // shell rc layer, unrelated to `.coulsonrc` precedence.)
        assert!(
            script.contains("env '"),
            "wrapper should re-apply env via env(1), got:\n{script}"
        );
    }

    #[test]
    fn finalize_managed_env_precedence_and_strips_managed_services() {
        use crate::process::provider::ListenTarget;
        let dir =
            std::env::temp_dir().join(format!("coulson-test-finalize-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".coulsonrc"),
            "RC_WINS=from_rc\nCOULSON_MANAGED_SERVICES=worker\nONLY_RC=r\n",
        )
        .unwrap();

        // `.coulson.toml [env]` carries some keys; `env_url` and `.coulsonrc`
        // override subsets so each precedence edge is exercised.
        let manifest = Some(serde_json::json!({
            "env": {
                "RC_WINS": "from_toml",
                "URL_WINS": "from_toml",
                "ONLY_TOML": "t",
            }
        }));
        let mut url = HashMap::new();
        url.insert("URL_WINS".to_string(), "from_url".to_string());
        url.insert("ONLY_URL".to_string(), "u".to_string());

        // Provider seed: defaults + early low-priority `.coulsonrc` copy.
        let mut env = HashMap::new();
        env.insert("ONLY_PROVIDER".to_string(), "p".to_string());
        let mut spec = ProcessSpec {
            command: PathBuf::new(),
            args: vec![],
            env,
            working_dir: PathBuf::from("/tmp"),
            listen_target: ListenTarget::Tcp {
                host: String::new(),
                port: 0,
            },
        };

        let coulsonrc = crate::process::provider::load_coulsonrc(&dir);
        let entries = apply_and_capture_env(&mut spec, &manifest, Some(&url), &coulsonrc, &dir);

        // --- merged child env: precedence + survival + strip ---
        // `.coulsonrc` (manual local override) beats both toml and env_url.
        assert_eq!(spec.env.get("RC_WINS").map(String::as_str), Some("from_rc"));
        // env_url beats `.coulson.toml [env]`.
        assert_eq!(
            spec.env.get("URL_WINS").map(String::as_str),
            Some("from_url")
        );
        // Each unique key from every layer survives.
        assert_eq!(spec.env.get("ONLY_TOML").map(String::as_str), Some("t"));
        assert_eq!(spec.env.get("ONLY_URL").map(String::as_str), Some("u"));
        assert_eq!(spec.env.get("ONLY_RC").map(String::as_str), Some("r"));
        assert_eq!(spec.env.get("ONLY_PROVIDER").map(String::as_str), Some("p"));
        // The managed-services meta-var must never leak into the child env.
        assert!(!spec.env.contains_key("COULSON_MANAGED_SERVICES"));

        // --- captured provenance: winning source per key, meta-var excluded ---
        let kind = |k: &str| entries.iter().find(|e| e.key == k).map(|e| e.source.kind());
        assert_eq!(kind("RC_WINS"), Some("dotenv"));
        assert_eq!(kind("URL_WINS"), Some("env_url"));
        assert_eq!(kind("ONLY_TOML"), Some("toml"));
        assert_eq!(kind("ONLY_PROVIDER"), Some("provider"));
        assert!(kind("COULSON_MANAGED_SERVICES").is_none());
        // The dotenv source carries the concrete file.
        let rc = entries.iter().find(|e| e.key == "RC_WINS").unwrap();
        assert!(matches!(&rc.source, EnvSource::Dotenv(p) if p.ends_with(".coulsonrc")));
        // Ordered by source precedence (low → high), key within tier.
        let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "ONLY_PROVIDER",
                "ONLY_TOML",
                "ONLY_URL",
                "URL_WINS",
                "ONLY_RC",
                "RC_WINS"
            ]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn layered_env_merge_and_resolve() {
        let mut env = LayeredEnv::default();
        env.push(
            EnvSource::Provider,
            HashMap::from([("A".into(), "prov".into()), ("PORT".into(), "1".into())]),
        );
        env.push(
            EnvSource::TomlEnv,
            HashMap::from([("A".into(), "toml".into()), ("B".into(), "toml".into())]),
        );
        env.push(
            EnvSource::EnvUrl,
            HashMap::from([("B".into(), "url".into()), ("C".into(), "url".into())]),
        );
        env.push(
            EnvSource::Dotenv(PathBuf::from("/app/.coulsonrc")),
            HashMap::from([("A".into(), "rc".into()), ("D".into(), "rc".into())]),
        );

        // merge: higher layers win.
        let merged = env.merge();
        assert_eq!(merged.get("A").map(String::as_str), Some("rc")); // dotenv top
        assert_eq!(merged.get("B").map(String::as_str), Some("url")); // env_url > toml
        assert_eq!(merged.get("C").map(String::as_str), Some("url"));
        assert_eq!(merged.get("D").map(String::as_str), Some("rc"));
        assert_eq!(merged.get("PORT").map(String::as_str), Some("1")); // provider-only

        // resolve: same fold, tagged with the winning source; sorted by key.
        let resolved = env.resolve();
        let kind = |k: &str| {
            resolved
                .iter()
                .find(|e| e.key == k)
                .map(|e| e.source.kind())
        };
        assert_eq!(kind("A"), Some("dotenv"));
        assert_eq!(kind("B"), Some("env_url"));
        assert_eq!(kind("C"), Some("env_url"));
        assert_eq!(kind("PORT"), Some("provider"));
        // Ordered by source precedence (low → high), key within tier:
        // provider(PORT) < env_url(B,C) < dotenv(A,D).
        let keys: Vec<&str> = resolved.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, vec!["PORT", "B", "C", "A", "D"]);
    }

    #[test]
    fn port_is_reserved_from_toml_and_env_url() {
        // PORT is the provider/listen_target contract; toml [env] and env_url
        // must not be able to override it (resolve_port never reads them).
        let provider = HashMap::from([("PORT".to_string(), "PROVIDER".to_string())]);
        let manifest = Some(serde_json::json!({ "env": { "PORT": "9999", "X": "x" } }));
        let url = HashMap::from([("PORT".to_string(), "8888".to_string())]);
        let coulsonrc = HashMap::new();
        let merged = build_layered_env(
            provider,
            &manifest,
            Some(&url),
            &coulsonrc,
            Path::new("/app"),
        )
        .merge();
        // PORT stays the provider's value; overlays' PORT is stripped.
        assert_eq!(merged.get("PORT").map(String::as_str), Some("PROVIDER"));
        // Non-PORT overlay keys still apply.
        assert_eq!(merged.get("X").map(String::as_str), Some("x"));
    }

    #[test]
    fn wrapper_script_bash_strips_bash_env_and_skips_norc() {
        use crate::process::provider::ListenTarget;
        let shell = PathBuf::from("/bin/bash");
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "5000".to_string());
        let spec = ProcessSpec {
            command: PathBuf::new(),
            args: vec!["bundle exec rails server -p $PORT".to_string()],
            env,
            working_dir: PathBuf::from("/tmp"),
            listen_target: ListenTarget::Tcp {
                host: "127.0.0.1".to_string(),
                port: 5000,
            },
        };
        let script = generate_wrapper_script(&shell, &spec);
        // bash inner must run with --noprofile --norc AND have BASH_ENV
        // stripped via env(1), so $BASH_ENV cannot source a clobbering script.
        assert!(
            script.contains("env -u BASH_ENV"),
            "bash wrapper must env -u BASH_ENV, got:\n{script}"
        );
        assert!(
            script.contains("/bin/bash --noprofile --norc -c"),
            "bash wrapper must use --noprofile --norc, got:\n{script}"
        );
    }

    #[test]
    fn login_shell_args_zsh_sources_rc_then_env_then_user_shell() {
        let shell = PathBuf::from("/bin/zsh");
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "5000".to_string());
        let args = login_shell_args(&shell, "bundle exec rails server -p $PORT", &env);
        assert_eq!(args[0], "-l");
        assert_eq!(args[1], "-c");
        let body = &args[2];
        // Sources zsh rc, then exec env(1) prefix, then user shell -f -c '...'
        assert!(
            body.contains(". ~/.zshrc"),
            "expected rc source, got: {body}"
        );
        assert!(
            body.contains("exec env "),
            "expected env(1) prefix, got: {body}"
        );
        // Inner zsh must run with `-f` so `.zshenv` cannot re-clobber the env
        // we just injected via env(1).
        assert!(
            body.contains("/bin/zsh -f -c"),
            "inner command must run via user shell with -f, got: {body}"
        );
        assert!(
            !body.contains(" sh -c "),
            "must not downgrade to sh -c, got: {body}"
        );
    }

    #[test]
    fn login_shell_args_bash_strips_bash_env_and_uses_norc() {
        let shell = PathBuf::from("/bin/bash");
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "5000".to_string());
        let args = login_shell_args(&shell, "bundle exec rails server -p $PORT", &env);
        let body = &args[2];
        // Outer manually sources ~/.bashrc, then env -u BASH_ENV strips the
        // sneaky BASH_ENV pointer, then bash --noprofile --norc -c runs the
        // command without re-sourcing any startup file.
        assert!(
            body.contains(". ~/.bashrc"),
            "expected bash rc source, got: {body}"
        );
        assert!(
            body.contains("env -u BASH_ENV"),
            "expected env -u BASH_ENV, got: {body}"
        );
        assert!(
            body.contains("/bin/bash --noprofile --norc -c"),
            "inner bash must use --noprofile --norc, got: {body}"
        );
    }

    #[test]
    fn login_shell_args_unknown_shell_skips_rc_source() {
        // For non-bash/zsh shells we don't manually `. ~/.foorc`; the outer
        // `$SHELL -l` is responsible for sourcing the right login config.
        let shell = PathBuf::from("/bin/ksh");
        let env = HashMap::new();
        let args = login_shell_args(&shell, "echo hi", &env);
        let body = &args[2];
        assert!(!body.contains(". ~/."), "no manual rc source, got: {body}");
        assert!(
            body.contains("/bin/ksh -c"),
            "inner command runs via user shell, got: {body}"
        );
    }

    // -- .coulson.toml [env] injection into ProcessSpec --

    #[test]
    fn manifest_env_injected_into_spec() {
        use std::fs;
        let dir =
            std::env::temp_dir().join(format!("coulson-test-env-inject-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create a .coulson.toml with [env]
        fs::write(
            dir.join(".coulson.toml"),
            r#"
kind = "procfile"
[env]
MY_VAR = "from_toml"
OVERRIDE = "toml_wins"
"#,
        )
        .unwrap();

        // Create a Procfile so procfile provider detects it
        fs::write(dir.join("Procfile"), "web: echo hello").unwrap();

        let manifest = load_coulson_toml_manifest(&dir);
        assert!(manifest.is_some());
        let manifest = manifest.unwrap();
        let env_obj = manifest.get("env").and_then(|v| v.as_object());
        assert!(env_obj.is_some());
        let env_obj = env_obj.unwrap();
        assert_eq!(
            env_obj.get("MY_VAR").and_then(|v| v.as_str()),
            Some("from_toml")
        );
        assert_eq!(
            env_obj.get("OVERRIDE").and_then(|v| v.as_str()),
            Some("toml_wins")
        );

        fs::remove_dir_all(&dir).ok();
    }

    // -- resolve_log_dir / process_log_path --

    #[test]
    fn resolve_log_dir_falls_back_to_app_runtime_dir() {
        let manifest: Option<serde_json::Value> = None;
        let root = Path::new("/app");
        let app_dir = Path::new("/run/coulson/managed/myapp");
        assert_eq!(
            resolve_log_dir(&manifest, root, app_dir),
            PathBuf::from("/run/coulson/managed/myapp")
        );
    }

    #[test]
    fn resolve_log_dir_empty_manifest_uses_default() {
        let manifest = Some(serde_json::json!({}));
        let root = Path::new("/app");
        let app_dir = Path::new("/run/coulson/managed/myapp");
        assert_eq!(
            resolve_log_dir(&manifest, root, app_dir),
            PathBuf::from("/run/coulson/managed/myapp")
        );
    }

    #[test]
    fn resolve_log_dir_explicit_absolute() {
        let manifest = Some(serde_json::json!({ "log_dir": "/var/log/myapp" }));
        let root = Path::new("/app");
        let app_dir = Path::new("/run/coulson/managed/myapp");
        assert_eq!(
            resolve_log_dir(&manifest, root, app_dir),
            PathBuf::from("/var/log/myapp")
        );
    }

    #[test]
    fn resolve_log_dir_explicit_relative_joins_root() {
        let manifest = Some(serde_json::json!({ "log_dir": "logs" }));
        let root = Path::new("/home/user/myapp");
        let app_dir = Path::new("/run/coulson/managed/myapp");
        assert_eq!(
            resolve_log_dir(&manifest, root, app_dir),
            PathBuf::from("/home/user/myapp/logs")
        );
    }

    #[test]
    fn resolve_log_dir_deprecated_log_path_uses_parent() {
        let manifest = Some(serde_json::json!({ "log_path": "logs/web.log" }));
        let root = Path::new("/home/user/myapp");
        let app_dir = Path::new("/run/coulson/managed/myapp");
        // The deprecated single-file `log_path` collapses to its parent dir, so
        // companions land next to the web log instead of using app-prefixed names.
        assert_eq!(
            resolve_log_dir(&manifest, root, app_dir),
            PathBuf::from("/home/user/myapp/logs")
        );
    }

    #[test]
    fn resolve_log_dir_prefers_log_dir_over_deprecated_log_path() {
        let manifest = Some(serde_json::json!({ "log_dir": "logs", "log_path": "old/web.log" }));
        let root = Path::new("/home/user/myapp");
        let app_dir = Path::new("/run/coulson/managed/myapp");
        assert_eq!(
            resolve_log_dir(&manifest, root, app_dir),
            PathBuf::from("/home/user/myapp/logs")
        );
    }

    #[test]
    fn process_log_path_names_by_process_type() {
        let log_dir = Path::new("/run/coulson/managed/myapp");
        assert_eq!(
            process_log_path(log_dir, "web"),
            PathBuf::from("/run/coulson/managed/myapp/web.log")
        );
        assert_eq!(
            process_log_path(log_dir, "worker"),
            PathBuf::from("/run/coulson/managed/myapp/worker.log")
        );
    }

    // -- prefetch_env_url returns None when no env_url configured --

    #[tokio::test]
    async fn prefetch_env_url_none_when_no_manifest() {
        let dir =
            std::env::temp_dir().join(format!("coulson-test-prefetch-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // No .coulson.toml at all
        let result = prefetch_env_url(&dir).await.unwrap();
        assert!(result.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn prefetch_env_url_none_when_no_env_url_field() {
        let dir = std::env::temp_dir().join(format!(
            "coulson-test-prefetch-nofield-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".coulson.toml"), "kind = \"asgi\"\n").unwrap();
        let result = prefetch_env_url(&dir).await.unwrap();
        assert!(result.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn prefetch_env_url_err_when_url_unreachable() {
        let dir =
            std::env::temp_dir().join(format!("coulson-test-prefetch-err-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".coulson.toml"),
            "env_url = \"http://127.0.0.1:1/nonexistent\"\n",
        )
        .unwrap();
        let result = prefetch_env_url(&dir).await;
        assert!(result.is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
