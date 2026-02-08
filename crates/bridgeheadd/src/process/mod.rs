use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use tokio::process::{Child, Command};
use tracing::{debug, info, warn};

const SOCKETS_DIR_RAW: &str = "/tmp/bridgehead/managed";

pub type ProcessManagerHandle = std::sync::Arc<tokio::sync::Mutex<ProcessManager>>;

pub fn new_process_manager(idle_timeout: Duration) -> ProcessManagerHandle {
    std::sync::Arc::new(tokio::sync::Mutex::new(ProcessManager::new(idle_timeout)))
}

pub struct ProcessManager {
    processes: HashMap<String, ManagedProcess>,
    idle_timeout: Duration,
}

struct ManagedProcess {
    child: Child,
    socket_path: PathBuf,
    last_active: Instant,
}

impl ProcessManager {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            processes: HashMap::new(),
            idle_timeout,
        }
    }

    /// Returns the UDS path for the managed app, starting the process if needed.
    pub async fn ensure_running(
        &mut self,
        app_id: &str,
        root: &Path,
    ) -> anyhow::Result<String> {
        // Check if already running and alive
        if let Some(proc) = self.processes.get_mut(app_id) {
            match proc.child.try_wait() {
                Ok(None) => {
                    proc.last_active = Instant::now();
                    return Ok(proc.socket_path.to_string_lossy().to_string());
                }
                _ => {
                    info!(app_id, "managed process exited, will restart");
                    let removed = self.processes.remove(app_id).unwrap();
                    cleanup_socket(&removed.socket_path);
                }
            }
        }

        std::fs::create_dir_all(SOCKETS_DIR_RAW)
            .with_context(|| format!("failed to create {SOCKETS_DIR_RAW}"))?;
        // On macOS /tmp → /private/tmp; canonicalize so pingora's peer address matches.
        let sockets_dir = std::fs::canonicalize(SOCKETS_DIR_RAW)
            .unwrap_or_else(|_| PathBuf::from(SOCKETS_DIR_RAW));
        let socket_path = sockets_dir.join(format!("{app_id}.sock"));
        cleanup_socket(&socket_path);

        let module = detect_module(root)?;
        let granian = find_granian(root)?;

        info!(
            app_id,
            socket = %socket_path.display(),
            module = %module,
            granian = %granian.display(),
            root = %root.display(),
            "starting managed ASGI process"
        );

        let child = Command::new(&granian)
            .arg(&module)
            .arg("--uds")
            .arg(&socket_path)
            .arg("--interface")
            .arg("asgi")
            .current_dir(root)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("failed to spawn granian for {app_id}"))?;

        wait_for_uds_health(&socket_path, Duration::from_secs(30)).await?;

        let path_str = socket_path.to_string_lossy().to_string();
        self.processes.insert(
            app_id.to_string(),
            ManagedProcess {
                child,
                socket_path,
                last_active: Instant::now(),
            },
        );

        Ok(path_str)
    }

    pub fn mark_active(&mut self, app_id: &str) {
        if let Some(proc) = self.processes.get_mut(app_id) {
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
                to_remove.push(app_id.clone());
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

/// Detect the ASGI module to pass to granian.
/// Priority: bridgehead.json `module` field > app.py > main.py
fn detect_module(root: &Path) -> anyhow::Result<String> {
    let manifest_path = root.join("bridgehead.json");
    if manifest_path.exists() {
        if let Ok(raw) = std::fs::read_to_string(&manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(module) = manifest.get("module").and_then(|v| v.as_str()) {
                    return Ok(module.to_string());
                }
            }
        }
    }

    if root.join("app.py").exists() {
        return Ok("app:app".to_string());
    }
    if root.join("main.py").exists() {
        return Ok("main:app".to_string());
    }

    bail!(
        "cannot detect ASGI module in {}: no app.py or main.py found",
        root.display()
    )
}

/// Find granian binary: .venv/bin/ → venv/bin/ → PATH
fn find_granian(root: &Path) -> anyhow::Result<PathBuf> {
    let manifest_path = root.join("bridgehead.json");
    if manifest_path.exists() {
        if let Ok(raw) = std::fs::read_to_string(&manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(cmd) = manifest.get("command").and_then(|v| v.as_str()) {
                    let path = PathBuf::from(cmd);
                    if path.exists() {
                        return Ok(path);
                    }
                    warn!(command = cmd, "bridgehead.json command not found, trying defaults");
                }
            }
        }
    }

    let candidates = [
        root.join(".venv/bin/granian"),
        root.join("venv/bin/granian"),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    if let Ok(output) = std::process::Command::new("which")
        .arg("granian")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    bail!(
        "granian not found for {}: checked .venv/bin/, venv/bin/, and PATH",
        root.display()
    )
}

/// Poll Unix socket connect until it accepts connections or timeout.
async fn wait_for_uds_health(path: &Path, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        match tokio::net::UnixStream::connect(path).await {
            Ok(_) => {
                debug!(socket = %path.display(), "managed process health check passed");
                return Ok(());
            }
            Err(_) => {
                if start.elapsed() > timeout {
                    bail!(
                        "managed process at {} failed to start within {timeout:?}",
                        path.display()
                    );
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
