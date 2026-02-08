use std::collections::HashMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use tokio::process::{Child, Command};
use tracing::{debug, info, warn};

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
    port: u16,
    last_active: Instant,
}

impl ProcessManager {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            processes: HashMap::new(),
            idle_timeout,
        }
    }

    /// Returns the port for the managed app, starting the process if needed.
    pub async fn ensure_running(&mut self, app_id: &str, root: &Path) -> anyhow::Result<u16> {
        // Check if already running and alive
        if let Some(proc) = self.processes.get_mut(app_id) {
            match proc.child.try_wait() {
                Ok(None) => {
                    // Still running
                    proc.last_active = Instant::now();
                    return Ok(proc.port);
                }
                _ => {
                    // Process exited, remove and re-spawn
                    info!(app_id, "managed process exited, will restart");
                    self.processes.remove(app_id);
                }
            }
        }

        // Spawn new process
        let port = allocate_port()?;
        let module = detect_module(root)?;
        let granian = find_granian(root)?;

        info!(
            app_id,
            port,
            module = %module,
            granian = %granian.display(),
            root = %root.display(),
            "starting managed ASGI process"
        );

        let child = Command::new(&granian)
            .arg(&module)
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--interface")
            .arg("asgi")
            .current_dir(root)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .with_context(|| format!("failed to spawn granian for {app_id}"))?;

        wait_for_health(port, Duration::from_secs(30)).await?;

        self.processes.insert(
            app_id.to_string(),
            ManagedProcess {
                child,
                port,
                last_active: Instant::now(),
            },
        );

        Ok(port)
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
                info!(app_id, port = proc.port, "reaping idle managed process");
                // kill_on_drop will handle cleanup, but let's be explicit
                let _ = proc.child.start_kill();
            }
        }

        to_remove.len()
    }

    /// Kill all managed processes (called on daemon shutdown).
    pub fn shutdown_all(&mut self) {
        for (app_id, mut proc) in self.processes.drain() {
            info!(app_id, port = proc.port, "shutting down managed process");
            let _ = proc.child.start_kill();
        }
    }
}

fn allocate_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("failed to bind ephemeral port")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Detect the ASGI module to pass to granian.
/// Priority: bridgehead.json `module` field > app.py > main.py
fn detect_module(root: &Path) -> anyhow::Result<String> {
    // Check bridgehead.json for explicit module
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
    // Check bridgehead.json for explicit command
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

    // Fall back to PATH
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

/// Poll TCP connect until the port accepts connections or timeout.
async fn wait_for_health(port: u16, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    let addr = format!("127.0.0.1:{port}");
    loop {
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(_) => {
                debug!(port, "managed process health check passed");
                return Ok(());
            }
            Err(_) => {
                if start.elapsed() > timeout {
                    bail!("managed process on port {port} failed to start within {timeout:?}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
