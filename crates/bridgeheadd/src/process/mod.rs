use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use tokio::process::{Child, Command};
use tracing::{debug, info, warn};

const SOCKETS_DIR_RAW: &str = "/tmp/bridgehead/managed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsgiServer {
    Granian,
    Uvicorn,
}

impl std::fmt::Display for AsgiServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsgiServer::Granian => write!(f, "granian"),
            AsgiServer::Uvicorn => write!(f, "uvicorn"),
        }
    }
}

struct AsgiServerInfo {
    server_type: AsgiServer,
    binary: PathBuf,
}

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
        let server = find_asgi_server(root)?;

        info!(
            app_id,
            socket = %socket_path.display(),
            module = %module,
            server = %server.server_type,
            binary = %server.binary.display(),
            root = %root.display(),
            "starting managed ASGI process"
        );

        let log_path = sockets_dir.join(format!("{app_id}.log"));
        let log_file = std::fs::File::create(&log_path)
            .with_context(|| format!("failed to create log file {}", log_path.display()))?;
        let stderr_file = log_file
            .try_clone()
            .with_context(|| "failed to clone log file handle")?;

        let mut cmd = Command::new(&server.binary);
        cmd.arg(&module);
        match server.server_type {
            AsgiServer::Granian => {
                cmd.arg("--uds")
                    .arg(&socket_path)
                    .arg("--interface")
                    .arg("asgi");
            }
            AsgiServer::Uvicorn => {
                cmd.arg("--uds")
                    .arg(&socket_path);
            }
        }
        let child = cmd
            .current_dir(root)
            .kill_on_drop(true)
            .stdout(stderr_file)
            .stderr(log_file)
            .spawn()
            .with_context(|| format!("failed to spawn {} for {app_id}", server.server_type))?;

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

/// Find the best available ASGI server for the given app directory.
///
/// Resolution order:
///   1. `bridgehead.json` `server` field (`"granian"` | `"uvicorn"`) → use that server
///   2. `bridgehead.json` `command` field → use as binary path, infer server type from name
///   3. Auto-detect: try granian first (venv → PATH), then uvicorn (venv → PATH)
fn find_asgi_server(root: &Path) -> anyhow::Result<AsgiServerInfo> {
    let manifest_path = root.join("bridgehead.json");
    if manifest_path.exists() {
        if let Ok(raw) = std::fs::read_to_string(&manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&raw) {
                let server_pref = manifest.get("server").and_then(|v| v.as_str());
                let command = manifest.get("command").and_then(|v| v.as_str());

                // Explicit server preference
                if let Some(server_name) = server_pref {
                    let server_type = match server_name {
                        "granian" => AsgiServer::Granian,
                        "uvicorn" => AsgiServer::Uvicorn,
                        other => {
                            warn!(
                                server = other,
                                "unknown server in bridgehead.json, trying auto-detect"
                            );
                            return auto_detect_server(root);
                        }
                    };
                    if let Some(cmd) = command {
                        let path = PathBuf::from(cmd);
                        if path.exists() {
                            return Ok(AsgiServerInfo {
                                server_type,
                                binary: path,
                            });
                        }
                        warn!(
                            command = cmd,
                            "bridgehead.json command not found, searching defaults"
                        );
                    }
                    let binary = find_server_binary(root, server_name)?;
                    return Ok(AsgiServerInfo {
                        server_type,
                        binary,
                    });
                }

                // Command field without explicit server → infer type from binary name
                if let Some(cmd) = command {
                    let path = PathBuf::from(cmd);
                    if path.exists() {
                        let name = path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        let server_type = if name.contains("uvicorn") {
                            AsgiServer::Uvicorn
                        } else {
                            AsgiServer::Granian
                        };
                        return Ok(AsgiServerInfo {
                            server_type,
                            binary: path,
                        });
                    }
                    warn!(
                        command = cmd,
                        "bridgehead.json command not found, trying defaults"
                    );
                }
            }
        }
    }

    auto_detect_server(root)
}

/// Try granian first, then uvicorn. Returns the first server found.
fn auto_detect_server(root: &Path) -> anyhow::Result<AsgiServerInfo> {
    if let Ok(binary) = find_server_binary(root, "granian") {
        return Ok(AsgiServerInfo {
            server_type: AsgiServer::Granian,
            binary,
        });
    }
    if let Ok(binary) = find_server_binary(root, "uvicorn") {
        return Ok(AsgiServerInfo {
            server_type: AsgiServer::Uvicorn,
            binary,
        });
    }
    bail!(
        "no ASGI server found for {}: checked granian and uvicorn in .venv/bin/, venv/bin/, and PATH",
        root.display()
    )
}

/// Look for a server binary in the app's virtualenv, then in PATH.
fn find_server_binary(root: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let candidates = [
        root.join(format!(".venv/bin/{name}")),
        root.join(format!("venv/bin/{name}")),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }
    if let Some(path) = which_binary(name) {
        return Ok(path);
    }
    bail!("{name} not found in .venv/bin/, venv/bin/, or PATH")
}

fn which_binary(name: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("which")
        .arg(name)
        .output()
        .ok()?;
    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a unique temp directory for a test case.
    fn temp_app_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bridgehead-test-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Place a dummy binary in `.venv/bin/<name>`.
    fn place_venv_binary(root: &Path, name: &str) {
        let bin_dir = root.join(".venv/bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join(name), "#!/bin/sh\n").unwrap();
    }

    /// Place a dummy binary in `venv/bin/<name>` (non-dot variant).
    fn place_venv_nondot_binary(root: &Path, name: &str) {
        let bin_dir = root.join("venv/bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join(name), "#!/bin/sh\n").unwrap();
    }

    // ---------------------------------------------------------------
    // AsgiServer display
    // ---------------------------------------------------------------

    #[test]
    fn server_display_names() {
        assert_eq!(AsgiServer::Granian.to_string(), "granian");
        assert_eq!(AsgiServer::Uvicorn.to_string(), "uvicorn");
    }

    // ---------------------------------------------------------------
    // find_server_binary
    // ---------------------------------------------------------------

    #[test]
    fn finds_granian_in_dot_venv() {
        let root = temp_app_dir("find-granian-dotvenv");
        place_venv_binary(&root, "granian");
        let result = find_server_binary(&root, "granian").unwrap();
        assert_eq!(result, root.join(".venv/bin/granian"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn finds_uvicorn_in_dot_venv() {
        let root = temp_app_dir("find-uvicorn-dotvenv");
        place_venv_binary(&root, "uvicorn");
        let result = find_server_binary(&root, "uvicorn").unwrap();
        assert_eq!(result, root.join(".venv/bin/uvicorn"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn prefers_dot_venv_over_venv() {
        let root = temp_app_dir("prefer-dotvenv");
        place_venv_binary(&root, "granian");
        place_venv_nondot_binary(&root, "granian");
        let result = find_server_binary(&root, "granian").unwrap();
        assert_eq!(result, root.join(".venv/bin/granian"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn falls_back_to_venv_nondot() {
        let root = temp_app_dir("fallback-venv");
        place_venv_nondot_binary(&root, "uvicorn");
        let result = find_server_binary(&root, "uvicorn").unwrap();
        assert_eq!(result, root.join("venv/bin/uvicorn"));
        fs::remove_dir_all(&root).ok();
    }

    // ---------------------------------------------------------------
    // auto_detect_server
    // ---------------------------------------------------------------

    #[test]
    fn auto_detect_prefers_granian() {
        let root = temp_app_dir("auto-both");
        place_venv_binary(&root, "granian");
        place_venv_binary(&root, "uvicorn");
        let info = auto_detect_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Granian);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn auto_detect_finds_uvicorn_when_no_granian() {
        let root = temp_app_dir("auto-uvicorn-only");
        place_venv_binary(&root, "uvicorn");
        let info = auto_detect_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Uvicorn);
        assert_eq!(info.binary, root.join(".venv/bin/uvicorn"));
        fs::remove_dir_all(&root).ok();
    }

    // ---------------------------------------------------------------
    // find_asgi_server — manifest server field
    // ---------------------------------------------------------------

    #[test]
    fn manifest_server_selects_uvicorn() {
        let root = temp_app_dir("manifest-uvicorn");
        place_venv_binary(&root, "granian");
        place_venv_binary(&root, "uvicorn");
        fs::write(
            root.join("bridgehead.json"),
            r#"{"server": "uvicorn"}"#,
        )
        .unwrap();
        let info = find_asgi_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Uvicorn);
        assert_eq!(info.binary, root.join(".venv/bin/uvicorn"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn manifest_server_selects_granian() {
        let root = temp_app_dir("manifest-granian");
        place_venv_binary(&root, "granian");
        place_venv_binary(&root, "uvicorn");
        fs::write(
            root.join("bridgehead.json"),
            r#"{"server": "granian"}"#,
        )
        .unwrap();
        let info = find_asgi_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Granian);
        assert_eq!(info.binary, root.join(".venv/bin/granian"));
        fs::remove_dir_all(&root).ok();
    }

    // ---------------------------------------------------------------
    // find_asgi_server — manifest server + command
    // ---------------------------------------------------------------

    #[test]
    fn manifest_server_plus_command() {
        let root = temp_app_dir("manifest-server-cmd");
        place_venv_binary(&root, "uvicorn");
        let custom = root.join(".venv/bin/uvicorn");
        let manifest = format!(
            r#"{{"server": "uvicorn", "command": "{}"}}"#,
            custom.display()
        );
        fs::write(root.join("bridgehead.json"), manifest).unwrap();
        let info = find_asgi_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Uvicorn);
        assert_eq!(info.binary, custom);
        fs::remove_dir_all(&root).ok();
    }

    // ---------------------------------------------------------------
    // find_asgi_server — manifest command only (infer type)
    // ---------------------------------------------------------------

    #[test]
    fn manifest_command_infers_uvicorn() {
        let root = temp_app_dir("manifest-cmd-uvicorn");
        place_venv_binary(&root, "uvicorn");
        let uvicorn_path = root.join(".venv/bin/uvicorn");
        let manifest = format!(r#"{{"command": "{}"}}"#, uvicorn_path.display());
        fs::write(root.join("bridgehead.json"), manifest).unwrap();
        let info = find_asgi_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Uvicorn);
        assert_eq!(info.binary, uvicorn_path);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn manifest_command_infers_granian() {
        let root = temp_app_dir("manifest-cmd-granian");
        place_venv_binary(&root, "granian");
        let granian_path = root.join(".venv/bin/granian");
        let manifest = format!(r#"{{"command": "{}"}}"#, granian_path.display());
        fs::write(root.join("bridgehead.json"), manifest).unwrap();
        let info = find_asgi_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Granian);
        assert_eq!(info.binary, granian_path);
        fs::remove_dir_all(&root).ok();
    }

    // ---------------------------------------------------------------
    // find_asgi_server — no manifest, auto-detect
    // ---------------------------------------------------------------

    #[test]
    fn no_manifest_auto_detects_uvicorn() {
        let root = temp_app_dir("no-manifest-uvicorn");
        place_venv_binary(&root, "uvicorn");
        let info = find_asgi_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Uvicorn);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn no_manifest_auto_detects_granian() {
        let root = temp_app_dir("no-manifest-granian");
        place_venv_binary(&root, "granian");
        let info = find_asgi_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Granian);
        fs::remove_dir_all(&root).ok();
    }

    // ---------------------------------------------------------------
    // find_asgi_server — unknown server falls back to auto-detect
    // ---------------------------------------------------------------

    #[test]
    fn manifest_unknown_server_falls_back() {
        let root = temp_app_dir("manifest-unknown");
        place_venv_binary(&root, "uvicorn");
        fs::write(
            root.join("bridgehead.json"),
            r#"{"server": "hypercorn"}"#,
        )
        .unwrap();
        let info = find_asgi_server(&root).unwrap();
        // Falls back to auto-detect → finds uvicorn
        assert_eq!(info.server_type, AsgiServer::Uvicorn);
        fs::remove_dir_all(&root).ok();
    }

    // ---------------------------------------------------------------
    // detect_module
    // ---------------------------------------------------------------

    #[test]
    fn detect_module_from_app_py() {
        let root = temp_app_dir("module-app-py");
        fs::write(root.join("app.py"), "").unwrap();
        assert_eq!(detect_module(&root).unwrap(), "app:app");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_from_main_py() {
        let root = temp_app_dir("module-main-py");
        fs::write(root.join("main.py"), "").unwrap();
        assert_eq!(detect_module(&root).unwrap(), "main:app");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_prefers_app_over_main() {
        let root = temp_app_dir("module-both");
        fs::write(root.join("app.py"), "").unwrap();
        fs::write(root.join("main.py"), "").unwrap();
        assert_eq!(detect_module(&root).unwrap(), "app:app");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_from_manifest() {
        let root = temp_app_dir("module-manifest");
        fs::write(
            root.join("bridgehead.json"),
            r#"{"module": "mymod:create_app"}"#,
        )
        .unwrap();
        assert_eq!(detect_module(&root).unwrap(), "mymod:create_app");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_manifest_overrides_files() {
        let root = temp_app_dir("module-manifest-override");
        fs::write(root.join("app.py"), "").unwrap();
        fs::write(
            root.join("bridgehead.json"),
            r#"{"module": "custom:factory"}"#,
        )
        .unwrap();
        assert_eq!(detect_module(&root).unwrap(), "custom:factory");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_fails_with_no_entry_point() {
        let root = temp_app_dir("module-none");
        assert!(detect_module(&root).is_err());
        fs::remove_dir_all(&root).ok();
    }
}
