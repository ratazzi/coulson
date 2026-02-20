use std::path::{Path, PathBuf};

use anyhow::bail;
use serde_json::Value;
use tracing::warn;

use super::provider::{DetectedApp, ListenTarget, ManagedApp, ProcessProvider, ProcessSpec};

pub struct AsgiProvider;

impl ProcessProvider for AsgiProvider {
    fn kind(&self) -> &str {
        "asgi"
    }

    fn display_name(&self) -> &str {
        "Python ASGI"
    }

    fn detect(&self, dir: &Path, manifest: Option<&Value>) -> Option<DetectedApp> {
        // If manifest explicitly says kind=asgi, trust it.
        if let Some(m) = manifest {
            if m.get("kind").and_then(|v| v.as_str()) == Some("asgi") {
                return Some(DetectedApp {
                    kind: "asgi".into(),
                    meta: Value::Null,
                });
            }
        }

        // Convention-based detection:
        // has (app.py || main.py) AND (pyproject.toml || requirements.txt)
        let has_entry = dir.join("app.py").exists() || dir.join("main.py").exists();
        let has_deps = dir.join("pyproject.toml").exists() || dir.join("requirements.txt").exists();
        if has_entry && has_deps {
            Some(DetectedApp {
                kind: "asgi".into(),
                meta: Value::Null,
            })
        } else {
            None
        }
    }

    fn resolve(&self, app: &ManagedApp) -> anyhow::Result<ProcessSpec> {
        let module = detect_module(&app.root)?;
        let server = find_asgi_server(&app.root)?;
        let socket_path = app.socket_path();

        let mut args = vec![module];
        match server.server_type {
            AsgiServer::Granian => {
                args.extend([
                    "--uds".into(),
                    socket_path.to_string_lossy().to_string(),
                    "--interface".into(),
                    "asgi".into(),
                ]);
            }
            AsgiServer::Uvicorn => {
                args.extend(["--uds".into(), socket_path.to_string_lossy().to_string()]);
            }
        }

        let mut env = std::collections::HashMap::new();
        env.extend(app.env_overrides.clone());

        Ok(ProcessSpec {
            command: server.binary,
            args,
            env,
            working_dir: app.root.clone(),
            listen_target: ListenTarget::Uds(socket_path),
        })
    }
}

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

/// Detect the ASGI module to pass to granian / uvicorn.
/// Priority: coulson.json `module` field > app.py > main.py
fn detect_module(root: &Path) -> anyhow::Result<String> {
    let manifest_path = root.join("coulson.json");
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
///   1. `coulson.json` `server` field (`"granian"` | `"uvicorn"`) → use that server
///   2. `coulson.json` `command` field → use as binary path, infer server type from name
///   3. Auto-detect: try uvicorn first (venv → PATH), then granian (venv → PATH)
fn find_asgi_server(root: &Path) -> anyhow::Result<AsgiServerInfo> {
    let manifest_path = root.join("coulson.json");
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
                                "unknown server in coulson.json, trying auto-detect"
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
                            "coulson.json command not found, searching defaults"
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
                        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
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
                        "coulson.json command not found, trying defaults"
                    );
                }
            }
        }
    }

    auto_detect_server(root)
}

/// Try uvicorn first (single-process, better for dev), then granian.
fn auto_detect_server(root: &Path) -> anyhow::Result<AsgiServerInfo> {
    if let Ok(binary) = find_server_binary(root, "uvicorn") {
        return Ok(AsgiServerInfo {
            server_type: AsgiServer::Uvicorn,
            binary,
        });
    }
    if let Ok(binary) = find_server_binary(root, "granian") {
        return Ok(AsgiServerInfo {
            server_type: AsgiServer::Granian,
            binary,
        });
    }
    bail!(
        "no ASGI server found for {}: checked uvicorn and granian in .venv/bin/, venv/bin/, and PATH",
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
    if let Some(path) = super::provider::which_binary(name) {
        return Ok(path);
    }
    bail!("{name} not found in .venv/bin/, venv/bin/, or PATH")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a unique temp directory for a test case.
    fn temp_app_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("coulson-test-{label}-{}", std::process::id()));
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

    #[test]
    fn detect_asgi_by_convention() {
        let root = temp_app_dir("detect-asgi-conv");
        fs::write(root.join("app.py"), "").unwrap();
        fs::write(root.join("requirements.txt"), "").unwrap();
        let provider = AsgiProvider;
        let detected = provider.detect(&root, None);
        assert!(detected.is_some());
        assert_eq!(detected.unwrap().kind, "asgi");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_asgi_by_manifest() {
        let root = temp_app_dir("detect-asgi-manifest");
        let provider = AsgiProvider;
        let manifest = serde_json::json!({ "kind": "asgi" });
        let detected = provider.detect(&root, Some(&manifest));
        assert!(detected.is_some());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_asgi_no_match() {
        let root = temp_app_dir("detect-asgi-nomatch");
        fs::write(root.join("index.html"), "").unwrap();
        let provider = AsgiProvider;
        assert!(provider.detect(&root, None).is_none());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn server_display_names() {
        assert_eq!(AsgiServer::Granian.to_string(), "granian");
        assert_eq!(AsgiServer::Uvicorn.to_string(), "uvicorn");
    }

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

    #[test]
    fn auto_detect_prefers_uvicorn() {
        let root = temp_app_dir("auto-both");
        place_venv_binary(&root, "granian");
        place_venv_binary(&root, "uvicorn");
        let info = auto_detect_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Uvicorn);
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

    #[test]
    fn manifest_server_selects_uvicorn() {
        let root = temp_app_dir("manifest-uvicorn");
        place_venv_binary(&root, "granian");
        place_venv_binary(&root, "uvicorn");
        fs::write(root.join("coulson.json"), r#"{"server": "uvicorn"}"#).unwrap();
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
        fs::write(root.join("coulson.json"), r#"{"server": "granian"}"#).unwrap();
        let info = find_asgi_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Granian);
        assert_eq!(info.binary, root.join(".venv/bin/granian"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn manifest_server_plus_command() {
        let root = temp_app_dir("manifest-server-cmd");
        place_venv_binary(&root, "uvicorn");
        let custom = root.join(".venv/bin/uvicorn");
        let manifest = format!(
            r#"{{"server": "uvicorn", "command": "{}"}}"#,
            custom.display()
        );
        fs::write(root.join("coulson.json"), manifest).unwrap();
        let info = find_asgi_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Uvicorn);
        assert_eq!(info.binary, custom);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn manifest_command_infers_uvicorn() {
        let root = temp_app_dir("manifest-cmd-uvicorn");
        place_venv_binary(&root, "uvicorn");
        let uvicorn_path = root.join(".venv/bin/uvicorn");
        let manifest = format!(r#"{{"command": "{}"}}"#, uvicorn_path.display());
        fs::write(root.join("coulson.json"), manifest).unwrap();
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
        fs::write(root.join("coulson.json"), manifest).unwrap();
        let info = find_asgi_server(&root).unwrap();
        assert_eq!(info.server_type, AsgiServer::Granian);
        assert_eq!(info.binary, granian_path);
        fs::remove_dir_all(&root).ok();
    }

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

    #[test]
    fn manifest_unknown_server_falls_back() {
        let root = temp_app_dir("manifest-unknown");
        place_venv_binary(&root, "uvicorn");
        fs::write(root.join("coulson.json"), r#"{"server": "hypercorn"}"#).unwrap();
        let info = find_asgi_server(&root).unwrap();
        // Falls back to auto-detect → finds uvicorn
        assert_eq!(info.server_type, AsgiServer::Uvicorn);
        fs::remove_dir_all(&root).ok();
    }

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
            root.join("coulson.json"),
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
        fs::write(root.join("coulson.json"), r#"{"module": "custom:factory"}"#).unwrap();
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
