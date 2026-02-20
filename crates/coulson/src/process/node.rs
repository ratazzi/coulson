use std::path::{Path, PathBuf};

use anyhow::bail;
use serde_json::Value;
use tracing::debug;

use super::provider::{
    allocate_port, DetectedApp, ListenTarget, ManagedApp, ProcessProvider, ProcessSpec,
};

/// Node.js provider — manages Node applications via `package.json` scripts.
///
/// Detection: directory contains `package.json` with a `"dev"` or `"start"` script.
/// Resolves to `<pm> run dev` / `<pm> run start` / `node <main>` with TCP port assignment.
pub struct NodeProvider;

impl ProcessProvider for NodeProvider {
    fn kind(&self) -> &str {
        "node"
    }

    fn display_name(&self) -> &str {
        "Node.js"
    }

    fn detect(&self, dir: &Path, manifest: Option<&Value>) -> Option<DetectedApp> {
        if let Some(m) = manifest {
            if m.get("kind").and_then(|v| v.as_str()) == Some("node") {
                return Some(DetectedApp {
                    kind: "node".into(),
                    meta: Value::Null,
                });
            }
        }

        // Convention: package.json with scripts.dev or scripts.start
        let pkg_path = dir.join("package.json");
        if pkg_path.exists() {
            if let Ok(raw) = std::fs::read_to_string(&pkg_path) {
                if let Ok(pkg) = serde_json::from_str::<Value>(&raw) {
                    let scripts = pkg.get("scripts");
                    if let Some(s) = scripts {
                        if s.get("dev").is_some() || s.get("start").is_some() {
                            return Some(DetectedApp {
                                kind: "node".into(),
                                meta: Value::Null,
                            });
                        }
                    }
                }
            }
        }

        None
    }

    fn resolve(&self, app: &ManagedApp) -> anyhow::Result<ProcessSpec> {
        let root = &app.root;

        // Check coulson.json command override
        if let Some(manifest) = &app.manifest {
            if let Some(cmd) = manifest.get("command").and_then(|v| v.as_str()) {
                let port = allocate_port()?;
                let mut env = std::collections::HashMap::new();
                env.insert("PORT".to_string(), port.to_string());
                env.extend(app.env_overrides.clone());
                return Ok(ProcessSpec {
                    command: PathBuf::from(cmd),
                    args: vec![],
                    env,
                    working_dir: root.clone(),
                    listen_target: ListenTarget::Tcp {
                        host: "127.0.0.1".to_string(),
                        port,
                    },
                });
            }
        }

        // Read package.json
        let pkg_path = root.join("package.json");
        let pkg: Value = if pkg_path.exists() {
            let raw = std::fs::read_to_string(&pkg_path)?;
            serde_json::from_str(&raw)?
        } else {
            Value::Null
        };

        let pm = detect_package_manager(root);
        debug!(root = %root.display(), pm = %pm.name(), "detected Node.js package manager");

        // Allocate a free TCP port
        let port = allocate_port()?;

        let mut env = std::collections::HashMap::new();
        env.insert("PORT".to_string(), port.to_string());
        env.extend(app.env_overrides.clone());

        let listen_target = ListenTarget::Tcp {
            host: "127.0.0.1".to_string(),
            port,
        };

        let scripts = pkg.get("scripts");
        let has_dev = scripts
            .and_then(|s| s.get("dev"))
            .and_then(|v| v.as_str())
            .is_some();
        let has_start = scripts
            .and_then(|s| s.get("start"))
            .and_then(|v| v.as_str())
            .is_some();

        // Priority: dev > start > node <main>
        if has_dev {
            let binary = find_pm_binary(root, &pm)?;
            return Ok(ProcessSpec {
                command: binary,
                args: vec!["run".to_string(), "dev".to_string()],
                env,
                working_dir: root.clone(),
                listen_target,
            });
        }

        if has_start {
            let binary = find_pm_binary(root, &pm)?;
            return Ok(ProcessSpec {
                command: binary,
                args: vec!["run".to_string(), "start".to_string()],
                env,
                working_dir: root.clone(),
                listen_target,
            });
        }

        // Fallback: node <main>
        let main = detect_main_entry(root, &pkg)?;
        let node = find_node_binary(root)?;
        Ok(ProcessSpec {
            command: node,
            args: vec![main],
            env,
            working_dir: root.clone(),
            listen_target,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Bun,
    Pnpm,
    Yarn,
    Npm,
}

impl PackageManager {
    fn name(&self) -> &'static str {
        match self {
            Self::Bun => "bun",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Npm => "npm",
        }
    }
}

/// Detect package manager by lockfile presence.
fn detect_package_manager(root: &Path) -> PackageManager {
    if root.join("bun.lockb").exists() || root.join("bun.lock").exists() {
        return PackageManager::Bun;
    }
    if root.join("pnpm-lock.yaml").exists() {
        return PackageManager::Pnpm;
    }
    if root.join("yarn.lock").exists() {
        return PackageManager::Yarn;
    }
    PackageManager::Npm
}

/// Find the package manager binary in node_modules/.bin/ or PATH.
fn find_pm_binary(root: &Path, pm: &PackageManager) -> anyhow::Result<PathBuf> {
    let name = pm.name();
    let local = root.join(format!("node_modules/.bin/{name}"));
    if local.exists() {
        return Ok(local);
    }
    if let Some(path) = super::provider::which_binary(name) {
        return Ok(path);
    }
    bail!("{name} not found in node_modules/.bin/ or PATH")
}

/// Find the node binary.
fn find_node_binary(root: &Path) -> anyhow::Result<PathBuf> {
    let local = root.join("node_modules/.bin/node");
    if local.exists() {
        return Ok(local);
    }
    if let Some(path) = super::provider::which_binary("node") {
        return Ok(path);
    }
    bail!("node not found in node_modules/.bin/ or PATH")
}

/// Detect the main entry point for `node <main>` fallback.
/// Priority: package.json `main` field > `index.js` > `server.js`.
fn detect_main_entry(root: &Path, pkg: &Value) -> anyhow::Result<String> {
    if let Some(main) = pkg.get("main").and_then(|v| v.as_str()) {
        if root.join(main).exists() {
            return Ok(main.to_string());
        }
    }
    for candidate in &["index.js", "server.js"] {
        if root.join(candidate).exists() {
            return Ok((*candidate).to_string());
        }
    }
    bail!(
        "cannot detect Node.js entry point in {}: no main field, index.js, or server.js found",
        root.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("coulson-test-node-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detect_node_by_package_json_dev() {
        let dir = temp_dir("detect-dev");
        fs::write(
            dir.join("package.json"),
            r#"{"scripts":{"dev":"next dev"}}"#,
        )
        .unwrap();
        let p = NodeProvider;
        assert!(p.detect(&dir, None).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_node_by_package_json_start() {
        let dir = temp_dir("detect-start");
        fs::write(
            dir.join("package.json"),
            r#"{"scripts":{"start":"node index.js"}}"#,
        )
        .unwrap();
        let p = NodeProvider;
        assert!(p.detect(&dir, None).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_node_no_scripts() {
        let dir = temp_dir("detect-noscripts");
        fs::write(dir.join("package.json"), r#"{"name":"foo"}"#).unwrap();
        let p = NodeProvider;
        assert!(p.detect(&dir, None).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_node_no_match() {
        let dir = temp_dir("detect-nomatch");
        let p = NodeProvider;
        assert!(p.detect(&dir, None).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_pm_bun_lockb() {
        let dir = temp_dir("pm-bun-lockb");
        fs::write(dir.join("bun.lockb"), "").unwrap();
        assert_eq!(detect_package_manager(&dir), PackageManager::Bun);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_pm_bun_lock() {
        let dir = temp_dir("pm-bun-lock");
        fs::write(dir.join("bun.lock"), "").unwrap();
        assert_eq!(detect_package_manager(&dir), PackageManager::Bun);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_pm_pnpm() {
        let dir = temp_dir("pm-pnpm");
        fs::write(dir.join("pnpm-lock.yaml"), "").unwrap();
        assert_eq!(detect_package_manager(&dir), PackageManager::Pnpm);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_pm_yarn() {
        let dir = temp_dir("pm-yarn");
        fs::write(dir.join("yarn.lock"), "").unwrap();
        assert_eq!(detect_package_manager(&dir), PackageManager::Yarn);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_pm_npm_default() {
        let dir = temp_dir("pm-npm");
        assert_eq!(detect_package_manager(&dir), PackageManager::Npm);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_main_entry_from_main_field() {
        let dir = temp_dir("main-field");
        fs::write(dir.join("package.json"), r#"{"main":"app.js"}"#).unwrap();
        fs::write(dir.join("app.js"), "").unwrap();
        let pkg: Value = serde_json::from_str(r#"{"main":"app.js"}"#).unwrap();
        assert_eq!(detect_main_entry(&dir, &pkg).unwrap(), "app.js");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_main_entry_index_js() {
        let dir = temp_dir("main-index");
        fs::write(dir.join("index.js"), "").unwrap();
        assert_eq!(detect_main_entry(&dir, &Value::Null).unwrap(), "index.js");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_main_entry_server_js() {
        let dir = temp_dir("main-server");
        fs::write(dir.join("server.js"), "").unwrap();
        assert_eq!(detect_main_entry(&dir, &Value::Null).unwrap(), "server.js");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_main_entry_prefers_index_over_server() {
        let dir = temp_dir("main-prefer");
        fs::write(dir.join("index.js"), "").unwrap();
        fs::write(dir.join("server.js"), "").unwrap();
        assert_eq!(detect_main_entry(&dir, &Value::Null).unwrap(), "index.js");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_main_entry_fails_no_entry() {
        let dir = temp_dir("main-none");
        assert!(detect_main_entry(&dir, &Value::Null).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn allocate_port_returns_nonzero() {
        let port = allocate_port().unwrap();
        assert!(port > 0);
    }
}
