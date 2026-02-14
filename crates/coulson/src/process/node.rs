use std::path::Path;

use serde_json::Value;

use super::provider::{DetectedApp, ManagedApp, ProcessProvider, ProcessSpec};

/// Node.js provider — manages Node applications via `package.json` scripts.
///
/// Detection: directory contains `package.json` with a `"dev"` or `"start"` script.
/// Not yet implemented; will resolve to `npm run dev` / `node server.js` with port assignment.
#[allow(dead_code)]
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

    fn resolve(&self, _app: &ManagedApp) -> anyhow::Result<ProcessSpec> {
        anyhow::bail!(
            "Node provider is not yet implemented. Coming soon: npm run dev / node server.js"
        )
    }
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
}
