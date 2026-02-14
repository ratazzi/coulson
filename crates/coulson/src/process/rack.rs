use std::path::Path;

use serde_json::Value;

use super::provider::{DetectedApp, ManagedApp, ProcessProvider, ProcessSpec};

/// Rack/Puma provider — manages Ruby Rack applications.
///
/// Detection: directory contains `config.ru` (and optionally `Gemfile`).
/// Not yet implemented; will resolve to `bundle exec puma` with UDS binding.
#[allow(dead_code)]
pub struct RackProvider;

impl ProcessProvider for RackProvider {
    fn kind(&self) -> &str {
        "rack"
    }

    fn display_name(&self) -> &str {
        "Ruby Rack"
    }

    fn detect(&self, dir: &Path, manifest: Option<&Value>) -> Option<DetectedApp> {
        if let Some(m) = manifest {
            if m.get("kind").and_then(|v| v.as_str()) == Some("rack") {
                return Some(DetectedApp {
                    kind: "rack".into(),
                    meta: Value::Null,
                });
            }
        }

        // Convention: config.ru + Gemfile
        if dir.join("config.ru").exists() {
            return Some(DetectedApp {
                kind: "rack".into(),
                meta: Value::Null,
            });
        }

        None
    }

    fn resolve(&self, _app: &ManagedApp) -> anyhow::Result<ProcessSpec> {
        anyhow::bail!("Rack provider is not yet implemented. Coming soon: bundle exec puma --bind unix://{{socket}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("coulson-test-rack-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detect_rack_by_config_ru() {
        let dir = temp_dir("detect-configru");
        fs::write(dir.join("config.ru"), "run MyApp").unwrap();
        let p = RackProvider;
        assert!(p.detect(&dir, None).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_rack_by_manifest() {
        let dir = temp_dir("detect-manifest");
        let p = RackProvider;
        let m = serde_json::json!({ "kind": "rack" });
        assert!(p.detect(&dir, Some(&m)).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_rack_no_match() {
        let dir = temp_dir("detect-nomatch");
        fs::write(dir.join("index.html"), "").unwrap();
        let p = RackProvider;
        assert!(p.detect(&dir, None).is_none());
        fs::remove_dir_all(&dir).ok();
    }
}
