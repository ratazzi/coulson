use std::path::Path;

use serde_json::Value;

use super::provider::{DetectedApp, ManagedApp, ProcessProvider, ProcessSpec};

/// Docker / Docker Compose provider — manages containerized applications.
///
/// Detection: directory contains `Dockerfile`, `docker-compose.yml`,
/// `docker-compose.yaml`, or `compose.yml`.
/// Not yet implemented; will resolve to `docker compose up` with port mapping.
#[allow(dead_code)]
pub struct DockerProvider;

impl ProcessProvider for DockerProvider {
    fn kind(&self) -> &str {
        "docker"
    }

    fn display_name(&self) -> &str {
        "Docker / Compose"
    }

    fn detect(&self, dir: &Path, manifest: Option<&Value>) -> Option<DetectedApp> {
        if let Some(m) = manifest {
            if m.get("kind").and_then(|v| v.as_str()) == Some("docker") {
                return Some(DetectedApp {
                    kind: "docker".into(),
                    meta: Value::Null,
                });
            }
        }

        let compose_files = [
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ];
        for f in &compose_files {
            if dir.join(f).exists() {
                return Some(DetectedApp {
                    kind: "docker".into(),
                    meta: Value::Null,
                });
            }
        }

        if dir.join("Dockerfile").exists() {
            return Some(DetectedApp {
                kind: "docker".into(),
                meta: Value::Null,
            });
        }

        None
    }

    fn resolve(&self, _app: &ManagedApp) -> anyhow::Result<ProcessSpec> {
        anyhow::bail!(
            "Docker provider is not yet implemented. Coming soon: docker compose up / docker run"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coulson-test-docker-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detect_docker_compose_yml() {
        let dir = temp_dir("detect-compose");
        fs::write(dir.join("docker-compose.yml"), "version: '3'").unwrap();
        let p = DockerProvider;
        assert!(p.detect(&dir, None).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_dockerfile() {
        let dir = temp_dir("detect-dockerfile");
        fs::write(dir.join("Dockerfile"), "FROM node:20").unwrap();
        let p = DockerProvider;
        assert!(p.detect(&dir, None).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_docker_no_match() {
        let dir = temp_dir("detect-nomatch");
        fs::write(dir.join("app.py"), "").unwrap();
        let p = DockerProvider;
        assert!(p.detect(&dir, None).is_none());
        fs::remove_dir_all(&dir).ok();
    }
}
