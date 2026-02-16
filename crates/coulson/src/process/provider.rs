use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tracing::debug;

/// Metadata returned when a provider detects it can handle a directory.
pub struct DetectedApp {
    /// Provider kind that detected this app (e.g. "asgi", "rack", "node").
    pub kind: String,
    /// Provider-specific metadata (module name, server preference, etc.).
    pub meta: Value,
}

/// Full specification for starting a managed process, resolved by a provider.
pub struct ProcessSpec {
    pub command: PathBuf,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub working_dir: PathBuf,
    pub socket_path: PathBuf,
}

/// Context passed to a provider when resolving how to start an app.
pub struct ManagedApp {
    pub name: String,
    pub root: PathBuf,
    pub kind: String,
    pub manifest: Option<Value>,
    /// User-defined environment variable overrides (via control API).
    pub env_overrides: HashMap<String, String>,
    /// Directory where Unix sockets should be placed.
    pub socket_dir: PathBuf,
}

impl ManagedApp {
    /// Convenience: build the standard socket path for this app.
    pub fn socket_path(&self) -> PathBuf {
        self.socket_dir.join(format!("{}.sock", self.name))
    }
}

/// Trait implemented by each process provider (ASGI, Rack, Node, Docker, …).
///
/// A provider knows how to:
/// 1. **Detect** whether a directory contains an app it can manage.
/// 2. **Resolve** the concrete command, args, env, and socket path to start it.
///
/// # Environment resolution (future)
///
/// Future versions will support automatic environment loading from:
/// - `.env` / `.env.local` (dotenv)
/// - `mise.toml` / `.mise.toml` (via `mise env --json` subprocess)
/// - `.envrc` (via `direnv export json` subprocess)
/// - `coulson.json` `env` field
/// - Per-app overrides stored in SQLite via control API
///
/// For now, providers use their own defaults + `ManagedApp::env_overrides`.
pub trait ProcessProvider: Send + Sync {
    /// Unique identifier, used in DB `kind` column and `BackendTarget::Managed`.
    fn kind(&self) -> &str;

    /// Human-readable display name (e.g. "Python ASGI", "Ruby Rack").
    fn display_name(&self) -> &str;

    /// Try to detect if `dir` contains an app this provider can manage.
    ///
    /// `manifest` is the parsed `coulson.json` content if present.
    /// Returns `None` if the provider cannot handle this directory.
    fn detect(&self, dir: &Path, manifest: Option<&Value>) -> Option<DetectedApp>;

    /// Resolve a concrete [`ProcessSpec`] from the app context.
    fn resolve(&self, app: &ManagedApp) -> Result<ProcessSpec>;
}

/// Ordered collection of process providers. Earlier entries have higher priority
/// during auto-detection.
pub struct ProviderRegistry {
    providers: Vec<Box<dyn ProcessProvider>>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn register(&mut self, provider: impl ProcessProvider + 'static) {
        self.providers.push(Box::new(provider));
    }

    /// Find a provider by its kind identifier.
    pub fn get(&self, kind: &str) -> Option<&dyn ProcessProvider> {
        self.providers
            .iter()
            .find(|p| p.kind() == kind)
            .map(|p| p.as_ref())
    }

    /// Auto-detect which provider (if any) can handle the given directory.
    ///
    /// If `manifest` contains a `"kind"` field, the matching provider is tried
    /// first. Otherwise, providers are tried in registration order.
    pub fn detect(
        &self,
        dir: &Path,
        manifest: Option<&Value>,
    ) -> Option<(&dyn ProcessProvider, DetectedApp)> {
        // If manifest explicitly specifies a kind, prefer that provider.
        if let Some(m) = manifest {
            if let Some(kind) = m.get("kind").and_then(|v| v.as_str()) {
                if let Some(provider) = self.get(kind) {
                    if let Some(detected) = provider.detect(dir, manifest) {
                        return Some((provider, detected));
                    }
                }
            }
        }

        // Otherwise, try each provider in priority order.
        for p in &self.providers {
            if let Some(detected) = p.detect(dir, manifest) {
                return Some((p.as_ref(), detected));
            }
        }
        None
    }

    /// List all registered provider kind identifiers.
    pub fn kinds(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.kind()).collect()
    }
}

/// Search for a binary by name, first in the app's virtualenv / node_modules,
/// then in `PATH`.
pub fn which_binary(name: &str) -> Option<PathBuf> {
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

/// Poll a Unix domain socket until it accepts connections, or timeout.
pub async fn wait_for_uds_ready(path: &Path, timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        match tokio::net::UnixStream::connect(path).await {
            Ok(mut stream) => {
                // Cleanly close the probe connection
                let _ = stream.shutdown().await;
                debug!(socket = %path.display(), "managed process health check passed");
                return Ok(());
            }
            Err(_) => {
                if start.elapsed() > timeout {
                    anyhow::bail!(
                        "managed process at {} failed to become ready within {timeout:?}",
                        path.display()
                    );
                }
                const UDS_POLL_INTERVAL_MS: u64 = 100;
                tokio::time::sleep(Duration::from_millis(UDS_POLL_INTERVAL_MS)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal test provider for registry tests.
    struct DummyProvider {
        id: &'static str,
        should_detect: bool,
    }

    impl ProcessProvider for DummyProvider {
        fn kind(&self) -> &str {
            self.id
        }
        fn display_name(&self) -> &str {
            self.id
        }
        fn detect(&self, _dir: &Path, _manifest: Option<&Value>) -> Option<DetectedApp> {
            if self.should_detect {
                Some(DetectedApp {
                    kind: self.id.to_string(),
                    meta: Value::Null,
                })
            } else {
                None
            }
        }
        fn resolve(&self, _app: &ManagedApp) -> Result<ProcessSpec> {
            anyhow::bail!("dummy provider cannot resolve")
        }
    }

    #[test]
    fn registry_get_by_kind() {
        let mut reg = ProviderRegistry::new();
        reg.register(DummyProvider {
            id: "alpha",
            should_detect: false,
        });
        reg.register(DummyProvider {
            id: "beta",
            should_detect: false,
        });
        assert!(reg.get("alpha").is_some());
        assert!(reg.get("beta").is_some());
        assert!(reg.get("gamma").is_none());
    }

    #[test]
    fn registry_detect_priority_order() {
        let mut reg = ProviderRegistry::new();
        reg.register(DummyProvider {
            id: "first",
            should_detect: false,
        });
        reg.register(DummyProvider {
            id: "second",
            should_detect: true,
        });
        reg.register(DummyProvider {
            id: "third",
            should_detect: true,
        });

        let dir = Path::new("/tmp/fake");
        let (provider, detected) = reg.detect(dir, None).expect("should detect");
        assert_eq!(provider.kind(), "second"); // first matching wins
        assert_eq!(detected.kind, "second");
    }

    #[test]
    fn registry_detect_manifest_kind_takes_priority() {
        let mut reg = ProviderRegistry::new();
        reg.register(DummyProvider {
            id: "first",
            should_detect: true,
        });
        reg.register(DummyProvider {
            id: "second",
            should_detect: true,
        });

        let dir = Path::new("/tmp/fake");
        let manifest = serde_json::json!({ "kind": "second" });
        let (provider, _) = reg.detect(dir, Some(&manifest)).expect("should detect");
        assert_eq!(provider.kind(), "second"); // manifest kind wins
    }

    #[test]
    fn registry_kinds_lists_all() {
        let mut reg = ProviderRegistry::new();
        reg.register(DummyProvider {
            id: "a",
            should_detect: false,
        });
        reg.register(DummyProvider {
            id: "b",
            should_detect: false,
        });
        assert_eq!(reg.kinds(), vec!["a", "b"]);
    }
}
