use std::fs;

use anyhow::Context;
use tracing_subscriber::EnvFilter;

use crate::config::BridgeheadConfig;

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

pub fn ensure_runtime_paths(cfg: &BridgeheadConfig) -> anyhow::Result<()> {
    if let Some(parent) = cfg.control_socket.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create control socket dir: {}", parent.display())
        })?;
    }

    if cfg.control_socket.exists() {
        fs::remove_file(&cfg.control_socket).with_context(|| {
            format!(
                "failed to remove stale control socket: {}",
                cfg.control_socket.display()
            )
        })?;
    }

    if let Some(parent) = cfg.sqlite_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create sqlite dir: {}", parent.display()))?;
    }
    fs::create_dir_all(&cfg.apps_root)
        .with_context(|| format!("failed to create apps root: {}", cfg.apps_root.display()))?;

    Ok(())
}

pub async fn wait_for_shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
