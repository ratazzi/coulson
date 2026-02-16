use std::fs;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing_subscriber::EnvFilter;

use crate::config::CoulsonConfig;
use crate::scanner::ScanStats;

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

pub fn ensure_runtime_paths(cfg: &CoulsonConfig) -> anyhow::Result<()> {
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
    if let Some(parent) = cfg.scan_warnings_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create scan warnings dir: {}", parent.display()))?;
    }
    fs::create_dir_all(&cfg.apps_root)
        .with_context(|| format!("failed to create apps root: {}", cfg.apps_root.display()))?;
    fs::create_dir_all(&cfg.certs_dir)
        .with_context(|| format!("failed to create certs dir: {}", cfg.certs_dir.display()))?;

    Ok(())
}

pub async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => { tracing::info!("received SIGTERM, shutting down"); }
        _ = sigint.recv() => { tracing::info!("received SIGINT, shutting down"); }
    }
}

#[derive(Serialize)]
struct PersistedScanWarnings<'a> {
    updated_at: i64,
    scan: &'a ScanStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanWarningsFile {
    pub updated_at: i64,
    pub scan: ScanStats,
}

pub fn write_scan_warnings(path: &Path, stats: &ScanStats) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create warnings dir: {}", parent.display()))?;
    }
    let payload = PersistedScanWarnings {
        updated_at: OffsetDateTime::now_utc().unix_timestamp(),
        scan: stats,
    };
    let raw = serde_json::to_vec_pretty(&payload)?;
    fs::write(path, raw).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

pub fn read_scan_warnings(path: &Path) -> anyhow::Result<Option<ScanWarningsFile>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(path).with_context(|| format!("failed reading {}", path.display()))?;
    let data: ScanWarningsFile = serde_json::from_slice(&raw)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    Ok(Some(data))
}
