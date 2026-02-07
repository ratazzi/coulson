mod config;
mod control;
mod domain;
mod proxy;
mod runtime;
mod scanner;
mod store;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

use crate::config::BridgeheadConfig;
use crate::domain::BackendTarget;
use crate::store::AppRepository;

#[derive(Clone)]
pub struct SharedState {
    pub store: Arc<AppRepository>,
    pub routes: Arc<RwLock<HashMap<String, BackendTarget>>>,
    pub route_tx: broadcast::Sender<()>,
    pub domain_suffix: String,
    pub apps_root: std::path::PathBuf,
}

impl SharedState {
    pub fn reload_routes(&self) -> anyhow::Result<()> {
        let enabled_apps = self.store.list_enabled()?;
        let mut table = HashMap::with_capacity(enabled_apps.len());
        for app in enabled_apps {
            table.insert(app.domain.0, app.target);
        }
        *self.routes.write() = table;
        let _ = self.route_tx.send(());
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    runtime::init_tracing();

    let cfg = BridgeheadConfig::load().context("failed to load config")?;
    runtime::ensure_runtime_paths(&cfg)?;

    let store = Arc::new(AppRepository::new(&cfg.sqlite_path)?);
    store.init_schema()?;

    let (route_tx, _rx) = broadcast::channel(32);
    let state = SharedState {
        store,
        routes: Arc::new(RwLock::new(HashMap::new())),
        route_tx,
        domain_suffix: cfg.domain_suffix.clone(),
        apps_root: cfg.apps_root.clone(),
    };

    scanner::sync_from_apps_root(&state)?;
    state.reload_routes()?;

    let proxy_state = state.clone();
    let proxy_addr = cfg.listen_http;
    let proxy_task = tokio::spawn(async move {
        if let Err(err) = proxy::run_proxy(proxy_addr, proxy_state).await {
            error!(error = %err, "proxy exited with error");
        }
    });

    let control_state = state.clone();
    let control_socket = cfg.control_socket.clone();
    let control_task = tokio::spawn(async move {
        if let Err(err) = control::run_control_server(control_socket, control_state).await {
            error!(error = %err, "control server exited with error");
        }
    });

    let scan_state = state.clone();
    let scan_interval_secs = cfg.scan_interval_secs;
    let scan_task = tokio::spawn(async move {
        if scan_interval_secs == 0 {
            info!("apps scanner disabled (interval=0)");
            return;
        }
        loop {
            sleep(Duration::from_secs(scan_interval_secs)).await;
            match scanner::sync_from_apps_root(&scan_state) {
                Ok(count) => {
                    if let Err(err) = scan_state.reload_routes() {
                        error!(error = %err, "failed to reload routes after scan");
                    } else {
                        info!(scanned = count, "apps scan completed");
                    }
                }
                Err(err) => error!(error = %err, "apps scan failed"),
            }
        }
    });

    info!("bridgeheadd started");
    runtime::wait_for_shutdown().await;
    info!("shutdown signal received");

    proxy_task.abort();
    control_task.abort();
    scan_task.abort();

    Ok(())
}
