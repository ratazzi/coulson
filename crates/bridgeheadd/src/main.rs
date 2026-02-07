mod config;
mod control;
mod domain;
mod proxy;
mod runtime;
mod scanner;
mod store;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
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

enum Command {
    Serve,
    Scan,
    Ls,
}

fn parse_command() -> anyhow::Result<Command> {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        None => Ok(Command::Serve),
        Some("serve") => Ok(Command::Serve),
        Some("scan") => Ok(Command::Scan),
        Some("ls") => Ok(Command::Ls),
        Some(other) => bail!("unknown command: {other}. usage: bridgeheadd [serve|scan|ls]"),
    }
}

fn build_state(cfg: &BridgeheadConfig) -> anyhow::Result<SharedState> {
    runtime::ensure_runtime_paths(cfg)?;

    let store = Arc::new(AppRepository::new(&cfg.sqlite_path)?);
    store.init_schema()?;

    let (route_tx, _rx) = broadcast::channel(32);
    Ok(SharedState {
        store,
        routes: Arc::new(RwLock::new(HashMap::new())),
        route_tx,
        domain_suffix: cfg.domain_suffix.clone(),
        apps_root: cfg.apps_root.clone(),
    })
}

fn run_scan_once(cfg: BridgeheadConfig) -> anyhow::Result<()> {
    let state = build_state(&cfg)?;
    let stats = scanner::sync_from_apps_root(&state)?;
    state.reload_routes()?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "ok": true,
            "scan": stats
        }))?
    );
    Ok(())
}

fn run_ls(cfg: BridgeheadConfig) -> anyhow::Result<()> {
    let state = build_state(&cfg)?;
    let apps = state.store.list_all()?;
    println!("{}", serde_json::to_string(&apps)?);
    Ok(())
}

async fn run_serve(cfg: BridgeheadConfig) -> anyhow::Result<()> {
    let state = build_state(&cfg)?;

    let startup_scan = scanner::sync_from_apps_root(&state)?;
    state.reload_routes()?;
    info!(
        discovered = startup_scan.discovered,
        inserted = startup_scan.inserted,
        updated = startup_scan.updated,
        skipped_manual = startup_scan.skipped_manual,
        pruned = startup_scan.pruned,
        "startup apps scan completed"
    );

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
                Ok(stats) => {
                    if let Err(err) = scan_state.reload_routes() {
                        error!(error = %err, "failed to reload routes after scan");
                    } else {
                        info!(
                            discovered = stats.discovered,
                            inserted = stats.inserted,
                            updated = stats.updated,
                            skipped_manual = stats.skipped_manual,
                            pruned = stats.pruned,
                            "apps scan completed"
                        );
                    }
                }
                Err(err) => error!(error = %err, "apps scan failed"),
            }
        }
    });

    let watch_state = state.clone();
    let watch_root = cfg.apps_root.clone();
    let watch_enabled = cfg.watch_fs;
    let watch_task = tokio::spawn(async move {
        if !watch_enabled {
            info!("fs watcher disabled");
            return;
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<()>();
        let watcher = match build_watcher(watch_root.clone(), tx) {
            Ok(w) => w,
            Err(err) => {
                error!(error = %err, path = %watch_root.display(), "failed to start fs watcher");
                return;
            }
        };
        info!(path = %watch_root.display(), "fs watcher started");

        while rx.recv().await.is_some() {
            match scanner::sync_from_apps_root(&watch_state) {
                Ok(stats) => {
                    if let Err(err) = watch_state.reload_routes() {
                        error!(error = %err, "failed to reload routes after fs event");
                    } else {
                        info!(
                            discovered = stats.discovered,
                            inserted = stats.inserted,
                            updated = stats.updated,
                            skipped_manual = stats.skipped_manual,
                            pruned = stats.pruned,
                            "apps scan completed from fs event"
                        );
                    }
                }
                Err(err) => error!(error = %err, "apps scan failed from fs event"),
            }

            sleep(Duration::from_millis(200)).await;
            while rx.try_recv().is_ok() {}
        }

        drop(watcher);
    });

    info!("bridgeheadd started");
    runtime::wait_for_shutdown().await;
    info!("shutdown signal received");

    proxy_task.abort();
    control_task.abort();
    scan_task.abort();
    watch_task.abort();

    Ok(())
}

fn build_watcher(
    root: std::path::PathBuf,
    tx: mpsc::UnboundedSender<()>,
) -> anyhow::Result<RecommendedWatcher> {
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            use notify::event::{CreateKind, EventKind, ModifyKind, RemoveKind, RenameMode};
            let interested = matches!(
                event.kind,
                EventKind::Create(CreateKind::Any)
                    | EventKind::Create(CreateKind::File)
                    | EventKind::Create(CreateKind::Folder)
                    | EventKind::Modify(ModifyKind::Any)
                    | EventKind::Modify(ModifyKind::Data(_))
                    | EventKind::Modify(ModifyKind::Name(RenameMode::Any))
                    | EventKind::Remove(RemoveKind::Any)
                    | EventKind::Remove(RemoveKind::File)
                    | EventKind::Remove(RemoveKind::Folder)
            );
            if interested {
                let _ = tx.send(());
            }
        }
    })?;
    watcher.watch(&root, RecursiveMode::Recursive)?;
    Ok(watcher)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    runtime::init_tracing();
    let cfg = BridgeheadConfig::load().context("failed to load config")?;

    match parse_command()? {
        Command::Serve => run_serve(cfg).await,
        Command::Scan => run_scan_once(cfg),
        Command::Ls => run_ls(cfg),
    }
}
