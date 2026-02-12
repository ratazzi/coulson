mod config;
mod control;
mod domain;
mod mdns;
mod process;
mod proxy;
mod rpc_client;
mod runtime;
mod scanner;
pub mod share;
mod store;
mod tunnel;

// Re-export at crate root so generated capnp code can find it as `crate::tunnelrpc_capnp`
pub(crate) use tunnel::rpc::tunnelrpc_capnp;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use colored::Colorize;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::{Mutex, RwLock};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info};

use tabled::Tabled;

use crate::config::CoulsonConfig;
use crate::domain::BackendTarget;
use crate::process::{ProcessManagerHandle, ProviderRegistry};
use crate::rpc_client::RpcClient;
use crate::share::ShareSigner;
use crate::store::AppRepository;

type DedicatedPortMap = HashMap<u16, Arc<RwLock<Vec<RouteRule>>>>;

#[derive(Clone)]
pub struct RouteRule {
    pub target: BackendTarget,
    pub path_prefix: Option<String>,
    pub timeout_ms: Option<u64>,
    pub cors_enabled: bool,
    pub basic_auth_user: Option<String>,
    pub basic_auth_pass: Option<String>,
    pub spa_rewrite: bool,
    pub listen_port: Option<u16>,
    /// Optional static file root to try before forwarding to the backend.
    /// For Managed apps this is `{app_root}/public` when the directory exists.
    pub static_root: Option<String>,
}

#[derive(Clone)]
pub struct SharedState {
    pub store: Arc<AppRepository>,
    pub routes: Arc<RwLock<HashMap<String, Vec<RouteRule>>>>,
    pub dedicated_ports: Arc<RwLock<DedicatedPortMap>>,
    pub route_tx: broadcast::Sender<()>,
    pub domain_suffix: String,
    pub apps_root: std::path::PathBuf,
    pub scan_warnings_path: std::path::PathBuf,
    pub sqlite_path: std::path::PathBuf,
    pub tunnels: tunnel::TunnelManager,
    pub named_tunnel: Arc<Mutex<Option<tunnel::NamedTunnelHandle>>>,
    pub app_tunnels: tunnel::AppNamedTunnelManager,
    pub listen_http: std::net::SocketAddr,
    pub process_manager: ProcessManagerHandle,
    pub provider_registry: Arc<ProviderRegistry>,
    pub lan_access: bool,
    pub share_signer: Arc<ShareSigner>,
}

impl SharedState {
    pub fn reload_routes(&self) -> anyhow::Result<()> {
        let enabled_apps = self.store.list_enabled()?;
        let mut table: HashMap<String, Vec<RouteRule>> = HashMap::new();
        let mut port_rules: HashMap<u16, Vec<RouteRule>> = HashMap::new();
        for app in enabled_apps {
            let static_root = match &app.target {
                BackendTarget::Managed { root, .. } => {
                    let public = format!("{root}/public");
                    if std::path::Path::new(&public).is_dir() {
                        Some(public)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            let rule = RouteRule {
                target: app.target,
                path_prefix: app.path_prefix,
                timeout_ms: app.timeout_ms,
                cors_enabled: app.cors_enabled,
                basic_auth_user: app.basic_auth_user,
                basic_auth_pass: app.basic_auth_pass,
                spa_rewrite: app.spa_rewrite,
                listen_port: app.listen_port,
                static_root,
            };
            if let Some(port) = app.listen_port {
                port_rules.entry(port).or_default().push(rule.clone());
            }
            table.entry(app.domain.0).or_default().push(rule);
        }
        let sort_rules = |rules: &mut Vec<RouteRule>| {
            rules.sort_by(|a, b| {
                let a_len = a.path_prefix.as_ref().map(|s| s.len()).unwrap_or(0);
                let b_len = b.path_prefix.as_ref().map(|s| s.len()).unwrap_or(0);
                b_len.cmp(&a_len)
            });
        };
        for rules in table.values_mut() {
            sort_rules(rules);
        }
        for rules in port_rules.values_mut() {
            sort_rules(rules);
        }
        *self.routes.write() = table;

        // Update dedicated port rule sets
        {
            let mut dp = self.dedicated_ports.write();
            // Remove ports no longer needed
            dp.retain(|port, _| port_rules.contains_key(port));
            // Add or update
            for (port, rules) in port_rules {
                match dp.get(&port) {
                    Some(existing) => {
                        *existing.write() = rules;
                    }
                    None => {
                        dp.insert(port, Arc::new(RwLock::new(rules)));
                    }
                }
            }
        }

        let _ = self.route_tx.send(());
        Ok(())
    }
}

#[derive(Parser)]
#[command(name = "coulson", about = "Local development gateway")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon (proxy + control + scanner)
    Serve,
    /// One-shot scan of apps_root
    Scan,
    /// List registered apps
    Ls {
        #[arg(long, conflicts_with = "manual")]
        managed: bool,
        #[arg(long, conflicts_with = "managed")]
        manual: bool,
        #[arg(long)]
        domain: Option<String>,
    },
    /// Show scan warnings
    Warnings,
    /// Add an app
    #[command(alias = "recruit")]
    Add {
        /// App name or domain (for manual proxy mode)
        name: Option<String>,
        /// Target: port, host:port, or /path/to/socket (for manual proxy mode)
        target: Option<String>,
        /// Port override (for directory project mode)
        #[arg(long)]
        port: Option<u16>,
        /// Also start a tunnel (not yet implemented)
        #[arg(long)]
        tunnel: bool,
    },
    /// Remove an app
    #[command(alias = "dismiss")]
    Rm {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
    },
    /// Check system health
    Doctor,
    /// Generate a sharing URL for a tunnel-exposed app
    Share {
        /// App name or domain
        name: String,
        /// Expiry duration (e.g. 1h, 30m, 2d)
        #[arg(long, default_value = "24h")]
        expires: String,
    },
    /// Disable share auth for an app
    Unshare {
        /// App name or domain
        name: String,
    },
}

fn build_state(cfg: &CoulsonConfig) -> anyhow::Result<SharedState> {
    runtime::ensure_runtime_paths(cfg)?;

    let store = Arc::new(AppRepository::new(&cfg.sqlite_path, &cfg.domain_suffix)?);
    store.init_schema()?;
    store.migrate_domain_to_prefix()?;

    let share_signer = Arc::new(ShareSigner::load_or_generate(&store)?);

    let (route_tx, _rx) = broadcast::channel(32);
    let idle_timeout = Duration::from_secs(cfg.idle_timeout_secs);
    let registry = Arc::new(process::default_registry());
    let process_manager = process::new_process_manager(idle_timeout, Arc::clone(&registry));
    Ok(SharedState {
        store,
        routes: Arc::new(RwLock::new(HashMap::new())),
        dedicated_ports: Arc::new(RwLock::new(HashMap::new())),
        route_tx,
        domain_suffix: cfg.domain_suffix.clone(),
        apps_root: cfg.apps_root.clone(),
        scan_warnings_path: cfg.scan_warnings_path.clone(),
        sqlite_path: cfg.sqlite_path.clone(),
        tunnels: tunnel::new_tunnel_manager(),
        named_tunnel: Arc::new(Mutex::new(None)),
        app_tunnels: tunnel::new_app_tunnel_manager(),
        listen_http: cfg.listen_http,
        process_manager,
        provider_registry: registry,
        lan_access: cfg.lan_access,
        share_signer,
    })
}

fn run_scan_once(cfg: CoulsonConfig) -> anyhow::Result<()> {
    let state = build_state(&cfg)?;
    let stats = scanner::sync_from_apps_root(&state)?;
    runtime::write_scan_warnings(&state.scan_warnings_path, &stats)?;
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

fn run_ls(
    cfg: CoulsonConfig,
    managed: Option<bool>,
    domain: Option<String>,
) -> anyhow::Result<()> {
    let state = build_state(&cfg)?;
    let apps = state.store.list_filtered(managed, domain.as_deref())?;

    if apps.is_empty() {
        println!("No apps found.");
        return Ok(());
    }

    let rows: Vec<AppRow> = apps
        .iter()
        .map(|app| {
            let status = if app.enabled {
                "enabled".green().to_string()
            } else {
                "disabled".dimmed().to_string()
            };
            AppRow {
                name: app.name.bold().to_string(),
                domain: app.domain.0.cyan().to_string(),
                kind: format!("{:?}", app.kind).to_lowercase(),
                target: app.target.to_url_base().dimmed().to_string(),
                status,
            }
        })
        .collect();

    use tabled::settings::Style;
    let table = tabled::Table::new(&rows)
        .with(Style::blank())
        .to_string();
    println!("{table}");

    Ok(())
}

#[derive(Tabled)]
struct AppRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "DOMAIN")]
    domain: String,
    #[tabled(rename = "KIND")]
    kind: String,
    #[tabled(rename = "TARGET")]
    target: String,
    #[tabled(rename = "STATUS")]
    status: String,
}

fn run_warnings(cfg: CoulsonConfig) -> anyhow::Result<()> {
    let state = build_state(&cfg)?;
    let warnings = runtime::read_scan_warnings(&state.scan_warnings_path)?;
    println!("{}", serde_json::to_string(&warnings)?);
    Ok(())
}

fn run_doctor(cfg: CoulsonConfig) -> anyhow::Result<()> {
    println!("{}", "Coulson Doctor".bold());
    println!();

    let mut issues = 0u32;

    // 1. apps_root
    if cfg.apps_root.is_dir() {
        let count = std::fs::read_dir(&cfg.apps_root)
            .map(|entries| entries.flatten().count())
            .unwrap_or(0);
        print_check(true, &format!("apps_root exists ({}), {count} entries", cfg.apps_root.display()));
    } else {
        print_check(false, &format!("apps_root missing: {}", cfg.apps_root.display()));
        issues += 1;
    }

    // 2. SQLite database
    if cfg.sqlite_path.is_file() {
        let app_count = AppRepository::new(&cfg.sqlite_path, &cfg.domain_suffix)
            .and_then(|store| {
                store.init_schema()?;
                Ok(store)
            })
            .and_then(|store| {
                let apps = store.list_all()?;
                Ok(apps.len())
            });
        match app_count {
            Ok(n) => print_check(true, &format!("database OK, {n} apps registered")),
            Err(e) => {
                print_check(false, &format!("database error: {e}"));
                issues += 1;
            }
        }
    } else {
        print_check(false, &format!("database not found: {}", cfg.sqlite_path.display()));
        issues += 1;
    }

    // 3. Daemon (control socket ping)
    let client = RpcClient::new(&cfg.control_socket);
    match client.call("health.ping", serde_json::json!({})) {
        Ok(_) => print_check(true, "daemon running (health.ping OK)"),
        Err(_) => {
            print_check(false, &format!(
                "daemon not reachable at {}",
                cfg.control_socket.display()
            ));
            issues += 1;
        }
    }

    // 4. Listen port
    match std::net::TcpStream::connect_timeout(
        &cfg.listen_http,
        std::time::Duration::from_secs(2),
    ) {
        Ok(_) => print_check(true, &format!("proxy port {} reachable", cfg.listen_http)),
        Err(_) => {
            print_check(false, &format!("proxy port {} not reachable", cfg.listen_http));
            issues += 1;
        }
    }

    // 5. DNS resolution — test the bare domain suffix (dashboard host)
    match dns_resolves_to_localhost(&cfg.domain_suffix) {
        Some(true) => print_check(true, &format!("DNS {} resolves to localhost", cfg.domain_suffix)),
        Some(false) => {
            print_check(false, &format!("DNS {} does NOT resolve to localhost", cfg.domain_suffix));
            issues += 1;
        }
        None => {
            print_check(false, &format!("DNS {} resolution failed (mDNS not working?)", cfg.domain_suffix));
            issues += 1;
        }
    }

    // 6. Scan warnings
    match runtime::read_scan_warnings(&cfg.scan_warnings_path) {
        Ok(Some(data)) => {
            if data.scan.warning_count == 0 {
                print_check(true, "no scan warnings");
            } else {
                print_warn(&format!(
                    "{} scan warning(s), run `coulson warnings` for details",
                    data.scan.warning_count
                ));
                issues += 1;
            }
        }
        Ok(None) => print_check(true, "no scan warnings file (OK if first run)"),
        Err(_) => print_check(true, "no scan warnings file (OK if first run)"),
    }

    // 7. LAN access
    if cfg.lan_access {
        print_check(true, &format!("LAN access enabled, proxy on {}", cfg.listen_http));
        if cfg.listen_http.ip().is_loopback() {
            print_warn("proxy binds to loopback but LAN access is on — LAN clients cannot connect");
            issues += 1;
        }
    } else {
        print_check(true, &format!("LAN access disabled (loopback only, {})", cfg.listen_http));
    }

    println!();
    if issues == 0 {
        println!("{}", "All checks passed!".green().bold());
    } else {
        println!("{}", format!("{issues} issue(s) found").red().bold());
    }

    Ok(())
}

fn print_check(ok: bool, msg: &str) {
    if ok {
        println!("  {} {msg}", "✓".green());
    } else {
        println!("  {} {msg}", "✗".red());
    }
}

fn print_warn(msg: &str) {
    println!("  {} {msg}", "!".yellow());
}

fn dns_resolves_to_localhost(host: &str) -> Option<bool> {
    use std::net::ToSocketAddrs;
    let lookup = format!("{host}:80");
    match lookup.to_socket_addrs() {
        Ok(addrs) => {
            let localhost_v4: std::net::IpAddr = "127.0.0.1".parse().unwrap();
            let localhost_v6: std::net::IpAddr = "::1".parse().unwrap();
            let is_localhost = addrs
                .into_iter()
                .any(|a| a.ip() == localhost_v4 || a.ip() == localhost_v6);
            Some(is_localhost)
        }
        Err(_) => None,
    }
}

async fn run_serve(cfg: CoulsonConfig) -> anyhow::Result<()> {
    let state = build_state(&cfg)?;

    let startup_scan = scanner::sync_from_apps_root(&state)?;
    runtime::write_scan_warnings(&state.scan_warnings_path, &startup_scan)?;
    state.reload_routes()?;
    info!(
        discovered = startup_scan.discovered,
        inserted = startup_scan.inserted,
        updated = startup_scan.updated,
        skipped_manual = startup_scan.skipped_manual,
        pruned = startup_scan.pruned,
        "startup apps scan completed"
    );

    // Auto-connect named tunnel if credentials exist in settings
    {
        let creds_json = state.store.get_setting("named_tunnel.credentials");
        let domain = state.store.get_setting("named_tunnel.domain");
        if let (Ok(Some(creds_str)), Ok(Some(tunnel_domain))) = (creds_json, domain) {
            match serde_json::from_str::<tunnel::TunnelCredentials>(&creds_str) {
                Ok(credentials) => {
                    info!(
                        tunnel_domain = %tunnel_domain,
                        tunnel_id = %credentials.tunnel_id,
                        "auto-connecting named tunnel from saved credentials"
                    );
                    let local_proxy_port = cfg.listen_http.port();
                    let local_suffix = cfg.domain_suffix.clone();
                    match tunnel::start_named_tunnel(
                        credentials,
                        tunnel_domain,
                        local_suffix,
                        local_proxy_port,
                        state.store.clone(),
                        Some(state.share_signer.clone()),
                    )
                    .await
                    {
                        Ok(handle) => {
                            *state.named_tunnel.lock() = Some(handle);
                            info!("named tunnel auto-connected");
                        }
                        Err(err) => {
                            error!(error = %err, "failed to auto-connect named tunnel");
                        }
                    }
                }
                Err(err) => {
                    error!(error = %err, "failed to parse saved named tunnel credentials");
                }
            }
        }
    }

    // Auto-reconnect per-app named tunnels
    {
        match state.store.list_app_tunnels() {
            Ok(apps) => {
                for app in apps {
                    if let (Some(creds_json), Some(domain)) =
                        (&app.app_tunnel_creds, &app.app_tunnel_domain)
                    {
                        let routing = tunnel::transport::TunnelRouting::FixedHost {
                            local_host: app.domain.0.clone(),
                            local_proxy_port: state.listen_http.port(),
                        };
                        match serde_json::from_str::<tunnel::TunnelCredentials>(creds_json) {
                            Ok(credentials) => {
                                info!(
                                    app_id = %app.id.0,
                                    domain = %domain,
                                    "auto-reconnecting per-app named tunnel"
                                );
                                if let Err(err) = tunnel::start_app_named_tunnel(
                                    state.app_tunnels.clone(),
                                    app.id.0.clone(),
                                    credentials,
                                    domain.clone(),
                                    routing,
                                )
                                .await
                                {
                                    error!(error = %err, app_id = %app.id.0, "failed to auto-reconnect app tunnel");
                                }
                            }
                            Err(err) => {
                                error!(error = %err, app_id = %app.id.0, "failed to parse app tunnel credentials");
                            }
                        }
                    }
                }
            }
            Err(err) => {
                error!(error = %err, "failed to list app tunnels for auto-reconnect");
            }
        }
    }

    // Auto-reconnect quick tunnels
    {
        match state.store.list_quick_tunnels() {
            Ok(apps) => {
                for app in apps {
                    let routing = tunnel::transport::TunnelRouting::FixedHost {
                        local_host: app.domain.0.clone(),
                        local_proxy_port: state.listen_http.port(),
                    };
                    info!(
                        app_id = %app.id.0,
                        "auto-reconnecting quick tunnel"
                    );
                    match tunnel::start_quick_tunnel(
                        state.tunnels.clone(),
                        app.id.0.clone(),
                        routing,
                    )
                    .await
                    {
                        Ok(hostname) => {
                            let url = format!("https://{hostname}");
                            let _ = state.store.update_tunnel_url(&app.id.0, Some(&url));
                            info!(app_id = %app.id.0, tunnel_url = %url, "quick tunnel auto-reconnected");
                        }
                        Err(err) => {
                            error!(error = %err, app_id = %app.id.0, "failed to auto-reconnect quick tunnel");
                        }
                    }
                }
            }
            Err(err) => {
                error!(error = %err, "failed to list quick tunnels for auto-reconnect");
            }
        }
    }

    let proxy_state = state.clone();
    let proxy_addr = cfg.listen_http;
    let proxy_pm = state.process_manager.clone();
    let proxy_task = tokio::spawn(async move {
        if let Err(err) = proxy::run_proxy(proxy_addr, proxy_state, proxy_pm).await {
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
                    if let Err(err) =
                        runtime::write_scan_warnings(&scan_state.scan_warnings_path, &stats)
                    {
                        error!(error = %err, "failed to write scan warnings");
                    }
                    if let Err(err) = scan_state.reload_routes() {
                        error!(error = %err, "failed to reload routes after scan");
                    } else {
                        debug!(
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
                    if let Err(err) =
                        runtime::write_scan_warnings(&watch_state.scan_warnings_path, &stats)
                    {
                        error!(error = %err, "failed to write scan warnings");
                    }
                    if let Err(err) = watch_state.reload_routes() {
                        error!(error = %err, "failed to reload routes after fs event");
                    } else {
                        debug!(
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

    let dedicated_state = state.clone();
    let dedicated_task = tokio::spawn(async move {
        run_dedicated_port_manager(dedicated_state).await;
    });

    let mdns_state = state.clone();
    let mdns_task = tokio::spawn(async move {
        if let Err(err) = mdns::run_mdns_responder(mdns_state).await {
            error!(error = %err, "mdns responder exited with error");
        }
    });

    let reaper_pm = state.process_manager.clone();
    let reaper_task = tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(30)).await;
            let mut pm = reaper_pm.lock().await;
            let reaped = pm.reap_idle();
            if reaped > 0 {
                info!(reaped, "reaped idle managed processes");
            }
        }
    });

    info!("coulson started");
    runtime::wait_for_shutdown().await;
    info!("shutdown signal received");

    {
        let mut pm = state.process_manager.lock().await;
        pm.shutdown_all();
    }
    tunnel::shutdown_all(&state.tunnels);
    tunnel::shutdown_all_app_tunnels(&state.app_tunnels);
    if let Some(handle) = state.named_tunnel.lock().take() {
        info!("shutting down named tunnel");
        handle.task.abort();
    }

    proxy_task.abort();
    control_task.abort();
    scan_task.abort();
    watch_task.abort();
    dedicated_task.abort();
    mdns_task.abort();
    reaper_task.abort();

    Ok(())
}

async fn run_dedicated_port_manager(state: SharedState) {
    let mut rx = state.route_tx.subscribe();
    let mut running: HashMap<u16, tokio::task::JoinHandle<()>> = HashMap::new();

    // Start initial dedicated proxies
    sync_dedicated_proxies(&state, &mut running);

    loop {
        match rx.recv().await {
            Ok(()) => sync_dedicated_proxies(&state, &mut running),
            Err(broadcast::error::RecvError::Lagged(_)) => {
                sync_dedicated_proxies(&state, &mut running);
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }

    for (_, handle) in running.drain() {
        handle.abort();
    }
}

fn sync_dedicated_proxies(
    state: &SharedState,
    running: &mut HashMap<u16, tokio::task::JoinHandle<()>>,
) {
    let wanted: HashSet<u16> = {
        let dp = state.dedicated_ports.read();
        dp.keys().copied().collect()
    };

    // Stop proxies for removed ports
    let current: HashSet<u16> = running.keys().copied().collect();
    for port in current.difference(&wanted) {
        if let Some(handle) = running.remove(port) {
            info!(port, "stopping dedicated proxy");
            handle.abort();
        }
    }

    // Start proxies for new ports
    for port in wanted.difference(&current) {
        let rules = {
            let dp = state.dedicated_ports.read();
            match dp.get(port) {
                Some(r) => Arc::clone(r),
                None => continue,
            }
        };
        let port = *port;
        info!(port, "starting dedicated proxy");
        let handle = tokio::task::spawn_blocking(move || {
            if let Err(err) = proxy::run_dedicated_proxy_blocking(port, rules) {
                error!(error = %err, port, "dedicated proxy exited with error");
            }
        });
        running.insert(port, handle);
    }
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
    let cfg = CoulsonConfig::load().context("failed to load config")?;

    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Serve => run_serve(cfg).await,
        Commands::Scan => run_scan_once(cfg),
        Commands::Ls {
            managed,
            manual,
            domain,
        } => {
            let filter = if managed {
                Some(true)
            } else if manual {
                Some(false)
            } else {
                None
            };
            run_ls(cfg, filter, domain)
        }
        Commands::Warnings => run_warnings(cfg),
        Commands::Add {
            name,
            target,
            port,
            tunnel,
        } => run_add(cfg, name, target, port, tunnel),
        Commands::Rm { name } => run_rm(cfg, name),
        Commands::Doctor => run_doctor(cfg),
        Commands::Share { name, expires } => run_share(cfg, name, expires),
        Commands::Unshare { name } => run_unshare(cfg, name),
    }
}

fn run_add(
    cfg: CoulsonConfig,
    name: Option<String>,
    target: Option<String>,
    port: Option<u16>,
    tunnel: bool,
) -> anyhow::Result<()> {
    match (name.as_deref(), target.as_deref()) {
        // Manual proxy mode: coulson add <name> <target>
        (Some(n), Some(t)) => run_add_manual(&cfg, n, t),
        // Directory project mode: coulson add [--port P]
        (None, None) => run_add_directory(&cfg, port, tunnel),
        // name only without target: treat as directory mode with --name override
        (Some(n), None) => run_add_directory_with_name(&cfg, n, port, tunnel),
        (None, Some(_)) => bail!("target requires a name: coulson add <name> <target>"),
    }
}

fn run_add_directory(cfg: &CoulsonConfig, port: Option<u16>, tunnel: bool) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let dir_name = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app");
    let name = scanner::sanitize_name(dir_name);
    run_add_directory_inner(cfg, &name, &cwd, port, tunnel)
}

fn run_add_directory_with_name(
    cfg: &CoulsonConfig,
    name: &str,
    port: Option<u16>,
    tunnel: bool,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let name = scanner::sanitize_name(name);
    run_add_directory_inner(cfg, &name, &cwd, port, tunnel)
}

fn run_add_directory_inner(
    cfg: &CoulsonConfig,
    name: &str,
    cwd: &std::path::Path,
    port: Option<u16>,
    tunnel: bool,
) -> anyhow::Result<()> {
    let link_path = cfg.apps_root.join(name);

    // Conflict check
    if link_path.exists() || link_path.symlink_metadata().is_ok() {
        let meta = std::fs::symlink_metadata(&link_path)?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&link_path)?;
            let resolved = if target.is_absolute() {
                target.clone()
            } else {
                cfg.apps_root.join(&target)
            };
            let resolved = resolved
                .canonicalize()
                .unwrap_or(resolved);
            let cwd_canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
            if resolved == cwd_canonical {
                println!("{} {name}.{} already added", "=".bold(), cfg.domain_suffix);
                return Ok(());
            }
            bail!(
                "{} already points to {}. Use a different name: coulson add <name>",
                link_path.display(),
                resolved.display()
            );
        } else {
            bail!(
                "{} already exists (not a symlink). Remove it manually first.",
                link_path.display()
            );
        }
    }

    // --port mode: create a powfile
    if let Some(p) = port {
        std::fs::create_dir_all(&cfg.apps_root)?;
        std::fs::write(&link_path, format!("{p}\n"))?;
        println!(
            "{} {name}.{} -> 127.0.0.1:{p}",
            "+".green().bold(), cfg.domain_suffix
        );
        println!("  {}", format!("http://{name}.{}:{}", cfg.domain_suffix, cfg.listen_http.port()).cyan());
        return Ok(());
    }

    // Try auto-detect app kind
    let manifest_path = cwd.join("coulson.json");
    let manifest: Option<serde_json::Value> = if manifest_path.is_file() {
        let data = std::fs::read_to_string(&manifest_path).ok();
        data.and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    };

    let registry = process::default_registry();
    if let Some((_provider, detected)) = registry.detect(cwd, manifest.as_ref()) {
        std::fs::create_dir_all(&cfg.apps_root)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(cwd, &link_path).with_context(|| {
            format!(
                "failed to create symlink {} -> {}",
                link_path.display(),
                cwd.display()
            )
        })?;
        println!(
            "{} {name}.{} ({}) -> {}",
            "+".green().bold(),
            cfg.domain_suffix,
            detected.kind,
            cwd.display()
        );
        println!("  {}", format!("http://{name}.{}:{}", cfg.domain_suffix, cfg.listen_http.port()).cyan());
    } else {
        // No auto-detect, still create symlink (scanner will parse coulson.routes etc.)
        std::fs::create_dir_all(&cfg.apps_root)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(cwd, &link_path).with_context(|| {
            format!(
                "failed to create symlink {} -> {}",
                link_path.display(),
                cwd.display()
            )
        })?;
        println!(
            "{} {name}.{} -> {}",
            "+".green().bold(),
            cfg.domain_suffix,
            cwd.display()
        );
        println!("  {}", format!("http://{name}.{}:{}", cfg.domain_suffix, cfg.listen_http.port()).cyan());
        println!("  {}", "Tip: use --port to specify a target port, or add coulson.json/coulson.routes".dimmed());
    }

    if tunnel {
        println!("  {}", "Note: --tunnel is not yet implemented".yellow());
    }

    Ok(())
}

fn run_add_manual(cfg: &CoulsonConfig, name: &str, target: &str) -> anyhow::Result<()> {
    let domain = if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.{}", cfg.domain_suffix)
    };

    let client = RpcClient::new(&cfg.control_socket);

    if target.starts_with('/') {
        // Unix socket
        client.call(
            "app.create_unix_socket",
            serde_json::json!({
                "name": name,
                "domain": domain,
                "socket_path": target,
            }),
        )?;
        println!("{} {domain} -> unix:{target}", "+".green().bold());
    } else if let Ok(port) = target.parse::<u16>() {
        // Port only
        client.call(
            "app.create_tcp",
            serde_json::json!({
                "name": name,
                "domain": domain,
                "target_host": "127.0.0.1",
                "target_port": port,
            }),
        )?;
        println!("{} {domain} -> 127.0.0.1:{port}", "+".green().bold());
    } else if let Some((host, port_str)) = target.rsplit_once(':') {
        // host:port
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid port in target: {target}"))?;
        client.call(
            "app.create_tcp",
            serde_json::json!({
                "name": name,
                "domain": domain,
                "target_host": host,
                "target_port": port,
            }),
        )?;
        println!("{} {domain} -> {host}:{port}", "+".green().bold());
    } else {
        bail!("invalid target: {target}. Expected: port, host:port, or /path/to/socket");
    }

    println!("  {}", format!("http://{domain}:{}", cfg.listen_http.port()).cyan());
    Ok(())
}

fn run_rm(cfg: CoulsonConfig, name: Option<String>) -> anyhow::Result<()> {
    match name {
        Some(n) => run_rm_by_name(&cfg, &n),
        None => run_rm_cwd(&cfg),
    }
}

fn run_rm_by_name(cfg: &CoulsonConfig, name: &str) -> anyhow::Result<()> {
    // Strip domain suffix if present
    let bare_name = name
        .strip_suffix(&format!(".{}", cfg.domain_suffix))
        .unwrap_or(name);

    let mut removed_file = false;
    let mut removed_db = false;

    // Check apps_root for file/symlink
    let link_path = cfg.apps_root.join(bare_name);
    if link_path.symlink_metadata().is_ok() {
        std::fs::remove_file(&link_path).with_context(|| {
            format!("failed to remove {}", link_path.display())
        })?;
        removed_file = true;
    }

    // Best-effort RPC delete
    let client = RpcClient::new(&cfg.control_socket);
    if let Ok(result) = client.call("app.list", serde_json::json!({})) {
        if let Some(apps) = result.get("apps").and_then(|a| a.as_array()) {
            let domain_match = format!("{bare_name}.{}", cfg.domain_suffix);
            for app in apps {
                let matches = app.get("name").and_then(|n| n.as_str()) == Some(bare_name)
                    || app.get("domain").and_then(|d| d.as_str()) == Some(&domain_match)
                    || app.get("domain").and_then(|d| d.as_str()) == Some(bare_name);
                if matches {
                    if let Some(app_id) = app.get("id").and_then(|i| i.as_str()) {
                        if client
                            .call("app.delete", serde_json::json!({ "app_id": app_id }))
                            .is_ok()
                        {
                            removed_db = true;
                        }
                    }
                }
            }
        }
    }

    if !removed_file && !removed_db {
        bail!("app not found: {name}");
    }

    if removed_file {
        println!("{} {} from {}", "-".red().bold(), bare_name, cfg.apps_root.display());
    }
    if removed_db {
        println!("{} {bare_name} from database", "-".red().bold());
    }
    Ok(())
}

fn run_rm_cwd(cfg: &CoulsonConfig) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd_canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.clone());

    let entries = match std::fs::read_dir(&cfg.apps_root) {
        Ok(e) => e,
        Err(_) => bail!("no app found pointing to {}", cwd.display()),
    };

    let mut found = false;
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.file_type().is_symlink() {
            continue;
        }
        let target = match std::fs::read_link(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let resolved = if target.is_absolute() {
            target.clone()
        } else {
            cfg.apps_root.join(&target)
        };
        let resolved = resolved.canonicalize().unwrap_or(resolved);
        if resolved == cwd_canonical {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            std::fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
            println!("{} {} from {}", "-".red().bold(), name, cfg.apps_root.display());

            // Best-effort RPC delete
            let client = RpcClient::new(&cfg.control_socket);
            if let Ok(result) = client.call("app.list", serde_json::json!({})) {
                if let Some(apps) = result.get("apps").and_then(|a| a.as_array()) {
                    let domain_match = format!("{name}.{}", cfg.domain_suffix);
                    for app in apps {
                        let matches =
                            app.get("name").and_then(|n| n.as_str()) == Some(name)
                                || app.get("domain").and_then(|d| d.as_str())
                                    == Some(&domain_match);
                        if matches {
                            if let Some(app_id) = app.get("id").and_then(|i| i.as_str()) {
                                if client
                                    .call(
                                        "app.delete",
                                        serde_json::json!({ "app_id": app_id }),
                                    )
                                    .is_ok()
                                {
                                    println!("{} {name} from database", "-".red().bold());
                                }
                            }
                        }
                    }
                }
            }

            found = true;
        }
    }

    if !found {
        bail!("no app found pointing to {}", cwd.display());
    }
    Ok(())
}

fn run_share(cfg: CoulsonConfig, name: String, expires: String) -> anyhow::Result<()> {
    let duration = share::parse_duration(&expires)?;

    let domain = if name.contains('.') {
        name.clone()
    } else {
        format!("{name}.{}", cfg.domain_suffix)
    };

    let domain_prefix = crate::store::domain_to_db(&domain, &cfg.domain_suffix);

    // Get tunnel domain from daemon
    let client = RpcClient::new(&cfg.control_socket);
    let result = client
        .call("named_tunnel.status", serde_json::json!({}))
        .context("failed to query named tunnel status. Is the daemon running with a tunnel?")?;

    let tunnel_domain = result
        .get("tunnel_domain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no named tunnel running. Start one first with `coulson tunnel connect`"))?
        .to_string();

    // Build state to access the signer
    let state = build_state(&cfg)?;

    // Enable share_auth for this app
    if !state.store.set_share_auth(&domain_prefix, true)? {
        bail!("app not found: {domain}");
    }

    let token = state.share_signer.create_token(&domain, duration)?;

    let share_url = format!(
        "https://{domain_prefix}.{tunnel_domain}/_coulson/auth?t={token}"
    );

    println!("{share_url}");
    Ok(())
}

fn run_unshare(cfg: CoulsonConfig, name: String) -> anyhow::Result<()> {
    let domain = if name.contains('.') {
        name.clone()
    } else {
        format!("{name}.{}", cfg.domain_suffix)
    };
    let domain_prefix = crate::store::domain_to_db(&domain, &cfg.domain_suffix);

    let state = build_state(&cfg)?;
    if !state.store.set_share_auth(&domain_prefix, false)? {
        bail!("app not found: {domain}");
    }
    println!("share auth disabled for {domain}");
    Ok(())
}
