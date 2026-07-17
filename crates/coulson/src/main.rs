mod certs;
mod config;
mod control;
mod credentials;
mod dashboard;
mod domain;
mod forward;
mod hooks;
mod launchd;
mod mdns;
mod process;
mod proxy;
mod rpc_client;
mod runtime;
mod scanner;
pub mod service;
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

use crate::config::{CoulsonConfig, LOCALHOST_SUFFIX};
use crate::domain::{AppSpec, BackendTarget, TunnelMode};
use crate::hooks::{HookContextFactory, HookManager};
use crate::process::{ProcessManagerHandle, ProviderRegistry};
use crate::rpc_client::RpcClient;
use crate::share::ShareSigner;
use crate::store::AppRepository;

#[derive(Clone, Debug, serde::Serialize)]
pub struct InspectEvent {
    pub app_id: i64,
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub query_string: Option<String>,
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub timestamp: i64,
}

/// Maps dedicated listen_port → app domain for forwarding to main proxy.
type DedicatedPortMap = HashMap<u16, String>;

#[derive(Clone, PartialEq)]
pub struct RouteRule {
    pub target: BackendTarget,
    pub path_prefix: Option<String>,
    pub timeout_ms: Option<u64>,
    pub cors_enabled: bool,
    pub force_https: bool,
    pub basic_auth_user: Option<String>,
    pub basic_auth_pass: Option<String>,
    pub spa_rewrite: bool,
    pub listen_port: Option<u16>,
    /// Optional static file root to try before forwarding to the backend.
    /// For Managed apps this is `{app_root}/public` when the directory exists.
    pub static_root: Option<String>,
    pub app_id: Option<i64>,
    pub inspect_enabled: bool,
    pub lan_access: bool,
}

impl RouteRule {
    /// Build a `RouteRule` from an `AppSpec`. Used by `reload_routes` (hot
    /// route table) and by the replay pipeline (which must work even when the
    /// app is disabled and therefore absent from the route table).
    pub fn from_app_spec(app: AppSpec) -> Self {
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
        RouteRule {
            app_id: Some(app.id.0),
            inspect_enabled: app.inspect_enabled,
            lan_access: app.lan_access,
            target: app.target,
            path_prefix: app.path_prefix,
            timeout_ms: app.timeout_ms,
            cors_enabled: app.cors_enabled,
            force_https: app.force_https,
            basic_auth_user: app.basic_auth_user,
            basic_auth_pass: app.basic_auth_pass,
            spa_rewrite: app.spa_rewrite,
            listen_port: app.listen_port,
            static_root,
        }
    }
}

#[derive(Clone)]
pub struct SharedState {
    pub store: Arc<AppRepository>,
    pub routes: Arc<RwLock<HashMap<String, Vec<RouteRule>>>>,
    pub dedicated_ports: Arc<RwLock<DedicatedPortMap>>,
    pub route_tx: broadcast::Sender<()>,
    pub change_tx: broadcast::Sender<String>,
    pub domain_suffix: String,
    pub apps_root: std::path::PathBuf,
    pub scan_warnings_path: std::path::PathBuf,
    pub sqlite_path: std::path::PathBuf,
    pub tunnels: tunnel::TunnelManager,
    pub named_tunnel: Arc<Mutex<Option<tunnel::NamedTunnelHandle>>>,
    pub tunnel_conns: tunnel::TunnelConnections,
    pub app_tunnels: tunnel::AppNamedTunnelManager,
    pub listen_http: std::net::SocketAddr,
    pub listen_https: Option<std::net::SocketAddr>,
    pub process_manager: ProcessManagerHandle,
    pub provider_registry: Arc<ProviderRegistry>,
    pub share_signer: Arc<ShareSigner>,
    pub inspect_max_requests: usize,
    pub inspect_tx: broadcast::Sender<InspectEvent>,
    pub log_tx: broadcast::Sender<crate::process::LogLine>,
    pub network_change_tx: broadcast::Sender<()>,
    pub certs_dir: std::path::PathBuf,
    pub runtime_dir: std::path::PathBuf,
    pub hook_manager: Arc<HookManager>,
    pub inspector_username: Option<String>,
    pub inspector_password: Option<String>,
    /// Cached privileged-port status with TTL to avoid per-request disk I/O.
    forward_cache: Arc<Mutex<(bool, std::time::Instant)>>,
}

impl SharedState {
    const FORWARD_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

    fn has_privileged_http(&self) -> bool {
        if !cfg!(target_os = "macos") {
            return false;
        }
        let mut cache = self.forward_cache.lock();
        if cache.1.elapsed() < Self::FORWARD_CACHE_TTL {
            return cache.0;
        }
        let val = is_forward_configured_for_port(self.listen_http.port())
            || is_pf_configured_quick(&self.listen_http, &self.listen_https);
        *cache = (val, std::time::Instant::now());
        val
    }

    fn has_privileged_https(&self) -> bool {
        if !cfg!(target_os = "macos") {
            return false;
        }
        let https_port = match self.listen_https {
            Some(addr) => addr.port(),
            None => return false,
        };
        is_forward_https_configured_for_port(https_port)
            || is_pf_configured_quick(&self.listen_http, &self.listen_https)
    }

    pub fn use_default_http_port(&self) -> bool {
        self.listen_http.port() == 80 || self.has_privileged_http()
    }

    pub fn use_default_https_port(&self) -> bool {
        self.listen_https.is_some()
            && (self.listen_https.map(|a| a.port()) == Some(443) || self.has_privileged_https())
    }

    /// Build a `HookContextFactory` using the current runtime port/suffix state.
    /// Uses the cached PF-forwarding check so URLs reflect privileged-port status.
    pub fn hook_factory(&self) -> HookContextFactory {
        HookContextFactory::new(
            Arc::clone(&self.store),
            self.listen_http.port(),
            self.listen_https.map(|a| a.port()),
            self.use_default_http_port(),
            self.use_default_https_port(),
            self.domain_suffix.clone(),
        )
    }

    pub fn reload_routes(&self) -> anyhow::Result<bool> {
        let enabled_apps = self.store.list_enabled()?;
        let mut table: HashMap<String, Vec<RouteRule>> = HashMap::new();
        let mut port_domains: HashMap<u16, String> = HashMap::new();
        for app in enabled_apps {
            if let Some(port) = app.listen_port {
                port_domains.insert(port, app.domain.0.clone());
            }
            let domain = app.domain.0.clone();
            let cname = app.cname.clone();
            let rule = RouteRule::from_app_spec(app);
            // Register .localhost alias so apps are reachable via myapp.localhost
            if self.domain_suffix != LOCALHOST_SUFFIX {
                if let Some(prefix) = domain.strip_suffix(&format!(".{}", self.domain_suffix)) {
                    let localhost_domain = format!("{prefix}.{LOCALHOST_SUFFIX}");
                    table
                        .entry(localhost_domain)
                        .or_default()
                        .push(rule.clone());
                }
            }
            // Register cname alias so apps are reachable via custom domain
            if let Some(ref cname) = cname {
                table.entry(cname.clone()).or_default().push(rule.clone());
            }
            table.entry(domain).or_default().push(rule);
        }
        for rules in table.values_mut() {
            rules.sort_by(|a, b| {
                let a_len = a.path_prefix.as_ref().map(|s| s.len()).unwrap_or(0);
                let b_len = b.path_prefix.as_ref().map(|s| s.len()).unwrap_or(0);
                b_len.cmp(&a_len)
            });
        }
        let changed = {
            let current = self.routes.read();
            *current != table
        };
        *self.routes.write() = table;

        // Update dedicated port mappings
        let ports_changed = {
            let current = self.dedicated_ports.read();
            *current != port_domains
        };
        if ports_changed {
            *self.dedicated_ports.write() = port_domains;
        }

        if changed || ports_changed {
            let _ = self.route_tx.send(());
        }
        Ok(changed || ports_changed)
    }
}

#[derive(Parser)]
#[command(name = "coulson", about = "Local development gateway", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon (proxy + control + scanner)
    Serve,
    /// One-shot scan of apps directory
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
        /// App name, domain, or bare port
        name: Option<String>,
        /// Target: port, host:port, or /path/to/socket
        target: Option<String>,
        /// Link to app directory (creates symlink for CWD association)
        #[arg(long)]
        link: Option<std::path::PathBuf>,
        /// Also start a quick tunnel after adding
        #[arg(long)]
        tunnel: bool,
    },
    /// Remove an app
    #[command(alias = "dismiss")]
    Rm {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
    },
    /// Forward privileged ports via launchd socket activation (80/443 -> high ports)
    Forward {
        /// Target address for HTTP (port 80)
        #[arg(long, default_value = "127.0.0.1:18080")]
        http_target: std::net::SocketAddr,
        /// Target address for HTTPS (port 443)
        #[arg(long, default_value = "127.0.0.1:18443")]
        https_target: std::net::SocketAddr,
    },
    /// Check system health
    Doctor {
        /// Also check port forwarding configuration
        #[arg(long)]
        pf: bool,
    },
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
    /// Show logs for a managed app
    Logs {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
        /// Follow log output (like tail -f)
        #[arg(short, long)]
        follow: bool,
        /// Number of lines to show (default: 100)
        #[arg(short = 'n', long, default_value = "100")]
        lines: usize,
        /// Print the log file path and exit
        #[arg(long)]
        path: bool,
    },
    /// Show the resolved environment a managed app's web process would receive
    Env {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
        /// Print as plain KEY=value lines (no source column)
        #[arg(long)]
        bare: bool,
        /// Print as JSON (array of {key, value, source})
        #[arg(long)]
        json: bool,
        /// Show the would-be env (re-resolved now) instead of the running process
        #[arg(long)]
        preview: bool,
        /// With --preview, do not fetch env_url (offline)
        #[arg(long)]
        no_remote: bool,
    },
    /// Show running managed processes
    Ps,
    /// Start a managed process
    Start {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
    },
    /// Stop a managed process
    Stop {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
    },
    /// Restart a managed process (whole group, or one type: app:worker, :worker)
    Restart {
        /// App name or domain, optionally with :type (omit name to match CWD)
        name: Option<String>,
    },
    /// Trust the Coulson CA certificate (add to macOS login keychain)
    Trust {
        /// Install launchd forwarding daemon (80/443 -> Coulson listen ports)
        #[arg(long)]
        forward: bool,
        /// (deprecated, alias for --forward) Set up port forwarding
        #[arg(long, hide = true)]
        pf: bool,
        /// Force re-apply even if already configured
        #[arg(long)]
        force: bool,
    },
    /// Open app URL in default browser
    Open {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
    },
    /// Attach to a managed process's tmux session (Ctrl-B D to detach)
    Attach {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
    },
    /// Manage tunnels
    Tunnel {
        #[command(subcommand)]
        action: TunnelCommands,
    },
}

#[derive(Subcommand)]
enum TunnelCommands {
    /// Show tunnel status
    Status,
    /// Activate tunnel for an app
    Start {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
        /// Tunnel mode: quick, global, or named
        #[arg(long)]
        mode: Option<String>,
    },
    /// Deactivate tunnel for an app (preserves config)
    Stop {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
    },
    /// Connect global named tunnel
    Connect {
        /// Tunnel token (from Cloudflare dashboard)
        #[arg(long)]
        token: Option<String>,
        /// Tunnel domain
        #[arg(long)]
        domain: Option<String>,
    },
    /// Disconnect global named tunnel
    Disconnect,
    /// Create a global named tunnel via Cloudflare API
    Setup {
        /// Tunnel domain
        #[arg(long)]
        domain: String,
        /// Tunnel name (defaults to coulson-<domain>)
        #[arg(long)]
        tunnel_name: Option<String>,
        /// Cloudflare API token (saved to keychain after first use)
        #[arg(long)]
        api_token: Option<String>,
        /// Cloudflare account ID (saved to DB after first use)
        #[arg(long)]
        account_id: Option<String>,
    },
    /// Delete the global named tunnel via Cloudflare API
    Teardown {
        /// Cloudflare API token (reads from keychain if omitted)
        #[arg(long)]
        api_token: Option<String>,
    },
    /// Save a Cloudflare API token to keychain
    Login {
        /// API token (Account > Cloudflare Tunnel > Edit, Zone > DNS > Edit)
        token: String,
    },
    /// Remove saved CF API token from keychain
    Logout,
    /// Connect a per-app named tunnel using a Cloudflare tunnel token
    AppSetup {
        /// App name or domain
        name: String,
        /// Tunnel domain
        #[arg(long)]
        domain: String,
        /// Cloudflare tunnel token (from dashboard or `cloudflared tunnel token`)
        #[arg(long)]
        token: Option<String>,
    },
    /// Disconnect a per-app named tunnel
    AppTeardown {
        /// App name or domain
        name: String,
    },
}

fn build_state(cfg: &CoulsonConfig) -> anyhow::Result<SharedState> {
    runtime::ensure_runtime_paths(cfg)?;

    let (route_tx, _rx) = broadcast::channel(32);
    let (change_tx, _) = broadcast::channel::<String>(32);

    let mut store = AppRepository::new(&cfg.sqlite_path, &cfg.domain_suffix)?;
    store.set_change_tx(change_tx.clone());
    let store = Arc::new(store);
    store.init_schema()?;
    store.migrate_domain_to_prefix()?;

    let share_signer = Arc::new(ShareSigner::load_or_generate(&store)?);
    let (inspect_tx, _) = broadcast::channel(256);
    let (log_tx, _) = broadcast::channel::<crate::process::LogLine>(512);
    let (network_change_tx, _) = broadcast::channel(4);
    let idle_timeout = Duration::from_secs(cfg.idle_timeout_secs);
    let registry = Arc::new(process::default_registry());
    let hook_manager = Arc::new(HookManager::new(
        cfg.apps_root.join("hooks"),
        cfg.hook_timeout_secs,
    ));
    let pm_use_default_http = cfg.listen_http.port() == 80
        || is_forward_configured_for_port(cfg.listen_http.port())
        || is_pf_configured_quick(&cfg.listen_http, &cfg.listen_https);
    let pm_use_default_https = cfg.listen_https.is_some()
        && (cfg.listen_https.map(|a| a.port()) == Some(443)
            || cfg
                .listen_https
                .map(|a| is_forward_https_configured_for_port(a.port()))
                .unwrap_or(false)
            || is_pf_configured_quick(&cfg.listen_http, &cfg.listen_https));
    let pm_hook_factory = HookContextFactory::new(
        Arc::clone(&store),
        cfg.listen_http.port(),
        cfg.listen_https.map(|a| a.port()),
        pm_use_default_http,
        pm_use_default_https,
        cfg.domain_suffix.clone(),
    );
    let process_manager = process::new_process_manager(process::ProcessManagerConfig {
        idle_timeout,
        registry: Arc::clone(&registry),
        runtime_dir: cfg.runtime_dir.clone(),
        backend: cfg.process_backend,
        hook_manager: Arc::clone(&hook_manager),
        hook_factory: pm_hook_factory,
        log_tx: log_tx.clone(),
    });

    Ok(SharedState {
        store,
        routes: Arc::new(RwLock::new(HashMap::new())),
        dedicated_ports: Arc::new(RwLock::new(HashMap::new())),
        route_tx,
        change_tx,
        domain_suffix: cfg.domain_suffix.clone(),
        apps_root: cfg.apps_root.clone(),
        scan_warnings_path: cfg.scan_warnings_path.clone(),
        sqlite_path: cfg.sqlite_path.clone(),
        tunnels: tunnel::new_tunnel_manager(),
        named_tunnel: Arc::new(Mutex::new(None)),
        tunnel_conns: tunnel::new_tunnel_connections(),
        app_tunnels: tunnel::new_app_tunnel_manager(),
        listen_http: cfg.listen_http,
        listen_https: cfg.listen_https,
        process_manager,
        provider_registry: registry,
        share_signer,
        inspect_max_requests: cfg.inspect_max_requests,
        inspect_tx,
        log_tx: log_tx.clone(),
        network_change_tx,
        certs_dir: cfg.certs_dir.clone(),
        runtime_dir: cfg.runtime_dir.clone(),
        hook_manager,
        inspector_username: cfg.inspector_username.clone(),
        inspector_password: cfg.inspector_password.clone(),
        forward_cache: Arc::new(Mutex::new((
            is_forward_configured_for_port(cfg.listen_http.port()) || is_pf_configured(cfg),
            std::time::Instant::now(),
        ))),
    })
}

fn run_scan_once(cfg: CoulsonConfig) -> anyhow::Result<()> {
    let state = build_state(&cfg)?;
    let result = scanner::sync_from_apps_root(&state)?;
    runtime::write_scan_warnings(&state.scan_warnings_path, &result.stats)?;
    state.reload_routes()?;
    // No hook firing here: `coulson scan` is offline tooling without a running
    // daemon, so app URLs are not reachable and hooks would be meaningless.
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "ok": true,
            "scan": result.stats
        }))?
    );
    Ok(())
}

fn run_ls(cfg: CoulsonConfig, managed: Option<bool>, domain: Option<String>) -> anyhow::Result<()> {
    let state = build_state(&cfg)?;
    let apps = state.store.list_filtered(managed, domain.as_deref())?;

    if apps.is_empty() {
        println!("No apps found.");
        return Ok(());
    }

    let cwd_app = resolve_app_name(&cfg, None).ok();
    let rows: Vec<AppRow> = apps
        .iter()
        .map(|app| {
            let status = if app.enabled {
                "enabled".green().to_string()
            } else {
                "disabled".dimmed().to_string()
            };
            let is_cwd = cwd_app.as_deref() == Some(app.name.as_str());
            let marker = if is_cwd {
                format!("{} ", "→".green())
            } else {
                "  ".to_string()
            };
            AppRow {
                name: format!("{marker}{}", app.name.bold()),
                domain: app.domain.0.cyan().to_string(),
                kind: dashboard::render::effective_kind_label(app.kind, &app.target).to_string(),
                target: app.target.to_url_base().dimmed().to_string(),
                status,
            }
        })
        .collect();

    use tabled::settings::Style;
    let table = tabled::Table::new(&rows).with(Style::blank()).to_string();
    println!("{table}");

    if let Some(ref name) = cwd_app {
        if let Some(app) = apps.iter().find(|a| a.name == *name) {
            let port = daemon_http_port(&cfg);
            let ctx = domain::UrlContext {
                http_port: port,
                https_port: None,
                use_default_http_port: state.use_default_http_port(),
                use_default_https_port: state.use_default_https_port(),
                domain_suffix: &cfg.domain_suffix,
                global_tunnel_domain: None,
            };
            println!();
            for url in app.urls(&ctx) {
                println!("  {}", url.cyan());
            }
        }
    }

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

fn run_doctor(cfg: CoulsonConfig, check_pf: bool) -> anyhow::Result<()> {
    println!("{}", "Coulson Doctor".bold());
    println!();

    let mut issues = 0u32;

    // 1. apps_root
    if cfg.apps_root.is_dir() {
        let count = std::fs::read_dir(&cfg.apps_root)
            .map(|entries| entries.flatten().count())
            .unwrap_or(0);
        print_check(
            true,
            &format!(
                "apps_root exists ({}), {count} entries",
                cfg.apps_root.display()
            ),
        );
    } else {
        print_check(
            false,
            &format!("apps_root missing: {}", cfg.apps_root.display()),
        );
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
        print_check(
            false,
            &format!("database not found: {}", cfg.sqlite_path.display()),
        );
        issues += 1;
    }

    // 3. Daemon (control socket ping)
    let client = RpcClient::new(&cfg.control_socket);
    match client.call("health.ping", serde_json::json!({})) {
        Ok(_) => print_check(true, "daemon running (health.ping OK)"),
        Err(_) => {
            print_check(
                false,
                &format!("daemon not reachable at {}", cfg.control_socket.display()),
            );
            issues += 1;
        }
    }

    // 4. Listen port
    match std::net::TcpStream::connect_timeout(&cfg.listen_http, std::time::Duration::from_secs(2))
    {
        Ok(_) => print_check(true, &format!("proxy port {} reachable", cfg.listen_http)),
        Err(_) => {
            print_check(
                false,
                &format!("proxy port {} not reachable", cfg.listen_http),
            );
            issues += 1;
        }
    }

    // 5. DNS resolution — test the bare domain suffix (dashboard host)
    match dns_resolves_to_localhost(&cfg.domain_suffix) {
        Some(true) => print_check(
            true,
            &format!("DNS {} resolves to localhost", cfg.domain_suffix),
        ),
        Some(false) => {
            print_check(
                false,
                &format!("DNS {} does NOT resolve to localhost", cfg.domain_suffix),
            );
            issues += 1;
        }
        None => {
            print_check(
                false,
                &format!(
                    "DNS {} resolution failed (mDNS not working?)",
                    cfg.domain_suffix
                ),
            );
            issues += 1;
        }
    }

    // 6. CF API token (keychain)
    match credentials::get_api_token() {
        Ok(Some(_)) => print_check(true, "CF API token saved in keychain"),
        Ok(None) => print_check(true, "CF API token not set (OK if not using CF tunnels)"),
        Err(e) => {
            print_check(false, &format!("keychain access error: {e}"));
            issues += 1;
        }
    }

    // 7. Scan warnings
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

    // 8. LAN access (per-app)
    if cfg.listen_http.ip().is_unspecified() {
        print_check(
            true,
            &format!(
                "proxy on {} (per-app LAN access available)",
                cfg.listen_http
            ),
        );
    } else if cfg.listen_http.ip().is_loopback() {
        print_check(
            true,
            &format!(
                "proxy on {} (loopback only, per-app LAN access requires 0.0.0.0)",
                cfg.listen_http
            ),
        );
    } else {
        print_check(true, &format!("proxy on {}", cfg.listen_http));
    }

    // 9. TLS certificates
    if cfg.listen_https.is_some() {
        let ca_path = cfg.certs_dir.join("ca.crt");
        let cert_path = cfg.certs_dir.join("server.crt");
        let key_path = cfg.certs_dir.join("server.key");
        if ca_path.is_file() && cert_path.is_file() && key_path.is_file() {
            print_check(
                true,
                &format!("TLS certificates exist ({})", cfg.certs_dir.display()),
            );
            // Check if CA in macOS keychain matches the one on disk
            check_keychain_ca(&ca_path, &mut issues);
        } else {
            print_check(
                false,
                &format!(
                    "TLS certificate files missing in {}",
                    cfg.certs_dir.display()
                ),
            );
            issues += 1;
        }
    } else {
        print_check(true, "HTTPS listener disabled (no TLS check needed)");
    }

    // 10. port forwarding (optional)
    if check_pf {
        #[cfg(target_os = "macos")]
        {
            let plist_exists = std::path::Path::new(FORWARD_PLIST_PATH).exists();
            let service_loaded = is_forward_service_loaded();
            if plist_exists && service_loaded {
                let plist_has_https = is_forward_https_configured();
                let needs_https = cfg.listen_https.is_some();
                let http_port_matches = is_forward_configured_for_port(cfg.listen_http.port());
                let https_port_matches = cfg
                    .listen_https
                    .map(|a| is_forward_https_configured_for_port(a.port()))
                    .unwrap_or(true);
                if needs_https != plist_has_https {
                    let installed = if plist_has_https { "80/443" } else { "80" };
                    let expected = if needs_https { "80/443" } else { "80" };
                    print_check(
                        false,
                        &format!(
                            "forwarding daemon mismatch: installed={installed}, expected={expected}"
                        ),
                    );
                    print_warn("run: sudo coulson trust --forward --force");
                    issues += 1;
                } else if !http_port_matches || !https_port_matches {
                    print_check(
                        false,
                        "forwarding daemon target port does not match current listen port",
                    );
                    print_warn("run: sudo coulson trust --forward --force");
                    issues += 1;
                } else {
                    let fwd_desc = if needs_https {
                        "launchd forwarding daemon installed (80/443)"
                    } else {
                        "launchd forwarding daemon installed (80)"
                    };
                    print_check(true, fwd_desc);
                }
            } else if plist_exists && !service_loaded {
                print_check(
                    false,
                    "forwarding daemon plist exists but service not loaded",
                );
                print_warn("run: sudo coulson trust --forward --force");
                issues += 1;
            } else if is_pf_configured(&cfg) {
                let http_port = cfg.listen_http.port();
                let https_port = cfg.listen_https.map(|a| a.port());
                print_check(
                    true,
                    &format!(
                        "pf forwarding configured (80 -> {http_port}, 443 -> {})",
                        https_port.map_or("n/a".to_string(), |p| p.to_string())
                    ),
                );
                print_warn("pf forwarding is deprecated, consider: sudo coulson trust --forward");
            } else {
                print_check(false, "port forwarding not configured");
                print_warn("run: sudo coulson trust --forward");
                issues += 1;
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            print_check(true, "port forwarding check skipped (not macOS)");
        }
    }

    // 10. tmux process backend
    {
        use crate::config::ProcessBackend;
        let tmux_path = std::process::Command::new("which")
            .arg("tmux")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        match (tmux_path, cfg.process_backend) {
            (Some(path), _) => {
                let version = std::process::Command::new("tmux")
                    .arg("-V")
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                let backend_label = match cfg.process_backend {
                    ProcessBackend::Auto => "auto → tmux",
                    ProcessBackend::Tmux => "tmux",
                    ProcessBackend::Direct => "direct (tmux available but not used)",
                };
                print_check(
                    true,
                    &format!("tmux: {version} ({path}), backend: {backend_label}"),
                );
            }
            (None, ProcessBackend::Tmux) => {
                print_check(false, "tmux not found but COULSON_PROCESS_BACKEND=tmux");
                issues += 1;
            }
            (None, _) => {
                print_check(true, "tmux not found, using direct process backend");
            }
        }
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

/// Compare CA cert on disk with the one trusted in macOS system keychain.
/// Uses `security find-certificate -p` to export the keychain cert as PEM and compares directly.
#[cfg(target_os = "macos")]
fn check_keychain_ca(ca_path: &std::path::Path, issues: &mut u32) {
    use std::process::Command;

    let disk_pem = match std::fs::read_to_string(ca_path) {
        Ok(p) => p.trim().to_string(),
        Err(_) => {
            print_check(false, "cannot read CA cert from disk");
            *issues += 1;
            return;
        }
    };

    let output = Command::new("security")
        .args([
            "find-certificate",
            "-c",
            "Coulson Dev CA",
            "-p",
            "/Library/Keychains/System.keychain",
        ])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let kc_pem = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if disk_pem == kc_pem {
                print_check(true, "CA cert in system keychain matches disk");
            } else {
                print_check(
                    false,
                    "CA cert in system keychain does NOT match disk (stale)",
                );
                print_warn("run: sudo security delete-certificate -c \"Coulson Dev CA\" /Library/Keychains/System.keychain");
                print_warn(&format!(
                    "then: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
                    ca_path.display()
                ));
                *issues += 1;
            }
        }
        _ => {
            print_warn("CA cert not found in system keychain (HTTPS will show cert warnings)");
            print_warn(&format!(
                "run: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
                ca_path.display()
            ));
            *issues += 1;
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn check_keychain_ca(ca_path: &std::path::Path, issues: &mut u32) {
    if let Some((installed, _)) = linux_ca_installed(ca_path) {
        if installed {
            print_check(true, "CA cert installed in system trust store");
        } else {
            print_check(false, "CA cert not installed in system trust store");
            print_warn("run: sudo coulson trust");
            *issues += 1;
        }
    }
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
    // Only the daemon should clean up a stale control socket.
    if cfg.control_socket.exists() {
        std::fs::remove_file(&cfg.control_socket)?;
    }

    // Apply the configured tunnel request-body cap before any tunnel starts.
    // Saturate rather than wrap/panic on an absurd config value (a wrap could
    // silently shrink the cap instead of enlarging it).
    tunnel::proxy::set_max_tunnel_request_body(cfg.max_tunnel_body_mb.saturating_mul(1024 * 1024));

    let state = build_state(&cfg)?;

    let startup_scan = scanner::sync_from_apps_root(&state)?;
    runtime::write_scan_warnings(&state.scan_warnings_path, &startup_scan.stats)?;
    state.reload_routes()?;
    // app_add hooks deferred until after proxy is listening (see below).
    info!(
        discovered = startup_scan.stats.discovered,
        inserted = startup_scan.stats.inserted,
        updated = startup_scan.stats.updated,
        skipped_manual = startup_scan.stats.skipped_manual,
        pruned = startup_scan.stats.pruned,
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
                        state.tunnel_conns.clone(),
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
                                    app.id.0,
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
                    match tunnel::start_quick_tunnel(state.tunnels.clone(), app.id.0, routing).await
                    {
                        Ok(hostname) => {
                            let url = format!("https://{hostname}");
                            let _ = state.store.update_tunnel_url(app.id.0, Some(&url));
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

    // TLS certificate setup with dynamic per-SNI cert callback.
    // The wildcard cert covers *.{domain_suffix}; .localhost certs are
    // generated on demand (browsers reject *.localhost wildcards per PSL).
    let tls_config = if let Some(https_addr) = cfg.listen_https {
        match certs::CertManager::ensure(&cfg.certs_dir, &cfg.domain_suffix) {
            Ok(cm) => match cm.build_sni_provider(&cfg.domain_suffix) {
                Ok(sni_provider) => Some(proxy::TlsConfig {
                    bind: https_addr.to_string(),
                    ca_path: cm.ca_path().to_string(),
                    sni_callback: certs::SniCallback(sni_provider),
                }),
                Err(err) => {
                    error!(error = %err, "failed to build TLS SNI provider, HTTPS disabled");
                    None
                }
            },
            Err(err) => {
                error!(error = %err, "failed to initialize TLS certificates, HTTPS disabled");
                None
            }
        }
    } else {
        None
    };

    let proxy_state = state.clone();
    let proxy_addr = cfg.listen_http;
    let proxy_pm = state.process_manager.clone();
    let proxy_task = tokio::spawn(async move {
        if let Err(err) = proxy::run_proxy(proxy_addr, tls_config, proxy_state, proxy_pm).await {
            error!(error = %err, "proxy exited with error");
        }
    });

    // Fire app_add hooks after proxy task is spawned. Hooks run via
    // tokio::spawn + shell fork, so the proxy will be listening by the time
    // the hook process actually executes.
    service::fire_app_add_hooks(&state, &startup_scan.added_apps);

    let control_state = state.clone();
    let control_socket = cfg.control_socket.clone();
    let control_task = tokio::spawn(async move {
        if let Err(err) = control::run_control_server(control_socket, control_state).await {
            error!(error = %err, "control server exited with error");
        }
    });

    // Periodic scanner removed — startup scan + FS watcher is sufficient.
    let scan_task = tokio::spawn(async {});

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
                Ok(result) => {
                    if let Err(err) =
                        runtime::write_scan_warnings(&watch_state.scan_warnings_path, &result.stats)
                    {
                        error!(error = %err, "failed to write scan warnings");
                    }
                    match watch_state.reload_routes() {
                        Ok(true) => {
                            let _ = watch_state
                                .change_tx
                                .send("detail-tunnel,detail-features,detail-urls".to_string());
                            service::fire_app_add_hooks(&watch_state, &result.added_apps);
                        }
                        Ok(false) => {
                            service::fire_app_add_hooks(&watch_state, &result.added_apps);
                        }
                        Err(err) => {
                            error!(error = %err, "failed to reload routes after fs event");
                        }
                    }
                    debug!(
                        discovered = result.stats.discovered,
                        inserted = result.stats.inserted,
                        updated = result.stats.updated,
                        skipped_manual = result.stats.skipped_manual,
                        pruned = result.stats.pruned,
                        "apps scan completed from fs event"
                    );
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
            let reaped = pm.reap_idle().await;
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
        pm.shutdown_all().await;
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
    let snapshot: HashMap<u16, String> = {
        let dp = state.dedicated_ports.read();
        dp.clone()
    };

    // Stop proxies for removed ports
    let wanted: HashSet<u16> = snapshot.keys().copied().collect();
    let current: HashSet<u16> = running.keys().copied().collect();
    for port in current.difference(&wanted) {
        if let Some(handle) = running.remove(port) {
            info!(port, "stopping dedicated proxy");
            handle.abort();
        }
    }

    // Start proxies for new ports
    let upstream = format!("127.0.0.1:{}", state.listen_http.port());
    let ca_file = {
        let p = state.certs_dir.join("ca.crt");
        if p.exists() {
            Some(p.to_string_lossy().into_owned())
        } else {
            None
        }
    };
    for port in wanted.difference(&current) {
        let Some(domain) = snapshot.get(port) else {
            continue;
        };
        let port = *port;
        let host = domain.clone();
        let upstream = upstream.clone();
        let ca_file = ca_file.clone();
        info!(port, host = %host, "starting dedicated proxy");
        let handle = tokio::task::spawn_blocking(move || {
            if let Err(err) = proxy::run_dedicated_proxy_blocking(port, &upstream, &host, ca_file) {
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

    #[cfg(debug_assertions)]
    if !matches!(cli.command, Commands::Serve) {
        tracing::info!("debug build config:");
        tracing::info!("  control_socket = {}", cfg.control_socket.display());
        tracing::info!("  apps_root      = {}", cfg.apps_root.display());
        tracing::info!("  listen_http    = {}", cfg.listen_http);
    }

    match cli.command {
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
            link,
            tunnel,
        } => run_add(cfg, name, target, link, tunnel),
        Commands::Rm { name } => run_rm(cfg, name),
        Commands::Doctor { pf } => run_doctor(cfg, pf),
        Commands::Share { name, expires } => run_share(cfg, name, expires),
        Commands::Unshare { name } => run_unshare(cfg, name),
        Commands::Logs {
            name,
            follow,
            lines,
            path,
        } => run_logs(cfg, name, follow, lines, path),
        Commands::Env {
            name,
            bare,
            json,
            preview,
            no_remote,
        } => run_env(cfg, name, bare, json, preview, no_remote).await,
        Commands::Ps => run_ps(cfg),
        Commands::Start { name } => run_process_action(cfg, name, "process.start", None),
        Commands::Stop { name } => run_process_action(cfg, name, "process.stop", None),
        Commands::Restart { name } => {
            let (name, process_type) = parse_process_target(name)?;
            run_process_action(cfg, name, "process.restart", process_type)
        }
        Commands::Open { name } => run_open(cfg, name),
        Commands::Attach { name } => run_attach(cfg, name),
        Commands::Trust { forward, pf, force } => run_trust(cfg, forward || pf, force),
        Commands::Forward {
            http_target,
            https_target,
        } => run_forward(http_target, https_target).await,
        Commands::Tunnel { action } => run_tunnel(cfg, action),
    }
}

#[derive(Debug, PartialEq)]
enum AddMode<'a> {
    /// coulson add <name> <target> [--link dir]
    Manual { name: &'a str, target: &'a str },
    /// coulson add <port> — bare port, infer name from cwd
    BarePort(u16),
    /// coulson add — auto-detect cwd
    AutoDetect,
    /// coulson add <name> — custom name, auto-detect cwd
    Named { name: &'a str },
}

fn classify_add<'a>(name: Option<&'a str>, target: Option<&'a str>) -> anyhow::Result<AddMode<'a>> {
    match (name, target) {
        (Some(n), Some(t)) => Ok(AddMode::Manual { name: n, target: t }),
        (Some(n), None) if n.parse::<u16>().is_ok() => Ok(AddMode::BarePort(n.parse()?)),
        (None, None) => Ok(AddMode::AutoDetect),
        (Some(n), None) => Ok(AddMode::Named { name: n }),
        (None, Some(_)) => bail!("target requires a name: coulson add <name> <target>"),
    }
}

fn run_add(
    cfg: CoulsonConfig,
    name: Option<String>,
    target: Option<String>,
    link: Option<std::path::PathBuf>,
    tunnel: bool,
) -> anyhow::Result<()> {
    match classify_add(name.as_deref(), target.as_deref())? {
        AddMode::Manual { name: n, target: t } => run_add_manual(&cfg, n, t, link, tunnel),
        AddMode::BarePort(port) => {
            let cwd = std::env::current_dir().context("failed to get current directory")?;
            let dir_name = cwd.file_name().and_then(|n| n.to_str()).unwrap_or("app");
            let name = scanner::sanitize_name(dir_name);
            run_add_directory_inner(&cfg, &name, &cwd, Some(port), tunnel)
        }
        AddMode::AutoDetect => run_add_directory(&cfg, tunnel),
        AddMode::Named { name: n } => run_add_directory_with_name(&cfg, n, tunnel),
    }
}

fn run_add_directory(cfg: &CoulsonConfig, tunnel: bool) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let dir_name = cwd.file_name().and_then(|n| n.to_str()).unwrap_or("app");
    let name = scanner::sanitize_name(dir_name);
    run_add_directory_inner(cfg, &name, &cwd, None, tunnel)
}

fn run_add_directory_with_name(
    cfg: &CoulsonConfig,
    name: &str,
    tunnel: bool,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let name = scanner::sanitize_name(name);
    run_add_directory_inner(cfg, &name, &cwd, None, tunnel)
}

/// Query the running daemon for its HTTP port, falling back to config default.
fn daemon_http_port(cfg: &CoulsonConfig) -> u16 {
    RpcClient::new(&cfg.control_socket)
        .call("health.ping", serde_json::json!({}))
        .ok()
        .and_then(|v| v.get("http_port")?.as_u64())
        .map(|p| p as u16)
        .unwrap_or_else(|| cfg.listen_http.port())
}

/// Query the running daemon for its actual runtime directory, falling back to config.
/// The daemon and CLI may resolve `XDG_RUNTIME_DIR` differently (e.g. systemd vs
/// interactive shell), so client-side path computation can drift. Asking the daemon
/// directly avoids that mismatch.
fn daemon_runtime_dir(cfg: &CoulsonConfig) -> std::path::PathBuf {
    RpcClient::new(&cfg.control_socket)
        .call("health.ping", serde_json::json!({}))
        .ok()
        .and_then(|v| v.get("runtime_dir")?.as_str().map(std::path::PathBuf::from))
        .unwrap_or_else(|| cfg.runtime_dir.clone())
}

/// Print reachable URLs for a domain.
fn print_app_urls(domain: &str, suffix: &str, port: u16) {
    let ctx = domain::UrlContext {
        http_port: port,
        https_port: None,
        use_default_http_port: false,
        use_default_https_port: false,
        domain_suffix: suffix,
        global_tunnel_domain: None,
    };
    for url in domain::domain_urls(domain, "/", &ctx) {
        println!("  {}", url.cyan());
    }
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
            let resolved = resolved.canonicalize().unwrap_or(resolved);
            let cwd_canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
            // symlink-to-dir: resolved == CWD
            // symlink-to-file: resolved parent == CWD
            let already = resolved == cwd_canonical
                || resolved
                    .parent()
                    .and_then(|p| p.canonicalize().ok())
                    .map(|p| p == cwd_canonical)
                    .unwrap_or(false);
            if already {
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

    // Explicit port mode
    if let Some(p) = port {
        std::fs::create_dir_all(&cfg.apps_root)?;

        if cfg.link_dir {
            // Legacy mode: write powfile directly in apps_root
            std::fs::write(&link_path, format!("{p}\n"))?;
            println!("  {} {}", "+".green().bold(), link_path.display());
        } else {
            // Default mode: write .coulson in CWD, symlink from apps_root
            let dotfile = cwd.join(".coulson");
            if dotfile.exists() {
                bail!(
                    "{} already exists. Remove it first or use COULSON_LINK_DIR=1 for legacy mode.",
                    dotfile.display()
                );
            }
            std::fs::write(&dotfile, format!("{p}\n"))?;
            println!("  {} {}", "+".green().bold(), dotfile.display());
            #[cfg(unix)]
            std::os::unix::fs::symlink(&dotfile, &link_path).with_context(|| {
                format!(
                    "failed to create symlink {} -> {}",
                    link_path.display(),
                    dotfile.display()
                )
            })?;
            println!(
                "  {} {} -> {}",
                "+".green().bold(),
                link_path.display(),
                dotfile.display()
            );
        }

        println!(
            "  {} {name}.{} -> 127.0.0.1:{p}",
            "+".green().bold(),
            cfg.domain_suffix
        );
        let hp = daemon_http_port(cfg);
        let domain = format!("{name}.{}", cfg.domain_suffix);
        print_app_urls(&domain, &cfg.domain_suffix, hp);
        // Notify daemon to pick up the new app immediately
        let _ = RpcClient::new(&cfg.control_socket).call("apps.scan", serde_json::json!({}));
        if tunnel {
            start_tunnel_after_add(cfg, name)?;
        }
        return Ok(());
    }

    // Try auto-detect app kind
    let toml_path = cwd.join(".coulson.toml");
    let manifest: Option<serde_json::Value> = if toml_path.is_file() {
        let data = std::fs::read_to_string(&toml_path)
            .with_context(|| format!("failed to read {}", toml_path.display()))?;
        let table: toml::Value = toml::from_str(&data)
            .with_context(|| format!("invalid TOML in {}", toml_path.display()))?;
        Some(serde_json::to_value(table)?)
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
            "  {} {} -> {}",
            "+".green().bold(),
            link_path.display(),
            cwd.display()
        );
        println!(
            "  {} {name}.{} ({}) -> {}",
            "+".green().bold(),
            cfg.domain_suffix,
            detected.kind,
            cwd.display()
        );
        let hp = daemon_http_port(cfg);
        let domain = format!("{name}.{}", cfg.domain_suffix);
        print_app_urls(&domain, &cfg.domain_suffix, hp);
    } else {
        // No auto-detect, still create symlink (scanner will parse .coulson.toml/.coulson etc.)
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
            "  {} {} -> {}",
            "+".green().bold(),
            link_path.display(),
            cwd.display()
        );
        println!(
            "  {} {name}.{} -> {}",
            "+".green().bold(),
            cfg.domain_suffix,
            cwd.display()
        );
        let hp = daemon_http_port(cfg);
        let domain = format!("{name}.{}", cfg.domain_suffix);
        print_app_urls(&domain, &cfg.domain_suffix, hp);
        println!(
            "  {}",
            "Tip: use `coulson add <port>` to specify a target port, or add .coulson.toml/.coulson"
                .dimmed()
        );
    }

    // Notify daemon to pick up the new app immediately
    let _ = RpcClient::new(&cfg.control_socket).call("apps.scan", serde_json::json!({}));

    if tunnel {
        start_tunnel_after_add(cfg, name)?;
    }

    Ok(())
}

fn start_tunnel_after_add(cfg: &CoulsonConfig, name: &str) -> anyhow::Result<()> {
    let client = RpcClient::new(&cfg.control_socket);

    // Trigger a scan so the daemon picks up the newly added app
    if let Err(e) = client.call("apps.scan", serde_json::json!({})) {
        eprintln!(
            "  {}",
            format!("Warning: could not trigger scan: {e}").yellow()
        );
        eprintln!(
            "  {}",
            "Start the daemon first, then run: coulson tunnel start".dimmed()
        );
        return Ok(());
    }

    // Resolve app_id
    let (bare_name, app_id) = match resolve_app_id(&client, cfg, Some(name.to_string())) {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "  {}",
                "Warning: app not found in daemon after scan. Start the daemon first, then run: coulson tunnel start"
                    .yellow()
            );
            return Ok(());
        }
    };

    // Start quick tunnel
    let result = client.call(
        "app.update",
        serde_json::json!({ "app_id": app_id, "tunnel_mode": "quick" }),
    )?;

    let url = result
        .get("tunnel_url")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    println!("  {} tunnel started for {bare_name}", "~".green().bold(),);
    println!("  {}", url.cyan());

    Ok(())
}

fn run_add_manual(
    cfg: &CoulsonConfig,
    name: &str,
    target: &str,
    link: Option<std::path::PathBuf>,
    tunnel: bool,
) -> anyhow::Result<()> {
    // Unix socket targets use RPC (powfile format doesn't support socket paths)
    if target.starts_with('/') {
        if link.is_some() {
            bail!("--link is not supported with unix socket targets");
        }
        return run_add_manual_rpc(cfg, name, target, tunnel);
    }

    // Validate TCP target format
    let display = if target.parse::<u16>().is_ok() {
        format!("127.0.0.1:{target}")
    } else if target.contains(':') {
        let (_, port_str) = target.rsplit_once(':').unwrap();
        port_str
            .parse::<u16>()
            .with_context(|| format!("invalid port in target: {target}"))?;
        target.to_string()
    } else {
        bail!("invalid target: {target}. Expected: port, host:port, or /path/to/socket");
    };

    std::fs::create_dir_all(&cfg.apps_root)?;
    let link_path = cfg.apps_root.join(name);
    if link_path.exists() || link_path.symlink_metadata().is_ok() {
        // Idempotent: if existing powfile has the same target, treat as success
        if let Ok(content) = std::fs::read_to_string(&link_path) {
            if content.trim() == target {
                let domain = if name.contains('.') {
                    name.to_string()
                } else {
                    format!("{name}.{}", cfg.domain_suffix)
                };
                println!("{} {domain} already registered", "=".bold());
                return Ok(());
            }
        }
        bail!("{} already exists", link_path.display());
    }

    if let Some(dir) = link {
        // --link mode: write .coulson in app dir, symlink from apps_root
        let dir = dir
            .canonicalize()
            .with_context(|| format!("invalid --link path: {}", dir.display()))?;
        let dotfile = dir.join(".coulson");
        if dotfile.exists() {
            bail!("{} already exists", dotfile.display());
        }
        std::fs::write(&dotfile, format!("{target}\n"))?;
        println!("  {} {}", "+".green().bold(), dotfile.display());
        #[cfg(unix)]
        std::os::unix::fs::symlink(&dotfile, &link_path).with_context(|| {
            format!(
                "failed to create symlink {} -> {}",
                link_path.display(),
                dotfile.display()
            )
        })?;
        println!(
            "  {} {} -> {}",
            "+".green().bold(),
            link_path.display(),
            dotfile.display()
        );
    } else {
        // No --link: write powfile directly in apps_root
        std::fs::write(&link_path, format!("{target}\n"))?;
        println!("  {} {}", "+".green().bold(), link_path.display());
    }

    let domain = if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.{}", cfg.domain_suffix)
    };
    println!("  {} {domain} -> {display}", "+".green().bold());
    let hp = daemon_http_port(cfg);
    print_app_urls(&domain, &cfg.domain_suffix, hp);

    // Notify daemon to pick up the new app
    let _ = RpcClient::new(&cfg.control_socket).call("apps.scan", serde_json::json!({}));

    if tunnel {
        start_tunnel_after_add(cfg, name)?;
    }

    Ok(())
}

/// Unix socket targets bypass powfile and use RPC directly.
fn run_add_manual_rpc(
    cfg: &CoulsonConfig,
    name: &str,
    target: &str,
    tunnel: bool,
) -> anyhow::Result<()> {
    let domain = if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.{}", cfg.domain_suffix)
    };
    let client = RpcClient::new(&cfg.control_socket);
    let result = client.call(
        "app.create",
        serde_json::json!({
            "name": name,
            "domain": domain,
            "target_type": "unix_socket",
            "target_value": target,
        }),
    )?;
    let http_port = result
        .get("http_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(cfg.listen_http.port() as u64);
    println!("  {} {domain} -> unix:{target}", "+".green().bold());
    print_app_urls(&domain, &cfg.domain_suffix, http_port as u16);
    if tunnel {
        start_tunnel_after_add(cfg, name)?;
    }
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

    eprint!("Remove {bare_name}? [y/N] ");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        println!("Cancelled.");
        return Ok(());
    }

    let mut removed_db = false;

    // Check apps_root for file/symlink
    let removed_file = scanner::remove_app_fs_entry(&cfg.apps_root, bare_name);

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
                    if let Some(app_id) = app.get("id").and_then(|i| i.as_i64()) {
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
        println!("{} {bare_name} not found, nothing to remove", "=".bold());
        return Ok(());
    }

    if removed_file {
        println!(
            "{} {} from {}",
            "-".red().bold(),
            bare_name,
            cfg.apps_root.display()
        );
    }
    if removed_db {
        println!("{} {bare_name} from database", "-".red().bold());
    }
    Ok(())
}

fn run_rm_cwd(cfg: &CoulsonConfig) -> anyhow::Result<()> {
    let bare_name = resolve_app_name(cfg, None)?;

    // Verify the symlink actually exists before removing
    let link_path = cfg.apps_root.join(&bare_name);
    if link_path.symlink_metadata().is_err() {
        let cwd = std::env::current_dir().unwrap_or_default();
        bail!("no app found pointing to {}", cwd.display());
    }

    run_rm_by_name(cfg, &bare_name)
}

/// Resolve an app name (domain prefix) from an explicit argument or CWD.
///
/// - Some(name): strip domain suffix if present, return bare name
/// - None: scan apps_root symlinks for one pointing to CWD, fallback to CWD dir name
fn resolve_app_name(cfg: &CoulsonConfig, name: Option<&str>) -> anyhow::Result<String> {
    if let Some(n) = name {
        let bare = n
            .strip_suffix(&format!(".{}", cfg.domain_suffix))
            .unwrap_or(n);
        return Ok(bare.to_string());
    }

    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd_canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.clone());

    if let Ok(entries) = std::fs::read_dir(&cfg.apps_root) {
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
            // symlink-to-dir: resolved == CWD
            if resolved == cwd_canonical {
                let found = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                return Ok(found.to_string());
            }
            // symlink-to-file: resolved parent == CWD
            if let Some(parent) = resolved.parent() {
                let parent_canonical = parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf());
                if parent_canonical == cwd_canonical {
                    let found = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");
                    return Ok(found.to_string());
                }
            }
        }
    }

    // Fallback: use CWD directory name
    let dir_name = cwd.file_name().and_then(|n| n.to_str()).unwrap_or("app");
    Ok(scanner::sanitize_name(dir_name))
}

/// Resolve app name → app_id via RPC `app.list`.
fn resolve_app_id(
    client: &RpcClient,
    cfg: &CoulsonConfig,
    name: Option<String>,
) -> anyhow::Result<(String, i64)> {
    let bare_name = resolve_app_name(cfg, name.as_deref())?;
    let domain_match = format!("{bare_name}.{}", cfg.domain_suffix);

    let result = client.call("app.list", serde_json::json!({}))?;
    let app_id = result
        .get("apps")
        .and_then(|a| a.as_array())
        .and_then(|apps| {
            apps.iter().find(|a| {
                a.get("name").and_then(|n| n.as_str()) == Some(&bare_name)
                    || a.get("domain").and_then(|d| d.as_str()) == Some(&domain_match)
                    || a.get("domain").and_then(|d| d.as_str()) == Some(&bare_name)
            })
        })
        .and_then(|a| a.get("id")?.as_i64())
        .ok_or_else(|| anyhow::anyhow!("app not found: {bare_name}"))?;

    Ok((bare_name, app_id))
}

async fn run_env(
    cfg: CoulsonConfig,
    name: Option<String>,
    bare: bool,
    json: bool,
    preview: bool,
    no_remote: bool,
) -> anyhow::Result<()> {
    // Each row is (key, value, source_kind, source_label).
    let rows: Vec<(String, String, String, String)> = if preview {
        // Re-resolve locally: what the app *would* get if started now.
        let bare_name = resolve_app_name(&cfg, name.as_deref())?;
        let domain_match = format!("{bare_name}.{}", cfg.domain_suffix);
        let state = build_state(&cfg)?;
        let app = state
            .store
            .list_all()?
            .into_iter()
            .find(|a| a.name == bare_name || a.domain.0 == domain_match || a.domain.0 == bare_name)
            .ok_or_else(|| anyhow::anyhow!("app not found: {bare_name}"))?;
        let (app_id, root, kind, mname) = match &app.target {
            crate::domain::BackendTarget::Managed {
                app_id,
                root,
                kind,
                name,
            } => (*app_id, root.clone(), kind.clone(), name.clone()),
            _ => bail!(
                "`coulson env` is only available for managed apps; {bare_name} is a static/proxy app"
            ),
        };
        let entries = {
            let pm = state.process_manager.lock().await;
            pm.inspect_env(
                app_id,
                &mname,
                std::path::Path::new(&root),
                &kind,
                !no_remote,
            )
            .await?
        };
        eprintln!(
            "{}",
            "(preview — computed now, not the running process; PORT is a preview allocation)"
                .dimmed()
        );
        entries
            .into_iter()
            .map(|e| {
                let kind = e.source.kind().to_string();
                let label = e.source.label();
                (e.key, e.value, kind, label)
            })
            .collect()
    } else {
        // Live: the env the running process was actually started with.
        let client = RpcClient::new(&cfg.control_socket);
        let (_bare_name, app_id) = resolve_app_id(&client, &cfg, name)?;
        let result = client.call("process.env", serde_json::json!({ "app_id": app_id }))?;
        result
            .get("env")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        let key = e.get("key")?.as_str()?.to_string();
                        let value = e.get("value")?.as_str()?.to_string();
                        let source = e.get("source")?;
                        let kind = source.get("kind")?.as_str()?.to_string();
                        let label = source.get("label")?.as_str()?.to_string();
                        Some((key, value, kind, label))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    if json {
        let arr: Vec<serde_json::Value> = rows
            .iter()
            .map(|(k, v, kind, label)| {
                serde_json::json!({
                    "key": k,
                    "value": v,
                    "source": { "kind": kind, "label": label },
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }
    if bare {
        for (k, v, _, _) in &rows {
            println!("{k}={v}");
        }
        return Ok(());
    }
    if rows.is_empty() {
        return Ok(());
    }

    // Aligned KEY + SOURCE columns (bounded widths); VALUE last. Long values
    // are truncated to the terminal width so rows stay one line and aligned.
    // When output is not a TTY (piped), values are shown in full.
    let key_w = rows
        .iter()
        .map(|(k, ..)| k.chars().count())
        .max()
        .unwrap_or(0)
        .max("KEY".len());
    let src_w = rows
        .iter()
        .map(|(_, _, _, label)| label.chars().count())
        .max()
        .unwrap_or(0)
        .max("SOURCE".len());

    const SEP: usize = 2; // spaces between columns
    let value_budget = terminal_size::terminal_size().map(|(w, _)| {
        (w.0 as usize)
            .saturating_sub(key_w + src_w + SEP * 2)
            .max(8)
    });

    println!(
        "{}  {}  {}",
        format!("{:<key_w$}", "KEY").dimmed(),
        format!("{:<src_w$}", "SOURCE").dimmed(),
        "VALUE".dimmed()
    );
    for (k, v, kind, label) in &rows {
        let src_cell = format!("{label:<src_w$}");
        let src_cell = match kind.as_str() {
            "dotenv" => src_cell.green(),
            "env_url" => src_cell.cyan(),
            "toml" => src_cell.yellow(),
            _ => src_cell.dimmed(),
        };
        let value = match value_budget {
            Some(budget) if v.chars().count() > budget => {
                let head: String = v.chars().take(budget.saturating_sub(1)).collect();
                format!("{head}…")
            }
            _ => v.clone(),
        };
        println!("{}  {}  {}", format!("{k:<key_w$}").bold(), src_cell, value);
    }
    Ok(())
}

fn run_ps(cfg: CoulsonConfig) -> anyhow::Result<()> {
    let client = RpcClient::new(&cfg.control_socket);
    let result = client.call("process.list", serde_json::json!({}))?;

    let processes = result
        .get("processes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if processes.is_empty() {
        println!("No managed processes running.");
        return Ok(());
    }

    // Build app_id → (name, domain) map from app.list
    let app_map: HashMap<String, (String, String)> =
        if let Ok(app_result) = client.call("app.list", serde_json::json!({})) {
            app_result
                .get("apps")
                .and_then(|v| v.as_array())
                .map(|apps| {
                    apps.iter()
                        .filter_map(|a| {
                            let id = a
                                .get("id")
                                .map(|v| v.to_string().trim_matches('"').to_string())?;
                            let name = a.get("name")?.as_str()?.to_string();
                            let domain = a
                                .get("domain")
                                .and_then(|d| d.as_str())
                                .unwrap_or("")
                                .to_string();
                            Some((id, (name, domain)))
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            HashMap::new()
        };

    #[derive(Tabled)]
    struct PsRow {
        #[tabled(rename = "NAME")]
        name: String,
        #[tabled(rename = "PID")]
        pid: String,
        #[tabled(rename = "KIND")]
        kind: String,
        #[tabled(rename = "UPTIME")]
        uptime: String,
        #[tabled(rename = "IDLE")]
        idle: String,
        #[tabled(rename = "STATUS")]
        status: String,
    }

    let rows: Vec<PsRow> = processes
        .iter()
        .map(|p| {
            let app_id = p
                .get("app_id")
                .map(|v| v.to_string().trim_matches('"').to_string())
                .unwrap_or_default();
            let (name, _domain) = app_map
                .get(&app_id)
                .cloned()
                .unwrap_or_else(|| (app_id.to_string(), String::new()));
            let pid = p.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
            let kind_raw = p.get("kind").and_then(|v| v.as_str()).unwrap_or("unknown");
            let kind = match kind_raw {
                "asgi" => "ASGI",
                "node" => "Node",
                "procfile" => "Procfile",
                other => other,
            };
            let uptime_secs = p.get("uptime_secs").and_then(|v| v.as_u64()).unwrap_or(0);
            let idle_secs = p.get("idle_secs").and_then(|v| v.as_u64()).unwrap_or(0);
            let alive = p.get("alive").and_then(|v| v.as_bool()).unwrap_or(false);

            let uptime = format_duration(uptime_secs);
            let idle = format_duration(idle_secs);
            let status = if alive {
                "running".green().to_string()
            } else {
                "exited".red().to_string()
            };

            PsRow {
                name: name.bold().to_string(),
                pid: pid.to_string(),
                kind: kind.to_string(),
                uptime,
                idle,
                status,
            }
        })
        .collect();

    use tabled::settings::Style;
    let table = tabled::Table::new(&rows).with(Style::blank()).to_string();
    println!("{table}");

    Ok(())
}

/// Split a `[name][:type]` restart target into its parts: `app` addresses the
/// whole group, `app:worker` one process type, `:worker` a type of the CWD app.
fn parse_process_target(arg: Option<String>) -> anyhow::Result<(Option<String>, Option<String>)> {
    let Some(arg) = arg else {
        return Ok((None, None));
    };
    match arg.split_once(':') {
        None => Ok((Some(arg), None)),
        Some((name, ptype)) => {
            if ptype.is_empty() {
                anyhow::bail!("missing process type after ':' in '{arg}'");
            }
            let name = (!name.is_empty()).then(|| name.to_string());
            Ok((name, Some(ptype.to_string())))
        }
    }
}

fn run_process_action(
    cfg: CoulsonConfig,
    name: Option<String>,
    method: &str,
    process_type: Option<String>,
) -> anyhow::Result<()> {
    let client = RpcClient::new(&cfg.control_socket);
    let (bare_name, app_id) = resolve_app_id(&client, &cfg, name)?;

    let mut params = serde_json::json!({ "app_id": app_id });
    if let Some(ptype) = &process_type {
        params["process_type"] = serde_json::json!(ptype);
    }
    let result = client.call(method, params)?;

    let action = match method {
        "process.start" => "started",
        "process.stop" => "stopped",
        "process.restart" => "restarted",
        _ => "done",
    };
    let display = match &process_type {
        Some(ptype) => format!("{bare_name}:{ptype}"),
        None => bare_name,
    };
    println!("{} {display} {action}", "✓".green());

    // Show URLs after start/restart (not after a companion-only restart —
    // companions don't serve HTTP)
    if method != "process.stop" && process_type.as_deref().is_none_or(|t| t == "web") {
        if let Some(app) = client
            .call("app.list", serde_json::json!({}))
            .ok()
            .and_then(|v| {
                v.get("apps")?
                    .as_array()?
                    .iter()
                    .find(|a| a.get("id").and_then(|id| id.as_i64()) == Some(app_id))
                    .cloned()
            })
        {
            if let Some(domain) = app.get("domain").and_then(|d| d.as_str()) {
                let port = result
                    .get("listen")
                    .and_then(|l| l.get("port"))
                    .and_then(|p| p.as_u64())
                    .map(|p| p as u16)
                    .unwrap_or_else(|| cfg.listen_http.port());
                print_app_urls(domain, &cfg.domain_suffix, port);
            }
        }
    }

    Ok(())
}

fn run_open(cfg: CoulsonConfig, name: Option<String>) -> anyhow::Result<()> {
    let app_name = resolve_app_name(&cfg, name.as_deref())?;
    let state = build_state(&cfg)?;
    let domain_match = format!("{app_name}.{}", cfg.domain_suffix);
    let all_apps = state.store.list_filtered(None, None)?;
    let app = all_apps
        .iter()
        .find(|a| a.name == app_name || a.domain.0 == domain_match || a.domain.0 == app_name)
        .with_context(|| format!("app not found: {app_name}"))?;

    let port = daemon_http_port(&cfg);
    let ctx = domain::UrlContext {
        http_port: port,
        https_port: None,
        use_default_http_port: state.use_default_http_port(),
        use_default_https_port: state.use_default_https_port(),
        domain_suffix: &cfg.domain_suffix,
        global_tunnel_domain: None,
    };
    let urls = app.urls(&ctx);
    let url = urls
        .first()
        .with_context(|| format!("no URL available for {app_name}"))?;

    println!("  Opening {}", url.cyan());
    let status = std::process::Command::new("open")
        .arg(url)
        .status()
        .context("failed to run `open`")?;
    if !status.success() {
        bail!("open exited with {status}");
    }
    Ok(())
}

fn run_attach(cfg: CoulsonConfig, name: Option<String>) -> anyhow::Result<()> {
    use crate::config::ProcessBackend;

    if cfg.process_backend == ProcessBackend::Direct {
        bail!("attach requires tmux backend (set COULSON_PROCESS_BACKEND=auto or tmux)");
    }

    if !process::tmux_available() {
        bail!("tmux not found in PATH");
    }

    let bare_name = resolve_app_name(&cfg, name.as_deref())?;
    let session_name = bare_name.clone();

    // Check if the tmux session exists
    let status = std::process::Command::new("tmux")
        .args(["-L", "coulson", "has-session", "-t", &session_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;

    if !status.success() {
        bail!(
            "no tmux session for '{bare_name}' (process may not be running or using direct backend)"
        );
    }

    // Replace current process with tmux attach
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new("tmux")
        .args(["-L", "coulson", "attach-session", "-t", &session_name])
        .exec();
    // exec() only returns on error
    bail!("failed to exec tmux: {err}");
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn run_logs(
    cfg: CoulsonConfig,
    name: Option<String>,
    follow: bool,
    lines: usize,
    path: bool,
) -> anyhow::Result<()> {
    let client = RpcClient::new(&cfg.control_socket);

    // Try RPC first, fallback to local DB
    let (bare_name, _app_id, app_root) = match resolve_app_id(&client, &cfg, name.clone()) {
        Ok((n, id)) => {
            let state = build_state(&cfg).ok();
            let app = state
                .as_ref()
                .and_then(|s| s.store.list_all().ok())
                .and_then(|apps| apps.into_iter().find(|a| a.id.0 == id));
            let root = app.and_then(|a| match a.target {
                crate::domain::BackendTarget::Managed { root, .. } => Some(root),
                _ => None,
            });
            (n, id, root)
        }
        Err(_) => {
            let bare_name = resolve_app_name(&cfg, name.as_deref())?;
            let domain_match = format!("{bare_name}.{}", cfg.domain_suffix);
            let state = build_state(&cfg)?;
            let apps = state.store.list_all()?;
            let app = apps
                .into_iter()
                .find(|a| {
                    a.name == bare_name || a.domain.0 == domain_match || a.domain.0 == bare_name
                })
                .ok_or_else(|| anyhow::anyhow!("app not found: {bare_name}"))?;
            let id = app.id.0;
            let root = match &app.target {
                crate::domain::BackendTarget::Managed { root, .. } => Some(root.clone()),
                _ => None,
            };
            (bare_name, id, root)
        }
    };

    let app_dir = daemon_runtime_dir(&cfg).join("managed").join(&bare_name);
    let log_dir = match app_root {
        Some(ref root) => {
            let root = std::path::Path::new(root);
            let manifest = crate::process::load_coulson_toml_manifest(root);
            crate::process::resolve_log_dir(&manifest, root, &app_dir)
        }
        None => app_dir,
    };
    let log_path = crate::process::process_log_path(&log_dir, "web");

    if path {
        println!("{}", log_path.display());
        return Ok(());
    }

    if !log_path.exists() {
        bail!(
            "no logs found for {bare_name} (expected {})",
            log_path.display()
        );
    }

    let log_path = log_path.to_string_lossy();

    if follow {
        eprintln!("{} $ tail -F {log_path}", format!("[{bare_name}]").blue());
        std::process::Command::new("tail")
            .args(["-F", &log_path])
            .status()
            .context("failed to run tail -f")?;
    } else {
        eprintln!(
            "{} $ tail -n {lines} {log_path}",
            format!("[{bare_name}]").blue()
        );
        std::process::Command::new("tail")
            .args(["-n", &lines.to_string(), &log_path])
            .status()
            .context("failed to run tail")?;
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
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no named tunnel running. Start one first with `coulson tunnel connect`"
            )
        })?
        .to_string();

    // Build state to access the signer
    let state = build_state(&cfg)?;

    // Enable share_auth for this app
    if !state.store.set_share_auth(&domain_prefix, true)? {
        bail!("app not found: {domain}");
    }

    let token = state.share_signer.create_token(&domain, duration)?;

    let share_url = format!("https://{domain_prefix}.{tunnel_domain}/_coulson/auth?t={token}");

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

fn run_tunnel_login(token: &str) -> anyhow::Result<()> {
    let handle = tokio::runtime::Handle::current();
    let body: serde_json::Value = tokio::task::block_in_place(|| {
        handle.block_on(async {
            let client = reqwest::Client::new();
            let resp = client
                .get("https://api.cloudflare.com/client/v4/user/tokens/verify")
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await?;
            resp.json().await.map_err(anyhow::Error::from)
        })
    })?;
    if body.get("success").and_then(|v| v.as_bool()) != Some(true) {
        bail!("token verification failed: {body}");
    }

    credentials::store_api_token(token)?;
    println!("{} API token verified and saved to keychain", "✓".green());
    Ok(())
}

fn run_tunnel(cfg: CoulsonConfig, action: TunnelCommands) -> anyhow::Result<()> {
    let client = RpcClient::new(&cfg.control_socket);

    match action {
        TunnelCommands::Status => {
            // Build app info from app.list
            let apps: Vec<serde_json::Value> =
                if let Ok(app_result) = client.call("app.list", serde_json::json!({})) {
                    app_result
                        .get("apps")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default()
                } else {
                    vec![]
                };

            let app_name = |app_id: &str| -> String {
                apps.iter()
                    .find(|a| {
                        a.get("id")
                            .map(|v| v.to_string().trim_matches('"').to_string())
                            .as_deref()
                            == Some(app_id)
                    })
                    .and_then(|a| a.get("name").and_then(|v| v.as_str()))
                    .unwrap_or(app_id)
                    .to_string()
            };

            // Quick tunnels
            let qt = client.call("tunnel.status", serde_json::json!({}))?;
            let quick_tunnels = qt
                .get("tunnels")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            if !quick_tunnels.is_empty() {
                println!("{}", "Quick Tunnels".bold());

                #[derive(Tabled)]
                struct TunnelRow {
                    #[tabled(rename = "APP")]
                    app: String,
                    #[tabled(rename = "URL")]
                    url: String,
                    #[tabled(rename = "STATUS")]
                    status: String,
                }

                let rows: Vec<TunnelRow> = quick_tunnels
                    .iter()
                    .map(|t| {
                        let aid = t
                            .get("app_id")
                            .map(|v| v.to_string().trim_matches('"').to_string())
                            .unwrap_or_default();
                        let url = t
                            .get("hostname")
                            .and_then(|v| v.as_str())
                            .map(|h| format!("https://{h}"))
                            .unwrap_or_default();
                        let running = t.get("running").and_then(|v| v.as_bool()).unwrap_or(false);
                        let status = if running {
                            "running".green().to_string()
                        } else {
                            "stopped".dimmed().to_string()
                        };
                        TunnelRow {
                            app: app_name(&aid).bold().to_string(),
                            url: url.cyan().to_string(),
                            status,
                        }
                    })
                    .collect();

                use tabled::settings::Style;
                let table = tabled::Table::new(&rows).with(Style::blank()).to_string();
                println!("{table}");
                println!();
            }

            // Named tunnel
            let nt = client.call("named_tunnel.status", serde_json::json!({}))?;
            println!("{}", "Named Tunnel".bold());
            let connected = nt
                .get("connected")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if connected {
                let tunnel_id = nt.get("tunnel_id").and_then(|v| v.as_str()).unwrap_or("?");
                let domain = nt
                    .get("tunnel_domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                println!(
                    "  {} {} ({})",
                    "connected".green(),
                    domain.cyan(),
                    tunnel_id.dimmed()
                );

                // Show apps exposed via global mode
                let global_apps: Vec<&serde_json::Value> = apps
                    .iter()
                    .filter(|a| {
                        a.get("tunnel_mode").and_then(|v| v.as_str()) == Some("global")
                            && a.get("enabled").and_then(|v| v.as_bool()) == Some(true)
                    })
                    .collect();
                if !global_apps.is_empty() {
                    println!();
                    println!("  {}", "Exposed Apps (global mode)".dimmed());
                    for a in &global_apps {
                        let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                        let app_domain = a.get("domain").and_then(|v| v.as_str()).unwrap_or("?");
                        let prefix = app_domain
                            .strip_suffix(&format!(".{}", cfg.domain_suffix))
                            .unwrap_or(app_domain);
                        println!(
                            "    {}  {}",
                            name.bold(),
                            format!("https://{prefix}.{domain}").cyan()
                        );
                    }
                }
            } else {
                let configured = nt
                    .get("configured")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if configured {
                    let domain = nt.get("domain").and_then(|v| v.as_str()).unwrap_or("?");
                    println!(
                        "  {} (configured: {})",
                        "disconnected".yellow(),
                        domain.dimmed()
                    );
                } else {
                    println!("  {}", "not configured".dimmed());
                }
            }

            // Per-app named tunnels
            let per_app: Vec<&serde_json::Value> = apps
                .iter()
                .filter(|a| {
                    a.get("tunnel_mode").and_then(|v| v.as_str()) == Some("named")
                        || a.get("app_tunnel_id").and_then(|v| v.as_str()).is_some()
                })
                .collect();
            if !per_app.is_empty() {
                println!();
                println!("{}", "Per-App Tunnels".bold());

                #[derive(Tabled)]
                struct AppTunnelRow {
                    #[tabled(rename = "APP")]
                    app: String,
                    #[tabled(rename = "DOMAIN")]
                    domain: String,
                    #[tabled(rename = "STATUS")]
                    status: String,
                }

                let rows: Vec<AppTunnelRow> = per_app
                    .iter()
                    .map(|a| {
                        let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                        let domain = a
                            .get("app_tunnel_domain")
                            .and_then(|v| v.as_str())
                            .unwrap_or("-");
                        let mode = a
                            .get("tunnel_mode")
                            .and_then(|v| v.as_str())
                            .unwrap_or("none");
                        let status = if mode == "named" {
                            "running".green().to_string()
                        } else {
                            "stopped".dimmed().to_string()
                        };
                        AppTunnelRow {
                            app: name.bold().to_string(),
                            domain: domain.cyan().to_string(),
                            status,
                        }
                    })
                    .collect();

                use tabled::settings::Style;
                let table = tabled::Table::new(&rows).with(Style::blank()).to_string();
                println!("{table}");
            }

            // CF credentials status
            println!();
            let has_token = credentials::get_api_token().ok().flatten().is_some();
            if has_token {
                println!("Cloudflare API Token: {}", "saved in keychain".green());
            } else {
                println!("Cloudflare API Token: {}", "not configured".dimmed());
            }

            Ok(())
        }
        TunnelCommands::Start { name, mode } => {
            let (bare_name, app_id) = resolve_app_id(&client, &cfg, name)?;

            let tunnel_mode: TunnelMode = match mode.as_deref() {
                Some(m @ ("quick" | "global" | "named")) => m.parse().expect("validated mode"),
                Some(m) => bail!("invalid mode: {m}, must be quick/global/named"),
                None => {
                    // Auto-infer mode:
                    // 1. has saved per-app tunnel creds → named (reconnect)
                    // 2. global named tunnel is connected → global (expose via it)
                    // 3. otherwise → quick
                    let app_info = find_app_json(&client, app_id)?;
                    let has_creds = app_info
                        .get("app_tunnel_creds")
                        .and_then(|v| v.as_str())
                        .is_some();
                    if has_creds {
                        TunnelMode::Named
                    } else {
                        let global_connected = client
                            .call("named_tunnel.status", serde_json::json!({}))
                            .ok()
                            .and_then(|v| v.get("connected").and_then(|c| c.as_bool()))
                            .unwrap_or(false);
                        if global_connected {
                            TunnelMode::Global
                        } else {
                            TunnelMode::Quick
                        }
                    }
                }
            };

            let result = client.call(
                "app.update",
                serde_json::json!({ "app_id": app_id, "tunnel_mode": tunnel_mode.as_str() }),
            )?;

            println!(
                "{} tunnel started for {bare_name} ({tunnel_mode})",
                "✓".green(),
            );

            // Show relevant info based on mode
            match tunnel_mode {
                TunnelMode::Quick => {
                    let url = result
                        .get("tunnel_url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    println!("  {}", url.cyan());
                }
                TunnelMode::Named => {
                    let domain = result
                        .get("tunnel_domain")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    println!("  domain: {}", domain.cyan());
                }
                TunnelMode::Global => {
                    let domain = client
                        .call("named_tunnel.status", serde_json::json!({}))
                        .ok()
                        .and_then(|v| {
                            let d = v.get("domain")?.as_str()?;
                            Some(format!("{bare_name}.{d}"))
                        });
                    if let Some(d) = domain {
                        println!("  {}", format!("http://{d}").cyan());
                    }
                }
                TunnelMode::None => {}
            }

            Ok(())
        }
        TunnelCommands::Stop { name } => {
            let (bare_name, app_id) = resolve_app_id(&client, &cfg, name)?;
            client.call(
                "app.update",
                serde_json::json!({ "app_id": app_id, "tunnel_mode": "none" }),
            )?;
            println!("{} tunnel stopped for {bare_name}", "✓".green());
            Ok(())
        }
        TunnelCommands::Connect { token, domain } => {
            let mut params = serde_json::json!({});
            if let Some(t) = &token {
                params["token"] = serde_json::json!(t);
            }
            if let Some(d) = &domain {
                params["domain"] = serde_json::json!(d);
            }
            let result = client.call("named_tunnel.connect", params)?;
            let tunnel_domain = result.get("domain").and_then(|v| v.as_str()).unwrap_or("?");
            println!("{} named tunnel connected", "✓".green());
            println!("  domain: {}", tunnel_domain.cyan());
            Ok(())
        }
        TunnelCommands::Disconnect => {
            client.call("named_tunnel.disconnect", serde_json::json!({}))?;
            println!("{} named tunnel disconnected", "✓".green());
            Ok(())
        }
        TunnelCommands::Setup {
            domain,
            tunnel_name,
            api_token,
            account_id,
        } => {
            let token = match api_token {
                Some(t) => t,
                None => credentials::get_api_token()?
                    .ok_or_else(|| anyhow::anyhow!("no saved API token, pass --api-token"))?,
            };

            let mut params = serde_json::json!({
                "api_token": token,
                "domain": domain,
            });
            if let Some(a) = &account_id {
                params["account_id"] = serde_json::json!(a);
            }
            if let Some(n) = &tunnel_name {
                params["tunnel_name"] = serde_json::json!(n);
            }
            let result = client.call("named_tunnel.setup", params)?;

            // Save token to keychain on success
            credentials::store_api_token(&token)?;

            let tunnel_id = result
                .get("tunnel_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let cname = result
                .get("cname_target")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            println!("{} global named tunnel created", "✓".green());
            println!("  domain:  {}", domain.cyan());
            println!("  tunnel:  {}", tunnel_id.dimmed());
            println!("  CNAME:   *.{domain} -> {cname}");
            Ok(())
        }
        TunnelCommands::Teardown { api_token } => {
            let token = match api_token {
                Some(t) => t,
                None => credentials::get_api_token()?
                    .ok_or_else(|| anyhow::anyhow!("no saved API token, pass --api-token"))?,
            };
            client.call(
                "named_tunnel.teardown",
                serde_json::json!({ "api_token": token }),
            )?;
            println!("{} global named tunnel destroyed", "✓".green());
            Ok(())
        }
        TunnelCommands::Login { token } => {
            run_tunnel_login(&token)?;
            Ok(())
        }
        TunnelCommands::Logout => {
            credentials::delete_api_token()?;
            println!("{} CF API token removed from keychain", "✓".green());
            Ok(())
        }
        TunnelCommands::AppSetup {
            name,
            domain,
            token,
        } => {
            let (bare_name, app_id) = resolve_app_id(&client, &cfg, Some(name))?;
            let mut params = serde_json::json!({
                "app_id": app_id,
                "domain": domain,
            });
            if let Some(t) = &token {
                params["token"] = serde_json::json!(t);
            }
            let result = client.call("tunnel.app_setup", params)?;
            let tunnel_id = result
                .get("tunnel_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            println!("{} per-app tunnel created for {bare_name}", "✓".green());
            println!("  domain:  {}", domain.cyan());
            println!("  tunnel:  {}", tunnel_id.dimmed());
            if let Some(dns_id) = result.get("dns_record_id").and_then(|v| v.as_str()) {
                println!("  DNS:     {}", dns_id.dimmed());
            }
            Ok(())
        }
        TunnelCommands::AppTeardown { name } => {
            let (bare_name, app_id) = resolve_app_id(&client, &cfg, Some(name))?;
            client.call(
                "tunnel.app_teardown",
                serde_json::json!({ "app_id": app_id }),
            )?;
            println!("{} per-app tunnel destroyed for {bare_name}", "✓".green());
            Ok(())
        }
    }
}

/// Look up an app by ID from the RPC app.list result.
fn find_app_json(client: &RpcClient, app_id: i64) -> anyhow::Result<serde_json::Value> {
    let result = client.call("app.list", serde_json::json!({}))?;
    result
        .get("apps")
        .and_then(|v| v.as_array())
        .and_then(|apps| {
            apps.iter()
                .find(|a| a.get("id").and_then(|v| v.as_i64()) == Some(app_id))
                .cloned()
        })
        .ok_or_else(|| anyhow::anyhow!("app not found: {app_id}"))
}

fn run_trust(
    cfg: CoulsonConfig,
    #[allow(unused)] forward: bool,
    #[allow(unused)] force: bool,
) -> anyhow::Result<()> {
    let ca_path = cfg.certs_dir.join("ca.crt");

    if !ca_path.exists() {
        bail!(
            "CA certificate not found at {}. Run the daemon first to generate certificates.",
            ca_path.display()
        );
    }

    #[cfg(target_os = "macos")]
    {
        let ca_trusted = is_ca_trusted(&ca_path);

        println!("CA certificate: {}", ca_path.display());

        // Early return only when no forwarding is requested — forwarding
        // always falls through to setup_forward_daemon() which does its
        // own content-based comparison to handle config changes.
        if ca_trusted && !forward && !force {
            println!(
                "{}",
                "CA certificate already trusted in system keychain."
                    .green()
                    .bold()
            );
            return Ok(());
        }

        // Changes needed — require root
        let is_root = std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false);
        if !is_root {
            let mut cmd = "sudo coulson trust".to_string();
            if forward {
                cmd.push_str(" --forward");
            }
            if force {
                cmd.push_str(" --force");
            }
            bail!("This command requires root privileges. Run: {cmd}");
        }

        if ca_trusted {
            println!(
                "{}",
                "CA certificate already trusted in system keychain."
                    .green()
                    .bold()
            );
        } else {
            println!("Adding CA to macOS System keychain...");
            let status = std::process::Command::new("security")
                .args([
                    "add-trusted-cert",
                    "-d",
                    "-r",
                    "trustRoot",
                    "-k",
                    "/Library/Keychains/System.keychain",
                ])
                .arg(&ca_path)
                .status()
                .context("failed to run security command")?;

            if status.success() {
                println!("{}", "CA certificate trusted successfully!".green().bold());
                println!(
                    "HTTPS connections to *.{} will now be trusted.",
                    cfg.domain_suffix
                );
            } else {
                eprintln!("{}", "Failed to add CA to System keychain.".red());
            }
        }

        if forward {
            setup_forward_daemon(&cfg, force)?;
            // Clean up legacy pf rules if present
            cleanup_pf_rules();
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        println!("CA certificate: {}", ca_path.display());

        match linux_ca_installed(&ca_path) {
            Some((true, _)) => {
                println!(
                    "{}",
                    "CA certificate already installed in system trust store."
                        .green()
                        .bold()
                );
                return Ok(());
            }
            Some((false, dest)) => {
                // Require root
                let is_root = std::process::Command::new("id")
                    .arg("-u")
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
                    .unwrap_or(false);
                if !is_root {
                    bail!("This command requires root privileges. Run: sudo coulson trust");
                }

                std::fs::copy(&ca_path, &dest)
                    .with_context(|| format!("failed to copy CA cert to {}", dest.display()))?;

                // Detect and run the appropriate update command
                let update_cmd = if which_exists("update-ca-certificates") {
                    "update-ca-certificates"
                } else {
                    "update-ca-trust"
                };
                let status = std::process::Command::new(update_cmd)
                    .status()
                    .with_context(|| format!("failed to run {update_cmd}"))?;

                if status.success() {
                    println!("{}", "CA certificate trusted successfully!".green().bold());
                    println!(
                        "HTTPS connections to *.{} will now be trusted.",
                        cfg.domain_suffix
                    );
                } else {
                    eprintln!("{}", format!("Failed to run {update_cmd}.").red());
                }
            }
            None => {
                println!("To trust this CA certificate, import it into your system trust store:");
                println!("  {}", ca_path.display());
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn is_ca_trusted(ca_path: &std::path::Path) -> bool {
    let disk_pem = match std::fs::read_to_string(ca_path) {
        Ok(p) => p.trim().to_string(),
        Err(_) => return false,
    };
    let output = std::process::Command::new("security")
        .args([
            "find-certificate",
            "-c",
            "Coulson Dev CA",
            "-p",
            "/Library/Keychains/System.keychain",
        ])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let kc_pem = String::from_utf8_lossy(&out.stdout).trim().to_string();
            disk_pem == kc_pem
        }
        _ => false,
    }
}

/// Check if Coulson CA cert is installed in system trust store on Linux.
/// Returns `Some((is_installed, dest_path))` if a known trust store is found, `None` otherwise.
#[cfg(not(target_os = "macos"))]
fn linux_ca_installed(ca_path: &std::path::Path) -> Option<(bool, std::path::PathBuf)> {
    // Debian/Ubuntu: /usr/local/share/ca-certificates/
    let debian = std::path::Path::new("/usr/local/share/ca-certificates");
    // RHEL/Fedora: /etc/pki/ca-trust/source/anchors/
    let redhat = std::path::Path::new("/etc/pki/ca-trust/source/anchors");

    let dest_dir = if debian.is_dir() {
        debian
    } else if redhat.is_dir() {
        redhat
    } else {
        return None;
    };

    let dest = dest_dir.join("coulson-dev-ca.crt");
    if !dest.is_file() {
        return Some((false, dest));
    }

    let disk = std::fs::read_to_string(ca_path).unwrap_or_default();
    let installed = std::fs::read_to_string(&dest).unwrap_or_default();
    Some((disk.trim() == installed.trim(), dest))
}

#[cfg(not(target_os = "macos"))]
fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
const FORWARD_PLIST_PATH: &str = "/Library/LaunchDaemons/com.coulson.forward.plist";

/// Check if the launchd forwarding daemon is installed and loaded.
#[cfg(target_os = "macos")]
fn is_forward_configured() -> bool {
    std::path::Path::new(FORWARD_PLIST_PATH).exists() && is_forward_service_loaded()
}

/// Check if the forwarding daemon forwards port 80 to the given HTTP port.
#[cfg(target_os = "macos")]
fn is_forward_configured_for_port(http_port: u16) -> bool {
    if !is_forward_configured() {
        return false;
    }
    let plist = match std::fs::read_to_string(FORWARD_PLIST_PATH) {
        Ok(c) => c,
        Err(_) => return false,
    };
    // Match exact plist XML value to avoid port prefix false positives (e.g. 1808 vs 18080)
    plist.contains(&format!("<string>127.0.0.1:{http_port}</string>"))
}

/// Check if the installed plist includes HTTPS (CoulsonHTTPS) socket and service is loaded.
#[cfg(target_os = "macos")]
fn is_forward_https_configured() -> bool {
    std::fs::read_to_string(FORWARD_PLIST_PATH)
        .map(|c| c.contains("CoulsonHTTPS"))
        .unwrap_or(false)
        && is_forward_service_loaded()
}

/// Check if the forwarding daemon forwards port 443 to the given HTTPS port.
#[cfg(target_os = "macos")]
fn is_forward_https_configured_for_port(https_port: u16) -> bool {
    if !is_forward_https_configured() {
        return false;
    }
    let plist = match std::fs::read_to_string(FORWARD_PLIST_PATH) {
        Ok(c) => c,
        Err(_) => return false,
    };
    plist.contains(&format!("<string>127.0.0.1:{https_port}</string>"))
}

/// Check if the com.coulson.forward service is loaded in launchd.
#[cfg(target_os = "macos")]
fn is_forward_service_loaded() -> bool {
    std::process::Command::new("launchctl")
        .args(["print", "system/com.coulson.forward"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
fn is_forward_configured_for_port(_http_port: u16) -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
fn is_forward_https_configured_for_port(_https_port: u16) -> bool {
    false
}

/// Run the `coulson forward` subcommand: activate launchd sockets and forward.
async fn run_forward(
    http_target: std::net::SocketAddr,
    https_target: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let mut handles = Vec::new();

    match launchd::activate_socket("CoulsonHTTP") {
        Ok(fds) if !fds.is_empty() => {
            info!("activated CoulsonHTTP socket ({} fd(s))", fds.len());
            handles.push(tokio::spawn(forward::run_forwarder(fds, http_target)));
        }
        Ok(_) => info!("no CoulsonHTTP sockets activated"),
        Err(e) => error!("failed to activate CoulsonHTTP: {e}"),
    }

    match launchd::activate_socket("CoulsonHTTPS") {
        Ok(fds) if !fds.is_empty() => {
            info!("activated CoulsonHTTPS socket ({} fd(s))", fds.len());
            handles.push(tokio::spawn(forward::run_forwarder(fds, https_target)));
        }
        Ok(_) => info!("no CoulsonHTTPS sockets activated"),
        Err(e) => error!("failed to activate CoulsonHTTPS: {e}"),
    }

    if handles.is_empty() {
        anyhow::bail!("no sockets activated — is launchd running this process?");
    }

    for h in handles {
        h.await??;
    }
    Ok(())
}

/// Install the launchd forwarding daemon plist.
#[cfg(target_os = "macos")]
fn setup_forward_daemon(cfg: &CoulsonConfig, force: bool) -> anyhow::Result<()> {
    let http_port = cfg.listen_http.port();
    let https_port = cfg.listen_https.map(|a| a.port());

    // Find the coulson binary path
    let coulson_bin = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("/usr/local/bin/coulson"));

    let username = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "root".to_string());

    // Build ProgramArguments
    let mut args = format!(
        "        <string>{bin}</string>\n\
         \x20       <string>forward</string>\n\
         \x20       <string>--http-target</string>\n\
         \x20       <string>127.0.0.1:{http_port}</string>",
        bin = coulson_bin.display(),
    );
    if let Some(port) = https_port {
        args.push_str(&format!(
            "\n\
             \x20       <string>--https-target</string>\n\
             \x20       <string>127.0.0.1:{port}</string>"
        ));
    }

    // Build Sockets dict — always include HTTP; only include HTTPS if enabled
    let mut sockets = "\
        <key>CoulsonHTTP</key>\n\
        \x20       <dict>\n\
        \x20           <key>SockServiceName</key>\n\
        \x20           <string>80</string>\n\
        \x20           <key>SockType</key>\n\
        \x20           <string>stream</string>\n\
        \x20       </dict>"
        .to_string();
    if https_port.is_some() {
        sockets.push_str(
            "\n\
            \x20       <key>CoulsonHTTPS</key>\n\
            \x20       <dict>\n\
            \x20           <key>SockServiceName</key>\n\
            \x20           <string>443</string>\n\
            \x20           <key>SockType</key>\n\
            \x20           <string>stream</string>\n\
            \x20       </dict>",
        );
    }

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.coulson.forward</string>
    <key>ProgramArguments</key>
    <array>
{args}
    </array>
    <key>UserName</key>
    <string>{username}</string>
    <key>Sockets</key>
    <dict>
        {sockets}
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/coulson-forward.log</string>
</dict>
</plist>
"#
    );

    // Check if already installed with same content
    let ports_desc = if https_port.is_some() { "80/443" } else { "80" };

    let existing = std::fs::read_to_string(FORWARD_PLIST_PATH).unwrap_or_default();
    if existing == plist && !force {
        println!(
            "{}",
            format!("Forwarding daemon already installed ({ports_desc}).")
                .green()
                .bold()
        );
        return Ok(());
    }

    println!(
        "Installing forwarding daemon ({ports_desc} -> 127.0.0.1:{http_port}{})...",
        https_port.map_or(String::new(), |p| format!("/127.0.0.1:{p}"))
    );

    // Unload existing if present
    if std::path::Path::new(FORWARD_PLIST_PATH).exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", "system", FORWARD_PLIST_PATH])
            .status();
    }

    std::fs::write(FORWARD_PLIST_PATH, &plist)
        .with_context(|| format!("failed to write {FORWARD_PLIST_PATH}"))?;

    let status = std::process::Command::new("launchctl")
        .args(["bootstrap", "system", FORWARD_PLIST_PATH])
        .status()
        .context("failed to run launchctl bootstrap")?;

    if status.success() {
        println!(
            "{}",
            "Forwarding daemon installed successfully!".green().bold()
        );
        println!("  80  -> 127.0.0.1:{http_port}");
        if let Some(port) = https_port {
            println!("  443 -> 127.0.0.1:{port}");
        }
    } else {
        // Clean up plist to avoid dirty state where file exists but service isn't loaded
        let _ = std::fs::remove_file(FORWARD_PLIST_PATH);
        bail!("Failed to bootstrap forwarding daemon. Check: launchctl bootstrap system {FORWARD_PLIST_PATH}");
    }

    Ok(())
}

/// Remove legacy pf forwarding rules if present.
#[cfg(target_os = "macos")]
fn cleanup_pf_rules() {
    let anchor_path = std::path::Path::new("/etc/pf.anchors/coulson");
    let pf_conf_path = std::path::Path::new("/etc/pf.conf");
    let loopback_plist = "/Library/LaunchDaemons/com.coulson.loopback.plist";

    let mut cleaned = false;

    // Remove pf anchor file
    if anchor_path.exists() && std::fs::remove_file(anchor_path).is_ok() {
        println!("Removed legacy pf anchor: {}", anchor_path.display());
        cleaned = true;
    }

    // Remove coulson lines from pf.conf
    if let Ok(content) = std::fs::read_to_string(pf_conf_path) {
        if content.contains("coulson") {
            let new_conf: String = content
                .lines()
                .filter(|l| !l.contains("coulson"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            if std::fs::write(pf_conf_path, &new_conf).is_ok() {
                println!("Cleaned coulson rules from {}", pf_conf_path.display());
                let _ = std::process::Command::new("pfctl")
                    .args(["-f", "/etc/pf.conf"])
                    .status();
                cleaned = true;
            }
        }
    }

    // Remove loopback alias plist
    if std::path::Path::new(loopback_plist).exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", "system", loopback_plist])
            .status();
        if std::fs::remove_file(loopback_plist).is_ok() {
            println!("Removed legacy loopback plist: {loopback_plist}");
            cleaned = true;
        }
    }

    if cleaned {
        println!("{}", "Legacy pf rules cleaned up.".green().bold());
    }
}

// Legacy pf detection (for backward compatibility during transition)
#[cfg(target_os = "macos")]
fn is_pf_configured(cfg: &CoulsonConfig) -> bool {
    is_pf_configured_quick(&cfg.listen_http, &cfg.listen_https)
}

#[cfg(not(target_os = "macos"))]
fn is_pf_configured(_cfg: &CoulsonConfig) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn is_pf_configured_quick(
    listen_http: &std::net::SocketAddr,
    listen_https: &Option<std::net::SocketAddr>,
) -> bool {
    let http_port = listen_http.port();
    let https_port = listen_https.map(|a| a.port());
    let ip = crate::config::PF_REDIRECT_IP;
    let anchor_ref = "rdr-anchor \"coulson\"";
    let anchor_load = "load anchor \"coulson\" from \"/etc/pf.anchors/coulson\"";

    let mut expected_rules = format!(
        "rdr pass on lo0 inet proto tcp from any to any port 80 -> {ip} port {http_port}\n\
         rdr pass on lo0 inet6 proto tcp from any to any port 80 -> ::1 port {http_port}\n"
    );
    if let Some(port) = https_port {
        expected_rules.push_str(&format!(
            "rdr pass on lo0 inet proto tcp from any to any port 443 -> {ip} port {port}\n\
             rdr pass on lo0 inet6 proto tcp from any to any port 443 -> ::1 port {port}\n"
        ));
    }

    let anchor_path = std::path::Path::new("/etc/pf.anchors/coulson");
    let pf_conf_path = std::path::Path::new("/etc/pf.conf");
    let existing_anchor = std::fs::read_to_string(anchor_path).unwrap_or_default();
    let existing_pf_conf = std::fs::read_to_string(pf_conf_path).unwrap_or_default();
    existing_anchor == expected_rules
        && existing_pf_conf.contains(anchor_ref)
        && existing_pf_conf.contains(anchor_load)
}

#[cfg(not(target_os = "macos"))]
fn is_pf_configured_quick(
    _listen_http: &std::net::SocketAddr,
    _listen_https: &Option<std::net::SocketAddr>,
) -> bool {
    false
}

#[cfg(test)]
mod process_target_tests {
    use super::*;

    #[test]
    fn no_arg_is_group_of_cwd_app() {
        assert_eq!(parse_process_target(None).unwrap(), (None, None));
    }

    #[test]
    fn bare_name_is_whole_group() {
        assert_eq!(
            parse_process_target(Some("myapp".into())).unwrap(),
            (Some("myapp".into()), None)
        );
    }

    #[test]
    fn name_and_type() {
        assert_eq!(
            parse_process_target(Some("myapp:worker".into())).unwrap(),
            (Some("myapp".into()), Some("worker".into()))
        );
    }

    #[test]
    fn type_only_uses_cwd_app() {
        assert_eq!(
            parse_process_target(Some(":worker".into())).unwrap(),
            (None, Some("worker".into()))
        );
    }

    #[test]
    fn trailing_colon_is_an_error() {
        assert!(parse_process_target(Some("myapp:".into())).is_err());
    }
}

#[cfg(test)]
mod add_tests {
    use super::*;

    #[test]
    fn auto_detect_no_args() {
        let mode = classify_add(None, None).unwrap();
        assert_eq!(mode, AddMode::AutoDetect);
    }

    #[test]
    fn named_with_string() {
        let mode = classify_add(Some("myapp"), None).unwrap();
        assert_eq!(mode, AddMode::Named { name: "myapp" });
    }

    #[test]
    fn bare_port_number() {
        let mode = classify_add(Some("3001"), None).unwrap();
        assert_eq!(mode, AddMode::BarePort(3001));
    }

    #[test]
    fn manual_name_and_port() {
        let mode = classify_add(Some("myapp"), Some("3001")).unwrap();
        assert_eq!(
            mode,
            AddMode::Manual {
                name: "myapp",
                target: "3001"
            }
        );
    }

    #[test]
    fn manual_name_and_host_port() {
        let mode = classify_add(Some("myapp"), Some("192.168.1.5:3001")).unwrap();
        assert_eq!(
            mode,
            AddMode::Manual {
                name: "myapp",
                target: "192.168.1.5:3001"
            }
        );
    }

    #[test]
    fn manual_name_and_socket() {
        let mode = classify_add(Some("myapp"), Some("/tmp/app.sock")).unwrap();
        assert_eq!(
            mode,
            AddMode::Manual {
                name: "myapp",
                target: "/tmp/app.sock"
            }
        );
    }

    #[test]
    fn target_without_name_is_error() {
        assert!(classify_add(None, Some("3001")).is_err());
    }

    #[test]
    fn port_zero_is_name_not_port() {
        // port 0 parses as u16 but is unusual; still treated as bare port
        let mode = classify_add(Some("0"), None).unwrap();
        assert_eq!(mode, AddMode::BarePort(0));
    }

    #[test]
    fn large_number_beyond_u16_is_name() {
        let mode = classify_add(Some("99999"), None).unwrap();
        assert_eq!(mode, AddMode::Named { name: "99999" });
    }
}
