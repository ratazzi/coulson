mod certs;
mod config;
mod control;
mod dashboard;
mod domain;
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

use crate::config::CoulsonConfig;
use crate::domain::{BackendTarget, TunnelMode};
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
    pub certs_dir: std::path::PathBuf,
    pub runtime_dir: std::path::PathBuf,
}

impl SharedState {
    pub fn reload_routes(&self) -> anyhow::Result<bool> {
        let enabled_apps = self.store.list_enabled()?;
        let mut table: HashMap<String, Vec<RouteRule>> = HashMap::new();
        let mut port_domains: HashMap<u16, String> = HashMap::new();
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
            if let Some(port) = app.listen_port {
                port_domains.insert(port, app.domain.0.clone());
            }
            let rule = RouteRule {
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
            };
            table.entry(app.domain.0).or_default().push(rule);
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
    Doctor {
        /// Also check pf port forwarding configuration
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
    },
    /// Show running managed processes
    Ps,
    /// Restart a managed process
    Restart {
        /// App name or domain (omit to match CWD)
        name: Option<String>,
    },
    /// Trust the Coulson CA certificate (add to macOS login keychain)
    Trust {
        /// Also set up pf port forwarding (80/443 -> Coulson listen ports)
        #[arg(long)]
        pf: bool,
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
        /// Tunnel token (from CF dashboard)
        #[arg(long)]
        token: Option<String>,
        /// Tunnel domain
        #[arg(long)]
        domain: Option<String>,
    },
    /// Disconnect global named tunnel
    Disconnect,
    /// Save Cloudflare API credentials
    Configure {
        /// CF API token
        #[arg(long)]
        api_token: String,
        /// CF account ID
        #[arg(long)]
        account_id: String,
    },
    /// Create a global named tunnel via CF API
    Setup {
        /// Tunnel domain
        #[arg(long)]
        domain: String,
        /// Tunnel name (defaults to coulson-<domain>)
        #[arg(long)]
        tunnel_name: Option<String>,
        /// CF API token
        #[arg(long)]
        api_token: String,
        /// CF account ID
        #[arg(long)]
        account_id: String,
    },
    /// Delete the global named tunnel via CF API
    Teardown {
        /// CF API token
        #[arg(long)]
        api_token: String,
    },
    /// Create a per-app custom named tunnel via CF API
    AppSetup {
        /// App name or domain
        name: String,
        /// Tunnel domain
        #[arg(long)]
        domain: String,
        /// Auto-create DNS CNAME record
        #[arg(long)]
        auto_dns: bool,
    },
    /// Delete a per-app custom named tunnel via CF API
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
    let idle_timeout = Duration::from_secs(cfg.idle_timeout_secs);
    let registry = Arc::new(process::default_registry());
    let process_manager =
        process::new_process_manager(idle_timeout, Arc::clone(&registry), cfg.runtime_dir.clone());

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
        certs_dir: cfg.certs_dir.clone(),
        runtime_dir: cfg.runtime_dir.clone(),
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

fn run_ls(cfg: CoulsonConfig, managed: Option<bool>, domain: Option<String>) -> anyhow::Result<()> {
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
    let table = tabled::Table::new(&rows).with(Style::blank()).to_string();
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

    // 7. LAN access (per-app)
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

    // 8. TLS certificates
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

    // 9. pf port forwarding (optional)
    if check_pf {
        #[cfg(target_os = "macos")]
        {
            if is_pf_configured(&cfg) {
                let http_port = cfg.listen_http.port();
                let https_port = cfg.listen_https.map(|a| a.port());
                print_check(
                    true,
                    &format!(
                        "pf forwarding configured (80 -> {http_port}, 443 -> {})",
                        https_port.map_or("n/a".to_string(), |p| p.to_string())
                    ),
                );
            } else {
                print_check(false, "pf forwarding not configured");
                print_warn("run: sudo coulson trust --pf");
                issues += 1;
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            print_check(true, "pf check skipped (not macOS)");
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
fn check_keychain_ca(_ca_path: &std::path::Path, _issues: &mut u32) {
    // Keychain check is macOS-only
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

    // TLS certificate setup
    let tls_config = if let Some(https_addr) = cfg.listen_https {
        match certs::CertManager::ensure(&cfg.certs_dir, &cfg.domain_suffix) {
            Ok(cm) => Some(proxy::TlsConfig {
                bind: https_addr.to_string(),
                cert_path: cm.cert_path().to_string(),
                key_path: cm.key_path().to_string(),
                ca_path: cm.ca_path().to_string(),
            }),
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
                Ok(stats) => {
                    if let Err(err) =
                        runtime::write_scan_warnings(&watch_state.scan_warnings_path, &stats)
                    {
                        error!(error = %err, "failed to write scan warnings");
                    }
                    match watch_state.reload_routes() {
                        Ok(true) => {
                            let _ = watch_state
                                .change_tx
                                .send("detail-tunnel,detail-features,detail-urls".to_string());
                        }
                        Ok(false) => {}
                        Err(err) => {
                            error!(error = %err, "failed to reload routes after fs event");
                        }
                    }
                    debug!(
                        discovered = stats.discovered,
                        inserted = stats.inserted,
                        updated = stats.updated,
                        skipped_manual = stats.skipped_manual,
                        pruned = stats.pruned,
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
        Commands::Doctor { pf } => run_doctor(cfg, pf),
        Commands::Share { name, expires } => run_share(cfg, name, expires),
        Commands::Unshare { name } => run_unshare(cfg, name),
        Commands::Logs {
            name,
            follow,
            lines,
        } => run_logs(cfg, name, follow, lines),
        Commands::Ps => run_ps(cfg),
        Commands::Restart { name } => run_restart(cfg, name),
        Commands::Trust { pf } => run_trust(cfg, pf),
        Commands::Tunnel { action } => run_tunnel(cfg, action),
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
    let dir_name = cwd.file_name().and_then(|n| n.to_str()).unwrap_or("app");
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

    // --port mode
    if let Some(p) = port {
        std::fs::create_dir_all(&cfg.apps_root)?;

        if cfg.link_dir {
            // Legacy mode: write powfile directly in apps_root
            std::fs::write(&link_path, format!("{p}\n"))?;
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
            #[cfg(unix)]
            std::os::unix::fs::symlink(&dotfile, &link_path).with_context(|| {
                format!(
                    "failed to create symlink {} -> {}",
                    link_path.display(),
                    dotfile.display()
                )
            })?;
        }

        println!(
            "{} {name}.{} -> 127.0.0.1:{p}",
            "+".green().bold(),
            cfg.domain_suffix
        );
        println!(
            "  {}",
            format!(
                "http://{name}.{}:{}",
                cfg.domain_suffix,
                cfg.listen_http.port()
            )
            .cyan()
        );
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
        println!(
            "  {}",
            format!(
                "http://{name}.{}:{}",
                cfg.domain_suffix,
                cfg.listen_http.port()
            )
            .cyan()
        );
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
        println!(
            "  {}",
            format!(
                "http://{name}.{}:{}",
                cfg.domain_suffix,
                cfg.listen_http.port()
            )
            .cyan()
        );
        println!(
            "  {}",
            "Tip: use --port to specify a target port, or add coulson.json/coulson.routes".dimmed()
        );
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

    let (target_type, target_value, display) = if target.starts_with('/') {
        ("unix_socket", target.to_string(), format!("unix:{target}"))
    } else if let Ok(port) = target.parse::<u16>() {
        (
            "tcp",
            format!("127.0.0.1:{port}"),
            format!("127.0.0.1:{port}"),
        )
    } else if target.contains(':') {
        // Validate host:port
        let (_, port_str) = target.rsplit_once(':').unwrap();
        port_str
            .parse::<u16>()
            .with_context(|| format!("invalid port in target: {target}"))?;
        ("tcp", target.to_string(), target.to_string())
    } else {
        bail!("invalid target: {target}. Expected: port, host:port, or /path/to/socket");
    };

    client.call(
        "app.create",
        serde_json::json!({
            "name": name,
            "domain": domain,
            "target_type": target_type,
            "target_value": target_value,
        }),
    )?;
    println!("{} {domain} -> {display}", "+".green().bold());

    println!(
        "  {}",
        format!("http://{domain}:{}", cfg.listen_http.port()).cyan()
    );
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
        bail!("app not found: {name}");
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
) -> anyhow::Result<(String, String)> {
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
        .and_then(|a| {
            a.get("id")
                .map(|i| i.to_string().trim_matches('"').to_string())
        })
        .ok_or_else(|| anyhow::anyhow!("app not found: {bare_name}"))?;

    Ok((bare_name, app_id))
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
            let kind = p.get("kind").and_then(|v| v.as_str()).unwrap_or("unknown");
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

fn run_restart(cfg: CoulsonConfig, name: Option<String>) -> anyhow::Result<()> {
    let client = RpcClient::new(&cfg.control_socket);
    let (bare_name, app_id) = resolve_app_id(&client, &cfg, name)?;

    client.call("process.restart", serde_json::json!({ "app_id": app_id }))?;
    println!("{} {bare_name} restarted", "✓".green());
    Ok(())
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
) -> anyhow::Result<()> {
    let client = RpcClient::new(&cfg.control_socket);

    // Try RPC first, fallback to local DB
    let (bare_name, _app_id) = match resolve_app_id(&client, &cfg, name.clone()) {
        Ok(v) => v,
        Err(_) => {
            let bare_name = resolve_app_name(&cfg, name.as_deref())?;
            let domain_match = format!("{bare_name}.{}", cfg.domain_suffix);
            let state = build_state(&cfg)?;
            let apps = state.store.list_all()?;
            let app = apps
                .iter()
                .find(|a| {
                    a.name == bare_name || a.domain.0 == domain_match || a.domain.0 == bare_name
                })
                .ok_or_else(|| anyhow::anyhow!("app not found: {bare_name}"))?;
            (bare_name, app.id.0.to_string())
        }
    };

    let log_path = cfg
        .runtime_dir
        .join("managed")
        .join(format!("{bare_name}.log"));
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
            let cf_status = client.call("tunnel.configure_status", serde_json::json!({}));
            let cf_configured = cf_status
                .ok()
                .and_then(|v| v.get("configured").and_then(|c| c.as_bool()))
                .unwrap_or(false);
            if cf_configured {
                println!("CF Credentials: {}", "configured".green());
            } else {
                println!("CF Credentials: {}", "not configured".dimmed());
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
                    let app_info = find_app_json(&client, &app_id)?;
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
                    println!("  {}", "app exposed via global named tunnel".dimmed());
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
        TunnelCommands::Configure {
            api_token,
            account_id,
        } => {
            client.call(
                "tunnel.configure",
                serde_json::json!({ "api_token": api_token, "account_id": account_id }),
            )?;
            println!("{} CF credentials saved", "✓".green());
            Ok(())
        }
        TunnelCommands::Setup {
            domain,
            tunnel_name,
            api_token,
            account_id,
        } => {
            let mut params = serde_json::json!({
                "api_token": api_token,
                "account_id": account_id,
                "domain": domain,
            });
            if let Some(n) = &tunnel_name {
                params["tunnel_name"] = serde_json::json!(n);
            }
            let result = client.call("named_tunnel.setup", params)?;
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
            client.call(
                "named_tunnel.teardown",
                serde_json::json!({ "api_token": api_token }),
            )?;
            println!("{} global named tunnel destroyed", "✓".green());
            Ok(())
        }
        TunnelCommands::AppSetup {
            name,
            domain,
            auto_dns,
        } => {
            let (bare_name, app_id) = resolve_app_id(&client, &cfg, Some(name))?;
            let result = client.call(
                "tunnel.app_setup",
                serde_json::json!({
                    "app_id": app_id,
                    "domain": domain,
                    "auto_dns": auto_dns,
                }),
            )?;
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
fn find_app_json(client: &RpcClient, app_id: &str) -> anyhow::Result<serde_json::Value> {
    let result = client.call("app.list", serde_json::json!({}))?;
    result
        .get("apps")
        .and_then(|v| v.as_array())
        .and_then(|apps| {
            apps.iter()
                .find(|a| {
                    a.get("id")
                        .map(|v| v.to_string().trim_matches('"').to_string())
                        .as_deref()
                        == Some(app_id)
                })
                .cloned()
        })
        .ok_or_else(|| anyhow::anyhow!("app not found: {app_id}"))
}

fn run_trust(cfg: CoulsonConfig, #[allow(unused)] pf: bool) -> anyhow::Result<()> {
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
        let pf_ok = if pf { is_pf_configured(&cfg) } else { true };

        println!("CA certificate: {}", ca_path.display());

        if ca_trusted && pf_ok {
            println!(
                "{}",
                "CA certificate already trusted in system keychain."
                    .green()
                    .bold()
            );
            if pf {
                let http_port = cfg.listen_http.port();
                let https_port = cfg.listen_https.map(|a| a.port());
                println!(
                    "{}",
                    format!(
                        "Port forwarding already configured (80 -> {http_port}, 443 -> {}).",
                        https_port.map_or("disabled".to_string(), |p| p.to_string())
                    )
                    .green()
                    .bold()
                );
            }
            return Ok(());
        }

        // Changes needed — require root
        let is_root = std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false);
        if !is_root {
            let cmd = if pf {
                "sudo coulson trust --pf"
            } else {
                "sudo coulson trust"
            };
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

        if pf {
            setup_pf_forwarding(&cfg)?;
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        println!("CA certificate: {}", ca_path.display());
        println!("To trust this CA certificate, import it into your system trust store:");
        println!("  {}", ca_path.display());
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

#[cfg(target_os = "macos")]
fn build_pf_rules(cfg: &CoulsonConfig) -> (String, String, String) {
    let http_port = cfg.listen_http.port();
    let https_port = cfg.listen_https.map(|a| a.port());
    let anchor_ref = "rdr-anchor \"coulson\"".to_string();
    let anchor_load = "load anchor \"coulson\" from \"/etc/pf.anchors/coulson\"".to_string();

    let mut rules = format!(
        "rdr pass inet proto tcp from any to any port 80 -> 127.0.0.1 port {http_port}\n\
         rdr pass inet6 proto tcp from any to any port 80 -> ::1 port {http_port}\n"
    );
    if let Some(port) = https_port {
        rules.push_str(&format!(
            "rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port {port}\n\
             rdr pass inet6 proto tcp from any to any port 443 -> ::1 port {port}\n"
        ));
    }
    (rules, anchor_ref, anchor_load)
}

#[cfg(target_os = "macos")]
fn is_pf_configured(cfg: &CoulsonConfig) -> bool {
    let (rules, anchor_ref, anchor_load) = build_pf_rules(cfg);
    let anchor_path = std::path::Path::new("/etc/pf.anchors/coulson");
    let pf_conf_path = std::path::Path::new("/etc/pf.conf");
    let existing_anchor = std::fs::read_to_string(anchor_path).unwrap_or_default();
    let existing_pf_conf = std::fs::read_to_string(pf_conf_path).unwrap_or_default();
    existing_anchor == rules
        && existing_pf_conf.contains(&anchor_ref)
        && existing_pf_conf.contains(&anchor_load)
}

#[cfg(target_os = "macos")]
fn setup_pf_forwarding(cfg: &CoulsonConfig) -> anyhow::Result<()> {
    let http_port = cfg.listen_http.port();
    let https_port = cfg.listen_https.map(|a| a.port());

    let anchor_path = std::path::Path::new("/etc/pf.anchors/coulson");
    let pf_conf_path = std::path::Path::new("/etc/pf.conf");
    let (rules, anchor_ref, anchor_load) = build_pf_rules(cfg);

    // Check if already configured
    let existing_anchor = std::fs::read_to_string(anchor_path).unwrap_or_default();
    let existing_pf_conf = std::fs::read_to_string(pf_conf_path).unwrap_or_default();
    let anchor_ok = existing_anchor == rules;
    let pf_conf_ok =
        existing_pf_conf.contains(&anchor_ref) && existing_pf_conf.contains(&anchor_load);

    if anchor_ok && pf_conf_ok {
        println!(
            "{}",
            format!(
                "Port forwarding already configured (80 -> {http_port}, 443 -> {}).",
                https_port.map_or("disabled".to_string(), |p| p.to_string())
            )
            .green()
            .bold()
        );
        return Ok(());
    }

    println!(
        "Setting up port forwarding (80 -> {http_port}, 443 -> {})...",
        https_port.map_or("disabled".to_string(), |p| p.to_string())
    );

    // Write anchor file
    std::fs::write(anchor_path, &rules).context("failed to write /etc/pf.anchors/coulson")?;

    // Rewrite pf.conf with coulson anchors at correct positions
    // pf requires order: options, normalization, queueing, translation (rdr), filtering (anchor)
    if !pf_conf_ok {
        // Strip any existing coulson lines first
        let cleaned: Vec<&str> = existing_pf_conf
            .lines()
            .filter(|l| !l.contains("coulson"))
            .collect();

        let mut new_conf = String::new();
        let mut rdr_inserted = false;
        for line in &cleaned {
            // Insert rdr-anchor before the first filtering anchor line
            if !rdr_inserted && line.starts_with("anchor ") {
                new_conf.push_str(&anchor_ref);
                new_conf.push('\n');
                rdr_inserted = true;
            }
            new_conf.push_str(line);
            new_conf.push('\n');
        }
        if !rdr_inserted {
            new_conf.push_str(&anchor_ref);
            new_conf.push('\n');
        }
        // load anchor goes at the end
        new_conf.push_str(&anchor_load);
        new_conf.push('\n');

        std::fs::write(pf_conf_path, &new_conf).context("failed to write /etc/pf.conf")?;
    }

    // Reload pf
    let status = std::process::Command::new("pfctl")
        .args(["-f", "/etc/pf.conf"])
        .status()
        .context("failed to reload pf")?;

    if status.success() {
        println!("{}", "Port forwarding enabled successfully!".green().bold());
        println!("  80  -> 127.0.0.1:{http_port}");
        if let Some(port) = https_port {
            println!("  443 -> 127.0.0.1:{port}");
        }
    } else {
        bail!("Failed to reload pf rules. You can manually reload: pfctl -f /etc/pf.conf");
    }

    Ok(())
}
