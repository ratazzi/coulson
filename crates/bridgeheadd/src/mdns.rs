use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, UdpSocket};
use std::path::Path;

use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::SharedState;

const SERVICE_TYPE: &str = "_bridgehead._tcp.local.";
/// macOS updates this file on every network change (interface up/down, WiFi switch, etc.)
const RESOLV_CONF: &str = "/var/run/resolv.conf";
/// Fallback: poll local IP every N seconds when resolv.conf watching is unavailable
const IP_POLL_INTERVAL_SECS: u64 = 5;

pub async fn run_mdns_responder(state: SharedState) -> anyhow::Result<()> {
    let mdns = ServiceDaemon::new()?;
    mdns.disable_interface(IfKind::IPv6)?;
    let mut route_rx = state.route_tx.subscribe();

    // Primary: watch /var/run/resolv.conf for network changes
    let (net_tx, mut net_rx) = mpsc::channel::<()>(1);
    let _watcher = watch_resolv_conf(net_tx.clone());

    // Fallback: poll local IP for network changes
    let has_watcher = _watcher.is_some();
    let mut ip_poll_timer = interval(Duration::from_secs(IP_POLL_INTERVAL_SECS));
    let mut last_local_ip = detect_local_ip();

    // registered: domain -> fullname (for unregister)
    let mut registered: HashMap<String, String> = HashMap::new();

    // Initial sync
    sync_records(&mdns, &state, &mut registered);

    loop {
        tokio::select! {
            result = route_rx.recv() => {
                match result {
                    Ok(()) => sync_records(&mdns, &state, &mut registered),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "mdns responder lagged, re-syncing");
                        sync_records(&mdns, &state, &mut registered);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("mdns responder shutting down (channel closed)");
                        break;
                    }
                }
            }
            _ = net_rx.recv() => {
                info!("network change detected (resolv.conf), re-registering mdns records");
                reregister_all(&mdns, &mut registered);
                // Also update last_local_ip to stay in sync
                last_local_ip = detect_local_ip();
            }
            _ = ip_poll_timer.tick(), if !has_watcher => {
                let current_ip = detect_local_ip();
                if current_ip != last_local_ip {
                    info!(
                        old = ?last_local_ip,
                        new = ?current_ip,
                        "network change detected (IP changed), re-registering mdns records"
                    );
                    last_local_ip = current_ip;
                    reregister_all(&mdns, &mut registered);
                }
            }
        }
    }

    // Unregister all on shutdown
    for (domain, fullname) in &registered {
        if let Err(e) = mdns.unregister(fullname) {
            warn!(domain, error = %e, "failed to unregister mdns service");
        }
    }
    if let Err(e) = mdns.shutdown() {
        warn!(error = %e, "failed to shutdown mdns daemon");
    }

    Ok(())
}

fn detect_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

fn watch_resolv_conf(tx: mpsc::Sender<()>) -> Option<RecommendedWatcher> {
    let path = Path::new(RESOLV_CONF);
    if !path.exists() {
        warn!("resolv.conf not found at {RESOLV_CONF}, falling back to IP polling");
        return None;
    }

    let mut watcher = match notify::recommended_watcher(move |res: Result<Event, _>| {
        if let Ok(event) = res {
            if matches!(
                event.kind,
                EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
            ) {
                let _ = tx.try_send(());
            }
        }
    }) {
        Ok(w) => w,
        Err(e) => {
            warn!(error = %e, "failed to create resolv.conf watcher, falling back to IP polling");
            return None;
        }
    };

    if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
        warn!(error = %e, "failed to watch {RESOLV_CONF}, falling back to IP polling");
        return None;
    }

    info!("watching {RESOLV_CONF} for network changes");
    Some(watcher)
}

fn sync_records(
    mdns: &ServiceDaemon,
    state: &SharedState,
    registered: &mut HashMap<String, String>,
) {
    let current_domains: HashSet<String> = {
        let routes = state.routes.read();
        routes.keys().cloned().collect()
    };

    // Remove stale
    let stale: Vec<String> = registered
        .keys()
        .filter(|d| !current_domains.contains(*d))
        .cloned()
        .collect();
    for domain in stale {
        if let Some(fullname) = registered.remove(&domain) {
            if let Err(e) = mdns.unregister(&fullname) {
                warn!(domain, error = %e, "failed to unregister mdns service");
            } else {
                info!(domain, "mdns unregistered");
            }
        }
    }

    // Register new
    for domain in &current_domains {
        if registered.contains_key(domain) || !is_local_domain(domain) {
            continue;
        }
        match register_domain(mdns, domain) {
            Ok(fullname) => {
                info!(domain, "mdns registered");
                registered.insert(domain.clone(), fullname);
            }
            Err(e) => {
                error!(domain, error = %e, "failed to register mdns service");
            }
        }
    }
}

fn reregister_all(mdns: &ServiceDaemon, registered: &mut HashMap<String, String>) {
    if registered.is_empty() {
        return;
    }
    let domains: Vec<(String, String)> = registered.drain().collect();
    for (_domain, fullname) in &domains {
        let _ = mdns.unregister(fullname);
    }
    for (domain, _) in domains {
        match register_domain(mdns, &domain) {
            Ok(fullname) => {
                debug!(domain, "mdns re-registered");
                registered.insert(domain, fullname);
            }
            Err(e) => {
                error!(domain, error = %e, "failed to re-register mdns service");
            }
        }
    }
}

fn is_local_domain(domain: &str) -> bool {
    domain.ends_with(".local") || domain == "local"
}

fn register_domain(mdns: &ServiceDaemon, domain: &str) -> anyhow::Result<String> {
    let instance_name = domain;
    let hostname = format!("{domain}.");
    let properties: HashMap<String, String> = HashMap::new();

    let mut service_info = ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        &hostname,
        "127.0.0.1",
        0,
        Some(properties),
    )?;
    service_info.set_interfaces(vec![IfKind::LoopbackV4]);

    let fullname = service_info.get_fullname().to_string();
    let _ = mdns.unregister(&fullname);
    mdns.register(service_info)?;
    Ok(fullname)
}
