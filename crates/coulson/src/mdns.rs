use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, UdpSocket};
use std::path::Path;

use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::SharedState;

const SERVICE_TYPE: &str = "_coulson._tcp.local.";
/// macOS updates this file on every network change (interface up/down, WiFi switch, etc.)
const RESOLV_CONF: &str = "/var/run/resolv.conf";
/// Fallback: poll local IP every N seconds when resolv.conf watching is unavailable
const IP_POLL_INTERVAL_SECS: u64 = 5;

pub async fn run_mdns_responder(state: SharedState) -> anyhow::Result<()> {
    let mdns = ServiceDaemon::new()?;
    // Disable non-loopback IPv6 to avoid AAAA record pollution.
    // Per-service interface selection (loopback vs LAN) is handled by
    // register_domain() via ServiceInfo::set_interfaces().
    mdns.disable_interface(IfKind::IPv6)?;

    let mut route_rx = state.route_tx.subscribe();

    // Primary: watch /var/run/resolv.conf for network changes
    let (net_tx, mut net_rx) = mpsc::channel::<()>(1);
    let _watcher = watch_resolv_conf(net_tx.clone());

    // Fallback: poll local IP for network changes
    let has_watcher = _watcher.is_some();
    let mut ip_poll_timer = interval(Duration::from_secs(IP_POLL_INTERVAL_SECS));
    let mut last_local_ip = detect_local_ip();

    // registered: domain -> (fullname, was_lan)
    let mut registered: HashMap<String, (String, bool)> = HashMap::new();

    // Initial sync
    sync_records(&mdns, &state, &mut registered);

    loop {
        tokio::select! {
            result = route_rx.recv() => {
                match result {
                    Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
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
                reregister_all(&mdns, &state, &mut registered);
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
                    reregister_all(&mdns, &state, &mut registered);
                }
            }
        }
    }

    // Unregister all on shutdown
    for (domain, (fullname, _)) in &registered {
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
    // Use getifaddrs to find a non-loopback, non-tunnel IPv4 address.
    // This avoids returning VPN/tunnel IPs (utun*, tun*, ppp*) which
    // don't support mDNS multicast.
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return detect_local_ip_fallback();
        }

        let mut result = None;
        let mut cursor = ifaddrs;
        while !cursor.is_null() {
            let ifa = &*cursor;
            let flags = ifa.ifa_flags;

            // Skip down, loopback, and point-to-point (VPN/tunnel) interfaces
            if (flags & libc::IFF_UP as u32) == 0
                || (flags & libc::IFF_LOOPBACK as u32) != 0
                || (flags & libc::IFF_POINTOPOINT as u32) != 0
            {
                cursor = ifa.ifa_next;
                continue;
            }

            if !ifa.ifa_addr.is_null() {
                let sa = &*ifa.ifa_addr;
                #[allow(clippy::unnecessary_cast)]
                if sa.sa_family as libc::sa_family_t == libc::AF_INET as libc::sa_family_t {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if !ip.is_loopback() && !ip.is_link_local() {
                        result = Some(IpAddr::V4(ip));
                        break;
                    }
                }
            }

            cursor = ifa.ifa_next;
        }

        libc::freeifaddrs(ifaddrs);
        result.or_else(detect_local_ip_fallback)
    }
}

/// Fallback: connect to external address to determine local IP.
fn detect_local_ip_fallback() -> Option<IpAddr> {
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

/// Check if any route for this domain has lan_access enabled.
fn domain_has_lan_access(state: &SharedState, domain: &str) -> bool {
    let routes = state.routes.read();
    routes
        .get(domain)
        .map(|rules| rules.iter().any(|r| r.lan_access))
        .unwrap_or(false)
}

fn sync_records(
    mdns: &ServiceDaemon,
    state: &SharedState,
    registered: &mut HashMap<String, (String, bool)>,
) {
    let mut current_domains: HashSet<String> = {
        let routes = state.routes.read();
        routes.keys().cloned().collect()
    };
    // Always register the bare domain suffix (redirect host) and dashboard subdomain
    current_domains.insert(state.domain_suffix.clone());
    current_domains.insert(format!("dashboard.{}", state.domain_suffix));

    // Remove stale
    let stale: Vec<String> = registered
        .keys()
        .filter(|d| !current_domains.contains(*d))
        .cloned()
        .collect();
    for domain in stale {
        if let Some((fullname, _)) = registered.remove(&domain) {
            if let Err(e) = mdns.unregister(&fullname) {
                warn!(domain, error = %e, "failed to unregister mdns service");
            } else {
                info!(domain, "mdns unregistered");
            }
        }
    }

    // Re-register domains whose lan_access changed
    let lan_ip = detect_local_ip();
    let mut changed: Vec<String> = Vec::new();
    for domain in &current_domains {
        if !is_local_domain(domain) {
            continue;
        }
        let is_bare_suffix = domain == &state.domain_suffix;
        let use_lan = !is_bare_suffix && domain_has_lan_access(state, domain);
        if let Some((_, was_lan)) = registered.get(domain) {
            if *was_lan != use_lan {
                changed.push(domain.clone());
            }
        }
    }
    for domain in &changed {
        if let Some((fullname, _)) = registered.remove(domain) {
            let _ = mdns.unregister(&fullname);
        }
    }

    // Register new and re-register changed
    for domain in &current_domains {
        if registered.contains_key(domain) || !is_local_domain(domain) {
            continue;
        }
        let is_bare_suffix = domain == &state.domain_suffix;
        let use_lan = !is_bare_suffix && domain_has_lan_access(state, domain);
        match register_domain(mdns, domain, if use_lan { lan_ip } else { None }) {
            Ok(fullname) => {
                info!(domain, lan = use_lan, "mdns registered");
                registered.insert(domain.clone(), (fullname, use_lan));
            }
            Err(e) => {
                error!(domain, error = %e, "failed to register mdns service");
            }
        }
    }
}

fn reregister_all(
    mdns: &ServiceDaemon,
    state: &SharedState,
    registered: &mut HashMap<String, (String, bool)>,
) {
    if registered.is_empty() {
        return;
    }
    let lan_ip = detect_local_ip();
    let domains: Vec<(String, (String, bool))> = registered.drain().collect();
    for (_domain, (fullname, _)) in &domains {
        let _ = mdns.unregister(fullname);
    }
    for (domain, _) in domains {
        let is_bare_suffix = domain == state.domain_suffix;
        let use_lan = !is_bare_suffix && domain_has_lan_access(state, &domain);
        match register_domain(mdns, &domain, if use_lan { lan_ip } else { None }) {
            Ok(fullname) => {
                debug!(domain, lan = use_lan, "mdns re-registered");
                registered.insert(domain, (fullname, use_lan));
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

/// Register a domain in mDNS.
/// If `lan_ip` is Some, the A record uses that IP (for LAN-visible app domains).
/// If None, uses 127.0.0.1 (loopback only).
fn register_domain(
    mdns: &ServiceDaemon,
    domain: &str,
    lan_ip: Option<IpAddr>,
) -> anyhow::Result<String> {
    let instance_name = domain;
    let hostname = format!("{domain}.");
    let properties: HashMap<String, String> = HashMap::new();

    let ip_str = match lan_ip {
        Some(ip) => ip.to_string(),
        None => "127.0.0.1,::1".to_string(),
    };

    let mut service_info = ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        &hostname,
        &ip_str,
        0,
        Some(properties),
    )?;

    match lan_ip {
        Some(ip) => service_info.set_interfaces(vec![IfKind::Addr(ip)]),
        None => service_info.set_interfaces(vec![IfKind::LoopbackV4, IfKind::LoopbackV6]),
    }

    let fullname = service_info.get_fullname().to_string();
    let _ = mdns.unregister(&fullname);
    mdns.register(service_info)?;
    Ok(fullname)
}
