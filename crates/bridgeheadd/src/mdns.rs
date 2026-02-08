use std::collections::{HashMap, HashSet};

use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use tracing::{error, info, warn};

use crate::SharedState;

const SERVICE_TYPE: &str = "_bridgehead._tcp.local.";

pub async fn run_mdns_responder(state: SharedState) -> anyhow::Result<()> {
    let mdns = ServiceDaemon::new()?;
    mdns.disable_interface(IfKind::IPv6)?;
    let mut route_rx = state.route_tx.subscribe();

    // registered: domain -> fullname (for unregister)
    let mut registered: HashMap<String, String> = HashMap::new();

    // Initial sync
    sync_records(&mdns, &state, &mut registered);

    loop {
        match route_rx.recv().await {
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

fn is_local_domain(domain: &str) -> bool {
    domain.ends_with(".local") || domain == "local"
}

fn register_domain(mdns: &ServiceDaemon, domain: &str) -> anyhow::Result<String> {
    // instance name: use the domain prefix (part before .bridgehead.local)
    let instance_name = domain;
    // hostname must end with "." for mDNS
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
    // Unregister first to clear any stale registration from a previous run
    let _ = mdns.unregister(&fullname);
    mdns.register(service_info)?;
    Ok(fullname)
}
