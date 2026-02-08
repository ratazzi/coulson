use std::net::SocketAddr;

use anyhow::Context;
use hickory_resolver::Resolver;

const EDGE_SRV_NAME: &str = "_v2-origintunneld._tcp.argotunnel.com.";

/// Discover Cloudflare edge addresses via DNS SRV lookup.
pub async fn discover_edge_addrs() -> anyhow::Result<Vec<SocketAddr>> {
    let resolver = Resolver::builder_tokio()
        .context("failed to create DNS resolver")?
        .build();

    let srv_response = resolver
        .srv_lookup(EDGE_SRV_NAME)
        .await
        .context("SRV lookup for edge addresses failed")?;

    let mut addrs = Vec::new();
    for srv in srv_response.iter() {
        let target = srv.target().to_string();
        let port = srv.port();

        match resolver.lookup_ip(target.as_str()).await {
            Ok(ips) => {
                for ip in ips.iter() {
                    addrs.push(SocketAddr::new(ip, port));
                }
            }
            Err(err) => {
                tracing::warn!(target = %target, error = %err, "failed to resolve edge target");
            }
        }
    }

    if addrs.is_empty() {
        anyhow::bail!("no edge addresses discovered");
    }

    // Shuffle for load distribution
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    addrs.shuffle(&mut rng);

    Ok(addrs)
}
