pub mod edge;
pub mod proxy;
pub mod quick;
pub mod rpc;
pub mod transport;

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelCredentials {
    pub tunnel_id: String,
    pub account_tag: String,
    #[serde(with = "base64_serde")]
    pub secret: Vec<u8>,
    pub hostname: String,
}

mod base64_serde {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        encoded.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)
    }
}

pub struct TunnelHandle {
    pub task: JoinHandle<()>,
    pub credentials: TunnelCredentials,
    pub local_port: u16,
}

pub type TunnelManager = Arc<Mutex<HashMap<String, TunnelHandle>>>;

pub fn new_tunnel_manager() -> TunnelManager {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Start a quick tunnel for a local port. Returns the public hostname.
pub async fn start_quick_tunnel(
    manager: TunnelManager,
    app_id: String,
    local_port: u16,
) -> anyhow::Result<String> {
    // Check if already running
    {
        let tunnels = manager.lock();
        if tunnels.contains_key(&app_id) {
            anyhow::bail!("tunnel already running for app {}", app_id);
        }
    }

    let credentials = quick::register_quick_tunnel().await?;
    let hostname = credentials.hostname.clone();
    info!(hostname = %hostname, tunnel_id = %credentials.tunnel_id, "quick tunnel registered");

    // Spawn 4 connections to different edge nodes (like cloudflared)
    let creds = credentials.clone();
    let mgr = manager.clone();
    let aid = app_id.clone();
    let task = tokio::spawn(async move {
        let mut handles = Vec::new();
        for conn_index in 0..4u8 {
            let c = creds.clone();
            let h = tokio::spawn(async move {
                if let Err(err) = transport::run_tunnel_connection(&c, local_port, conn_index).await
                {
                    error!(error = ?err, conn_index, "tunnel connection failed");
                }
            });
            handles.push(h);
        }
        // Wait for all connections (they run forever with reconnection)
        for h in handles {
            let _ = h.await;
        }
        mgr.lock().remove(&aid);
    });

    manager.lock().insert(
        app_id,
        TunnelHandle {
            task,
            credentials,
            local_port,
        },
    );

    Ok(hostname)
}

/// Stop a running tunnel.
pub fn stop_tunnel(manager: &TunnelManager, app_id: &str) -> anyhow::Result<()> {
    let handle = manager
        .lock()
        .remove(app_id)
        .ok_or_else(|| anyhow::anyhow!("no tunnel running for app {}", app_id))?;
    handle.task.abort();
    info!(app_id = %app_id, "tunnel stopped");
    Ok(())
}

/// Get status of all active tunnels.
pub fn tunnel_status(manager: &TunnelManager) -> Vec<serde_json::Value> {
    let tunnels = manager.lock();
    tunnels
        .iter()
        .map(|(app_id, handle)| {
            serde_json::json!({
                "app_id": app_id,
                "hostname": handle.credentials.hostname,
                "tunnel_id": handle.credentials.tunnel_id,
                "local_port": handle.local_port,
            })
        })
        .collect()
}

/// Shutdown all tunnels (called during daemon shutdown).
pub fn shutdown_all(manager: &TunnelManager) {
    let mut tunnels = manager.lock();
    for (app_id, handle) in tunnels.drain() {
        info!(app_id = %app_id, "shutting down tunnel");
        handle.task.abort();
    }
}
