pub mod edge;
pub mod named;
pub mod proxy;
pub mod quick;
pub mod rpc;
pub mod share_auth;
pub mod transport;

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
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

/// Decode a Cloudflare tunnel token (base64-encoded JSON) into TunnelCredentials.
///
/// The token is base64 of `{"a":"account_tag","t":"tunnel_id","s":"base64_secret"}`.
pub fn decode_tunnel_token(token: &str) -> anyhow::Result<TunnelCredentials> {
    #[derive(Deserialize)]
    struct TokenPayload {
        a: String,
        t: String,
        s: String,
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .map_err(|e| anyhow::anyhow!("invalid base64 in tunnel token: {e}"))?;
    let payload: TokenPayload = serde_json::from_slice(&decoded)
        .map_err(|e| anyhow::anyhow!("invalid JSON in tunnel token: {e}"))?;
    let secret = base64::engine::general_purpose::STANDARD
        .decode(&payload.s)
        .map_err(|e| anyhow::anyhow!("invalid base64 secret in tunnel token: {e}"))?;

    Ok(TunnelCredentials {
        account_tag: payload.a,
        tunnel_id: payload.t,
        secret,
        hostname: String::new(),
    })
}

pub struct TunnelHandle {
    pub task: JoinHandle<()>,
    pub credentials: TunnelCredentials,
}

pub type TunnelManager = Arc<Mutex<HashMap<String, TunnelHandle>>>;

pub fn new_tunnel_manager() -> TunnelManager {
    Arc::new(Mutex::new(HashMap::new()))
}

pub struct NamedTunnelHandle {
    pub task: JoinHandle<()>,
    pub credentials: TunnelCredentials,
    pub tunnel_domain: String,
}

/// Start a named tunnel that routes by Host header to the local Pingora proxy.
pub async fn start_named_tunnel(
    credentials: TunnelCredentials,
    tunnel_domain: String,
    local_suffix: String,
    local_proxy_port: u16,
    store: Arc<crate::store::AppRepository>,
    share_signer: Option<Arc<crate::share::ShareSigner>>,
) -> anyhow::Result<NamedTunnelHandle> {
    let creds = credentials.clone();
    let td = tunnel_domain.clone();
    let task = tokio::spawn(async move {
        let mut handles = Vec::new();
        for conn_index in 0..4u8 {
            let c = creds.clone();
            let routing = transport::TunnelRouting::HostBased {
                tunnel_domain: td.clone(),
                local_suffix: local_suffix.clone(),
                local_proxy_port,
                store: store.clone(),
                share_signer: share_signer.clone(),
            };
            let h = tokio::spawn(async move {
                if let Err(err) = transport::run_tunnel_connection(&c, routing, conn_index).await {
                    error!(error = ?err, conn_index, "named tunnel connection failed");
                }
            });
            handles.push(h);
        }
        for h in handles {
            let _ = h.await;
        }
    });

    Ok(NamedTunnelHandle {
        task,
        credentials,
        tunnel_domain,
    })
}

/// Start a quick tunnel with the given routing. Returns the public hostname.
pub async fn start_quick_tunnel(
    manager: TunnelManager,
    app_id: String,
    routing: transport::TunnelRouting,
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
            let r = routing.clone();
            let h = tokio::spawn(async move {
                if let Err(err) = transport::run_tunnel_connection(&c, r, conn_index).await {
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
            })
        })
        .collect()
}

// Per-app named tunnel management

pub struct AppNamedTunnelHandle {
    pub task: JoinHandle<()>,
    pub credentials: TunnelCredentials,
    pub tunnel_domain: String,
    pub tunnel_id: String,
}

pub type AppNamedTunnelManager = Arc<Mutex<HashMap<String, AppNamedTunnelHandle>>>;

pub fn new_app_tunnel_manager() -> AppNamedTunnelManager {
    Arc::new(Mutex::new(HashMap::new()))
}

pub async fn start_app_named_tunnel(
    manager: AppNamedTunnelManager,
    app_id: String,
    credentials: TunnelCredentials,
    tunnel_domain: String,
    routing: transport::TunnelRouting,
) -> anyhow::Result<()> {
    {
        let tunnels = manager.lock();
        if tunnels.contains_key(&app_id) {
            anyhow::bail!("app tunnel already running for app {}", app_id);
        }
    }

    let tunnel_id = credentials.tunnel_id.clone();
    let creds = credentials.clone();
    let td = tunnel_domain.clone();
    let mgr = manager.clone();
    let aid = app_id.clone();
    let task = tokio::spawn(async move {
        let mut handles = Vec::new();
        for conn_index in 0..4u8 {
            let c = creds.clone();
            let r = routing.clone();
            let h = tokio::spawn(async move {
                if let Err(err) = transport::run_tunnel_connection(&c, r, conn_index).await {
                    error!(error = ?err, conn_index, "app named tunnel connection failed");
                }
            });
            handles.push(h);
        }
        for h in handles {
            let _ = h.await;
        }
        mgr.lock().remove(&aid);
    });

    manager.lock().insert(
        app_id,
        AppNamedTunnelHandle {
            task,
            credentials,
            tunnel_domain: td,
            tunnel_id,
        },
    );

    Ok(())
}

pub fn stop_app_named_tunnel(manager: &AppNamedTunnelManager, app_id: &str) -> anyhow::Result<()> {
    let handle = manager
        .lock()
        .remove(app_id)
        .ok_or_else(|| anyhow::anyhow!("no app tunnel running for app {}", app_id))?;
    handle.task.abort();
    info!(app_id = %app_id, "app named tunnel stopped");
    Ok(())
}

#[allow(dead_code)]
pub fn app_tunnel_status(manager: &AppNamedTunnelManager) -> Vec<serde_json::Value> {
    let tunnels = manager.lock();
    tunnels
        .iter()
        .map(|(app_id, handle)| {
            serde_json::json!({
                "app_id": app_id,
                "tunnel_id": handle.tunnel_id,
                "tunnel_domain": handle.tunnel_domain,
            })
        })
        .collect()
}

pub fn shutdown_all_app_tunnels(manager: &AppNamedTunnelManager) {
    let mut tunnels = manager.lock();
    for (app_id, handle) in tunnels.drain() {
        info!(app_id = %app_id, "shutting down app named tunnel");
        handle.task.abort();
    }
}

/// Shutdown all tunnels (called during daemon shutdown).
pub fn shutdown_all(manager: &TunnelManager) {
    let mut tunnels = manager.lock();
    for (app_id, handle) in tunnels.drain() {
        info!(app_id = %app_id, "shutting down tunnel");
        handle.task.abort();
    }
}
