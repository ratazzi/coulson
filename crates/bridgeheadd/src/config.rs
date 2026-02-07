use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;

#[derive(Debug, Clone)]
pub struct BridgeheadConfig {
    pub listen_http: SocketAddr,
    pub control_socket: PathBuf,
    pub sqlite_path: PathBuf,
    pub domain_suffix: String,
    pub apps_root: PathBuf,
    pub scan_interval_secs: u64,
}

impl Default for BridgeheadConfig {
    fn default() -> Self {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let pow_root = PathBuf::from(format!("{home}/.pow"));
        let apps_root = if pow_root.exists() {
            pow_root
        } else {
            PathBuf::from(format!("{home}/Bridgehead/Apps"))
        };
        Self {
            listen_http: "127.0.0.1:8080".parse().expect("default listen addr"),
            control_socket: PathBuf::from("/tmp/bridgehead/bridgeheadd.sock"),
            sqlite_path: PathBuf::from(format!("{home}/.bridgehead/state.db")),
            domain_suffix: "test".to_string(),
            apps_root,
            scan_interval_secs: 2,
        }
    }
}

impl BridgeheadConfig {
    pub fn load() -> anyhow::Result<Self> {
        let mut cfg = Self::default();

        if let Ok(addr) = env::var("BRIDGEHEAD_LISTEN_HTTP") {
            cfg.listen_http = addr
                .parse()
                .with_context(|| format!("invalid BRIDGEHEAD_LISTEN_HTTP: {addr}"))?;
        }

        if let Ok(path) = env::var("BRIDGEHEAD_CONTROL_SOCKET") {
            cfg.control_socket = PathBuf::from(path);
        }

        if let Ok(path) = env::var("BRIDGEHEAD_SQLITE_PATH") {
            cfg.sqlite_path = PathBuf::from(path);
        }

        if let Ok(suffix) = env::var("BRIDGEHEAD_DOMAIN_SUFFIX") {
            cfg.domain_suffix = suffix;
        }
        if let Ok(path) = env::var("BRIDGEHEAD_APPS_ROOT") {
            cfg.apps_root = PathBuf::from(path);
        }
        if let Ok(raw) = env::var("BRIDGEHEAD_SCAN_INTERVAL_SECS") {
            cfg.scan_interval_secs = raw
                .parse()
                .with_context(|| format!("invalid BRIDGEHEAD_SCAN_INTERVAL_SECS: {raw}"))?;
        }

        Ok(cfg)
    }
}
