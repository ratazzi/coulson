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
}

impl Default for BridgeheadConfig {
    fn default() -> Self {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        Self {
            listen_http: "127.0.0.1:8080".parse().expect("default listen addr"),
            control_socket: PathBuf::from("/tmp/bridgehead/bridgeheadd.sock"),
            sqlite_path: PathBuf::from(format!("{home}/.bridgehead/state.db")),
            domain_suffix: "test".to_string(),
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

        Ok(cfg)
    }
}
