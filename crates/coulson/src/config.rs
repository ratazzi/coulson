use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;

fn xdg_state_home() -> PathBuf {
    env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".local/state")
        })
}

fn xdg_config_home() -> PathBuf {
    env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        })
}

fn xdg_runtime_dir() -> PathBuf {
    if let Ok(dir) = env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(dir) = env::var("TMPDIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from("/tmp")
}

#[derive(Debug, Clone)]
pub struct CoulsonConfig {
    pub listen_http: SocketAddr,
    pub listen_https: Option<SocketAddr>,
    pub control_socket: PathBuf,
    pub sqlite_path: PathBuf,
    pub scan_warnings_path: PathBuf,
    pub domain_suffix: String,
    pub apps_root: PathBuf,
    pub scan_interval_secs: u64,
    pub watch_fs: bool,
    pub idle_timeout_secs: u64,
    pub lan_access: bool,
    pub link_dir: bool,
    pub inspect_max_requests: usize,
    pub certs_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Default for CoulsonConfig {
    fn default() -> Self {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let pow_root = PathBuf::from(format!("{home}/.pow"));
        let apps_root = if pow_root.exists() {
            pow_root
        } else {
            PathBuf::from(format!("{home}/.coulson"))
        };
        let runtime_dir = xdg_runtime_dir().join("coulson");
        let state_dir = xdg_state_home().join("coulson");
        let listen_http: SocketAddr = "127.0.0.1:8080".parse().expect("default listen addr");
        Self {
            listen_https: Some(SocketAddr::from(([127, 0, 0, 1], listen_http.port() + 363))),
            listen_http,
            control_socket: runtime_dir.join("coulson.sock"),
            sqlite_path: state_dir.join("state.db"),
            scan_warnings_path: state_dir.join("scan_warnings.json"),
            domain_suffix: "coulson.local".to_string(),
            apps_root,
            scan_interval_secs: 0,
            watch_fs: true,
            idle_timeout_secs: 900,
            lan_access: false,
            link_dir: false,
            inspect_max_requests: 200,
            certs_dir: xdg_config_home().join("coulson/certs"),
            runtime_dir,
        }
    }
}

impl CoulsonConfig {
    pub fn load() -> anyhow::Result<Self> {
        let mut cfg = Self::default();
        let explicit_listen = env::var("COULSON_LISTEN_HTTP").ok();

        if let Some(addr) = &explicit_listen {
            cfg.listen_http = addr
                .parse()
                .with_context(|| format!("invalid COULSON_LISTEN_HTTP: {addr}"))?;
        }

        if let Ok(path) = env::var("COULSON_CONTROL_SOCKET") {
            cfg.control_socket = PathBuf::from(path);
        }

        if let Ok(path) = env::var("COULSON_SQLITE_PATH") {
            cfg.sqlite_path = PathBuf::from(path);
        }
        if let Ok(path) = env::var("COULSON_SCAN_WARNINGS_PATH") {
            cfg.scan_warnings_path = PathBuf::from(path);
        }

        if let Ok(suffix) = env::var("COULSON_DOMAIN_SUFFIX") {
            cfg.domain_suffix = suffix;
        }
        if let Ok(path) = env::var("COULSON_APPS_ROOT") {
            cfg.apps_root = PathBuf::from(path);
        }
        if let Ok(raw) = env::var("COULSON_SCAN_INTERVAL_SECS") {
            cfg.scan_interval_secs = raw
                .parse()
                .with_context(|| format!("invalid COULSON_SCAN_INTERVAL_SECS: {raw}"))?;
        }
        if let Ok(raw) = env::var("COULSON_WATCH_FS") {
            cfg.watch_fs =
                parse_bool(&raw).with_context(|| format!("invalid COULSON_WATCH_FS: {raw}"))?;
        }
        if let Ok(raw) = env::var("COULSON_IDLE_TIMEOUT_SECS") {
            cfg.idle_timeout_secs = raw
                .parse()
                .with_context(|| format!("invalid COULSON_IDLE_TIMEOUT_SECS: {raw}"))?;
        }

        if let Ok(raw) = env::var("COULSON_LINK_DIR") {
            cfg.link_dir =
                parse_bool(&raw).with_context(|| format!("invalid COULSON_LINK_DIR: {raw}"))?;
        }

        if let Ok(raw) = env::var("COULSON_INSPECT_MAX_REQUESTS") {
            cfg.inspect_max_requests = raw
                .parse()
                .with_context(|| format!("invalid COULSON_INSPECT_MAX_REQUESTS: {raw}"))?;
        }

        if let Ok(raw) = env::var("COULSON_LAN_ACCESS") {
            cfg.lan_access =
                parse_bool(&raw).with_context(|| format!("invalid COULSON_LAN_ACCESS: {raw}"))?;
        }

        if let Ok(path) = env::var("COULSON_CERTS_DIR") {
            cfg.certs_dir = PathBuf::from(path);
        }
        if let Ok(path) = env::var("COULSON_RUNTIME_DIR") {
            cfg.runtime_dir = PathBuf::from(&path);
            // Also update control_socket default if not explicitly set
            if env::var("COULSON_CONTROL_SOCKET").is_err() {
                cfg.control_socket = cfg.runtime_dir.join("coulson.sock");
            }
        }

        // HTTPS listener
        if let Ok(raw) = env::var("COULSON_LISTEN_HTTPS") {
            match raw.trim().to_ascii_lowercase().as_str() {
                "off" | "0" | "false" => {
                    cfg.listen_https = None;
                }
                _ => {
                    cfg.listen_https = Some(
                        raw.parse()
                            .with_context(|| format!("invalid COULSON_LISTEN_HTTPS: {raw}"))?,
                    );
                }
            }
        } else {
            // Default: HTTP port + 363
            let port = cfg.listen_http.port().saturating_add(363);
            cfg.listen_https = Some(SocketAddr::from((cfg.listen_http.ip(), port)));
        }

        // When LAN access enabled and listen address not explicitly set, bind to all interfaces
        if cfg.lan_access && explicit_listen.is_none() {
            let port = cfg.listen_http.port();
            cfg.listen_http = SocketAddr::from(([0, 0, 0, 0], port));
            if let Some(ref mut https) = cfg.listen_https {
                let https_port = https.port();
                *https = SocketAddr::from(([0, 0, 0, 0], https_port));
            }
        }

        Ok(cfg)
    }
}

fn parse_bool(input: &str) -> anyhow::Result<bool> {
    match input.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("expected boolean"),
    }
}
