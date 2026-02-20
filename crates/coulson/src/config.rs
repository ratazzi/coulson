use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;

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

        // Layer 2: TOML config file (overrides defaults)
        let file = ConfigFile::load();
        if let Some(ref v) = file.listen_http {
            cfg.listen_http = v
                .parse()
                .with_context(|| format!("invalid listen_http in config.toml: {v}"))?;
        }
        if let Some(ref v) = file.control_socket {
            cfg.control_socket = expand_tilde(v);
        }
        if let Some(ref v) = file.sqlite_path {
            cfg.sqlite_path = expand_tilde(v);
        }
        if let Some(ref v) = file.scan_warnings_path {
            cfg.scan_warnings_path = expand_tilde(v);
        }
        if let Some(ref v) = file.domain_suffix {
            cfg.domain_suffix = v.clone();
        }
        if let Some(ref v) = file.apps_root {
            cfg.apps_root = expand_tilde(v);
        }
        if let Some(v) = file.watch_fs {
            cfg.watch_fs = v;
        }
        if let Some(v) = file.idle_timeout_secs {
            cfg.idle_timeout_secs = v;
        }
        if let Some(v) = file.lan_access {
            cfg.lan_access = v;
        }
        if let Some(v) = file.link_dir {
            cfg.link_dir = v;
        }
        if let Some(v) = file.inspect_max_requests {
            cfg.inspect_max_requests = v;
        }
        if let Some(ref v) = file.certs_dir {
            cfg.certs_dir = expand_tilde(v);
        }
        if let Some(ref v) = file.runtime_dir {
            cfg.runtime_dir = expand_tilde(v);
            if file.control_socket.is_none() {
                cfg.control_socket = cfg.runtime_dir.join("coulson.sock");
            }
        }

        // Layer 3: Environment variables (highest priority)
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
            // Also update control_socket if not explicitly set via ENV or TOML
            if env::var("COULSON_CONTROL_SOCKET").is_err() && file.control_socket.is_none() {
                cfg.control_socket = cfg.runtime_dir.join("coulson.sock");
            }
        }

        // HTTPS listener: env > toml > default
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
        } else if let Some(ref v) = file.listen_https {
            match v.trim().to_ascii_lowercase().as_str() {
                "off" | "0" | "false" => {
                    cfg.listen_https = None;
                }
                _ => {
                    cfg.listen_https =
                        Some(v.parse().with_context(|| {
                            format!("invalid listen_https in config.toml: {v}")
                        })?);
                }
            }
        } else {
            // Default: HTTP port + 363
            let port = cfg.listen_http.port().saturating_add(363);
            cfg.listen_https = Some(SocketAddr::from((cfg.listen_http.ip(), port)));
        }

        // When LAN access enabled and listen address not explicitly set, bind to all interfaces
        let explicit_listen_any = explicit_listen.is_some() || file.listen_http.is_some();
        if cfg.lan_access && !explicit_listen_any {
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

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(path)
    }
}

#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    listen_http: Option<String>,
    listen_https: Option<String>,
    control_socket: Option<String>,
    sqlite_path: Option<String>,
    scan_warnings_path: Option<String>,
    domain_suffix: Option<String>,
    apps_root: Option<String>,
    watch_fs: Option<bool>,
    idle_timeout_secs: Option<u64>,
    lan_access: Option<bool>,
    link_dir: Option<bool>,
    inspect_max_requests: Option<usize>,
    certs_dir: Option<String>,
    runtime_dir: Option<String>,
}

impl ConfigFile {
    fn load() -> Self {
        let path = xdg_config_home().join("coulson/config.toml");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        match toml::from_str(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!("failed to parse {}: {e}", path.display());
                Self::default()
            }
        }
    }
}
