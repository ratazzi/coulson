use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessBackend {
    /// Use tmux if available, else fall back to direct spawn.
    Auto,
    /// Require tmux; fail if missing.
    Tmux,
    /// Current behavior, no tmux.
    Direct,
}

/// Secondary domain suffix that is always available (RFC 6761 reserved).
/// Browsers and OS resolve `.localhost` to 127.0.0.1 with zero configuration.
pub const LOCALHOST_SUFFIX: &str = "localhost";

/// Directory name component used in all default paths.
/// Debug builds use "coulson-dev" for isolation from release installs.
#[cfg(debug_assertions)]
const DIR_NAME: &str = "coulson-dev";
#[cfg(not(debug_assertions))]
const DIR_NAME: &str = "coulson";

/// IPv4 loopback alias used as pf redirect target on macOS.
///
/// macOS pf corrupts SYN-ACK packets when `rdr ... -> 127.0.0.1 port X`
/// is active and a client connects directly to `127.0.0.1:X`.  Using a
/// separate loopback alias avoids this state-tracking conflict.
/// We use 127.49.27.41 (within 127.0.0.0/8) so that upstream apps see a
/// loopback REMOTE_ADDR — frameworks like Rails restrict dev tools
/// (web-console, etc.) to loopback connections.
#[cfg(target_os = "macos")]
pub const PF_REDIRECT_IP: &str = "127.49.27.41";

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
    pub link_dir: bool,
    pub inspect_max_requests: usize,
    /// Max request body (MiB) buffered per tunnel request before returning 413.
    pub max_tunnel_body_mb: usize,
    /// `host:port` destinations warp-routed tunnel TCP streams may reach.
    /// Empty (the default) refuses every stream.
    pub tunnel_tcp_allow: Vec<String>,
    pub certs_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub process_backend: ProcessBackend,
    pub hook_timeout_secs: u64,
    pub inspector_username: Option<String>,
    pub inspector_password: Option<String>,
}

impl Default for CoulsonConfig {
    fn default() -> Self {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());

        // Release builds fall back to ~/.pow if it exists; debug builds skip this.
        #[cfg(not(debug_assertions))]
        let apps_root = {
            let pow_root = PathBuf::from(format!("{home}/.pow"));
            if pow_root.exists() {
                pow_root
            } else {
                PathBuf::from(format!("{home}/.{DIR_NAME}"))
            }
        };
        #[cfg(debug_assertions)]
        let apps_root = PathBuf::from(format!("{home}/.{DIR_NAME}"));

        let runtime_dir = xdg_runtime_dir().join(DIR_NAME);
        let state_dir = xdg_state_home().join(DIR_NAME);
        let listen_http: SocketAddr = "0.0.0.0:18080".parse().expect("default listen addr");
        Self {
            listen_https: Some(SocketAddr::from(([0, 0, 0, 0], listen_http.port() + 363))),
            listen_http,
            control_socket: state_dir.join("coulson.sock"),
            sqlite_path: state_dir.join("state.db"),
            scan_warnings_path: state_dir.join("scan_warnings.json"),
            domain_suffix: "coulson.local".to_string(),
            apps_root,
            watch_fs: true,
            idle_timeout_secs: 900,
            link_dir: false,
            inspect_max_requests: 200,
            max_tunnel_body_mb: 100,
            tunnel_tcp_allow: Vec::new(),
            certs_dir: xdg_config_home().join(format!("{DIR_NAME}/certs")),
            runtime_dir,
            process_backend: ProcessBackend::Auto,
            hook_timeout_secs: 60,
            inspector_username: None,
            inspector_password: None,
        }
    }
}

impl CoulsonConfig {
    pub fn load() -> anyhow::Result<Self> {
        let mut cfg = Self::default();

        // Layer 2: TOML config file (overrides defaults)
        let file = ConfigFile::load();
        if let Some(ref v) = file.listen_http {
            cfg.listen_http = parse_listen_addr(v)
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
        if let Some(v) = file.link_dir {
            cfg.link_dir = v;
        }
        if let Some(v) = file.inspect_max_requests {
            cfg.inspect_max_requests = v;
        }
        if let Some(v) = file.max_tunnel_body_mb {
            cfg.max_tunnel_body_mb = v;
        }
        if let Some(ref v) = file.tunnel_tcp_allow {
            cfg.tunnel_tcp_allow = v.clone();
        }
        if let Some(ref v) = file.certs_dir {
            cfg.certs_dir = expand_tilde(v);
        }
        if let Some(ref v) = file.runtime_dir {
            cfg.runtime_dir = expand_tilde(v);
        }
        if let Some(ref v) = file.process_backend {
            cfg.process_backend = parse_process_backend(v)
                .with_context(|| format!("invalid process_backend in config.toml: {v}"))?;
        }
        if let Some(v) = file.hook_timeout_secs {
            cfg.hook_timeout_secs = v;
        }
        if let Some(ref insp) = file.inspector {
            if let Some(ref v) = insp.username {
                cfg.inspector_username = Some(v.clone());
            }
            if let Some(ref v) = insp.password {
                cfg.inspector_password = Some(v.clone());
            }
        }

        // Layer 3: Environment variables (highest priority)
        if let Ok(addr) = env::var("COULSON_LISTEN_HTTP") {
            cfg.listen_http = parse_listen_addr(&addr)
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

        if let Ok(raw) = env::var("COULSON_MAX_TUNNEL_BODY_MB") {
            cfg.max_tunnel_body_mb = raw
                .parse()
                .with_context(|| format!("invalid COULSON_MAX_TUNNEL_BODY_MB: {raw}"))?;
        }
        if let Ok(raw) = env::var("COULSON_TUNNEL_TCP_ALLOW") {
            cfg.tunnel_tcp_allow = raw
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(String::from)
                .collect();
        }
        validate_tcp_allow(&cfg.tunnel_tcp_allow)?;

        if let Ok(path) = env::var("COULSON_CERTS_DIR") {
            cfg.certs_dir = PathBuf::from(path);
        }
        if let Ok(path) = env::var("COULSON_RUNTIME_DIR") {
            cfg.runtime_dir = PathBuf::from(&path);
        }
        if let Ok(raw) = env::var("COULSON_HOOK_TIMEOUT_SECS") {
            cfg.hook_timeout_secs = raw
                .parse()
                .with_context(|| format!("invalid COULSON_HOOK_TIMEOUT_SECS: {raw}"))?;
        }
        if let Ok(v) = env::var("COULSON_INSPECTOR_USERNAME") {
            cfg.inspector_username = Some(v);
        }
        if let Ok(v) = env::var("COULSON_INSPECTOR_PASSWORD") {
            cfg.inspector_password = Some(v);
        }
        if let Ok(raw) = env::var("COULSON_PROCESS_BACKEND") {
            cfg.process_backend = parse_process_backend(&raw)
                .with_context(|| format!("invalid COULSON_PROCESS_BACKEND: {raw}"))?;
        }

        // HTTPS listener: env > toml > default
        if let Ok(raw) = env::var("COULSON_LISTEN_HTTPS") {
            match raw.trim().to_ascii_lowercase().as_str() {
                "off" | "0" | "false" => {
                    cfg.listen_https = None;
                }
                _ => {
                    cfg.listen_https = Some(
                        parse_listen_addr_with_ip(&raw, cfg.listen_http.ip())
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
                    cfg.listen_https = Some(
                        parse_listen_addr_with_ip(v, cfg.listen_http.ip())
                            .with_context(|| format!("invalid listen_https in config.toml: {v}"))?,
                    );
                }
            }
        } else {
            // Default: HTTP port + 363
            let port = cfg.listen_http.port().saturating_add(363);
            cfg.listen_https = Some(SocketAddr::from((cfg.listen_http.ip(), port)));
        }

        Ok(cfg)
    }
}

fn parse_process_backend(input: &str) -> anyhow::Result<ProcessBackend> {
    match input.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(ProcessBackend::Auto),
        "tmux" => Ok(ProcessBackend::Tmux),
        "direct" => Ok(ProcessBackend::Direct),
        _ => anyhow::bail!("expected auto, tmux, or direct"),
    }
}

fn parse_bool(input: &str) -> anyhow::Result<bool> {
    match input.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("expected boolean"),
    }
}

/// Parse a listen address: bare port (`18080`) → `0.0.0.0:18080`,
/// or a full `ip:port` string.
fn parse_listen_addr(input: &str) -> anyhow::Result<SocketAddr> {
    parse_listen_addr_with_ip(input, [0, 0, 0, 0].into())
}

/// Parse a listen address with a fallback IP for bare ports.
fn parse_listen_addr_with_ip(
    input: &str,
    default_ip: std::net::IpAddr,
) -> anyhow::Result<SocketAddr> {
    let trimmed = input.trim();
    if let Ok(port) = trimmed.parse::<u16>() {
        return Ok(SocketAddr::new(default_ip, port));
    }
    Ok(trimmed.parse()?)
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(path)
    }
}

/// Each `tunnel_tcp_allow` entry must be `host:port`, the form the tunnel
/// matches against, so a typo fails at startup instead of silently refusing.
fn validate_tcp_allow(entries: &[String]) -> anyhow::Result<()> {
    for dest in entries {
        let valid = dest
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
        if !valid {
            bail!("invalid tunnel_tcp_allow entry {dest:?}: expected host:port");
        }
    }
    Ok(())
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
    link_dir: Option<bool>,
    inspect_max_requests: Option<usize>,
    max_tunnel_body_mb: Option<usize>,
    tunnel_tcp_allow: Option<Vec<String>>,
    certs_dir: Option<String>,
    runtime_dir: Option<String>,
    process_backend: Option<String>,
    hook_timeout_secs: Option<u64>,
    inspector: Option<InspectorConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct InspectorConfig {
    username: Option<String>,
    password: Option<String>,
}

impl ConfigFile {
    fn load() -> Self {
        let config_dir = xdg_config_home().join(DIR_NAME);

        #[cfg(not(debug_assertions))]
        let cfg = Self::load_file(&config_dir.join("config.toml"));

        #[cfg(debug_assertions)]
        let cfg = {
            let mut base = Self::load_file(&config_dir.join("config.toml"));
            let dev = Self::load_file(&config_dir.join("config.dev.toml"));
            base.merge(dev);
            base
        };

        cfg
    }

    fn load_file(path: &std::path::Path) -> Self {
        let Ok(content) = std::fs::read_to_string(path) else {
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

    #[cfg(debug_assertions)]
    fn merge(&mut self, other: Self) {
        macro_rules! merge_field {
            ($($field:ident),*) => {
                $(if other.$field.is_some() { self.$field = other.$field; })*
            };
        }
        merge_field!(
            listen_http,
            listen_https,
            control_socket,
            sqlite_path,
            scan_warnings_path,
            domain_suffix,
            apps_root,
            watch_fs,
            idle_timeout_secs,
            link_dir,
            inspect_max_requests,
            max_tunnel_body_mb,
            tunnel_tcp_allow,
            certs_dir,
            runtime_dir,
            process_backend,
            hook_timeout_secs,
            inspector
        );
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    #[test]
    fn tcp_allow_entries_must_be_host_port() {
        let entries = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(validate_tcp_allow(&entries(&[
            "127.0.0.1:5432",
            "db.internal:6379",
            "[::1]:22"
        ]))
        .is_ok());
        assert!(validate_tcp_allow(&[]).is_ok());
        for bad in ["127.0.0.1", "127.0.0.1:", ":5432", "db:http", "db:70000"] {
            assert!(
                validate_tcp_allow(&entries(&[bad])).is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn merge_overrides_max_tunnel_body_mb() {
        let mut base = ConfigFile {
            max_tunnel_body_mb: Some(100),
            ..Default::default()
        };
        let dev = ConfigFile {
            max_tunnel_body_mb: Some(512),
            ..Default::default()
        };
        base.merge(dev);
        assert_eq!(base.max_tunnel_body_mb, Some(512));
    }

    #[test]
    fn merge_keeps_base_when_dev_field_unset() {
        let mut base = ConfigFile {
            max_tunnel_body_mb: Some(100),
            ..Default::default()
        };
        base.merge(ConfigFile::default());
        assert_eq!(base.max_tunnel_body_mb, Some(100));
    }
}
