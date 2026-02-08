use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

use crate::domain::{AppKind, DomainName};
use crate::store::{domain_to_db, route_key, ScanUpsertResult};
use crate::SharedState;

#[derive(Debug, Deserialize)]
struct BridgeheadManifest {
    name: Option<String>,
    domain: Option<String>,
    kind: Option<String>,
    #[allow(dead_code)]
    module: Option<String>,
    #[allow(dead_code)]
    server: Option<String>,
    #[allow(dead_code)]
    command: Option<String>,
    target_host: Option<String>,
    #[serde(default)]
    target_port: u16,
    path_prefix: Option<String>,
    timeout_ms: Option<u64>,
    #[serde(default)]
    socket_path: Option<String>,
    routes: Option<Vec<BridgeheadManifestRoute>>,
    enabled: Option<bool>,
    #[serde(default)]
    cors_enabled: Option<bool>,
    #[serde(default)]
    basic_auth_user: Option<String>,
    #[serde(default)]
    basic_auth_pass: Option<String>,
    #[serde(default)]
    spa_rewrite: Option<bool>,
    #[serde(default)]
    listen_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct BridgeheadManifestRoute {
    #[serde(default)]
    path_prefix: Option<String>,
    #[serde(default)]
    target_host: Option<String>,
    #[serde(default)]
    target_port: u16,
    #[serde(default)]
    socket_path: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    cors_enabled: Option<bool>,
    #[serde(default)]
    basic_auth_user: Option<String>,
    #[serde(default)]
    basic_auth_pass: Option<String>,
    #[serde(default)]
    spa_rewrite: Option<bool>,
    #[serde(default)]
    listen_port: Option<u16>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanStats {
    pub discovered: usize,
    pub inserted: usize,
    pub updated: usize,
    pub skipped_manual: usize,
    pub pruned: usize,
    pub conflicts: usize,
    pub conflict_domains: Vec<String>,
    #[serde(default)]
    pub parse_warnings: Vec<String>,
    #[serde(default)]
    pub warning_count: usize,
    #[serde(default)]
    pub has_issues: bool,
}

pub fn sync_from_apps_root(state: &SharedState) -> anyhow::Result<ScanStats> {
    let discovered = discover(&state.apps_root, &state.domain_suffix)?;
    let mut active_routes: HashSet<String> = HashSet::new();
    let mut inserted = 0usize;
    let mut updated = 0usize;
    let mut skipped_manual = 0usize;
    for app in &discovered.apps {
        let (_, op) = if app.kind == AppKind::Asgi {
            state.store.upsert_scanned_asgi(
                &app.name,
                &app.domain,
                app.app_root.as_deref().unwrap_or(""),
                app.enabled,
                "apps_root",
            )?
        } else if let Some(ref static_root) = app.static_root {
            state.store.upsert_scanned_static_dir(
                &app.name,
                &app.domain,
                static_root,
                app.enabled,
                "apps_root",
            )?
        } else {
            state.store.upsert_scanned_static(
                &app.name,
                &app.domain,
                app.path_prefix.as_deref(),
                &app.target_host,
                app.target_port,
                app.socket_path.as_deref(),
                app.timeout_ms,
                app.cors_enabled,
                app.basic_auth_user.as_deref(),
                app.basic_auth_pass.as_deref(),
                app.spa_rewrite,
                app.listen_port,
                app.enabled,
                "apps_root",
            )?
        };
        match op {
            ScanUpsertResult::Inserted => inserted += 1,
            ScanUpsertResult::Updated => updated += 1,
            ScanUpsertResult::SkippedManual => skipped_manual += 1,
        }
        let domain_prefix = domain_to_db(&app.domain.0, &state.domain_suffix);
        let route_key = route_key(&domain_prefix, app.path_prefix.as_deref().unwrap_or(""));
        active_routes.insert(route_key);
    }
    let pruned = state
        .store
        .prune_scanned_not_in("apps_root", &active_routes)?;
    let conflict_domains: Vec<String> = discovered
        .conflicts
        .into_iter()
        .map(|k| humanize_route_conflict_key(&k))
        .collect();
    let parse_warnings = discovered.parse_warnings;
    let warning_count = conflict_domains.len() + parse_warnings.len();
    Ok(ScanStats {
        discovered: discovered.apps.len(),
        inserted,
        updated,
        skipped_manual,
        pruned,
        conflicts: conflict_domains.len(),
        conflict_domains,
        parse_warnings,
        warning_count,
        has_issues: warning_count > 0,
    })
}

#[derive(Debug)]
struct DiscoveredStaticApp {
    name: String,
    kind: AppKind,
    domain: DomainName,
    path_prefix: Option<String>,
    target_host: String,
    target_port: u16,
    socket_path: Option<String>,
    timeout_ms: Option<u64>,
    cors_enabled: bool,
    basic_auth_user: Option<String>,
    basic_auth_pass: Option<String>,
    spa_rewrite: bool,
    listen_port: Option<u16>,
    app_root: Option<String>,
    static_root: Option<String>,
    enabled: bool,
    explicit_domain: bool,
}

struct DiscoverResult {
    apps: Vec<DiscoveredStaticApp>,
    conflicts: Vec<String>,
    parse_warnings: Vec<String>,
}

fn discover(root: &Path, suffix: &str) -> anyhow::Result<DiscoverResult> {
    if !root.exists() {
        return Ok(DiscoverResult {
            apps: Vec::new(),
            conflicts: Vec::new(),
            parse_warnings: Vec::new(),
        });
    }

    let mut by_route: HashMap<String, DiscoveredStaticApp> = HashMap::new();
    let mut conflicts: Vec<String> = Vec::new();
    let mut parse_warnings: Vec<String> = Vec::new();

    for entry in fs::read_dir(root)
        .with_context(|| format!("failed reading apps root: {}", root.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let file_name = entry.file_name().to_string_lossy().to_string();

        if file_type.is_symlink() {
            if file_name.starts_with('.') {
                continue;
            }
            let apps = discover_from_symlink(entry.path(), &file_name, suffix)?;
            for app in apps {
                insert_with_priority(&mut by_route, &mut conflicts, app);
            }
            continue;
        }

        if file_type.is_file() {
            if file_name.starts_with('.') {
                continue;
            }
            let raw = fs::read_to_string(entry.path())
                .with_context(|| format!("failed reading {}", entry.path().display()))?;
            let parse = parse_pow_file_routes(&raw);
            parse_warnings.extend(
                parse
                    .warnings
                    .into_iter()
                    .map(|w| format!("{}: {}", entry.path().display(), w)),
            );
            let routes = parse.routes;
            for route in routes {
                let domain_text = file_name_to_domain(&file_name, suffix);
                let domain = DomainName::parse(&domain_text, suffix).with_context(|| {
                    format!(
                        "invalid domain '{}' in {}",
                        domain_text,
                        entry.path().display()
                    )
                })?;

                let app = DiscoveredStaticApp {
                    name: sanitize_name(&file_name),
                    kind: AppKind::Static,
                    domain,
                    path_prefix: route.path_prefix,
                    target_host: route.target_host,
                    target_port: route.target_port,
                    socket_path: None,
                    timeout_ms: route.timeout_ms,
                    cors_enabled: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    app_root: None,
                    static_root: None,
                    enabled: true,
                    explicit_domain: file_name.ends_with(&format!(".{suffix}")),
                };
                insert_with_priority(&mut by_route, &mut conflicts, app);
            }
            continue;
        }

        if file_type.is_dir() {
            let dir_name = file_name;
            let routes_path = entry.path().join("bridgehead.routes");
            if routes_path.exists() {
                let raw = fs::read_to_string(&routes_path)
                    .with_context(|| format!("failed reading {}", routes_path.display()))?;
                let parse = parse_pow_file_routes(&raw);
                parse_warnings.extend(
                    parse
                        .warnings
                        .into_iter()
                        .map(|w| format!("{}: {}", routes_path.display(), w)),
                );
                let routes = parse.routes;
                let domain_text = file_name_to_domain(&dir_name, suffix);
                let domain = DomainName::parse(&domain_text, suffix).with_context(|| {
                    format!(
                        "invalid domain '{}' in {}",
                        domain_text,
                        routes_path.display()
                    )
                })?;
                let explicit_domain = dir_name.ends_with(&format!(".{suffix}"));
                for route in routes {
                    let app = DiscoveredStaticApp {
                        name: sanitize_name(&dir_name),
                        kind: AppKind::Static,
                        domain: domain.clone(),
                        path_prefix: route.path_prefix,
                        target_host: route.target_host,
                        target_port: route.target_port,
                        socket_path: None,
                        timeout_ms: route.timeout_ms,
                        cors_enabled: false,
                        basic_auth_user: None,
                        basic_auth_pass: None,
                        spa_rewrite: false,
                        listen_port: None,
                        app_root: None,
                        static_root: None,
                        enabled: true,
                        explicit_domain,
                    };
                    insert_with_priority(&mut by_route, &mut conflicts, app);
                }
                continue;
            }

            let manifest_path = entry.path().join("bridgehead.json");
            if !manifest_path.exists() {
                // Auto-detect ASGI app by convention
                if detect_asgi_app(&entry.path()) {
                    let domain_text = file_name_to_domain(&dir_name, suffix);
                    let domain =
                        DomainName::parse(&domain_text, suffix).with_context(|| {
                            format!(
                                "invalid domain '{}' in {}",
                                domain_text,
                                entry.path().display()
                            )
                        })?;
                    let root_str = entry.path().to_string_lossy().to_string();
                    let app = DiscoveredStaticApp {
                        name: sanitize_name(&dir_name),
                        kind: AppKind::Asgi,
                        domain,
                        path_prefix: None,
                        target_host: String::new(),
                        target_port: 0,
                        socket_path: None,
                        timeout_ms: None,
                        cors_enabled: false,
                        basic_auth_user: None,
                        basic_auth_pass: None,
                        spa_rewrite: false,
                        listen_port: None,
                        app_root: Some(root_str),
                        static_root: None,
                        enabled: true,
                        explicit_domain: dir_name.ends_with(&format!(".{suffix}")),
                    };
                    insert_with_priority(&mut by_route, &mut conflicts, app);
                } else if entry.path().join("public").is_dir() {
                    let domain_text = file_name_to_domain(&dir_name, suffix);
                    let domain =
                        DomainName::parse(&domain_text, suffix).with_context(|| {
                            format!(
                                "invalid domain '{}' in {}",
                                domain_text,
                                entry.path().display()
                            )
                        })?;
                    let public_root = entry.path().join("public").to_string_lossy().to_string();
                    let app = DiscoveredStaticApp {
                        name: sanitize_name(&dir_name),
                        kind: AppKind::Static,
                        domain,
                        path_prefix: None,
                        target_host: String::new(),
                        target_port: 0,
                        socket_path: None,
                        timeout_ms: None,
                        cors_enabled: false,
                        basic_auth_user: None,
                        basic_auth_pass: None,
                        spa_rewrite: false,
                        listen_port: None,
                        app_root: None,
                        static_root: Some(public_root),
                        enabled: true,
                        explicit_domain: dir_name.ends_with(&format!(".{suffix}")),
                    };
                    insert_with_priority(&mut by_route, &mut conflicts, app);
                }
                continue;
            }

            let raw = fs::read_to_string(&manifest_path)
                .with_context(|| format!("failed reading {}", manifest_path.display()))?;
            let manifest: BridgeheadManifest = serde_json::from_str(&raw)
                .with_context(|| format!("invalid JSON in {}", manifest_path.display()))?;

            let name = manifest.name.unwrap_or_else(|| dir_name.clone());
            let explicit_domain = manifest.domain.is_some();
            let domain = manifest
                .domain
                .unwrap_or_else(|| format!("{}.{}", sanitize_name(&dir_name), suffix));
            let domain = DomainName::parse(&domain, suffix).with_context(|| {
                format!("invalid domain '{}' in {}", domain, manifest_path.display())
            })?;

            let enabled = manifest.enabled.unwrap_or(true);
            let is_asgi = manifest.kind.as_deref() == Some("asgi");
            let dir_path = entry.path();

            if is_asgi {
                let root_str = dir_path.to_string_lossy().to_string();
                let app = DiscoveredStaticApp {
                    name,
                    kind: AppKind::Asgi,
                    domain,
                    path_prefix: None,
                    target_host: String::new(),
                    target_port: 0,
                    socket_path: None,
                    timeout_ms: None,
                    cors_enabled: manifest.cors_enabled.unwrap_or(false),
                    basic_auth_user: manifest.basic_auth_user,
                    basic_auth_pass: manifest.basic_auth_pass,
                    spa_rewrite: manifest.spa_rewrite.unwrap_or(false),
                    listen_port: manifest.listen_port,
                    app_root: Some(root_str),
                    static_root: None,
                    enabled,
                    explicit_domain,
                };
                insert_with_priority(&mut by_route, &mut conflicts, app);
            } else if let Some(routes) = manifest.routes {
                for route in routes {
                    let app = DiscoveredStaticApp {
                        name: name.clone(),
                        kind: AppKind::Static,
                        domain: domain.clone(),
                        path_prefix: normalize_path_prefix(route.path_prefix.as_deref()),
                        target_host: route.target_host.unwrap_or_else(|| "127.0.0.1".to_string()),
                        target_port: route.target_port,
                        socket_path: route.socket_path.or_else(|| manifest.socket_path.clone()),
                        timeout_ms: route.timeout_ms,
                        cors_enabled: route.cors_enabled.or(manifest.cors_enabled).unwrap_or(false),
                        basic_auth_user: route.basic_auth_user.or_else(|| manifest.basic_auth_user.clone()),
                        basic_auth_pass: route.basic_auth_pass.or_else(|| manifest.basic_auth_pass.clone()),
                        spa_rewrite: route.spa_rewrite.or(manifest.spa_rewrite).unwrap_or(false),
                        listen_port: route.listen_port.or(manifest.listen_port),
                        app_root: None,
                        static_root: None,
                        enabled,
                        explicit_domain,
                    };
                    insert_with_priority(&mut by_route, &mut conflicts, app);
                }
            } else {
                let target_host = manifest
                    .target_host
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                let app = DiscoveredStaticApp {
                    name,
                    kind: AppKind::Static,
                    domain,
                    path_prefix: normalize_path_prefix(manifest.path_prefix.as_deref()),
                    target_host,
                    target_port: manifest.target_port,
                    socket_path: manifest.socket_path,
                    timeout_ms: manifest.timeout_ms,
                    cors_enabled: manifest.cors_enabled.unwrap_or(false),
                    basic_auth_user: manifest.basic_auth_user,
                    basic_auth_pass: manifest.basic_auth_pass,
                    spa_rewrite: manifest.spa_rewrite.unwrap_or(false),
                    listen_port: manifest.listen_port,
                    app_root: None,
                    static_root: None,
                    enabled,
                    explicit_domain,
                };
                insert_with_priority(&mut by_route, &mut conflicts, app);
            }
        }
    }

    let mut apps: Vec<DiscoveredStaticApp> = by_route.into_values().collect();
    apps.sort_by(|a, b| {
        let p1 = a.path_prefix.as_deref().unwrap_or("");
        let p2 = b.path_prefix.as_deref().unwrap_or("");
        (a.domain.0.as_str(), p1).cmp(&(b.domain.0.as_str(), p2))
    });
    conflicts.sort();
    conflicts.dedup();
    parse_warnings.sort();
    parse_warnings.dedup();
    Ok(DiscoverResult {
        apps,
        conflicts,
        parse_warnings,
    })
}

fn discover_from_symlink(
    link_path: PathBuf,
    file_name: &str,
    suffix: &str,
) -> anyhow::Result<Vec<DiscoveredStaticApp>> {
    let target = fs::read_link(&link_path)
        .with_context(|| format!("failed reading symlink {}", link_path.display()))?;
    let resolved_target = if target.is_absolute() {
        target
    } else {
        link_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(target)
    };

    let meta = match fs::metadata(&resolved_target) {
        Ok(m) => m,
        Err(_) => return Ok(Vec::new()),
    };

    let domain_text = file_name_to_domain(file_name, suffix);
    let domain = DomainName::parse(&domain_text, suffix).with_context(|| {
        format!(
            "invalid domain '{}' in {}",
            domain_text,
            link_path.display()
        )
    })?;
    let explicit_domain = file_name.ends_with(&format!(".{suffix}"));
    let name = sanitize_name(file_name);

    if meta.is_file() {
        let raw = fs::read_to_string(&resolved_target)
            .with_context(|| format!("failed reading {}", resolved_target.display()))?;
        let mut out = Vec::new();
        for route in parse_pow_file_routes(&raw).routes {
            out.push(DiscoveredStaticApp {
                name: name.clone(),
                kind: AppKind::Static,
                domain: domain.clone(),
                path_prefix: route.path_prefix,
                target_host: route.target_host,
                target_port: route.target_port,
                socket_path: None,
                timeout_ms: route.timeout_ms,
                cors_enabled: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                app_root: None,
                static_root: None,
                enabled: true,
                explicit_domain,
            });
        }
        return Ok(out);
    }

    if meta.is_dir() {
        let routes_file = resolved_target.join("bridgehead.routes");
        if routes_file.exists() {
            let raw = fs::read_to_string(&routes_file)
                .with_context(|| format!("failed reading {}", routes_file.display()))?;
            let mut out = Vec::new();
            for route in parse_pow_file_routes(&raw).routes {
                out.push(DiscoveredStaticApp {
                    name: name.clone(),
                    kind: AppKind::Static,
                    domain: domain.clone(),
                    path_prefix: route.path_prefix,
                    target_host: route.target_host,
                    target_port: route.target_port,
                    socket_path: None,
                    timeout_ms: route.timeout_ms,
                    cors_enabled: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    app_root: None,
                    static_root: None,
                    enabled: true,
                    explicit_domain,
                });
            }
            return Ok(out);
        }

        let port_file = resolved_target.join("bridgehead.port");
        if !port_file.exists() {
            // Auto-detect ASGI app
            if detect_asgi_app(&resolved_target) {
                let root_str = resolved_target.to_string_lossy().to_string();
                return Ok(vec![DiscoveredStaticApp {
                    name,
                    kind: AppKind::Asgi,
                    domain,
                    path_prefix: None,
                    target_host: String::new(),
                    target_port: 0,
                    socket_path: None,
                    timeout_ms: None,
                    cors_enabled: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    app_root: Some(root_str),
                    static_root: None,
                    enabled: true,
                    explicit_domain,
                }]);
            }
            if resolved_target.join("public").is_dir() {
                let public_root = resolved_target.join("public").to_string_lossy().to_string();
                return Ok(vec![DiscoveredStaticApp {
                    name,
                    kind: AppKind::Static,
                    domain,
                    path_prefix: None,
                    target_host: String::new(),
                    target_port: 0,
                    socket_path: None,
                    timeout_ms: None,
                    cors_enabled: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    app_root: None,
                    static_root: Some(public_root),
                    enabled: true,
                    explicit_domain,
                }]);
            }
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(&port_file)
            .with_context(|| format!("failed reading {}", port_file.display()))?;
        if let Some((target_host, target_port, timeout_ms)) = parse_port_proxy_target(&raw) {
            return Ok(vec![DiscoveredStaticApp {
                name,
                kind: AppKind::Static,
                domain,
                path_prefix: None,
                target_host,
                target_port,
                socket_path: None,
                timeout_ms,
                cors_enabled: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                app_root: None,
                static_root: None,
                enabled: true,
                explicit_domain,
            }]);
        }
    }

    Ok(Vec::new())
}

fn file_name_to_domain(file_name: &str, suffix: &str) -> String {
    if file_name.ends_with(&format!(".{suffix}")) {
        file_name.to_string()
    } else {
        format!("{file_name}.{suffix}")
    }
}

#[derive(Debug)]
struct PowRoute {
    path_prefix: Option<String>,
    target_host: String,
    target_port: u16,
    timeout_ms: Option<u64>,
}

struct PowParseResult {
    routes: Vec<PowRoute>,
    warnings: Vec<String>,
}

fn parse_pow_file_routes(raw: &str) -> PowParseResult {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(route) = parse_pow_route_line(trimmed) {
            out.push(route);
        } else {
            warnings.push(format!("line {} ignored: invalid route syntax", idx + 1));
        }
    }
    if out.is_empty() {
        if let Some(route) = parse_pow_route_line(raw.trim()) {
            out.push(route);
        } else if !raw.trim().is_empty() {
            warnings.push("content ignored: invalid route syntax".to_string());
        }
    }
    PowParseResult {
        routes: out,
        warnings,
    }
}

fn parse_pow_route_line(line: &str) -> Option<PowRoute> {
    if line.is_empty() {
        return None;
    }

    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }

    let (path_prefix, target_token, timeout_token) = if parts[0].starts_with('/') {
        if parts.len() < 2 {
            return None;
        }
        let p = normalize_path_prefix(Some(parts[0]));
        let t = parts[1];
        let to = parts.get(2).copied();
        (p, t, to)
    } else {
        let t = parts[0];
        let to = parts.get(1).copied();
        (None, t, to)
    };

    let (target_host, target_port) = parse_target_token(target_token)?;
    let timeout_ms = timeout_token
        .and_then(|t| t.parse::<u64>().ok())
        .filter(|v| *v > 0);

    Some(PowRoute {
        path_prefix,
        target_host,
        target_port,
        timeout_ms,
    })
}

fn parse_target_token(token: &str) -> Option<(String, u16)> {
    let value = token.trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(port) = value.parse::<u16>() {
        if port > 0 {
            return Some(("127.0.0.1".to_string(), port));
        }
        return None;
    }

    let value = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .unwrap_or(value);
    let value = value.trim_end_matches('/');

    let (host, port_text) = value.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port = port_text.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some((host.to_string(), port))
}

fn parse_port_proxy_target(raw: &str) -> Option<(String, u16, Option<u64>)> {
    let route = parse_pow_route_line(raw.trim())?;
    if route.path_prefix.is_some() {
        return None;
    }
    Some((route.target_host, route.target_port, route.timeout_ms))
}

fn sanitize_name(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            out.push(ch.to_ascii_lowercase());
        }
    }
    if out.is_empty() {
        "app".to_string()
    } else {
        out
    }
}

fn normalize_path_prefix(input: Option<&str>) -> Option<String> {
    let raw = input?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return None;
    }
    if !trimmed.starts_with('/') {
        return None;
    }
    if trimmed.ends_with('/') {
        return Some(trimmed.trim_end_matches('/').to_string());
    }
    Some(trimmed.to_string())
}

/// Detect an ASGI app in a directory.
/// Returns true if the directory looks like a Python ASGI project:
/// has (app.py or main.py) AND (pyproject.toml or requirements.txt).
fn detect_asgi_app(dir: &Path) -> bool {
    let has_entry = dir.join("app.py").exists() || dir.join("main.py").exists();
    let has_deps = dir.join("pyproject.toml").exists() || dir.join("requirements.txt").exists();
    has_entry && has_deps
}

fn insert_with_priority(
    by_route: &mut HashMap<String, DiscoveredStaticApp>,
    conflicts: &mut Vec<String>,
    candidate: DiscoveredStaticApp,
) {
    let key = route_key(
        &candidate.domain.0,
        candidate.path_prefix.as_deref().unwrap_or(""),
    );
    match by_route.get(&key) {
        None => {
            by_route.insert(key, candidate);
        }
        Some(existing) => {
            conflicts.push(key.clone());
            // explicit domain beats inferred domain; otherwise keep first seen.
            if candidate.explicit_domain && !existing.explicit_domain {
                by_route.insert(key, candidate);
            }
        }
    }
}

fn humanize_route_conflict_key(key: &str) -> String {
    let Some((domain, path_prefix)) = key.split_once('|') else {
        return key.to_string();
    };
    if path_prefix.is_empty() {
        domain.to_string()
    } else {
        format!("{domain} (path={path_prefix})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_dir_name() {
        assert_eq!(sanitize_name("My App"), "myapp");
        assert_eq!(sanitize_name(""), "app");
    }

    #[test]
    fn parses_plain_port_target() {
        let out = parse_port_proxy_target("5006").expect("parse");
        assert_eq!(out.0, "127.0.0.1");
        assert_eq!(out.1, 5006);
        assert_eq!(out.2, None);
    }

    #[test]
    fn parses_http_host_port_target() {
        let out = parse_port_proxy_target("http://1.2.3.4:8080").expect("parse");
        assert_eq!(out.0, "1.2.3.4");
        assert_eq!(out.1, 8080);
        assert_eq!(out.2, None);
    }

    #[test]
    fn converts_file_name_to_domain() {
        assert_eq!(
            file_name_to_domain("myapp", "bridgehead.local"),
            "myapp.bridgehead.local"
        );
        assert_eq!(
            file_name_to_domain("www.myapp.bridgehead.local", "bridgehead.local"),
            "www.myapp.bridgehead.local"
        );
    }

    #[test]
    fn explicit_domain_wins_over_inferred() {
        let mut map = HashMap::new();
        let mut conflicts = Vec::new();
        insert_with_priority(
            &mut map,
            &mut conflicts,
            DiscoveredStaticApp {
                name: "a".to_string(),
                kind: AppKind::Static,
                domain: DomainName("myapp.bridgehead.local".to_string()),
                path_prefix: None,
                target_host: "127.0.0.1".to_string(),
                target_port: 5006,
                socket_path: None,
                timeout_ms: None,
                cors_enabled: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                app_root: None,
                static_root: None,
                enabled: true,
                explicit_domain: false,
            },
        );
        insert_with_priority(
            &mut map,
            &mut conflicts,
            DiscoveredStaticApp {
                name: "b".to_string(),
                kind: AppKind::Static,
                domain: DomainName("myapp.bridgehead.local".to_string()),
                path_prefix: None,
                target_host: "127.0.0.1".to_string(),
                target_port: 5007,
                socket_path: None,
                timeout_ms: None,
                cors_enabled: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                app_root: None,
                static_root: None,
                enabled: true,
                explicit_domain: true,
            },
        );
        let winner = map.get("myapp.bridgehead.local|").expect("winner");
        assert_eq!(winner.target_port, 5007);
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn parse_pow_file_routes_supports_multiple_lines() {
        let raw = r#"
        # comment
        /api 127.0.0.1:7001 5000
        7002
        "#;
        let parsed = parse_pow_file_routes(raw);
        let routes = parsed.routes;
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].path_prefix.as_deref(), Some("/api"));
        assert_eq!(routes[0].target_port, 7001);
        assert_eq!(routes[0].timeout_ms, Some(5000));
        assert_eq!(routes[1].path_prefix, None);
        assert_eq!(routes[1].target_port, 7002);
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn parse_pow_file_routes_reports_invalid_lines() {
        let raw = r#"
        /api
        bad:token
        /v1 127.0.0.1:7001
        "#;
        let parsed = parse_pow_file_routes(raw);
        assert_eq!(parsed.routes.len(), 1);
        assert_eq!(parsed.routes[0].path_prefix.as_deref(), Some("/v1"));
        assert!(parsed.warnings.len() >= 2);
    }

    #[test]
    fn humanize_conflict_key_default_route() {
        assert_eq!(humanize_route_conflict_key("myapp.bridgehead.local|"), "myapp.bridgehead.local");
    }

    #[test]
    fn humanize_conflict_key_path_route() {
        assert_eq!(
            humanize_route_conflict_key("myapp.bridgehead.local|/api"),
            "myapp.bridgehead.local (path=/api)"
        );
    }
}
