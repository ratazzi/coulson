use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

use crate::domain::{AppKind, DomainName};
use crate::process::ProviderRegistry;
use crate::store::{domain_to_db, route_key, ScanUpsertResult, StaticAppInput};
use crate::SharedState;

#[derive(Debug, Deserialize)]
struct CoulsonManifest {
    name: Option<String>,
    domain: Option<String>,
    #[allow(dead_code)]
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
    routes: Option<Vec<CoulsonManifestRoute>>,
    enabled: Option<bool>,
    #[serde(default)]
    cors_enabled: Option<bool>,
    #[serde(default)]
    force_https: Option<bool>,
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
struct CoulsonManifestRoute {
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
    force_https: Option<bool>,
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
    let skip_paths: Vec<&Path> = vec![
        state.scan_warnings_path.as_path(),
        state.sqlite_path.as_path(),
    ];
    let discovered = discover(
        &state.apps_root,
        &state.domain_suffix,
        &state.provider_registry,
        &skip_paths,
    )?;
    let mut active_routes: HashSet<String> = HashSet::new();
    let mut inserted = 0usize;
    let mut updated = 0usize;
    let mut skipped_manual = 0usize;
    for app in &discovered.apps {
        let (_, op) = match app.target_type.as_str() {
            "managed" => {
                let kind_str = app_kind_to_str(app.kind);
                state.store.upsert_scanned_managed(
                    &app.name,
                    &app.domain,
                    &app.target_value,
                    kind_str,
                    app.enabled,
                    "apps_root",
                    &app.fs_entry,
                )?
            }
            "static_dir" => state.store.upsert_scanned_static_dir(
                &app.name,
                &app.domain,
                &app.target_value,
                app.enabled,
                "apps_root",
                &app.fs_entry,
            )?,
            _ => state.store.upsert_scanned_static(
                &StaticAppInput {
                    name: &app.name,
                    domain: &app.domain,
                    path_prefix: app.path_prefix.as_deref(),
                    target_type: &app.target_type,
                    target_value: &app.target_value,
                    timeout_ms: app.timeout_ms,
                    cors_enabled: app.cors_enabled,
                    force_https: app.force_https,
                    basic_auth_user: app.basic_auth_user.as_deref(),
                    basic_auth_pass: app.basic_auth_pass.as_deref(),
                    spa_rewrite: app.spa_rewrite,
                    listen_port: app.listen_port,
                },
                app.enabled,
                "apps_root",
                &app.fs_entry,
            )?,
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
    target_type: String,
    target_value: String,
    timeout_ms: Option<u64>,
    cors_enabled: bool,
    force_https: bool,
    basic_auth_user: Option<String>,
    basic_auth_pass: Option<String>,
    spa_rewrite: bool,
    listen_port: Option<u16>,
    enabled: bool,
    explicit_domain: bool,
    fs_entry: String,
}

struct DiscoverResult {
    apps: Vec<DiscoveredStaticApp>,
    conflicts: Vec<String>,
    parse_warnings: Vec<String>,
}

fn discover(
    root: &Path,
    suffix: &str,
    registry: &ProviderRegistry,
    skip_paths: &[&Path],
) -> anyhow::Result<DiscoverResult> {
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
        let entry_path = entry.path();

        if skip_paths.iter().any(|p| *p == entry_path) {
            continue;
        }

        let file_type = entry.file_type()?;
        let file_name = entry.file_name().to_string_lossy().to_string();

        if file_type.is_symlink() {
            if file_name.starts_with('.') {
                continue;
            }
            let apps = discover_from_symlink(entry.path(), &file_name, suffix, registry)?;
            for app in apps {
                insert_with_priority(&mut by_route, &mut conflicts, app);
            }
            continue;
        }

        if file_type.is_file() {
            if file_name.starts_with('.') {
                continue;
            }
            // Skip known non-config files (e.g. SQLite databases left in apps_root)
            if let Some(ext) = entry_path.extension().and_then(|e| e.to_str()) {
                if matches!(ext, "db" | "db-wal" | "db-shm" | "log") {
                    continue;
                }
            }
            let raw = match fs::read_to_string(entry.path()) {
                Ok(r) => r,
                Err(_) => {
                    // Skip files that can't be read as UTF-8 (binary files)
                    continue;
                }
            };
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
                    target_type: "tcp".to_string(),
                    target_value: format!("{}:{}", route.target_host, route.target_port),
                    timeout_ms: route.timeout_ms,
                    cors_enabled: false,
                    force_https: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    enabled: true,
                    explicit_domain: file_name.ends_with(&format!(".{suffix}")),
                    fs_entry: file_name.clone(),
                };
                insert_with_priority(&mut by_route, &mut conflicts, app);
            }
            continue;
        }

        if file_type.is_dir() {
            let dir_name = file_name;
            let routes_path = entry.path().join("coulson.routes");
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
                        target_type: "tcp".to_string(),
                        target_value: format!("{}:{}", route.target_host, route.target_port),
                        timeout_ms: route.timeout_ms,
                        cors_enabled: false,
                        force_https: false,
                        basic_auth_user: None,
                        basic_auth_pass: None,
                        spa_rewrite: false,
                        listen_port: None,
                        enabled: true,
                        explicit_domain,
                        fs_entry: dir_name.clone(),
                    };
                    insert_with_priority(&mut by_route, &mut conflicts, app);
                }
                continue;
            }

            let manifest_path = entry.path().join("coulson.json");
            if !manifest_path.exists() {
                // Auto-detect managed app via provider registry
                if let Some((_provider, detected)) = registry.detect(&entry.path(), None) {
                    let domain_text = file_name_to_domain(&dir_name, suffix);
                    let domain = DomainName::parse(&domain_text, suffix).with_context(|| {
                        format!(
                            "invalid domain '{}' in {}",
                            domain_text,
                            entry.path().display()
                        )
                    })?;
                    let root_str = entry.path().to_string_lossy().to_string();
                    let app_kind = kind_str_to_app_kind(&detected.kind);
                    let app = DiscoveredStaticApp {
                        name: sanitize_name(&dir_name),
                        kind: app_kind,
                        domain,
                        path_prefix: None,
                        target_type: "managed".to_string(),
                        target_value: root_str,
                        timeout_ms: None,
                        cors_enabled: false,
                        force_https: false,
                        basic_auth_user: None,
                        basic_auth_pass: None,
                        spa_rewrite: false,
                        listen_port: None,
                        enabled: true,
                        explicit_domain: dir_name.ends_with(&format!(".{suffix}")),
                        fs_entry: dir_name.clone(),
                    };
                    insert_with_priority(&mut by_route, &mut conflicts, app);
                } else if entry.path().join("public").is_dir() {
                    let domain_text = file_name_to_domain(&dir_name, suffix);
                    let domain = DomainName::parse(&domain_text, suffix).with_context(|| {
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
                        target_type: "static_dir".to_string(),
                        target_value: public_root,
                        timeout_ms: None,
                        cors_enabled: false,
                        force_https: false,
                        basic_auth_user: None,
                        basic_auth_pass: None,
                        spa_rewrite: false,
                        listen_port: None,
                        enabled: true,
                        explicit_domain: dir_name.ends_with(&format!(".{suffix}")),
                        fs_entry: dir_name.clone(),
                    };
                    insert_with_priority(&mut by_route, &mut conflicts, app);
                }
                continue;
            }

            let raw = fs::read_to_string(&manifest_path)
                .with_context(|| format!("failed reading {}", manifest_path.display()))?;
            let manifest: CoulsonManifest = serde_json::from_str(&raw)
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
            let dir_path = entry.path();

            // Check if a provider can handle this directory (manifest kind or auto-detect)
            let manifest_value: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
            let is_managed = registry.detect(&dir_path, Some(&manifest_value));

            if let Some((_prov, detected)) = is_managed {
                let root_str = dir_path.to_string_lossy().to_string();
                let app_kind = kind_str_to_app_kind(&detected.kind);
                let app = DiscoveredStaticApp {
                    name,
                    kind: app_kind,
                    domain,
                    path_prefix: None,
                    target_type: "managed".to_string(),
                    target_value: root_str,
                    timeout_ms: None,
                    cors_enabled: manifest.cors_enabled.unwrap_or(false),
                    force_https: manifest.force_https.unwrap_or(false),
                    basic_auth_user: manifest.basic_auth_user,
                    basic_auth_pass: manifest.basic_auth_pass,
                    spa_rewrite: manifest.spa_rewrite.unwrap_or(false),
                    listen_port: manifest.listen_port,
                    enabled,
                    explicit_domain,
                    fs_entry: dir_name.clone(),
                };
                insert_with_priority(&mut by_route, &mut conflicts, app);
            } else if let Some(routes) = manifest.routes {
                for route in routes {
                    let socket = route.socket_path.or_else(|| manifest.socket_path.clone());
                    let (tt, tv) = if let Some(sp) = socket {
                        ("unix_socket".to_string(), sp)
                    } else {
                        let host = route.target_host.unwrap_or_else(|| "127.0.0.1".to_string());
                        ("tcp".to_string(), format!("{host}:{}", route.target_port))
                    };
                    let app = DiscoveredStaticApp {
                        name: name.clone(),
                        kind: AppKind::Static,
                        domain: domain.clone(),
                        path_prefix: normalize_path_prefix(route.path_prefix.as_deref()),
                        target_type: tt,
                        target_value: tv,
                        timeout_ms: route.timeout_ms,
                        cors_enabled: route
                            .cors_enabled
                            .or(manifest.cors_enabled)
                            .unwrap_or(false),
                        force_https: route.force_https.or(manifest.force_https).unwrap_or(false),
                        basic_auth_user: route
                            .basic_auth_user
                            .or_else(|| manifest.basic_auth_user.clone()),
                        basic_auth_pass: route
                            .basic_auth_pass
                            .or_else(|| manifest.basic_auth_pass.clone()),
                        spa_rewrite: route.spa_rewrite.or(manifest.spa_rewrite).unwrap_or(false),
                        listen_port: route.listen_port.or(manifest.listen_port),
                        enabled,
                        explicit_domain,
                        fs_entry: dir_name.clone(),
                    };
                    insert_with_priority(&mut by_route, &mut conflicts, app);
                }
            } else {
                let (tt, tv) = if let Some(sp) = manifest.socket_path {
                    ("unix_socket".to_string(), sp)
                } else {
                    let host = manifest
                        .target_host
                        .unwrap_or_else(|| "127.0.0.1".to_string());
                    (
                        "tcp".to_string(),
                        format!("{host}:{}", manifest.target_port),
                    )
                };
                let app = DiscoveredStaticApp {
                    name,
                    kind: AppKind::Static,
                    domain,
                    path_prefix: normalize_path_prefix(manifest.path_prefix.as_deref()),
                    target_type: tt,
                    target_value: tv,
                    timeout_ms: manifest.timeout_ms,
                    cors_enabled: manifest.cors_enabled.unwrap_or(false),
                    force_https: manifest.force_https.unwrap_or(false),
                    basic_auth_user: manifest.basic_auth_user,
                    basic_auth_pass: manifest.basic_auth_pass,
                    spa_rewrite: manifest.spa_rewrite.unwrap_or(false),
                    listen_port: manifest.listen_port,
                    enabled,
                    explicit_domain,
                    fs_entry: dir_name.clone(),
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
    registry: &ProviderRegistry,
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
        let is_toml = resolved_target
            .extension()
            .map(|ext| ext == "toml")
            .unwrap_or(false);
        let routes = if is_toml {
            parse_coulson_toml(&raw).unwrap_or_default()
        } else {
            parse_pow_file_routes(&raw).routes
        };
        let mut out = Vec::new();
        for route in routes {
            out.push(DiscoveredStaticApp {
                name: name.clone(),
                kind: AppKind::Static,
                domain: domain.clone(),
                path_prefix: route.path_prefix,
                target_type: "tcp".to_string(),
                target_value: format!("{}:{}", route.target_host, route.target_port),
                timeout_ms: route.timeout_ms,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                enabled: true,
                explicit_domain,
                fs_entry: file_name.to_string(),
            });
        }
        return Ok(out);
    }

    if meta.is_dir() {
        let routes_file = resolved_target.join("coulson.routes");
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
                    target_type: "tcp".to_string(),
                    target_value: format!("{}:{}", route.target_host, route.target_port),
                    timeout_ms: route.timeout_ms,
                    cors_enabled: false,
                    force_https: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    enabled: true,
                    explicit_domain,
                    fs_entry: file_name.to_string(),
                });
            }
            return Ok(out);
        }

        // .coulson.toml in the directory
        let coulson_toml_file = resolved_target.join(".coulson.toml");
        if coulson_toml_file.exists() {
            let raw = fs::read_to_string(&coulson_toml_file)
                .with_context(|| format!("failed reading {}", coulson_toml_file.display()))?;
            if let Ok(routes) = parse_coulson_toml(&raw) {
                let mut out = Vec::new();
                for route in routes {
                    out.push(DiscoveredStaticApp {
                        name: name.clone(),
                        kind: AppKind::Static,
                        domain: domain.clone(),
                        path_prefix: route.path_prefix,
                        target_type: "tcp".to_string(),
                        target_value: format!("{}:{}", route.target_host, route.target_port),
                        timeout_ms: route.timeout_ms,
                        cors_enabled: false,
                        force_https: false,
                        basic_auth_user: None,
                        basic_auth_pass: None,
                        spa_rewrite: false,
                        listen_port: None,
                        enabled: true,
                        explicit_domain,
                        fs_entry: file_name.to_string(),
                    });
                }
                return Ok(out);
            }
        }

        // .coulson (powfile format) in the directory
        let coulson_file = resolved_target.join(".coulson");
        if coulson_file.exists() {
            let raw = fs::read_to_string(&coulson_file)
                .with_context(|| format!("failed reading {}", coulson_file.display()))?;
            let mut out = Vec::new();
            for route in parse_pow_file_routes(&raw).routes {
                out.push(DiscoveredStaticApp {
                    name: name.clone(),
                    kind: AppKind::Static,
                    domain: domain.clone(),
                    path_prefix: route.path_prefix,
                    target_type: "tcp".to_string(),
                    target_value: format!("{}:{}", route.target_host, route.target_port),
                    timeout_ms: route.timeout_ms,
                    cors_enabled: false,
                    force_https: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    enabled: true,
                    explicit_domain,
                    fs_entry: file_name.to_string(),
                });
            }
            return Ok(out);
        }

        let port_file = resolved_target.join("coulson.port");
        if !port_file.exists() {
            // Auto-detect managed app via provider registry
            if let Some((_prov, detected)) = registry.detect(&resolved_target, None) {
                let root_str = resolved_target.to_string_lossy().to_string();
                let app_kind = kind_str_to_app_kind(&detected.kind);
                return Ok(vec![DiscoveredStaticApp {
                    name,
                    kind: app_kind,
                    domain,
                    path_prefix: None,
                    target_type: "managed".to_string(),
                    target_value: root_str,
                    timeout_ms: None,
                    cors_enabled: false,
                    force_https: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    enabled: true,
                    explicit_domain,
                    fs_entry: file_name.to_string(),
                }]);
            }
            if resolved_target.join("public").is_dir() {
                let public_root = resolved_target.join("public").to_string_lossy().to_string();
                return Ok(vec![DiscoveredStaticApp {
                    name,
                    kind: AppKind::Static,
                    domain,
                    path_prefix: None,
                    target_type: "static_dir".to_string(),
                    target_value: public_root,
                    timeout_ms: None,
                    cors_enabled: false,
                    force_https: false,
                    basic_auth_user: None,
                    basic_auth_pass: None,
                    spa_rewrite: false,
                    listen_port: None,
                    enabled: true,
                    explicit_domain,
                    fs_entry: file_name.to_string(),
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
                target_type: "tcp".to_string(),
                target_value: format!("{target_host}:{target_port}"),
                timeout_ms,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                enabled: true,
                explicit_domain,
                fs_entry: file_name.to_string(),
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

#[derive(Deserialize)]
struct CoulsonToml {
    port: Option<u16>,
    host: Option<String>,
    #[allow(dead_code)]
    kind: Option<String>,
    #[allow(dead_code)]
    module: Option<String>,
    #[allow(dead_code)]
    server: Option<String>,
    #[allow(dead_code)]
    command: Option<String>,
    timeout: Option<u64>,
    #[allow(dead_code)]
    cors: Option<bool>,
    #[allow(dead_code)]
    spa: Option<bool>,
    #[allow(dead_code)]
    listen_port: Option<u16>,
    routes: Option<Vec<CoulsonTomlRoute>>,
}

#[derive(Deserialize)]
struct CoulsonTomlRoute {
    path: Option<String>,
    target: String,
    timeout: Option<u64>,
}

fn parse_coulson_toml(raw: &str) -> anyhow::Result<Vec<PowRoute>> {
    let toml_cfg: CoulsonToml = toml::from_str(raw).context("invalid TOML in .coulson.toml")?;

    if let Some(routes) = toml_cfg.routes {
        let mut out = Vec::new();
        for route in routes {
            let (target_host, target_port) = parse_target_token(&route.target)
                .with_context(|| format!("invalid target '{}' in routes", route.target))?;
            out.push(PowRoute {
                path_prefix: normalize_path_prefix(route.path.as_deref()),
                target_host,
                target_port,
                timeout_ms: route.timeout.or(toml_cfg.timeout),
            });
        }
        return Ok(out);
    }

    if let Some(port) = toml_cfg.port {
        let host = toml_cfg.host.unwrap_or_else(|| "127.0.0.1".to_string());
        return Ok(vec![PowRoute {
            path_prefix: None,
            target_host: host,
            target_port: port,
            timeout_ms: toml_cfg.timeout,
        }]);
    }

    anyhow::bail!("TOML config must have either 'port' or 'routes'")
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

/// Remove the filesystem entry from apps_root.
///
/// - symlink → remove symlink + clean up .coulson/.coulson.toml target file
/// - file → remove file
/// - directory → skip (return false)
///
/// Returns true if something was actually removed.
pub fn remove_app_fs_entry(apps_root: &Path, fs_entry: &str) -> bool {
    let path = apps_root.join(fs_entry);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    if meta.file_type().is_dir() {
        tracing::debug!(path = %path.display(), "skipping directory removal");
        return false;
    }

    // If it's a symlink pointing to a .coulson or .coulson.toml file, clean that up too
    if meta.file_type().is_symlink() {
        if let Ok(target) = std::fs::read_link(&path) {
            let resolved = if target.is_absolute() {
                target
            } else {
                apps_root.join(&target)
            };
            if resolved.is_file() {
                if let Some(fname) = resolved.file_name().and_then(|n| n.to_str()) {
                    if fname == ".coulson" || fname == ".coulson.toml" {
                        if let Err(err) = std::fs::remove_file(&resolved) {
                            tracing::warn!(path = %resolved.display(), error = %err, "failed to remove symlink target file");
                        }
                    }
                }
            }
        }
    }

    match std::fs::remove_file(&path) {
        Ok(()) => {
            tracing::info!(path = %path.display(), "removed fs entry");
            true
        }
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "failed to remove fs entry");
            false
        }
    }
}

pub(crate) fn sanitize_name(name: &str) -> String {
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

/// Convert a provider kind string to AppKind enum.
fn kind_str_to_app_kind(kind: &str) -> AppKind {
    match kind {
        "asgi" => AppKind::Asgi,
        "rack" => AppKind::Rack,
        "docker" => AppKind::Container,
        // Node and other future kinds default to Static for now
        // until AppKind is extended.
        _ => AppKind::Static,
    }
}

/// Convert AppKind enum to the DB/provider kind string.
fn app_kind_to_str(kind: AppKind) -> &'static str {
    match kind {
        AppKind::Asgi => "asgi",
        AppKind::Rack => "rack",
        AppKind::Container => "container",
        AppKind::Static => "static",
    }
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
            file_name_to_domain("myapp", "coulson.local"),
            "myapp.coulson.local"
        );
        assert_eq!(
            file_name_to_domain("www.myapp.coulson.local", "coulson.local"),
            "www.myapp.coulson.local"
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
                domain: DomainName("myapp.coulson.local".to_string()),
                path_prefix: None,
                target_type: "tcp".to_string(),
                target_value: "127.0.0.1:5006".to_string(),
                timeout_ms: None,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                enabled: true,
                explicit_domain: false,
                fs_entry: "myapp".to_string(),
            },
        );
        insert_with_priority(
            &mut map,
            &mut conflicts,
            DiscoveredStaticApp {
                name: "b".to_string(),
                kind: AppKind::Static,
                domain: DomainName("myapp.coulson.local".to_string()),
                path_prefix: None,
                target_type: "tcp".to_string(),
                target_value: "127.0.0.1:5007".to_string(),
                timeout_ms: None,
                cors_enabled: false,
                force_https: false,
                basic_auth_user: None,
                basic_auth_pass: None,
                spa_rewrite: false,
                listen_port: None,
                enabled: true,
                explicit_domain: true,
                fs_entry: "myapp.coulson.local".to_string(),
            },
        );
        let winner = map.get("myapp.coulson.local|").expect("winner");
        assert_eq!(winner.target_value, "127.0.0.1:5007");
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
        assert_eq!(
            humanize_route_conflict_key("myapp.coulson.local|"),
            "myapp.coulson.local"
        );
    }

    #[test]
    fn humanize_conflict_key_path_route() {
        assert_eq!(
            humanize_route_conflict_key("myapp.coulson.local|/api"),
            "myapp.coulson.local (path=/api)"
        );
    }

    #[test]
    fn parse_coulson_toml_port_only() {
        let raw = "port = 5006\n";
        let routes = parse_coulson_toml(raw).expect("parse");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].target_host, "127.0.0.1");
        assert_eq!(routes[0].target_port, 5006);
        assert!(routes[0].path_prefix.is_none());
    }

    #[test]
    fn parse_coulson_toml_port_with_host() {
        let raw = "port = 3000\nhost = \"192.168.1.1\"\n";
        let routes = parse_coulson_toml(raw).expect("parse");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].target_host, "192.168.1.1");
        assert_eq!(routes[0].target_port, 3000);
    }

    #[test]
    fn parse_coulson_toml_routes() {
        let raw = r#"
            timeout = 5000

            [[routes]]
            path = "/api"
            target = "127.0.0.1:3000"

            [[routes]]
            target = "8080"
            timeout = 10000
        "#;
        let routes = parse_coulson_toml(raw).expect("parse");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].path_prefix.as_deref(), Some("/api"));
        assert_eq!(routes[0].target_port, 3000);
        assert_eq!(routes[0].timeout_ms, Some(5000));
        assert_eq!(routes[1].path_prefix, None);
        assert_eq!(routes[1].target_port, 8080);
        assert_eq!(routes[1].timeout_ms, Some(10000));
    }

    #[test]
    fn parse_coulson_toml_invalid() {
        let raw = "not_a_valid_field = true\n";
        let result = parse_coulson_toml(raw);
        assert!(result.is_err());
    }

    // --- parse_target_token ---

    #[test]
    fn parse_target_host_port_no_scheme() {
        let (host, port) = parse_target_token("192.168.1.1:3000").expect("parse");
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 3000);
    }

    #[test]
    fn parse_target_https_scheme_stripped() {
        let (host, port) = parse_target_token("https://myhost:4443").expect("parse");
        assert_eq!(host, "myhost");
        assert_eq!(port, 4443);
    }

    #[test]
    fn parse_target_trailing_slash_stripped() {
        let (host, port) = parse_target_token("http://myhost:9000/").expect("parse");
        assert_eq!(host, "myhost");
        assert_eq!(port, 9000);
    }

    #[test]
    fn parse_target_empty_returns_none() {
        assert!(parse_target_token("").is_none());
    }

    #[test]
    fn parse_target_port_zero_returns_none() {
        assert!(parse_target_token("0").is_none());
        assert!(parse_target_token("127.0.0.1:0").is_none());
    }

    #[test]
    fn parse_target_no_port_returns_none() {
        assert!(parse_target_token("just-a-host").is_none());
    }

    // --- parse_pow_route_line ---

    #[test]
    fn pow_route_plain_port() {
        let r = parse_pow_route_line("5006").expect("parse");
        assert!(r.path_prefix.is_none());
        assert_eq!(r.target_host, "127.0.0.1");
        assert_eq!(r.target_port, 5006);
        assert!(r.timeout_ms.is_none());
    }

    #[test]
    fn pow_route_host_port_no_scheme() {
        let r = parse_pow_route_line("10.0.0.1:8080").expect("parse");
        assert!(r.path_prefix.is_none());
        assert_eq!(r.target_host, "10.0.0.1");
        assert_eq!(r.target_port, 8080);
    }

    #[test]
    fn pow_route_with_path_prefix_and_timeout() {
        let r = parse_pow_route_line("/api 127.0.0.1:3000 30000").expect("parse");
        assert_eq!(r.path_prefix.as_deref(), Some("/api"));
        assert_eq!(r.target_host, "127.0.0.1");
        assert_eq!(r.target_port, 3000);
        assert_eq!(r.timeout_ms, Some(30000));
    }

    #[test]
    fn pow_route_with_path_prefix_no_timeout() {
        let r = parse_pow_route_line("/static 127.0.0.1:4000").expect("parse");
        assert_eq!(r.path_prefix.as_deref(), Some("/static"));
        assert_eq!(r.target_port, 4000);
        assert!(r.timeout_ms.is_none());
    }

    #[test]
    fn pow_route_path_only_no_target_returns_none() {
        assert!(parse_pow_route_line("/api").is_none());
    }

    #[test]
    fn pow_route_empty_returns_none() {
        assert!(parse_pow_route_line("").is_none());
    }

    #[test]
    fn pow_route_timeout_zero_ignored() {
        let r = parse_pow_route_line("5006 0").expect("parse");
        assert!(r.timeout_ms.is_none());
    }

    #[test]
    fn pow_route_non_numeric_timeout_ignored() {
        let r = parse_pow_route_line("5006 abc").expect("parse");
        assert!(r.timeout_ms.is_none());
    }

    // --- parse_pow_file_routes ---

    #[test]
    fn pow_file_empty_returns_no_routes() {
        let parsed = parse_pow_file_routes("");
        assert!(parsed.routes.is_empty());
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn pow_file_whitespace_only_returns_no_routes() {
        let parsed = parse_pow_file_routes("   \n  \n  ");
        assert!(parsed.routes.is_empty());
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn pow_file_comments_only_returns_no_routes() {
        // When all lines are comments, routes is empty but the fallback
        // raw.trim() parse attempt generates a warning.
        let parsed = parse_pow_file_routes("# comment\n# another");
        assert!(parsed.routes.is_empty());
        assert_eq!(parsed.warnings.len(), 1);
    }

    #[test]
    fn pow_file_single_port_no_newline() {
        let parsed = parse_pow_file_routes("5006");
        assert_eq!(parsed.routes.len(), 1);
        assert_eq!(parsed.routes[0].target_port, 5006);
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn pow_file_mixed_valid_and_invalid() {
        let raw = "/api 127.0.0.1:3000\nbadline\n/v2 127.0.0.1:4000 5000";
        let parsed = parse_pow_file_routes(raw);
        assert_eq!(parsed.routes.len(), 2);
        assert_eq!(parsed.routes[0].path_prefix.as_deref(), Some("/api"));
        assert_eq!(parsed.routes[1].path_prefix.as_deref(), Some("/v2"));
        assert_eq!(parsed.routes[1].timeout_ms, Some(5000));
        assert_eq!(parsed.warnings.len(), 1);
    }

    #[test]
    fn pow_file_all_invalid_lines() {
        let raw = "bad\nworse\n";
        let parsed = parse_pow_file_routes(raw);
        assert!(parsed.routes.is_empty());
        assert!(parsed.warnings.len() >= 2);
    }

    // --- normalize_path_prefix ---

    #[test]
    fn normalize_path_none() {
        assert!(normalize_path_prefix(None).is_none());
    }

    #[test]
    fn normalize_path_root_returns_none() {
        assert!(normalize_path_prefix(Some("/")).is_none());
    }

    #[test]
    fn normalize_path_empty_returns_none() {
        assert!(normalize_path_prefix(Some("")).is_none());
    }

    #[test]
    fn normalize_path_strips_trailing_slash() {
        assert_eq!(
            normalize_path_prefix(Some("/api/")),
            Some("/api".to_string())
        );
    }

    #[test]
    fn normalize_path_no_leading_slash_returns_none() {
        assert!(normalize_path_prefix(Some("api")).is_none());
    }

    #[test]
    fn normalize_path_valid() {
        assert_eq!(
            normalize_path_prefix(Some("/api/v1")),
            Some("/api/v1".to_string())
        );
    }

    // --- parse_coulson_toml edge cases ---

    #[test]
    fn parse_coulson_toml_no_port_no_routes_errors() {
        let raw = "host = \"localhost\"\n";
        assert!(parse_coulson_toml(raw).is_err());
    }

    #[test]
    fn parse_coulson_toml_with_timeout() {
        let raw = "port = 5006\ntimeout = 3000\n";
        let routes = parse_coulson_toml(raw).expect("parse");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].timeout_ms, Some(3000));
    }

    #[test]
    fn parse_coulson_toml_route_timeout_overrides_global() {
        let raw = r#"
            timeout = 5000

            [[routes]]
            target = "127.0.0.1:3000"
            timeout = 10000
        "#;
        let routes = parse_coulson_toml(raw).expect("parse");
        assert_eq!(routes[0].timeout_ms, Some(10000));
    }

    #[test]
    fn parse_coulson_toml_route_inherits_global_timeout() {
        let raw = r#"
            timeout = 5000

            [[routes]]
            target = "127.0.0.1:3000"
        "#;
        let routes = parse_coulson_toml(raw).expect("parse");
        assert_eq!(routes[0].timeout_ms, Some(5000));
    }

    #[test]
    fn parse_coulson_toml_route_path_normalized() {
        let raw = r#"
            [[routes]]
            path = "/api/"
            target = "127.0.0.1:3000"
        "#;
        let routes = parse_coulson_toml(raw).expect("parse");
        assert_eq!(routes[0].path_prefix.as_deref(), Some("/api"));
    }
}
