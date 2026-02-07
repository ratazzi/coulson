use std::fs;
use std::path::Path;

use anyhow::Context;
use serde::Deserialize;

use crate::domain::DomainName;
use crate::SharedState;

#[derive(Debug, Deserialize)]
struct BridgeheadManifest {
    name: Option<String>,
    domain: Option<String>,
    target_host: Option<String>,
    target_port: u16,
    enabled: Option<bool>,
}

pub fn sync_from_apps_root(state: &SharedState) -> anyhow::Result<usize> {
    let discovered = discover(&state.apps_root, &state.domain_suffix)?;
    for app in &discovered {
        state.store.upsert_static(
            &app.name,
            &app.domain,
            &app.target_host,
            app.target_port,
            app.enabled,
        )?;
    }
    Ok(discovered.len())
}

#[derive(Debug)]
struct DiscoveredStaticApp {
    name: String,
    domain: DomainName,
    target_host: String,
    target_port: u16,
    enabled: bool,
}

fn discover(root: &Path, suffix: &str) -> anyhow::Result<Vec<DiscoveredStaticApp>> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut apps = Vec::new();
    for entry in fs::read_dir(root)
        .with_context(|| format!("failed reading apps root: {}", root.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let file_name = entry.file_name().to_string_lossy().to_string();

        if file_type.is_file() {
            if file_name.starts_with('.') {
                continue;
            }
            let raw = fs::read_to_string(entry.path())
                .with_context(|| format!("failed reading {}", entry.path().display()))?;
            if let Some((target_host, target_port)) = parse_port_proxy_target(&raw) {
                let domain_text = file_name_to_domain(&file_name, suffix);
                let domain = DomainName::parse(&domain_text, suffix).with_context(|| {
                    format!(
                        "invalid domain '{}' in {}",
                        domain_text,
                        entry.path().display()
                    )
                })?;

                apps.push(DiscoveredStaticApp {
                    name: sanitize_name(&file_name),
                    domain,
                    target_host,
                    target_port,
                    enabled: true,
                });
            }
            continue;
        }

        if file_type.is_dir() {
            let dir_name = file_name;
            let manifest_path = entry.path().join("bridgehead.json");
            if !manifest_path.exists() {
                continue;
            }

            let raw = fs::read_to_string(&manifest_path)
                .with_context(|| format!("failed reading {}", manifest_path.display()))?;
            let manifest: BridgeheadManifest = serde_json::from_str(&raw)
                .with_context(|| format!("invalid JSON in {}", manifest_path.display()))?;

            let name = manifest.name.unwrap_or_else(|| dir_name.clone());
            let domain = manifest
                .domain
                .unwrap_or_else(|| format!("{}.{}", sanitize_name(&dir_name), suffix));
            let domain = DomainName::parse(&domain, suffix).with_context(|| {
                format!("invalid domain '{}' in {}", domain, manifest_path.display())
            })?;

            let target_host = manifest
                .target_host
                .unwrap_or_else(|| "127.0.0.1".to_string());

            apps.push(DiscoveredStaticApp {
                name,
                domain,
                target_host,
                target_port: manifest.target_port,
                enabled: manifest.enabled.unwrap_or(true),
            });
        }
    }

    Ok(apps)
}

fn file_name_to_domain(file_name: &str, suffix: &str) -> String {
    if file_name.ends_with(&format!(".{suffix}")) {
        file_name.to_string()
    } else {
        format!("{file_name}.{suffix}")
    }
}

fn parse_port_proxy_target(raw: &str) -> Option<(String, u16)> {
    let value = raw.trim();
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
    }

    #[test]
    fn parses_http_host_port_target() {
        let out = parse_port_proxy_target("http://1.2.3.4:8080").expect("parse");
        assert_eq!(out.0, "1.2.3.4");
        assert_eq!(out.1, 8080);
    }
}
