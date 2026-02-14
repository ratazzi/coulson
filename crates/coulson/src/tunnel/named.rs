use anyhow::Context;
use base64::Engine;
use serde::Deserialize;

use super::TunnelCredentials;

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Deserialize)]
struct CfApiResponse<T> {
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Vec<CfApiError>,
}

#[derive(Debug, Deserialize)]
struct CfApiError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CfTunnelResult {
    id: String,
    name: String,
}

fn cf_error_message(errors: &[CfApiError]) -> String {
    errors
        .iter()
        .map(|e| format!("[{}] {}", e.code, e.message))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Create a named Cloudflare Tunnel via the CF API.
/// Returns (credentials, tunnel_id).
pub async fn create_named_tunnel(
    api_token: &str,
    account_id: &str,
    name: &str,
) -> anyhow::Result<(TunnelCredentials, String)> {
    // Generate 32-byte random secret
    let secret: [u8; 32] = rand::random();
    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(secret);

    let client = reqwest::Client::new();
    let url = format!("{CF_API_BASE}/accounts/{account_id}/cfd_tunnel");

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_token}"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "name": name,
            "tunnel_secret": secret_b64,
        }))
        .send()
        .await
        .context("failed to contact Cloudflare API")?;

    let status = resp.status();
    let body: CfApiResponse<CfTunnelResult> = resp
        .json()
        .await
        .context("failed to parse CF API response")?;

    if !body.success || body.result.is_none() {
        let msg = if body.errors.is_empty() {
            format!("CF API returned {status}")
        } else {
            cf_error_message(&body.errors)
        };
        anyhow::bail!("failed to create named tunnel: {msg}");
    }

    let result = body.result.unwrap();
    let credentials = TunnelCredentials {
        tunnel_id: result.id.clone(),
        account_tag: account_id.to_string(),
        secret: secret.to_vec(),
        hostname: format!("{}.cfargotunnel.com", result.id),
    };

    Ok((credentials, result.id))
}

/// Delete a named Cloudflare Tunnel via the CF API.
pub async fn delete_named_tunnel(
    api_token: &str,
    account_id: &str,
    tunnel_id: &str,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{CF_API_BASE}/accounts/{account_id}/cfd_tunnel/{tunnel_id}");

    let resp = client
        .delete(&url)
        .header("Authorization", format!("Bearer {api_token}"))
        .send()
        .await
        .context("failed to contact Cloudflare API for tunnel deletion")?;

    let status = resp.status();
    let body: CfApiResponse<serde_json::Value> = resp
        .json()
        .await
        .context("failed to parse CF API delete response")?;

    if !body.success {
        let msg = if body.errors.is_empty() {
            format!("CF API returned {status}")
        } else {
            cf_error_message(&body.errors)
        };
        anyhow::bail!("failed to delete named tunnel: {msg}");
    }

    Ok(())
}

/// Find the Cloudflare zone_id for a domain by matching the longest zone suffix.
pub async fn find_zone_id(api_token: &str, domain: &str) -> anyhow::Result<String> {
    #[derive(Debug, Deserialize)]
    struct Zone {
        id: String,
        name: String,
    }

    let client = reqwest::Client::new();
    let mut page = 1u32;
    let mut best: Option<(String, usize)> = None; // (zone_id, zone_name_len)

    loop {
        let url = format!("{CF_API_BASE}/zones?per_page=50&page={page}");
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {api_token}"))
            .send()
            .await
            .context("failed to contact Cloudflare zones API")?;

        let body: CfApiResponse<Vec<Zone>> = resp
            .json()
            .await
            .context("failed to parse CF zones response")?;

        if !body.success {
            let msg = if body.errors.is_empty() {
                "unknown error".to_string()
            } else {
                cf_error_message(&body.errors)
            };
            anyhow::bail!("failed to list zones: {msg}");
        }

        let zones = body.result.unwrap_or_default();
        if zones.is_empty() {
            break;
        }

        for zone in &zones {
            // domain must equal zone name or end with .zone_name
            let is_match = domain == zone.name || domain.ends_with(&format!(".{}", zone.name));
            if is_match {
                let len = zone.name.len();
                if best.as_ref().is_none_or(|(_, best_len)| len > *best_len) {
                    best = Some((zone.id.clone(), len));
                }
            }
        }

        page += 1;
    }

    best.map(|(id, _)| id)
        .ok_or_else(|| anyhow::anyhow!("no zone found matching domain: {domain}"))
}

/// Create a CNAME DNS record pointing `name` to `{tunnel_id}.cfargotunnel.com`.
/// Returns the DNS record ID.
pub async fn create_dns_cname(
    api_token: &str,
    zone_id: &str,
    name: &str,
    tunnel_id: &str,
) -> anyhow::Result<String> {
    #[derive(Debug, Deserialize)]
    struct DnsRecord {
        id: String,
    }

    let client = reqwest::Client::new();
    let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records");
    let content = format!("{tunnel_id}.cfargotunnel.com");

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_token}"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "type": "CNAME",
            "name": name,
            "content": content,
            "proxied": true,
        }))
        .send()
        .await
        .context("failed to contact CF DNS API")?;

    let status = resp.status();
    let body: CfApiResponse<DnsRecord> = resp
        .json()
        .await
        .context("failed to parse CF DNS create response")?;

    if !body.success || body.result.is_none() {
        let msg = if body.errors.is_empty() {
            format!("CF API returned {status}")
        } else {
            cf_error_message(&body.errors)
        };
        anyhow::bail!("failed to create DNS CNAME: {msg}");
    }

    Ok(body.result.unwrap().id)
}

/// Delete a DNS record by zone_id and record_id.
pub async fn delete_dns_record(
    api_token: &str,
    zone_id: &str,
    record_id: &str,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}");

    let resp = client
        .delete(&url)
        .header("Authorization", format!("Bearer {api_token}"))
        .send()
        .await
        .context("failed to contact CF DNS API for record deletion")?;

    let status = resp.status();
    let body: CfApiResponse<serde_json::Value> = resp
        .json()
        .await
        .context("failed to parse CF DNS delete response")?;

    if !body.success {
        let msg = if body.errors.is_empty() {
            format!("CF API returned {status}")
        } else {
            cf_error_message(&body.errors)
        };
        anyhow::bail!("failed to delete DNS record: {msg}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_create_tunnel_response() {
        let json = r#"{
            "success": true,
            "result": {
                "id": "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415",
                "name": "coulson-tunnel",
                "created_at": "2024-01-01T00:00:00Z",
                "deleted_at": null,
                "connections": [],
                "status": "inactive"
            },
            "errors": [],
            "messages": []
        }"#;

        let resp: CfApiResponse<CfTunnelResult> = serde_json::from_str(json).expect("parse");
        assert!(resp.success);
        let result = resp.result.unwrap();
        assert_eq!(result.id, "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415");
        assert_eq!(result.name, "coulson-tunnel");
    }

    #[test]
    fn parse_error_response() {
        let json = r#"{
            "success": false,
            "result": null,
            "errors": [
                {"code": 1003, "message": "Invalid or missing account id"}
            ],
            "messages": []
        }"#;

        let resp: CfApiResponse<CfTunnelResult> = serde_json::from_str(json).expect("parse");
        assert!(!resp.success);
        assert!(resp.result.is_none());
        assert_eq!(resp.errors.len(), 1);
        assert_eq!(resp.errors[0].code, 1003);
    }
}
