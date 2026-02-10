use anyhow::Context;
use base64::Engine;
use serde::Deserialize;

use super::TunnelCredentials;

const QUICK_TUNNEL_API: &str = "https://api.trycloudflare.com/tunnel";

#[derive(Debug, Deserialize)]
struct QuickTunnelResponse {
    success: bool,
    result: QuickTunnelResult,
    #[serde(default)]
    errors: Vec<QuickTunnelError>,
}

#[derive(Debug, Deserialize)]
struct QuickTunnelResult {
    id: String,
    hostname: String,
    account_tag: String,
    secret: String,
}

#[derive(Debug, Deserialize)]
struct QuickTunnelError {
    code: i64,
    message: String,
}

/// Register a quick tunnel with Cloudflare's trycloudflare.com service.
pub async fn register_quick_tunnel() -> anyhow::Result<TunnelCredentials> {
    let client = reqwest::Client::new();
    let resp = client
        .post(QUICK_TUNNEL_API)
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            format!("coulson/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await
        .context("failed to contact quick tunnel API")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("quick tunnel API returned {}: {}", status, body);
    }

    let data: QuickTunnelResponse = resp
        .json()
        .await
        .context("failed to parse quick tunnel response")?;

    if !data.success {
        let msg = data
            .errors
            .iter()
            .map(|e| format!("[{}] {}", e.code, e.message))
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!("quick tunnel registration failed: {}", msg);
    }

    let secret = base64::engine::general_purpose::STANDARD
        .decode(&data.result.secret)
        .context("failed to decode tunnel secret")?;

    Ok(TunnelCredentials {
        tunnel_id: data.result.id,
        account_tag: data.result.account_tag,
        secret,
        hostname: data.result.hostname,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_quick_tunnel_response() {
        let json = r#"{
            "success": true,
            "result": {
                "id": "d383d8a6-d0bc-4a9d-9c41-0dc78f0db81e",
                "name": "qt-test",
                "hostname": "test-abc.trycloudflare.com",
                "account_tag": "00000000000000000000000000000000",
                "secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            },
            "errors": []
        }"#;

        let resp: QuickTunnelResponse = serde_json::from_str(json).expect("parse");
        assert!(resp.success);
        assert_eq!(resp.result.id, "d383d8a6-d0bc-4a9d-9c41-0dc78f0db81e");
        assert_eq!(resp.result.hostname, "test-abc.trycloudflare.com");

        let secret = base64::engine::general_purpose::STANDARD
            .decode(&resp.result.secret)
            .expect("decode secret");
        assert_eq!(secret.len(), 32);
    }
}
