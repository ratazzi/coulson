use bytes::Bytes;
use tracing::{debug, warn};

use crate::share::ShareSigner;

pub enum ShareAuthResult {
    /// Auth passed or not required, continue proxying.
    Continue,
    /// Middleware already sent a response (302 / 403), caller should return.
    Handled,
}

/// Check share authentication before proxying.
/// Handles `/_coulson/auth?t=<jwt>` for token-to-cookie exchange,
/// and validates `_coulson_cookie` on all other paths.
pub fn check_share_auth(
    parts: &http::request::Parts,
    send_response: &mut h2::server::SendResponse<Bytes>,
    share_signer: &ShareSigner,
    local_host: &str,
) -> anyhow::Result<ShareAuthResult> {
    let path = parts.uri.path();

    if path == "/_coulson/auth" {
        return handle_auth_exchange(parts, send_response, share_signer, local_host);
    }

    // Validate cookie on all other paths.
    // HTTP/2 allows Cookie to be split across multiple header entries (RFC 9113 8.2.3),
    // so we must check all of them.
    let token = match extract_cookie_from_headers(&parts.headers, "_coulson_cookie") {
        Some(t) => t,
        None => {
            debug!(local_host = %local_host, "no _coulson_cookie, returning 403");
            send_h2_response(send_response, 403, &[], b"403 Forbidden: missing auth cookie")?;
            return Ok(ShareAuthResult::Handled);
        }
    };

    match share_signer.validate_token(token) {
        Some(claims) if claims.sub == local_host => {
            debug!(local_host = %local_host, "share auth cookie valid");
            Ok(ShareAuthResult::Continue)
        }
        _ => {
            debug!(local_host = %local_host, "invalid or expired _coulson_cookie, returning 403");
            send_h2_response(
                send_response,
                403,
                &[],
                b"403 Forbidden: invalid or expired auth",
            )?;
            Ok(ShareAuthResult::Handled)
        }
    }
}

fn handle_auth_exchange(
    parts: &http::request::Parts,
    send_response: &mut h2::server::SendResponse<Bytes>,
    share_signer: &ShareSigner,
    local_host: &str,
) -> anyhow::Result<ShareAuthResult> {
    let query = parts.uri.query().unwrap_or("");
    let token = match extract_query_param(query, "t") {
        Some(t) => t,
        None => {
            warn!(local_host = %local_host, "/_coulson/auth missing t parameter");
            send_h2_response(send_response, 403, &[], b"403 Forbidden: missing token")?;
            return Ok(ShareAuthResult::Handled);
        }
    };

    match share_signer.validate_token(token) {
        Some(claims) if claims.sub == local_host => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let remaining = claims.exp.saturating_sub(now);

            let cookie = format!(
                "_coulson_cookie={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={remaining}"
            );

            debug!(local_host = %local_host, remaining_secs = remaining, "share auth exchange OK, setting cookie");

            send_h2_response(
                send_response,
                302,
                &[("location", "/"), ("set-cookie", &cookie)],
                b"Redirecting...",
            )?;
            Ok(ShareAuthResult::Handled)
        }
        _ => {
            warn!(local_host = %local_host, "/_coulson/auth invalid or expired token");
            send_h2_response(
                send_response,
                403,
                &[],
                b"403 Forbidden: invalid or expired token",
            )?;
            Ok(ShareAuthResult::Handled)
        }
    }
}

fn extract_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

/// Search all Cookie header entries for a named cookie.
/// HTTP/2 may split cookies across multiple header entries.
fn extract_cookie_from_headers<'a>(
    headers: &'a http::HeaderMap,
    name: &str,
) -> Option<&'a str> {
    for value in headers.get_all("cookie") {
        if let Ok(s) = value.to_str() {
            if let Some(v) = extract_cookie(s, name) {
                return Some(v);
            }
        }
    }
    None
}

fn extract_cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    for part in header.split(';') {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == name {
                return Some(v.trim());
            }
        }
    }
    None
}

fn send_h2_response(
    send_response: &mut h2::server::SendResponse<Bytes>,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> anyhow::Result<()> {
    let mut builder = http::Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder = builder.header("content-type", "text/plain");
    let response = builder.body(()).unwrap();
    let mut send_stream = send_response.send_response(response, false)?;
    send_stream.send_data(Bytes::from(body.to_vec()), true)?;
    Ok(())
}
