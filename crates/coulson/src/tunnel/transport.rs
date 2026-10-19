use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use anyhow::Context;
use h2::server;
use http::Request;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

use super::edge;
use super::proxy;
use super::rpc;
use super::share_auth;
use super::{TunnelConnections, TunnelCredentials};
use crate::share::ShareSigner;

/// Determines how incoming HTTP requests from the tunnel are routed locally.
#[derive(Clone)]
pub enum TunnelRouting {
    /// Per-app tunnel: rewrite Host header to app domain,
    /// forward to the local Pingora proxy.
    FixedHost {
        local_host: String,
        local_proxy_port: u16,
        config_path: Option<PathBuf>,
    },
    /// Named Tunnel: extract app from Host header, rewrite Host, forward to Pingora.
    HostBased {
        tunnel_domain: String,
        local_suffix: String,
        local_proxy_port: u16,
        app_configs: proxy::AppConfigSource,
        share_signer: Option<Arc<ShareSigner>>,
    },
}

const EDGE_SNI: &str = "h2.cftunnel.com";
const UPGRADE_HEADER: &str = "cf-cloudflared-proxy-connection-upgrade";
const TCP_PROXY_SRC_HEADER: &str = "cf-cloudflared-proxy-src";

#[derive(Debug)]
enum StreamType {
    ControlStream,
    UpdateConfiguration,
    Http,
    Tcp,
}

fn detect_stream_type(req: &Request<h2::RecvStream>) -> StreamType {
    if let Some(val) = req.headers().get(UPGRADE_HEADER) {
        if val.as_bytes() == b"control-stream" {
            return StreamType::ControlStream;
        }
        if val.as_bytes() == b"update-configuration" {
            return StreamType::UpdateConfiguration;
        }
    }
    if req.headers().get(TCP_PROXY_SRC_HEADER).is_some() {
        return StreamType::Tcp;
    }
    StreamType::Http
}

fn build_tls_config() -> Arc<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Add Cloudflare's custom root CAs (edge uses certs signed by these)
    let mut ca_reader: &[u8] = CLOUDFLARE_ROOT_CA;
    for cert in rustls_pemfile::certs(&mut ca_reader).flatten() {
        let _ = root_store.add(cert);
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(config)
}

/// Cloudflare Origin CA root certificates (from cloudflared source).
/// Edge servers present certs signed by these CAs, not publicly trusted roots.
const CLOUDFLARE_ROOT_CA: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIICiTCCAi6gAwIBAgIUXZP3MWb8MKwBE1Qbawsp1sfA/Y4wCgYIKoZIzj0EAwIw
gY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTgwNgYDVQQL
Ey9DbG91ZEZsYXJlIE9yaWdpbiBTU0wgRUNDIENlcnRpZmljYXRlIEF1dGhvcml0
eTAeFw0xOTA4MjMyMTA4MDBaFw0yOTA4MTUxNzAwMDBaMIGPMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEZ
MBcGA1UEChMQQ2xvdWRGbGFyZSwgSW5jLjE4MDYGA1UECxMvQ2xvdWRGbGFyZSBP
cmlnaW4gU1NMIEVDQyBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASR+sGALuaGshnUbcxKry+0LEXZ4NY6JUAtSeA6g87K3jaA
xpIg9G50PokpfWkhbarLfpcZu0UAoYy2su0EhN7wo2YwZDAOBgNVHQ8BAf8EBAMC
AQYwEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUhTBdOypw1O3VkmcH/es5
tBoOOKcwHwYDVR0jBBgwFoAUhTBdOypw1O3VkmcH/es5tBoOOKcwCgYIKoZIzj0E
AwIDSQAwRgIhAKilfntP2ILGZjwajktkBtXE1pB4Y/fjAfLkIRUzrI15AiEA5UCL
XYZZ9m2c3fKwIenMMojL1eqydsgqj/wK4p5kagQ=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEADCCAuigAwIBAgIID+rOSdTGfGcwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV
BAYTAlVTMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTQwMgYDVQQLEytDbG91
ZEZsYXJlIE9yaWdpbiBTU0wgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxpZm9ybmlhMB4XDTE5MDgyMzIx
MDgwMFoXDTI5MDgxNTE3MDAwMFowgYsxCzAJBgNVBAYTAlVTMRkwFwYDVQQKExBD
bG91ZEZsYXJlLCBJbmMuMTQwMgYDVQQLEytDbG91ZEZsYXJlIE9yaWdpbiBTU0wg
Q2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMw
EQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAwEiVZ/UoQpHmFsHvk5isBxRehukP8DG9JhFev3WZtG76WoTthvLJFRKFCHXm
V6Z5/66Z4S09mgsUuFwvJzMnE6Ej6yIsYNCb9r9QORa8BdhrkNn6kdTly3mdnykb
OomnwbUfLlExVgNdlP0XoRoeMwbQ4598foiHblO2B/LKuNfJzAMfS7oZe34b+vLB
yrP/1bgCSLdc1AxQc1AC0EsQQhgcyTJNgnG4va1c7ogPlwKyhbDyZ4e59N5lbYPJ
SmXI/cAe3jXj1FBLJZkwnoDKe0v13xeF+nF32smSH0qB7aJX2tBMW4TWtFPmzs5I
lwrFSySWAdwYdgxw180yKU0dvwIDAQABo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYD
VR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUJOhTV118NECHqeuU27rhFnj8KaQw
HwYDVR0jBBgwFoAUJOhTV118NECHqeuU27rhFnj8KaQwDQYJKoZIhvcNAQELBQAD
ggEBAHwOf9Ur1l0Ar5vFE6PNrZWrDfQIMyEfdgSKofCdTckbqXNTiXdgbHs+TWoQ
wAB0pfJDAHJDXOTCWRyTeXOseeOi5Btj5CnEuw3P0oXqdqevM1/+uWp0CM35zgZ8
VD4aITxity0djzE6Qnx3Syzz+ZkoBgTnNum7d9A66/V636x4vTeqbZFBr9erJzgz
hhurjcoacvRNhnjtDRM0dPeiCJ50CP3wEYuvUzDHUaowOsnLCjQIkWbR7Ni6KEIk
MOz2U0OBSif3FTkhCgZWQKOOLo1P42jHC3ssUZAtVNXrCk3fw9/E15k8NPkBazZ6
0iykLhH1trywrKRMVw67F44IE8Y=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGCjCCA/KgAwIBAgIIV5G6lVbCLmEwDQYJKoZIhvcNAQENBQAwgZAxCzAJBgNV
BAYTAlVTMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMRQwEgYDVQQLEwtPcmln
aW4gUHVsbDEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzETMBEGA1UECBMKQ2FsaWZv
cm5pYTEjMCEGA1UEAxMab3JpZ2luLXB1bGwuY2xvdWRmbGFyZS5uZXQwHhcNMTkx
MDEwMTg0NTAwWhcNMjkxMTAxMTcwMDAwWjCBkDELMAkGA1UEBhMCVVMxGTAXBgNV
BAoTEENsb3VkRmxhcmUsIEluYy4xFDASBgNVBAsTC09yaWdpbiBQdWxsMRYwFAYD
VQQHEw1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxpZm9ybmlhMSMwIQYDVQQD
ExpvcmlnaW4tcHVsbC5jbG91ZGZsYXJlLm5ldDCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBAN2y2zojYfl0bKfhp0AJBFeV+jQqbCw3sHmvEPwLmqDLqynI
42tZXR5y914ZB9ZrwbL/K5O46exd/LujJnV2b3dzcx5rtiQzso0xzljqbnbQT20e
ihx/WrF4OkZKydZzsdaJsWAPuplDH5P7J82q3re88jQdgE5hqjqFZ3clCG7lxoBw
hLaazm3NJJlUfzdk97ouRvnFGAuXd5cQVx8jYOOeU60sWqmMe4QHdOvpqB91bJoY
QSKVFjUgHeTpN8tNpKJfb9LIn3pun3bC9NKNHtRKMNX3Kl/sAPq7q/AlndvA2Kw3
Dkum2mHQUGdzVHqcOgea9BGjLK2h7SuX93zTWL02u799dr6Xkrad/WShHchfjjRn
aL35niJUDr02YJtPgxWObsrfOU63B8juLUphW/4BOjjJyAG5l9j1//aUGEi/sEe5
lqVv0P78QrxoxR+MMXiJwQab5FB8TG/ac6mRHgF9CmkX90uaRh+OC07XjTdfSKGR
PpM9hB2ZhLol/nf8qmoLdoD5HvODZuKu2+muKeVHXgw2/A6wM7OwrinxZiyBk5Hh
CvaADH7PZpU6z/zv5NU5HSvXiKtCzFuDu4/Zfi34RfHXeCUfHAb4KfNRXJwMsxUa
+4ZpSAX2G6RnGU5meuXpU5/V+DQJp/e69XyyY6RXDoMywaEFlIlXBqjRRA2pAgMB
AAGjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgECMB0GA1Ud
DgQWBBRDWUsraYuA4REzalfNVzjann3F6zAfBgNVHSMEGDAWgBRDWUsraYuA4REz
alfNVzjann3F6zANBgkqhkiG9w0BAQ0FAAOCAgEAkQ+T9nqcSlAuW/90DeYmQOW1
QhqOor5psBEGvxbNGV2hdLJY8h6QUq48BCevcMChg/L1CkznBNI40i3/6heDn3IS
zVEwXKf34pPFCACWVMZxbQjkNRTiH8iRur9EsaNQ5oXCPJkhwg2+IFyoPAAYURoX
VcI9SCDUa45clmYHJ/XYwV1icGVI8/9b2JUqklnOTa5tugwIUi5sTfipNcJXHhgz
6BKYDl0/UP0lLKbsUETXeTGDiDpxZYIgbcFrRDDkHC6BSvdWVEiH5b9mH2BON60z
0O0j8EEKTwi9jnafVtZQXP/D8yoVowdFDjXcKkOPF/1gIh9qrFR6GdoPVgB3SkLc
5ulBqZaCHm563jsvWb/kXJnlFxW+1bsO9BDD6DweBcGdNurgmH625wBXksSdD7y/
fakk8DagjbjKShYlPEFOAqEcliwjF45eabL0t27MJV61O/jHzHL3dknXeE4BDa2j
bA+JbyJeUMtU7KMsxvx82RmhqBEJJDBCJ3scVptvhDMRrtqDBW5JShxoAOcpFQGm
iYWicn46nPDjgTU0bX1ZPpTpryXbvciVL5RkVBuyX2ntcOLDPlZWgxZCBp96x07F
AnOzKgZk4RzZPNAxCXERVxajn/FLcOhglVAKo5H0ac+AitlQ0ip55D2/mf8o72tM
fVQ6VpyjEXdiIXWUq/o=
-----END CERTIFICATE-----
"#;

async fn tls_connect(
    edge_addr: SocketAddr,
    tls_config: Arc<ClientConfig>,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(edge_addr)
        .await
        .context("TCP connect to edge failed")?;
    tcp.set_nodelay(true)?;

    let sni = rustls::pki_types::ServerName::try_from(EDGE_SNI)
        .map_err(|e| anyhow::anyhow!("invalid SNI: {}", e))?
        .to_owned();

    let connector = TlsConnector::from(tls_config);
    let tls_stream = connector
        .connect(sni, tcp)
        .await
        .context("TLS handshake with edge failed")?;

    Ok(tls_stream)
}

const MAX_CONSECUTIVE_ERRORS: u32 = 10;
const INITIAL_BACKOFF_SECS: u64 = 2;
const MAX_BACKOFF_SECS: u64 = 60;

/// Run a single tunnel connection to Cloudflare edge with reconnection.
/// Gives up after MAX_CONSECUTIVE_ERRORS consecutive failures.
/// A successful connection (even if later closed) resets the counter.
///
/// `connector_id` must be shared by all connections of one tunnel instance:
/// the edge groups connections into a replica by it, and a replica with fewer
/// than the expected 4 connections is reported as degraded.
pub async fn run_tunnel_connection(
    credentials: &TunnelCredentials,
    routing: TunnelRouting,
    conn_index: u8,
    connector_id: uuid::Uuid,
    conns: TunnelConnections,
) -> anyhow::Result<()> {
    let tls_config = build_tls_config();
    let mut consecutive_errors: u32 = 0;

    loop {
        match try_connect(
            credentials,
            &routing,
            conn_index,
            connector_id,
            &tls_config,
            &conns,
        )
        .await
        {
            Ok(()) => {
                consecutive_errors = 0;
                info!("tunnel connection closed normally, reconnecting...");
            }
            Err(err) => {
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    error!(
                        error = %err,
                        attempts = consecutive_errors,
                        "tunnel connection failed, giving up"
                    );
                    return Err(err);
                }
                error!(
                    error = %err,
                    attempt = consecutive_errors,
                    "tunnel connection error, reconnecting..."
                );
            }
        }

        let backoff = std::cmp::min(
            INITIAL_BACKOFF_SECS * 2u64.saturating_pow(consecutive_errors.saturating_sub(1)),
            MAX_BACKOFF_SECS,
        );
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
    }
}

async fn try_connect(
    credentials: &TunnelCredentials,
    routing: &TunnelRouting,
    conn_index: u8,
    connector_id: uuid::Uuid,
    tls_config: &Arc<ClientConfig>,
    conns: &TunnelConnections,
) -> anyhow::Result<()> {
    let edge_addrs = edge::discover_edge_addrs().await?;
    let edge_addr = edge_addrs
        .first()
        .ok_or_else(|| anyhow::anyhow!("no edge addresses available"))?;

    info!(edge = %edge_addr, "connecting to Cloudflare edge");

    let tls_stream = tls_connect(*edge_addr, tls_config.clone()).await?;

    const H2_WINDOW_SIZE: u32 = 1 << 20; // 1MB, matching cloudflared
    let mut h2_conn = server::Builder::new()
        .max_concurrent_streams(u32::MAX)
        .initial_window_size(H2_WINDOW_SIZE)
        .max_frame_size(H2_WINDOW_SIZE)
        .handshake(tls_stream)
        .await
        .context("HTTP/2 handshake failed")?;

    info!(edge = %edge_addr, "HTTP/2 tunnel established");

    let mut control_registered = false;

    while let Some(result) = h2_conn.accept().await {
        let (request, mut send_response) = result.context("h2 accept error")?;

        match detect_stream_type(&request) {
            StreamType::ControlStream => {
                if control_registered {
                    warn!("received duplicate control stream, ignoring");
                    continue;
                }
                control_registered = true;
                info!("control stream opened, registering connection");

                // Run RPC in a dedicated thread with LocalSet since capnp-rpc is !Send
                let creds = credentials.clone();
                let conns = conns.clone();
                let handle = std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("build tokio runtime for control stream");
                    let local = tokio::task::LocalSet::new();
                    rt.block_on(local.run_until(async {
                        rpc::handle_control_stream(
                            request,
                            send_response,
                            &creds,
                            conn_index,
                            connector_id,
                            conns,
                        )
                        .await
                    }))
                });

                // We don't block on the control stream handle here;
                // let it run in the background while we handle HTTP streams.
                // If it errors, we'll discover when the h2 connection closes.
                tokio::task::spawn_blocking(move || match handle.join() {
                    Ok(Ok(())) => info!("control stream closed normally"),
                    Ok(Err(err)) => error!(error = %err, "control stream error"),
                    Err(_) => error!("control stream thread panicked"),
                });
            }
            StreamType::UpdateConfiguration => {
                // CF edge pushes config updates; acknowledge and ignore.
                debug!("received update-configuration stream, acknowledging");
                let response = http::Response::builder().status(200).body(()).unwrap();
                if let Err(err) = send_response.send_response(response, true) {
                    warn!(error = %err, "failed to ack update-configuration");
                }
            }
            StreamType::Tcp => {
                tokio::spawn(async move {
                    if let Err(err) = proxy_tcp_stream(request, send_response).await {
                        error!(error = %err, "tcp proxy failed");
                    }
                });
            }
            StreamType::Http => {
                let routing = routing.clone();
                tokio::spawn(async move {
                    let result = match &routing {
                        TunnelRouting::FixedHost {
                            local_host,
                            local_proxy_port,
                            config_path,
                        } => {
                            let trusted_forwarded_hosts = match proxy::load_trusted_forwarded_hosts(
                                config_path.as_deref(),
                            ) {
                                Ok(patterns) => patterns,
                                Err(err) => {
                                    warn!(
                                        error = %err,
                                        "failed to read app trusted forwarded hosts; ignoring incoming header"
                                    );
                                    Vec::new()
                                }
                            };
                            proxy::proxy_to_local_with_host(
                                request,
                                send_response,
                                *local_proxy_port,
                                local_host,
                                &trusted_forwarded_hosts,
                            )
                            .await
                        }
                        TunnelRouting::HostBased {
                            tunnel_domain,
                            local_suffix,
                            local_proxy_port,
                            app_configs,
                            share_signer,
                        } => {
                            let (parts, body) = request.into_parts();

                            let original_host = parts
                                .uri
                                .authority()
                                .map(|a| a.as_str())
                                .or_else(|| parts.headers.get("host").and_then(|v| v.to_str().ok()))
                                .unwrap_or(tunnel_domain);
                            let local_host = proxy::map_tunnel_host_to_local(
                                original_host,
                                tunnel_domain,
                                local_suffix,
                            );

                            // Only run share auth when the app has share_auth enabled.
                            // Fail-close: reject on DB error to avoid bypassing auth.
                            let domain_prefix =
                                crate::store::domain_to_db(&local_host, local_suffix);
                            let share_required =
                                match app_configs.store.is_share_auth_required(&domain_prefix) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        error!(
                                            error = %e,
                                            domain_prefix = %domain_prefix,
                                            "share_auth query failed, denying request"
                                        );
                                        let resp = http::Response::builder()
                                            .status(503)
                                            .header("content-type", "text/plain")
                                            .body(())
                                            .unwrap();
                                        match send_response.send_response(resp, false) {
                                            Ok(mut stream) => {
                                                let _ = stream.send_data(
                                                    bytes::Bytes::from("503 Service Unavailable"),
                                                    true,
                                                );
                                            }
                                            Err(e) => {
                                                error!(error = %e, "failed to send 503 response");
                                            }
                                        }
                                        return;
                                    }
                                };

                            let share_authorized = if share_required {
                                if let Some(signer) = share_signer {
                                    match share_auth::check_share_auth(
                                        &parts,
                                        &mut send_response,
                                        signer,
                                        &local_host,
                                    ) {
                                        Ok(share_auth::ShareAuthResult::Handled) => return,
                                        Ok(share_auth::ShareAuthResult::Continue) => true,
                                        Err(err) => {
                                            error!(error = %err, "share auth middleware error");
                                            return;
                                        }
                                    }
                                } else {
                                    error!(
                                        "share_auth required but signer not configured, denying"
                                    );
                                    let resp = http::Response::builder()
                                        .status(503)
                                        .header("content-type", "text/plain")
                                        .body(())
                                        .unwrap();
                                    match send_response.send_response(resp, false) {
                                        Ok(mut stream) => {
                                            let _ = stream.send_data(
                                                bytes::Bytes::from("503 Service Unavailable"),
                                                true,
                                            );
                                        }
                                        Err(e) => {
                                            error!(error = %e, "failed to send 503 response");
                                        }
                                    }
                                    return;
                                }
                            } else {
                                false
                            };

                            let request = Request::from_parts(parts, body);
                            proxy::proxy_by_host(
                                request,
                                send_response,
                                tunnel_domain,
                                local_suffix,
                                *local_proxy_port,
                                app_configs,
                                share_authorized,
                            )
                            .await
                        }
                    };
                    if let Err(err) = result {
                        error!(error = %err, "proxy request failed");
                    }
                });
            }
        }
    }

    // Remove this connection's info on disconnect
    conns.write().retain(|c| c.conn_index != conn_index);

    Ok(())
}

/// What warp-routed TCP streams (Workers VPC, WARP clients) may reach.
///
/// The edge sends any destination the account routes to this tunnel, and a
/// loopback connection to coulson's own proxy is trusted as a local user,
/// skipping tunnel basic auth. So streams are refused unless their
/// destination is allowlisted, and never reach coulson's own listeners.
pub struct TcpForwardPolicy {
    /// `host:port` destinations, matched exactly against the requested one.
    pub allow: Vec<String>,
    /// True for ports coulson itself listens on.
    pub is_own_port: Box<dyn Fn(u16) -> bool + Send + Sync>,
}

/// Unset (e.g. CLI quick tunnels) refuses every stream.
static TCP_FORWARD_POLICY: OnceLock<TcpForwardPolicy> = OnceLock::new();

/// Install the TCP forwarding policy. Called once at daemon startup.
pub fn set_tcp_forward_policy(policy: TcpForwardPolicy) {
    let _ = TCP_FORWARD_POLICY.set(policy);
}

/// Check `dest` against the policy and resolve it. The returned addresses
/// are the ones to dial, so the check and the connection share one lookup.
async fn authorize_tcp_destination(dest: &str) -> Result<Vec<SocketAddr>, String> {
    let policy = TCP_FORWARD_POLICY
        .get()
        .ok_or("TCP forwarding is not configured")?;
    if !is_allowed_destination(&policy.allow, dest) {
        return Err("destination is not in tunnel_tcp_allow".to_string());
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(dest)
        .await
        .map_err(|err| format!("failed to resolve destination: {err}"))?
        .collect();
    if targets_own_listener(&addrs, &policy.is_own_port) {
        return Err("destination is a coulson listener".to_string());
    }
    Ok(addrs)
}

fn is_allowed_destination(allow: &[String], dest: &str) -> bool {
    allow.iter().any(|entry| entry.eq_ignore_ascii_case(dest))
}

fn targets_own_listener(addrs: &[SocketAddr], is_own_port: impl Fn(u16) -> bool) -> bool {
    addrs.iter().any(|addr| {
        (addr.ip().is_loopback() || addr.ip().is_unspecified()) && is_own_port(addr.port())
    })
}

async fn proxy_tcp_stream(
    request: Request<h2::RecvStream>,
    mut send_response: h2::server::SendResponse<bytes::Bytes>,
) -> anyhow::Result<()> {
    let (parts, recv_body) = request.into_parts();
    let dest = parts
        .uri
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            parts
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .context("no destination in TCP stream request")?;

    let addrs = match authorize_tcp_destination(&dest).await {
        Ok(addrs) => addrs,
        Err(reason) => {
            warn!(%dest, %reason, "TCP proxy: refused");
            let resp = http::Response::builder().status(403).body(()).unwrap();
            let _ = send_response.send_response(resp, true);
            return Ok(());
        }
    };

    debug!(%dest, "TCP proxy: dialing origin");

    let mut tcp_stream = match TcpStream::connect(&addrs[..]).await {
        Ok(s) => s,
        Err(err) => {
            warn!(%dest, error = %err, "TCP proxy: connect failed");
            let resp = http::Response::builder().status(502).body(()).unwrap();
            let _ = send_response.send_response(resp, true);
            anyhow::bail!("TCP proxy: failed to connect to {dest}: {err}");
        }
    };

    let response = http::Response::builder().status(200).body(()).unwrap();
    let send_stream = send_response
        .send_response(response, false)
        .context("TCP proxy: failed to send ACK")?;

    debug!(%dest, "TCP proxy: connection established, piping");

    let mut h2_stream = rpc::H2Stream::new(recv_body, send_stream);
    let _ = tokio::io::copy_bidirectional(&mut h2_stream, &mut tcp_stream).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_destination_must_be_allowlisted_exactly() {
        let allow = vec!["127.0.0.1:5432".to_string(), "DB.internal:6379".to_string()];
        assert!(is_allowed_destination(&allow, "127.0.0.1:5432"));
        assert!(is_allowed_destination(&allow, "db.internal:6379"));
        assert!(!is_allowed_destination(&allow, "127.0.0.1:5433"));
        assert!(!is_allowed_destination(&allow, "127.0.0.1"));
        assert!(!is_allowed_destination(&[], "127.0.0.1:5432"));
    }

    #[test]
    fn tcp_destination_never_reaches_own_listeners() {
        let own = |port: u16| port == 18080;
        let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(targets_own_listener(&[addr("127.0.0.1:18080")], own));
        assert!(targets_own_listener(&[addr("[::1]:18080")], own));
        assert!(targets_own_listener(&[addr("0.0.0.0:18080")], own));
        // Any resolved address counts, not just the first.
        assert!(targets_own_listener(
            &[addr("192.168.1.5:18080"), addr("127.0.0.1:18080")],
            own
        ));
        assert!(!targets_own_listener(&[addr("127.0.0.1:5432")], own));
        // A LAN address isn't trusted as loopback by the proxy.
        assert!(!targets_own_listener(&[addr("192.168.1.5:18080")], own));
    }

    /// Open a TCP stream the way the edge does (an h2 request carrying
    /// `cf-cloudflared-proxy-src`) and return the status plus, when accepted,
    /// what the destination echoes back.
    async fn edge_tcp_stream(dest: &str) -> (u16, Option<Vec<u8>>) {
        // A wrongly accepted stream to a silent listener would otherwise hang.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            edge_tcp_stream_inner(dest),
        )
        .await
        .unwrap_or_else(|_| panic!("TCP stream to {dest} did not finish"))
    }

    async fn edge_tcp_stream_inner(dest: &str) -> (u16, Option<Vec<u8>>) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut conn = server::handshake(server_io).await.unwrap();
            let (request, send_response) = conn.accept().await.unwrap().unwrap();
            assert!(matches!(detect_stream_type(&request), StreamType::Tcp));
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            proxy_tcp_stream(request, send_response).await.unwrap();
        });

        let (client, conn) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(conn);
        let mut client = client.ready().await.unwrap();
        let request = Request::builder()
            .uri(format!("http://{dest}/"))
            .header(TCP_PROXY_SRC_HEADER, "203.0.113.7:4000")
            .body(())
            .unwrap();
        let (response, mut send) = client.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        let status = response.status().as_u16();
        if status != 200 {
            return (status, None);
        }
        send.send_data(bytes::Bytes::from_static(b"ping"), true)
            .unwrap();
        let mut body = response.into_body();
        let mut echoed = Vec::new();
        while let Some(chunk) = body.data().await {
            echoed.extend_from_slice(&chunk.unwrap());
        }
        (status, Some(echoed))
    }

    #[tokio::test]
    async fn tcp_stream_is_gated_by_policy() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    sock.read_to_end(&mut buf).await.unwrap();
                    sock.write_all(&buf).await.unwrap();
                });
            }
        });
        // Stands in for coulson's own proxy port.
        let own = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let own_addr = own.local_addr().unwrap();
        let other = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other_addr = other.local_addr().unwrap();

        let own_port = own_addr.port();
        set_tcp_forward_policy(TcpForwardPolicy {
            allow: vec![echo_addr.to_string(), own_addr.to_string()],
            is_own_port: Box::new(move |port| port == own_port),
        });

        assert_eq!(
            edge_tcp_stream(&echo_addr.to_string()).await,
            (200, Some(b"ping".to_vec()))
        );
        assert_eq!(edge_tcp_stream(&other_addr.to_string()).await, (403, None));
        // Allowlisted, but coulson's own listener stays off limits.
        assert_eq!(edge_tcp_stream(&own_addr.to_string()).await, (403, None));
    }
}
