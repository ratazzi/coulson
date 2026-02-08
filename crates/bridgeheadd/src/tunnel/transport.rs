use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use h2::server;
use http::Request;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

use super::edge;
use super::proxy;
use super::rpc;
use super::TunnelCredentials;

/// Determines how incoming HTTP requests from the tunnel are routed locally.
#[derive(Clone)]
pub enum TunnelRouting {
    /// Quick Tunnel: all requests go to a fixed local port.
    FixedPort(u16),
    /// Named Tunnel: extract app from Host header, rewrite Host, forward to Pingora.
    HostBased {
        tunnel_domain: String,
        local_suffix: String,
        local_proxy_port: u16,
    },
}

const EDGE_SNI: &str = "h2.cftunnel.com";
const UPGRADE_HEADER: &str = "cf-cloudflared-proxy-connection-upgrade";

#[derive(Debug)]
enum StreamType {
    ControlStream,
    UpdateConfiguration,
    Http,
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

/// Run a single tunnel connection to Cloudflare edge with reconnection.
pub async fn run_tunnel_connection(
    credentials: &TunnelCredentials,
    routing: TunnelRouting,
    conn_index: u8,
) -> anyhow::Result<()> {
    let tls_config = build_tls_config();

    loop {
        match try_connect(credentials, &routing, conn_index, &tls_config).await {
            Ok(()) => {
                info!("tunnel connection closed normally, reconnecting...");
            }
            Err(err) => {
                error!(error = %err, "tunnel connection error, reconnecting...");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn try_connect(
    credentials: &TunnelCredentials,
    routing: &TunnelRouting,
    conn_index: u8,
    tls_config: &Arc<ClientConfig>,
) -> anyhow::Result<()> {
    let edge_addrs = edge::discover_edge_addrs().await?;
    let edge_addr = edge_addrs
        .first()
        .ok_or_else(|| anyhow::anyhow!("no edge addresses available"))?;

    info!(edge = %edge_addr, "connecting to Cloudflare edge");

    let tls_stream = tls_connect(*edge_addr, tls_config.clone()).await?;

    let mut h2_conn = server::Builder::new()
        .max_concurrent_streams(u32::MAX)
        .initial_window_size(1 << 20) // 1MB, matching cloudflared
        .max_frame_size(1 << 20) // 1MB
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
                let handle = std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("build tokio runtime for control stream");
                    let local = tokio::task::LocalSet::new();
                    rt.block_on(local.run_until(async {
                        rpc::handle_control_stream(request, send_response, &creds, conn_index)
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
                info!("received update-configuration stream, acknowledging");
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .unwrap();
                if let Err(err) = send_response.send_response(response, true) {
                    warn!(error = %err, "failed to ack update-configuration");
                }
            }
            StreamType::Http => {
                let routing = routing.clone();
                tokio::spawn(async move {
                    let result = match &routing {
                        TunnelRouting::FixedPort(port) => {
                            proxy::proxy_to_local(request, send_response, *port).await
                        }
                        TunnelRouting::HostBased {
                            tunnel_domain,
                            local_suffix,
                            local_proxy_port,
                        } => {
                            proxy::proxy_by_host(
                                request,
                                send_response,
                                tunnel_domain,
                                local_suffix,
                                *local_proxy_port,
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

    Ok(())
}
