use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Context as _;
use bytes::{Buf, Bytes};
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::twoparty::VatNetwork;
use capnp_rpc::RpcSystem;
use h2::{RecvStream, SendStream};
use http::{Request, Response};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::info;

use super::{TunnelConnectionInfo, TunnelConnections, TunnelCredentials};

pub mod tunnelrpc_capnp {
    #![allow(unused_parens, dead_code, clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/tunnelrpc_capnp.rs"));
}

/// Adapter: h2 RecvStream + SendStream → AsyncRead + AsyncWrite
struct H2Stream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    recv_buf: Bytes,
}

impl H2Stream {
    fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            recv_buf: Bytes::new(),
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.recv_buf.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.recv_buf.len());
            buf.put_slice(&self.recv_buf[..len]);
            self.recv_buf.advance(len);
            return Poll::Ready(Ok(()));
        }

        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                self.recv
                    .flow_control()
                    .release_capacity(data.len())
                    .map_err(std::io::Error::other)?;
                let len = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.recv_buf = data.slice(len..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.send.reserve_capacity(buf.len());

        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let len = std::cmp::min(capacity, buf.len());
                let data = Bytes::copy_from_slice(&buf[..len]);
                self.send
                    .send_data(data, false)
                    .map_err(std::io::Error::other)?;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "h2 stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let _ = self.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

/// Handle the control stream: set up Cap'n Proto RPC, bootstrap RegistrationServer,
/// call registerConnection, and keep the stream alive.
///
/// Must be called from within a `tokio::task::LocalSet` since capnp-rpc is !Send.
pub async fn handle_control_stream(
    request: Request<RecvStream>,
    mut send_response: h2::server::SendResponse<Bytes>,
    credentials: &TunnelCredentials,
    conn_index: u8,
    conns: TunnelConnections,
) -> anyhow::Result<()> {
    let recv_stream = request.into_body();

    let response = Response::builder()
        .status(200)
        .body(())
        .context("build response")?;
    let send_stream = send_response
        .send_response(response, false)
        .context("send control stream response")?;

    let stream = H2Stream::new(recv_stream, send_stream);
    let (reader, writer) = tokio::io::split(stream);
    let reader = reader.compat();
    let writer = writer.compat_write();

    let network = VatNetwork::new(reader, writer, Side::Client, Default::default());

    let mut rpc_system = RpcSystem::new(Box::new(network), None);
    let bootstrap: tunnelrpc_capnp::registration_server::Client =
        rpc_system.bootstrap(Side::Server);

    // Spawn the RPC event loop on the current LocalSet
    let rpc_handle = tokio::task::spawn_local(rpc_system);

    // Call registerConnection
    let reg_result = register_connection(&bootstrap, credentials, conn_index, &conns).await;

    match reg_result {
        Ok(()) => {
            // Keep the RPC system alive until it exits (edge closes connection)
            let _ = rpc_handle.await;
            Ok(())
        }
        Err(e) => {
            rpc_handle.abort();
            Err(e)
        }
    }
}

async fn register_connection(
    bootstrap: &tunnelrpc_capnp::registration_server::Client,
    credentials: &TunnelCredentials,
    conn_index: u8,
    conns: &TunnelConnections,
) -> anyhow::Result<()> {
    let mut request = bootstrap.register_connection_request();
    {
        let mut params = request.get();

        let mut auth = params.reborrow().init_auth();
        auth.set_account_tag(&credentials.account_tag);
        auth.set_tunnel_secret(&credentials.secret);

        let tunnel_id_bytes = parse_tunnel_id(&credentials.tunnel_id)?;
        params.reborrow().set_tunnel_id(&tunnel_id_bytes);
        params.reborrow().set_conn_index(conn_index);

        let mut options = params.reborrow().init_options();
        let mut client_info = options.reborrow().init_client();
        client_info.set_client_id(&uuid::Uuid::new_v4().as_bytes()[..]);
        client_info.set_version(concat!("coulson/", env!("CARGO_PKG_VERSION")));
        client_info.set_arch(std::env::consts::ARCH);

        let feature_list = [
            "serialized_headers",
            "allow_remote_config",
            "support_datagram_v2",
            "management_logs",
        ];
        let mut features = client_info
            .reborrow()
            .init_features(feature_list.len() as u32);
        for (i, f) in feature_list.iter().enumerate() {
            features.set(i as u32, f);
        }
    }

    let response = request
        .send()
        .promise
        .await
        .context("registerConnection RPC failed")?;

    let conn_response = response
        .get()
        .context("read registerConnection response")?
        .get_result()
        .context("get result field")?;

    let result = conn_response.get_result();

    match result.which().context("read result union")? {
        tunnelrpc_capnp::connection_response::result::Which::ConnectionDetails(details) => {
            let details = details.context("read connection details")?;
            let location = details
                .get_location_name()
                .context("get location")?
                .to_str()
                .unwrap_or("unknown");
            let uuid_bytes = details.get_uuid().context("get uuid")?;
            let conn_uuid = if uuid_bytes.len() == 16 {
                uuid::Uuid::from_slice(uuid_bytes)
                    .map(|u| u.to_string())
                    .unwrap_or_else(|_| hex_encode(uuid_bytes))
            } else {
                hex_encode(uuid_bytes)
            };
            info!(
                location = %location,
                connection_uuid = %conn_uuid,
                "tunnel connection registered"
            );

            conns.write().push(TunnelConnectionInfo {
                location: location.to_string(),
                conn_index,
                connected_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
            });
        }
        tunnelrpc_capnp::connection_response::result::Which::Error(err) => {
            let err = err.context("read connection error")?;
            let cause = err
                .get_cause()
                .context("get cause")?
                .to_str()
                .unwrap_or("unknown");
            let should_retry = err.get_should_retry();
            let retry_after = err.get_retry_after();
            anyhow::bail!(
                "registerConnection failed: {} (retry={}, retry_after={}ns)",
                cause,
                should_retry,
                retry_after
            );
        }
    }

    Ok(())
}

fn parse_tunnel_id(id: &str) -> anyhow::Result<Vec<u8>> {
    if let Ok(uuid) = uuid::Uuid::parse_str(id) {
        return Ok(uuid.as_bytes().to_vec());
    }
    hex_decode(id).map_err(|e| anyhow::anyhow!("failed to parse tunnel ID: {}", e))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.replace('-', "");
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("hex decode: {}", e)))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
