use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use tracing::info;

use crate::domain::BackendTarget;
use crate::SharedState;

#[derive(Clone)]
struct BridgeProxy {
    shared: SharedState,
}

#[derive(Default)]
struct ProxyCtx {
    target: Option<BackendTarget>,
}

#[async_trait]
impl ProxyHttp for BridgeProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let host = extract_host(
            session
                .req_header()
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok()),
        );
        let Some(host) = host else {
            write_json_error(session, 400, "missing_host").await?;
            return Ok(true);
        };

        let target = {
            let routes = self.shared.routes.read();
            routes.get(&host).cloned()
        };

        let Some(target) = target else {
            write_json_error(session, 404, "route_not_found").await?;
            return Ok(true);
        };

        ctx.target = Some(target);
        Ok(false)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let Some(target) = ctx.target.take() else {
            return Error::e_explain(ErrorType::InternalError, "missing upstream target");
        };

        match target {
            BackendTarget::Tcp { host, port } => {
                let peer = Box::new(HttpPeer::new(format!("{host}:{port}"), false, host));
                Ok(peer)
            }
        }
    }
}

pub async fn run_proxy(addr: SocketAddr, state: SharedState) -> anyhow::Result<()> {
    let bind = addr.to_string();
    info!(%bind, "proxy listening");

    tokio::task::spawn_blocking(move || run_proxy_blocking(&bind, state)).await??;
    Ok(())
}

fn run_proxy_blocking(bind: &str, state: SharedState) -> anyhow::Result<()> {
    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, BridgeProxy { shared: state });
    service.add_tcp(bind);
    server.add_service(service);
    server.run_forever();
}

async fn write_json_error(session: &mut Session, status: u16, code: &str) -> Result<()> {
    let mut resp = ResponseHeader::build(status, None)?;
    resp.insert_header("content-type", "application/json")?;

    session
        .write_response_header(Box::new(resp), false)
        .await?;
    let body = format!(r#"{{"error":"{code}"}}"#);
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await?;
    Ok(())
}

fn extract_host(raw: Option<&str>) -> Option<String> {
    let raw = raw?;
    let host = raw.split(':').next()?.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_is_normalized() {
        let host = extract_host(Some("MyApp.test:8080")).expect("host");
        assert_eq!(host, "myapp.test");
    }
}
