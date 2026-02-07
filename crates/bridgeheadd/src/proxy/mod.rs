use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::http_proxy_service;
use std::collections::HashMap;
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
            resolve_target(&routes, &host)
        };

        let Some(target) = target else {
            write_json_error(session, 404, "route_not_found").await?;
            return Ok(true);
        };

        ctx.target = Some(target);
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
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
    let body = format!(r#"{{"error":"{code}"}}"#);
    let mut resp = ResponseHeader::build(status, None)?;
    resp.insert_header("content-type", "application/json")?;
    resp.insert_header("content-length", body.len().to_string())?;
    resp.insert_header("connection", "close")?;

    session.write_response_header(Box::new(resp), false).await?;
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

fn resolve_target(routes: &HashMap<String, BackendTarget>, host: &str) -> Option<BackendTarget> {
    if let Some(hit) = routes.get(host) {
        return Some(hit.clone());
    }

    let mut parts: Vec<&str> = host.split('.').collect();
    while parts.len() > 2 {
        parts.remove(0);
        let candidate = parts.join(".");
        if let Some(hit) = routes.get(&candidate) {
            return Some(hit.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_is_normalized() {
        let host = extract_host(Some("MyApp.test:8080")).expect("host");
        assert_eq!(host, "myapp.test");
    }

    #[test]
    fn subdomain_falls_back_to_parent_host() {
        let mut routes = HashMap::new();
        routes.insert(
            "myapp.test".to_string(),
            BackendTarget::Tcp {
                host: "127.0.0.1".to_string(),
                port: 5006,
            },
        );
        let out = resolve_target(&routes, "www.myapp.test").expect("fallback");
        match out {
            BackendTarget::Tcp { host, port } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 5006);
            }
        }
    }
}
