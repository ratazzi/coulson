use bytes::Bytes;
use h2::RecvStream;
use http::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::info;

/// Proxy an HTTP request from the Cloudflare edge to a local service.
/// For HTTP/2 transport, responses use real HTTP status codes and headers
/// (not the base64 serialized format used by the older h2mux protocol).
pub async fn proxy_to_local(
    request: Request<RecvStream>,
    mut send_response: h2::server::SendResponse<Bytes>,
    local_port: u16,
) -> anyhow::Result<()> {
    let (parts, mut body) = request.into_parts();

    let uri = format!(
        "http://127.0.0.1:{}{}",
        local_port,
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    info!(uri = %uri, method = %parts.method, "proxying request to local");

    // Build the request to local service
    let mut local_req = http::Request::builder()
        .method(parts.method.clone())
        .uri(&uri);

    // Forward relevant headers (skip CF internal headers)
    for (name, value) in &parts.headers {
        let name_str = name.as_str();
        if !name_str.starts_with("cf-cloudflared-") && name_str != "cf-ray" {
            local_req = local_req.header(name, value);
        }
    }

    // Collect body from h2 stream
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        body_bytes.extend_from_slice(&chunk);
    }

    let local_req = local_req.body(http_body_util::Full::new(Bytes::from(body_bytes)))?;

    // Send to local service
    let client = Client::builder(TokioExecutor::new()).build_http();
    let local_resp = client.request(local_req).await?;

    let (resp_parts, resp_body) = local_resp.into_parts();

    // HTTP/2 transport: send real status code and real headers directly
    let mut response = http::Response::builder().status(resp_parts.status);
    for (name, value) in &resp_parts.headers {
        response = response.header(name, value);
    }

    let response = response.body(()).unwrap();
    let mut send_stream = send_response.send_response(response, false)?;

    // Stream response body
    use http_body_util::BodyExt;
    let mut body_stream = resp_body;
    while let Some(frame) = body_stream.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            send_stream.send_data(data.clone(), false)?;
        }
    }

    // End stream
    send_stream.send_data(Bytes::new(), true)?;

    info!(status = %resp_parts.status, "proxy response sent");
    Ok(())
}
