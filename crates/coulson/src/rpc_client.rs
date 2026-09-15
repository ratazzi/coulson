use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde_json::{json, Value};

pub struct RpcClient {
    socket_path: PathBuf,
}

impl RpcClient {
    pub fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
        }
    }

    pub fn call(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "failed to connect to {}. Is coulson running?",
                self.socket_path.display()
            )
        })?;

        stream.write_all(&request_payload(method, params)?)?;
        stream.shutdown(std::net::Shutdown::Write)?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        parse_response(&line)
    }

    /// Async IO lets callers bound the whole request, including a stalled or
    /// slowly streaming daemon response, with one deadline.
    pub async fn call_async(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let mut stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to {}. Is coulson running?",
                    self.socket_path.display()
                )
            })?;
        stream.write_all(&request_payload(method, params)?).await?;
        stream.shutdown().await?;
        let mut reader = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        parse_response(&line)
    }
}

fn request_payload(method: &str, params: Value) -> anyhow::Result<Vec<u8>> {
    let request_id = uuid::Uuid::now_v7().to_string();
    let envelope = json!({
        "request_id": request_id,
        "method": method,
        "params": params,
    });

    let mut payload = serde_json::to_string(&envelope)?;
    payload.push('\n');
    Ok(payload.into_bytes())
}

fn parse_response(line: &str) -> anyhow::Result<Value> {
    let resp: Value = serde_json::from_str(line.trim())
        .context("failed to parse response from coulson daemon")?;

    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    } else {
        let msg = resp
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        bail!("{msg}");
    }
}
