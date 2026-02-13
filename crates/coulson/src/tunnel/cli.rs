use anyhow::{bail, Context};
use regex::Regex;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

use super::transport::TunnelRouting;
use super::{TunnelCredentials, TunnelHandle, TunnelManager};

pub async fn start_quick_tunnel_cli(
    manager: TunnelManager,
    app_id: String,
    routing: TunnelRouting,
) -> anyhow::Result<String> {
    let (local_host, local_port) = match &routing {
        TunnelRouting::FixedHost {
            local_host,
            local_proxy_port,
        } => (local_host.clone(), *local_proxy_port),
        _ => bail!("CLI quick tunnel requires FixedHost routing"),
    };

    let mut child = tokio::process::Command::new("cloudflared")
        .args([
            "tunnel",
            "--no-autoupdate",
            "--protocol",
            "http2",
            "--url",
            &format!("http://127.0.0.1:{local_port}"),
            "--http-host-header",
            &local_host,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to start cloudflared (is it installed?)")?;

    let stderr = child
        .stderr
        .take()
        .context("failed to capture cloudflared stderr")?;
    let (hostname, lines) = extract_hostname(stderr).await?;
    info!(hostname = %hostname, "quick tunnel started via cloudflared CLI");

    let aid = app_id.clone();
    let mgr = manager.clone();
    let task = tokio::spawn(async move {
        // Keep draining stderr to prevent SIGPIPE
        let mut lines = lines;
        tokio::spawn(async move {
            while let Ok(Some(_)) = lines.next_line().await {}
        });
        let status = child.wait().await;
        match status {
            Ok(s) => warn!(app_id = %aid, status = %s, "cloudflared exited"),
            Err(e) => error!(app_id = %aid, error = %e, "cloudflared wait failed"),
        }
        mgr.lock().remove(&aid);
    });

    manager.lock().insert(
        app_id,
        TunnelHandle {
            task,
            credentials: TunnelCredentials {
                tunnel_id: String::new(),
                account_tag: String::new(),
                secret: Vec::new(),
                hostname: hostname.clone(),
            },
        },
    );

    Ok(hostname)
}

type StderrLines = tokio::io::Lines<BufReader<tokio::process::ChildStderr>>;

async fn extract_hostname(
    stderr: tokio::process::ChildStderr,
) -> anyhow::Result<(String, StderrLines)> {
    let re = Regex::new(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com").unwrap();
    let reader = BufReader::new(stderr);
    let mut lines = reader.lines();

    let result = timeout(Duration::from_secs(30), async {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(m) = re.find(&line) {
                let hostname = m.as_str().strip_prefix("https://").unwrap().to_string();
                return Ok((hostname, lines));
            }
        }
        bail!("cloudflared exited without providing a tunnel URL")
    })
    .await;

    match result {
        Ok(r) => r,
        Err(_) => bail!("timed out waiting for cloudflared to provide a tunnel URL (30s)"),
    }
}
