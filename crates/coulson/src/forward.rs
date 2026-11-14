use std::net::SocketAddr;
use std::os::unix::io::{FromRawFd, RawFd};

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

/// Run a TCP forwarder: accept connections on launchd-activated FDs and
/// bidirectionally copy data to the given target address.
pub async fn run_forwarder(fds: Vec<RawFd>, target: SocketAddr) -> anyhow::Result<()> {
    if fds.is_empty() {
        anyhow::bail!("no file descriptors to forward");
    }

    let mut handles = Vec::new();

    for fd in fds {
        let std_listener = unsafe {
            let listener = std::net::TcpListener::from_raw_fd(fd);
            listener.set_nonblocking(true)?;
            listener
        };
        let listener = TcpListener::from_std(std_listener)?;
        let local_addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| format!("fd={fd}"));

        info!("forwarding {local_addr} -> {target}");

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((inbound, peer)) => {
                        debug!("accepted {peer} on {local_addr}");
                        let target = target;
                        tokio::spawn(async move {
                            if let Err(e) = proxy_connection(inbound, target).await {
                                debug!("connection from {peer} ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        // Back off so a persistent error (e.g. EMFILE) doesn't spin.
                        error!("accept error on {local_addr}: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all listeners (they run forever unless cancelled)
    for h in handles {
        let _ = h.await;
    }

    Ok(())
}

async fn proxy_connection(mut inbound: TcpStream, target: SocketAddr) -> anyhow::Result<()> {
    let mut outbound = TcpStream::connect(target).await?;
    copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}
