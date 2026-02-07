// src/proxy.rs

use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use arti_client::{TorClient, DataStream, StreamPrefs};
use arti_client::isolation::IsolationToken;
use tor_rtcompat::Runtime;

use crate::config::Config;

pub async fn start_socks_server<R: Runtime>(
    tor: Arc<TorClient<R>>,
    cfg: Config,
) -> Result<()> {
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], cfg.socks_port));
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind SOCKS listener")?;

    info!("SOCKS5 proxy listening on {}", bind_addr);

    loop {
        let (socket, _) = listener.accept().await?;
        let tor = tor.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_socks_connection(socket, tor).await {
                // Intentionally vague to avoid side channels
                error!("SOCKS connection failed: {e}");
            }
        });
    }
}

async fn handle_socks_connection<R: Runtime>(
    mut client: TcpStream,
    tor: Arc<TorClient<R>>,
) -> Result<()> {
    // ------------------------------------------------------------
    // 1. SOCKS5 greeting
    // ------------------------------------------------------------
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        // Consume minimal time & exit
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        anyhow::bail!("Invalid SOCKS version");
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    // We only support NO AUTH (0x00)
    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xFF]).await?;
        anyhow::bail!("No supported auth method");
    }

    client.write_all(&[0x05, 0x00]).await?;

    // ------------------------------------------------------------
    // 2. Request
    // ------------------------------------------------------------
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;

    if req[0] != 0x05 || req[1] != 0x01 {
        reply_failure(&mut client).await?;
        anyhow::bail!("Unsupported SOCKS command");
    }

    let (host, port) = match req[3] {
        // IPv4
        0x01 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            (IpAddr::from(addr).to_string(), u16::from_be_bytes(port))
        }
        // Domain
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            (
                String::from_utf8_lossy(&domain).into_owned(),
                u16::from_be_bytes(port),
            )
        }
        _ => {
            reply_failure(&mut client).await?;
            anyhow::bail!("Unsupported address type");
        }
    };

    // ------------------------------------------------------------
    // 3. Tor connection with isolation
    // ------------------------------------------------------------
    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(IsolationToken::new());

    let tor_stream: DataStream = match tor
        .connect_with_prefs((host.as_str(), port), &prefs)
        .await
    {
        Ok(s) => s,
        Err(_) => {
            reply_failure(&mut client).await?;
            anyhow::bail!("Tor connect failed");
        }
    };

    // ------------------------------------------------------------
    // 4. Success reply
    // ------------------------------------------------------------
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // ------------------------------------------------------------
    // 5. Bidirectional relay
    // ------------------------------------------------------------
    let (mut cr, mut cw) = client.split();
    let (mut tr, mut tw) = tokio::io::split(tor_stream);

    tokio::try_join!(
        tokio::io::copy(&mut cr, &mut tw),
        tokio::io::copy(&mut tr, &mut cw),
    )?;

    Ok(())
}

async fn reply_failure(stream: &mut TcpStream) -> Result<()> {
    // Generic failure reply (avoids leaking failure cause)
    stream
        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}
