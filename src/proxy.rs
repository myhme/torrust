// src/proxy.rs
//
// Minimal SOCKS5 → Tor proxy.
// Designed to behave like Tor Browser:
// - no paranoia knobs
// - no churn logic
// - per-connection isolation only
// - Tor defaults decide circuit lifetime

use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use arti_client::{TorClient, DataStream, StreamPrefs};
use arti_client::isolation::IsolationToken;
use tor_rtcompat::Runtime;

use crate::config::Config;

pub async fn start_socks_server<R: Runtime>(
    tor: Arc<TorClient<R>>,
    cfg: Config,
) -> Result<()> {
    // Bind only inside WireGuard namespace
    let bind_addr = SocketAddr::from(([10, 8, 0, 1], cfg.socks_port));
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind SOCKS listener")?;

    tracing::info!("SOCKS5 proxy listening on {}", bind_addr);

    loop {
        let (socket, _) = listener.accept().await?;
        let tor = tor.clone();

        tokio::spawn(async move {
            let _ = handle_socks_connection(socket, tor).await;
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
        // Fail quietly and uniformly
        reply_failure(&mut client).await?;
        return Ok(());
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    // Only NO AUTH supported
    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xFF]).await?;
        return Ok(());
    }

    client.write_all(&[0x05, 0x00]).await?;

    // ------------------------------------------------------------
    // 2. CONNECT request
    // ------------------------------------------------------------
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;

    if req[0] != 0x05 || req[1] != 0x01 {
        reply_failure(&mut client).await?;
        return Ok(());
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
        // Domain name
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
            return Ok(());
        }
    };

    // ------------------------------------------------------------
    // 3. Tor connection (Tor defaults + per-connection isolation)
    // ------------------------------------------------------------
    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(IsolationToken::new());

    let tor_stream: DataStream = match tor
        .connect_with_prefs((host.as_str(), port), &prefs)
        .await
    {
        Ok(stream) => stream,
        Err(_) => {
            reply_failure(&mut client).await?;
            return Ok(());
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

    let _ = tokio::try_join!(
        tokio::io::copy(&mut cr, &mut tw),
        tokio::io::copy(&mut tr, &mut cw),
    );

    Ok(())
}

async fn reply_failure(stream: &mut TcpStream) -> Result<()> {
    // Generic SOCKS failure — no reason codes, no side channels
    stream
        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}
