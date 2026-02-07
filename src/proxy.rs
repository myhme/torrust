// src/proxy.rs

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

use arti_client::{TorClient, Stream};

use crate::config::Config;

/// Start a SOCKS5 proxy that forwards all traffic through Tor
pub async fn start_socks_server(
    tor: Arc<TorClient>,
    cfg: Config,
) -> Result<()> {
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], cfg.socks_port));
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind SOCKS listener")?;

    info!("SOCKS5 proxy listening on {}", bind_addr);

    loop {
        let (socket, _) = listener.accept().await?;
        let tor = tor.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_socks_connection(socket, tor).await {
                error!("SOCKS connection error: {e}");
            }
        });
    }
}

async fn handle_socks_connection(
    mut client: TcpStream,
    tor: Arc<TorClient>,
) -> Result<()> {
    // -------------------------------
    // SOCKS5 handshake (minimal)
    // -------------------------------
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        anyhow::bail!("Unsupported SOCKS version");
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    // No authentication
    client.write_all(&[0x05, 0x00]).await?;

    // -------------------------------
    // SOCKS5 request
    // -------------------------------
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;

    if req[0] != 0x05 || req[1] != 0x01 {
        anyhow::bail!("Only CONNECT supported");
    }

    let atyp = req[3];
    let target = match atyp {
        0x01 => { // IPv4
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            (
                std::net::IpAddr::from(addr).to_string(),
                u16::from_be_bytes(port),
            )
        }
        0x03 => { // Domain
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            (
                String::from_utf8(domain)?,
                u16::from_be_bytes(port),
            )
        }
        0x04 => { // IPv6
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            (
                std::net::IpAddr::from(addr).to_string(),
                u16::from_be_bytes(port),
            )
        }
        _ => anyhow::bail!("Unsupported address type"),
    };

    // -------------------------------
    // Tor connection (Arti 0.39)
    // -------------------------------
    let mut tor_stream: Stream = tor
        .connect((target.0.as_str(), target.1))
        .await
        .context("Tor connect failed")?;

    // SOCKS success response
    client.write_all(&[
        0x05, 0x00, 0x00, 0x01,
        0, 0, 0, 0,
        0, 0,
    ]).await?;

    // -------------------------------
    // Bidirectional relay
    // -------------------------------
    let (mut cr, mut cw) = client.split();
    let (mut tr, mut tw) = tokio::io::split(tor_stream);

    tokio::try_join!(
        tokio::io::copy(&mut cr, &mut tw),
        tokio::io::copy(&mut tr, &mut cw),
    )?;

    Ok(())
}
