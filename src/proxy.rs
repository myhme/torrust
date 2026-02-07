// src/proxy.rs

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use arti_client::{TorClient, DataStream};
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
                error!("SOCKS connection error: {e}");
            }
        });
    }
}

async fn handle_socks_connection<R: Runtime>(
    mut client: TcpStream,
    tor: Arc<TorClient<R>>,
) -> Result<()> {
    // ------------------------------------------------------------
    // 1. SOCKS5 Handshake
    // ------------------------------------------------------------
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;
    if header[0] != 0x05 { anyhow::bail!("Unsupported SOCKS version"); }
    
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;
    
    // Accept Method 00 (No Auth)
    client.write_all(&[0x05, 0x00]).await?;

    // ------------------------------------------------------------
    // 2. Read Request
    // ------------------------------------------------------------
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 { 
        anyhow::bail!("Only SOCKS5 CONNECT is supported"); 
    }

    let target = match req[3] {
        0x01 => { // IPv4
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            (std::net::IpAddr::from(addr).to_string(), u16::from_be_bytes(port))
        }
        0x03 => { // Domain
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            (String::from_utf8(domain)?, u16::from_be_bytes(port))
        }
        _ => anyhow::bail!("Unsupported address type"),
    };

    // ------------------------------------------------------------
    // 3. Connect via Tor
    // ------------------------------------------------------------
    // FIX: Removed 'mut' (DataStream does not need to be mutable for split)
    let tor_stream: DataStream = tor
        .connect((target.0.as_str(), target.1))
        .await
        .context("Tor connect failed")?;

    // ------------------------------------------------------------
    // 4. Success Response
    // ------------------------------------------------------------
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // ------------------------------------------------------------
    // 5. Pipe Data
    // ------------------------------------------------------------
    let (mut cr, mut cw) = client.split();
    let (mut tr, mut tw) = tokio::io::split(tor_stream);

    tokio::try_join!(
        tokio::io::copy(&mut cr, &mut tw),
        tokio::io::copy(&mut tr, &mut cw),
    )?;

    Ok(())
}