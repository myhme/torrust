// src/dns.rs

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, debug};

use arti_client::{TorClient, DataStream};
use tor_rtcompat::Runtime; // Import Runtime

use crate::config::Config;

// Cloudflare DNS via Onion (Hidden Resolver)
const ONION_DNS_RESOLVER: (&str, u16) = ("dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion", 53);
const FALLBACK_DNS_RESOLVER: (&str, u16) = ("1.1.1.1", 53);

pub async fn start_dns_server<R: Runtime>(
    tor: Arc<TorClient<R>>, // Added <R>
    cfg: Config,
) -> Result<()> {
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], cfg.dns_port));
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind DNS listener")?;

    info!("DNS-over-Tor proxy listening on {}", bind_addr);

    loop {
        let (socket, _) = listener.accept().await?;
        let tor = tor.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_dns_connection(socket, tor).await {
                error!("DNS connection error: {e}");
            }
        });
    }
}

async fn handle_dns_connection<R: Runtime>(
    mut client: TcpStream,
    tor: Arc<TorClient<R>>, // Added <R>
) -> Result<()> {
    // ------------------------------------------------------------
    // 1. Read DNS Query
    // ------------------------------------------------------------
    let mut len_buf = [0u8; 2];
    client.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    let mut query = vec![0u8; len];
    client.read_exact(&mut query).await?;

    // ------------------------------------------------------------
    // 2. Connect to Upstream Resolver
    // ------------------------------------------------------------
    let mut tor_stream: DataStream = match tor.connect(ONION_DNS_RESOLVER).await {
        Ok(stream) => {
            debug!("DNS: Using Onion resolver");
            stream
        },
        Err(e) => {
            debug!("DNS: Onion resolver failed ({}), using fallback", e);
            tor.connect(FALLBACK_DNS_RESOLVER)
                .await
                .context("Tor DNS fallback connect failed")?
        }
    };

    // ------------------------------------------------------------
    // 3. Forward Query
    // ------------------------------------------------------------
    tor_stream.write_all(&len_buf).await?;
    tor_stream.write_all(&query).await?;

    // ------------------------------------------------------------
    // 4. Read Response
    // ------------------------------------------------------------
    let mut resp_len_buf = [0u8; 2];
    tor_stream.read_exact(&mut resp_len_buf).await?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

    let mut response = vec![0u8; resp_len];
    tor_stream.read_exact(&mut response).await?;

    // ------------------------------------------------------------
    // 5. Return to Client
    // ------------------------------------------------------------
    client.write_all(&resp_len_buf).await?;
    client.write_all(&response).await?;

    Ok(())
}