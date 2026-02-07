// src/dns.rs

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use arti_client::{TorClient, DataStream};

use crate::config::Config;

// ------------------------------------------------------------
// DNS resolver selection (boot-time, stable)
// ------------------------------------------------------------

// Primary: Tor-friendly onion DNS resolver
// (chosen to avoid clearnet exits when possible)
const ONION_DNS_RESOLVER: (&str, u16) =
    ("dnslibertyvxk7q.onion", 53);

// Fallback: single well-known recursive resolver
// Used ONLY if onion resolver fails
const FALLBACK_DNS_RESOLVER: (&str, u16) =
    ("1.1.1.1", 53);

/// Start a DNS-over-TCP proxy that forwards all queries over Tor
pub async fn start_dns_server(
    tor: Arc<TorClient>,
    cfg: Config,
) -> Result<()> {
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], cfg.dns_port));
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind DNS listener")?;

    info!("DNS proxy listening on {}", bind_addr);

    // ------------------------------------------------------------
    // Resolver selection (once per boot)
    // ------------------------------------------------------------
    let resolver = match tor.connect(ONION_DNS_RESOLVER).await {
        Ok(_) => {
            info!("Using onion DNS resolver");
            ONION_DNS_RESOLVER
        }
        Err(_) => {
            info!("Onion resolver unavailable, using clearnet fallback");
            FALLBACK_DNS_RESOLVER
        }
    };

    loop {
        let (socket, _) = listener.accept().await?;
        let tor = tor.clone();
        let resolver = resolver;

        tokio::spawn(async move {
            if let Err(e) = handle_dns_connection(socket, tor, resolver).await {
                error!("DNS proxy error: {e}");
            }
        });
    }
}

async fn handle_dns_connection(
    mut client: TcpStream,
    tor: Arc<TorClient>,
    resolver: (&str, u16),
) -> Result<()> {
    // ------------------------------------------------------------
    // DNS-over-TCP framing (RFC 7766)
    // ------------------------------------------------------------
    let mut len_buf = [0u8; 2];
    client.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;

    if msg_len == 0 || msg_len > 4096 {
        anyhow::bail!("Invalid DNS message length");
    }

    let mut dns_msg = vec![0u8; msg_len];
    client.read_exact(&mut dns_msg).await?;

    // ------------------------------------------------------------
    // Forward DNS request over Tor
    // ------------------------------------------------------------
    let mut tor_stream: DataStream = tor
        .connect(resolver)
        .await
        .context("Tor DNS connect failed")?;

    // DNS-over-TCP framing
    tor_stream.write_all(&len_buf).await?;
    tor_stream.write_all(&dns_msg).await?;

    // ------------------------------------------------------------
    // Read DNS response
    // ------------------------------------------------------------
    let mut resp_len_buf = [0u8; 2];
    tor_stream.read_exact(&mut resp_len_buf).await?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

    if resp_len == 0 || resp_len > 4096 {
        anyhow::bail!("Invalid DNS response length");
    }

    let mut resp = vec![0u8; resp_len];
    tor_stream.read_exact(&mut resp).await?;

    // ------------------------------------------------------------
    // Return response to client
    // ------------------------------------------------------------
    client.write_all(&resp_len_buf).await?;
    client.write_all(&resp).await?;

    Ok(())
}
