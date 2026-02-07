// src/dns.rs

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

use arti_client::{TorClient, DataStream};
use arti_client::runtime::TokioRuntime;

use crate::config::Config;

// ------------------------------------------------------------
// DNS resolver configuration
// ------------------------------------------------------------

// Small, conservative onion resolver pool.
// Chosen ONCE at boot to avoid fingerprinting.
const ONION_DNS_RESOLVERS: &[(&str, u16)] = &[
    ("dnslb5r4i6c5w5o7.onion", 53),
    ("resolver.dnscrypt.info.onion", 53),
];

// Single clearnet fallback.
// Used ONLY if onion resolver fails.
const FALLBACK_DNS_RESOLVER: (&str, u16) = ("1.1.1.1", 53);

fn select_dns_resolver() -> (&'static str, u16) {
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let idx = rng.gen_range(0..ONION_DNS_RESOLVERS.len());
    ONION_DNS_RESOLVERS[idx]
}

/// Start a TCP DNS proxy that forwards all queries over Tor
pub async fn start_dns_server(
    tor: Arc<TorClient<TokioRuntime>>,
    cfg: Config,
) -> Result<()> {
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], cfg.dns_port));
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind DNS listener")?;

    // Resolver is chosen ONCE per boot
    let resolver = select_dns_resolver();

    info!(
        "DNS proxy listening on {} (onion resolver selected)",
        bind_addr
    );

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
    tor: Arc<TorClient<TokioRuntime>>,
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
    // Forward DNS request over Tor (TCP)
    // Onion-first, single fallback
    // ------------------------------------------------------------
    let mut tor_stream: DataStream = match tor.connect(resolver).await {
        Ok(s) => s,
        Err(_) => {
            // Single, non-rotating fallback
            tor.connect(FALLBACK_DNS_RESOLVER)
                .await
                .context("Tor DNS fallback connect failed")?
        }
    };

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
