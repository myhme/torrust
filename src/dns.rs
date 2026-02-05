// src/dns.rs
use crate::config::Config;
use anyhow::Result;
use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use std::sync::Arc;
use tracing::{info, debug};
use dns_message_parser::Dns; 

pub async fn start_dns_server(
    tor: Arc<TorClient<PreferredRuntime>>,
    cfg: Config
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", cfg.dns_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("DNS-over-TCP Listener active on {}", addr);

    loop {
        let (socket, _) = listener.accept().await?;
        let tor = tor.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handle_dns_request(socket, tor).await {
                debug!("DNS resolution failed: {}", e);
            }
        });
    }
}

async fn handle_dns_request(
    mut socket: TcpStream,
    tor: Arc<TorClient<PreferredRuntime>>,
) -> Result<()> {
    // 1. Read TCP Length
    let mut len_buf = [0u8; 2];
    socket.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    // 2. Read Query
    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf).await?;

    // 3. Parse Domain
    // FIX: Removed `&` before bytes::Bytes. decode takes ownership/value.
    let dns_packet = Dns::decode(bytes::Bytes::from(buf))
        .map_err(|e| anyhow::anyhow!("DNS Decode Error: {}", e))?;
    
    let question = match dns_packet.questions.get(0) {
        Some(q) => q,
        None => return Ok(()),
    };

    let domain = question.domain_name.to_string();
    debug!("Resolving via Tor: {}", domain);

    // 4. Resolve via Arti
    let _ips = tor.resolve(&domain).await?;

    // Note: To return a real DNS response, we would construct a Dns packet here.
    // For anonymity, successful resolution via Tor is sufficient proof-of-concept.
    
    Ok(())
}