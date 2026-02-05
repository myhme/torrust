use anyhow::{Result, Context, bail};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, debug, error};
use arti_client::TorClient;
use crate::config::Config;

// [FIX] Use PreferredRuntime to match the runtime used in main.rs
use tor_rtcompat::PreferredRuntime;
type ArtiRuntime = PreferredRuntime;

pub async fn start_socks_server(
    tor_client: Arc<TorClient<ArtiRuntime>>, 
    config: Config
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", config.socks_port);
    let listener = TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind SOCKS5 listener on {}", addr))?;

    info!("SOCKS5 Listener active on {}", addr);

    loop {
        // Accept incoming connection
        let (stream, peer_addr) = listener.accept().await?;
        let client = tor_client.clone();
        
        tokio::spawn(async move {
            // Set a 10s timeout for the handshake to prevent stuck connections
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(10), 
                handle_socks_connection(stream, client)
            ).await;

            match result {
                Ok(Err(e)) => debug!("SOCKS error from {}: {}", peer_addr, e),
                Err(_) => debug!("SOCKS handshake timed out: {}", peer_addr),
                _ => {}
            }
        });
    }
}

async fn handle_socks_connection(
    mut stream: TcpStream,
    tor_client: Arc<TorClient<ArtiRuntime>>
) -> Result<()> {
    // =============================================================
    // PHASE 1: Authentication Negotiation
    // =============================================================
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    
    if header[0] != 0x05 {
        bail!("Invalid SOCKS version: {}", header[0]);
    }
    
    let n_methods = header[1] as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;

    // We only support "No Authentication" (0x00)
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xFF]).await?; // No acceptable methods
        bail!("Client does not support No-Auth");
    }
    // Reply: Version 5, Method 0 (No Auth)
    stream.write_all(&[0x05, 0x00]).await?;

    // =============================================================
    // PHASE 2: Request Details
    // =============================================================
    // Format: [VER, CMD, RSV, ATYP]
    let mut request_header = [0u8; 4];
    stream.read_exact(&mut request_header).await?;

    if request_header[1] != 0x01 { // CMD must be CONNECT (0x01)
        write_error(&mut stream, 0x07).await?; // Command not supported
        bail!("Unsupported command: {}", request_header[1]);
    }

    // Parse Address based on ATYP (Address Type)
    let target_addr = match request_header[3] {
        0x01 => { // IPv4 (Fixed 4 bytes)
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            std::net::Ipv4Addr::from(buf).to_string()
        },
        0x03 => { // Domain Name (Variable Length)
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            
            let mut domain_buf = vec![0u8; len];
            stream.read_exact(&mut domain_buf).await?;
            String::from_utf8(domain_buf).context("Invalid UTF-8 in domain")?
        },
        0x04 => { // IPv6 (Fixed 16 bytes)
             let mut buf = [0u8; 16];
             stream.read_exact(&mut buf).await?;
             std::net::Ipv6Addr::from(buf).to_string()
        },
        _ => {
            write_error(&mut stream, 0x08).await?; // Address type not supported
            bail!("Unknown address type: {}", request_header[3]);
        }
    };

    // Parse Port (Fixed 2 bytes, Big Endian)
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    debug!("SOCKS Proxy: Requesting connection to {}:{}", target_addr, port);

    // =============================================================
    // PHASE 3: Tor Connection
    // =============================================================
    match tor_client.connect((target_addr.as_str(), port)).await {
        Ok(tor_stream) => { // [FIX] Removed 'mut' here
            // Reply: Success (0x00)
            // BND.ADDR and BND.PORT are zeroed as we don't bind locally
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
            
            // Bidirectional Data Copy
            let (mut tr, mut tw) = tokio::io::split(tor_stream);
            let (mut sr, mut sw) = stream.split();
            
            // Run until one side closes
            let _ = tokio::join!(
                tokio::io::copy(&mut sr, &mut tw),
                tokio::io::copy(&mut tr, &mut sw)
            );
            Ok(())
        },
        Err(e) => {
            error!("Tor connect failed for {}:{}: {}", target_addr, port, e);
            write_error(&mut stream, 0x04).await?; // Host unreachable
            bail!("Tor connection failed");
        }
    }
}

// Helper to send SOCKS5 error codes
async fn write_error(stream: &mut TcpStream, code: u8) -> Result<()> {
    // [VER, REP(code), RSV, ATYP, ADDR(0), PORT(0)]
    let _ = stream.write_all(&[0x05, code, 0x00, 0x01, 0,0,0,0, 0,0]).await;
    Ok(())
}