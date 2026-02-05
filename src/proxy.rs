// src/proxy.rs
use crate::config::Config;
use anyhow::Result;
use arti_client::{TorClient, IsolationToken};
use tor_rtcompat::PreferredRuntime;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use rand::Rng;
use tracing::{info, debug, warn};

pub async fn start_socks_server(
    tor: Arc<TorClient<PreferredRuntime>>,
    cfg: Config
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", cfg.socks_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("SOCKS5 Listener active on {}", addr);

    let stable_token = IsolationToken::new();

    loop {
        let (socket, _) = listener.accept().await?;
        let tor = tor.clone();
        let cfg = cfg.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, tor, cfg, stable_token).await {
                debug!("Proxy connection failed: {}", e);
            }
        });
    }
}

async fn handle_connection(
    mut client: TcpStream,
    tor: Arc<TorClient<PreferredRuntime>>,
    cfg: Config,
    stable_token: IsolationToken,
) -> Result<()> {
    // 1. SOCKS5 Handshake
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await?;
    if buf[0] != 0x05 { return Ok(()); }
    client.write_all(&[0x05, 0x00]).await?;

    // 2. Read Request
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    if head[1] != 0x01 { return Ok(()); }

    // 3. Parse Target
    let addr_type = head[3];
    let host = match addr_type {
        0x01 => { // IPv4
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        },
        0x03 => { // Domain
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        },
        _ => { warn!("Unsupported address type"); return Ok(()); }
    };
    
    let port = client.read_u16().await?;

    // 4. ISOLATION
    let mut prefs = arti_client::StreamPrefs::new();
    let is_paranoid = rand::thread_rng().gen_range(0..100) < cfg.paranoid_traffic_percent;
    
    if is_paranoid {
        debug!("Paranoid Mode: New Circuit -> {}:{}", host, port);
        // FIX: Method name is now set_isolation
        prefs.set_isolation(IsolationToken::new());
    } else {
        prefs.set_isolation(stable_token);
    }

    // 5. Connect
    let mut tor_stream = tor.connect_with_prefs((host.as_str(), port), &prefs).await?;

    // 6. Reply Success
    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await?;

    // 7. Pipe
    tokio::io::copy_bidirectional(&mut client, &mut tor_stream).await?;

    Ok(())
}