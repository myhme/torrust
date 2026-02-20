// src/proxy.rs

use anyhow::{Context, Result};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener};
use tokio::time::{timeout, Duration};

use arti_client::{DataStream, StreamPrefs, TorClient};
use arti_client::isolation::IsolationToken;
use tor_rtcompat::Runtime;
use zeroize::Zeroize;

// TLS Imports
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use rustls_pemfile::{certs, private_key};

use crate::config::Config;

pub async fn start_socks_server<R: Runtime>(
    tor: Arc<TorClient<R>>,
    cfg: Config,
) -> Result<()> {
    // 1. Load TLS Certificates
    let cert_file = File::open(&cfg.tls_cert_path)
        .with_context(|| format!("Failed to open cert: {:?}", cfg.tls_cert_path))?;
    let key_file = File::open(&cfg.tls_key_path)
        .with_context(|| format!("Failed to open key: {:?}", cfg.tls_key_path))?;

    let certs: Vec<_> = certs(&mut BufReader::new(cert_file)).filter_map(Result::ok).collect();
    let key = private_key(&mut BufReader::new(key_file))?.context("Invalid private key")?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS config")?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    // 2. Bind Listener globally inside the container (isolated by docker-compose network_mode)
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], cfg.socks_port));
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind SOCKS listener")?;

    tracing::info!("SOCKS5-over-TLS proxy listening on {}", bind_addr);

    loop {
        let (socket, _) = listener.accept().await?;
        let tor = tor.clone();
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(tls_stream) => {
                    let _ = handle_socks_connection(tls_stream, tor).await;
                }
                Err(e) => tracing::debug!("TLS handshake failed: {}", e),
            }
        });
    }
}

async fn handle_socks_connection<R: Runtime, S>(
    mut client: S,
    tor: Arc<TorClient<R>>,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // HARDENING: 5-second timeout to prevent memory exhaustion
    let handshake_result = timeout(Duration::from_secs(5), async {
        let mut header = [0u8; 2];
        client.read_exact(&mut header).await?;

        if header[0] != 0x05 {
            header.zeroize();
            return Err(anyhow::anyhow!("Invalid SOCKS version"));
        }
        header.zeroize();

        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        client.read_exact(&mut methods).await?;

        if !methods.contains(&0x00) {
            methods.zeroize();
            client.write_all(&[0x05, 0xFF]).await?;
            return Err(anyhow::anyhow!("No allowed auth methods"));
        }
        methods.zeroize();
        client.write_all(&[0x05, 0x00]).await?;

        let mut req = [0u8; 4];
        client.read_exact(&mut req).await?;

        if req[0] != 0x05 || req[1] != 0x01 {
            req.zeroize();
            return Err(anyhow::anyhow!("Invalid command"));
        }
        req.zeroize();

        let (host, port) = match req[3] {
            0x01 => {
                let mut addr = [0u8; 4];
                client.read_exact(&mut addr).await?;
                let mut p = [0u8; 2];
                client.read_exact(&mut p).await?;
                let res = (IpAddr::from(addr).to_string(), u16::from_be_bytes(p));
                addr.zeroize();
                p.zeroize();
                res
            }
            0x03 => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                let mut domain_bytes = vec![0u8; len[0] as usize];
                client.read_exact(&mut domain_bytes).await?;
                let mut p = [0u8; 2];
                client.read_exact(&mut p).await?;
                
                let domain_str = String::from_utf8_lossy(&domain_bytes).into_owned();
                let port_num = u16::from_be_bytes(p);
                
                // CRITICAL HARDENING: Erase raw bytes immediately
                domain_bytes.zeroize(); 
                len.zeroize();
                p.zeroize();
                
                (domain_str, port_num)
            }
            _ => return Err(anyhow::anyhow!("Unsupported address type")),
        };

        Ok((host, port))
    }).await;

    let (mut host, port) = match handshake_result {
        Ok(Ok(res)) => res,
        _ => {
            reply_failure(&mut client).await?;
            return Ok(());
        }
    };

    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(IsolationToken::new());

    // Connect to Tor, then immediately zero out the destination domain string
    let tor_stream_result = tor.connect_with_prefs((host.as_str(), port), &prefs).await;
    host.zeroize(); // <--- ERASES TARGET METADATA FROM RAM

    let tor_stream: DataStream = match tor_stream_result {
        Ok(stream) => stream,
        Err(_) => {
            reply_failure(&mut client).await?;
            return Ok(());
        }
    };

    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    let (cr, cw) = tokio::io::split(client);
    let (tr, tw) = tokio::io::split(tor_stream);

    // Use zeroizing copy to wipe payload buffers instantly
    let _ = tokio::try_join!(
        zeroizing_copy(cr, tw),
        zeroizing_copy(tr, cw),
    );

    Ok(())
}

async fn zeroizing_copy<R, W>(mut reader: R, mut writer: W) -> Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e.into()),
        };
        writer.write_all(&buf[..n]).await?;
        buf[..n].zeroize(); // ERASE buffer immediately after transit
    }
    buf.zeroize();
    Ok(())
}

async fn reply_failure<S: AsyncWriteExt + Unpin>(stream: &mut S) -> Result<()> {
    let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
    Ok(())
}