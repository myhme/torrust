// src/proxy.rs
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

use arti_client::{DataStream, StreamPrefs, TorClient};
use arti_client::isolation::IsolationToken;
use tor_rtcompat::Runtime;
use zeroize::Zeroize;

use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use rustls_pemfile::{certs, private_key};

use crate::config::Config;

type IsolationMap = Arc<Mutex<HashMap<u64, IsolationToken>>>;

pub async fn start_socks_server<R: Runtime>(
    tor: Arc<TorClient<R>>,
    cfg: Config,
) -> Result<()> {
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

    let bind_addr = SocketAddr::from(([0, 0, 0, 0], cfg.socks_port));
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind SOCKS listener")?;

    let isolation_map: IsolationMap = Arc::new(Mutex::new(HashMap::new()));
    let default_token = IsolationToken::new();

    tracing::info!("SOCKS5-over-TLS proxy listening on {} (IsolateSOCKSAuth enabled)", bind_addr);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        
        if let Err(e) = socket.set_nodelay(true) {
            tracing::warn!("Failed to set TCP_NODELAY: {}", e);
        }
        
        let tor = tor.clone();
        let acceptor = tls_acceptor.clone();
        let iso_map = isolation_map.clone();
        let def_token = default_token.clone();
        let auto_isolate = cfg.auto_isolate_domains; // Capture the config flag

        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(tls_stream) => {
                    let _ = handle_socks_connection(tls_stream, tor, iso_map, def_token, auto_isolate).await;
                }
                Err(e) => tracing::warn!("TLS handshake failed from {}: {}", peer_addr, e),
            }
        });
    }
}

async fn handle_socks_connection<R: Runtime, S>(
    mut client: S,
    tor: Arc<TorClient<R>>,
    isolation_map: IsolationMap,
    default_token: IsolationToken,
    auto_isolate: bool, // NEW: Receive the toggle flag
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let handshake_result = timeout(Duration::from_secs(10), async {
        let mut header = [0u8; 2];
        client.read_exact(&mut header).await.context("Failed to read SOCKS header")?;

        if header[0] != 0x05 {
            header.zeroize();
            return Err(anyhow::anyhow!("Invalid SOCKS version"));
        }
        
        let nmethods = header[1] as usize;
        header.zeroize(); 

        let mut methods = vec![0u8; nmethods];
        client.read_exact(&mut methods).await.context("Failed to read SOCKS methods")?;

        let mut auth_method = 0xFF;
        
        if methods.contains(&0x02) {
            auth_method = 0x02; 
        } 
        else if methods.contains(&0x00) {
            auth_method = 0x00;
        }

        if auth_method == 0xFF {
            methods.zeroize();
            let _ = client.write_all(&[0x05, 0xFF]).await;
            let _ = client.flush().await; 
            return Err(anyhow::anyhow!("No allowed auth methods"));
        }
        methods.zeroize();
        
        client.write_all(&[0x05, auth_method]).await?;
        client.flush().await?; 

        let mut cred_hash: Option<u64> = None;

        if auth_method == 0x02 {
            let mut auth_ver = [0u8; 2];
            client.read_exact(&mut auth_ver).await.context("Failed to read Auth VER/ULEN")?;
            
            let ulen = auth_ver[1] as usize;
            let mut uname = vec![0u8; ulen];
            client.read_exact(&mut uname).await.context("Failed to read Username")?;
            
            let mut plen_buf = [0u8; 1];
            client.read_exact(&mut plen_buf).await.context("Failed to read PLEN")?;
            
            let plen = plen_buf[0] as usize;
            let mut passwd = vec![0u8; plen];
            client.read_exact(&mut passwd).await.context("Failed to read Password")?;

            let mut hasher = DefaultHasher::new();
            uname.hash(&mut hasher);
            passwd.hash(&mut hasher);
            cred_hash = Some(hasher.finish());

            auth_ver.zeroize();
            uname.zeroize();
            plen_buf.zeroize();
            passwd.zeroize();

            client.write_all(&[0x01, 0x00]).await?;
            client.flush().await?;
        }

        let mut req = [0u8; 4];
        client.read_exact(&mut req).await.context("Failed to read SOCKS connect request")?;

        if req[0] != 0x05 || req[1] != 0x01 {
            req.zeroize();
            return Err(anyhow::anyhow!("Invalid SOCKS command"));
        }
        
        let addr_type = req[3];
        req.zeroize(); 

        let (host, port) = match addr_type {
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
                
                domain_bytes.zeroize(); 
                len.zeroize();
                p.zeroize();
                
                (domain_str, port_num)
            }
            _ => return Err(anyhow::anyhow!("Unsupported SOCKS address type")),
        };

        Ok((host, port, cred_hash))
    }).await;

    let (mut host, port, cred_hash) = match handshake_result {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => {
            tracing::warn!("SOCKS Error: {:#}", e);
            let _ = reply_failure(&mut client).await;
            return Ok(());
        }
        Err(_) => {
            tracing::warn!("SOCKS Handshake Timeout");
            let _ = reply_failure(&mut client).await;
            return Ok(());
        }
    };

    let stream_token = match cred_hash {
        Some(hash) => {
            // SOCKS Auth provided: Isolate based on the provided credentials
            let mut map = isolation_map.lock().unwrap();
            if map.len() > 1000 {
                map.clear();
            }
            map.entry(hash).or_insert_with(IsolationToken::new).clone()
        }
        None => {
            // No SOCKS Auth provided
            if auto_isolate {
                // Feature ON: Isolate based on the target domain
                let mut hasher = DefaultHasher::new();
                host.hash(&mut hasher);
                let host_hash = hasher.finish();
                
                let mut map = isolation_map.lock().unwrap();
                if map.len() > 1000 {
                    map.clear();
                }
                map.entry(host_hash).or_insert_with(IsolationToken::new).clone()
            } else {
                // Feature OFF: Route through the default shared circuit
                default_token
            }
        }
    };

    tracing::debug!("Routing {}:{} through Tor...", host, port);

    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(stream_token);

    let tor_stream_result = tor.connect_with_prefs((host.as_str(), port), &prefs).await;
    host.zeroize(); 

    let tor_stream: DataStream = match tor_stream_result {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!("Tor failed to route to target: {}", e);
            let _ = reply_failure(&mut client).await;
            return Ok(());
        }
    };

    let _ = client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
    let _ = client.flush().await; 

    let (cr, cw) = tokio::io::split(client);
    let (tr, tw) = tokio::io::split(tor_stream);

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
        let _ = writer.write_all(&buf[..n]).await;
        let _ = writer.flush().await; 
        buf[..n].zeroize(); 
    }
    buf.zeroize();
    Ok(())
}

async fn reply_failure<S: AsyncWriteExt + Unpin>(stream: &mut S) -> Result<()> {
    let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
    let _ = stream.flush().await;
    Ok(())
}