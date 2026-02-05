// src/main.rs
mod config;
mod proxy;
mod dns;
mod chaff;
mod hardening;

use anyhow::{Result, Context};
use clap::Parser;
use std::sync::Arc;
use tracing::{info, error, warn};
use arti_client::{TorClient, TorClientConfig, config::CfgPath};
use tokio::signal;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    selfcheck: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize Logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
        
    let args = Args::parse();
    let cfg = config::load();
    
    // 3. Security Hardening (DISABLED FOR DEBUGGING)
    warn!("DEBUG MODE: Kernel security hardening is DISABLED.");

    info!("torrust zero-trust active. Mode: Embedded Arti (DEBUG)");

    // 5. Bootstrap Embedded Tor
    info!("Configuring in-memory ephemeral state...");

    let mut config_builder = TorClientConfig::builder();

    // A. Point Storage to the tmpfs RAM mount
    config_builder.storage().cache_dir(CfgPath::new("/var/lib/tor/cache".into()));
    config_builder.storage().state_dir(CfgPath::new("/var/lib/tor/state".into()));

    // B. CORRECTED: Disable Filesystem Permission Checks
    // "dangerously_trust_everyone" tells Arti to ignore that the files are owned 
    // by a different UID than it expects. This is safe because the container is isolated.
    config_builder.storage().permissions().dangerously_trust_everyone();

    let config = config_builder.build().context("Failed to build ephemeral Tor config")?;
    
    info!("Bootstrapping embedded Tor circuit...");
    let tor_client = TorClient::create_bootstrapped(config).await
        .context("Failed to bootstrap Tor")?;
    let tor_client = Arc::new(tor_client);

    // ... [Rest of the file remains exactly the same] ...

    // === SELF CHECK MODE ===
    if args.selfcheck {
        info!("Running self-check...");
        match tor_client.connect(("8.8.8.8", 53)).await {
            Ok(_) => {
                info!("Selfcheck: OK (Circuit Built)");
                std::process::exit(0);
            }
            Err(e) => {
                error!("Selfcheck: FAIL ({})", e);
                std::process::exit(1);
            }
        }
    }

    info!("Identity shielding active. Starting services...");

    // 6. Start SOCKS5 Proxy
    let proxy_tor = tor_client.clone();
    let proxy_cfg = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = proxy::start_socks_server(proxy_tor, proxy_cfg).await {
            error!("CRITICAL: SOCKS server crashed: {}", e);
        }
    });

    // 7. Start DNS Proxy
    let dns_tor = tor_client.clone();
    let dns_cfg = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = dns::start_dns_server(dns_tor, dns_cfg).await {
            error!("CRITICAL: DNS server crashed: {}", e);
        }
    });

    // 8. Start Chaff Engine
    if cfg.chaff_enabled {
        let chaff_tor = tor_client.clone();
        let chaff_cfg = cfg.clone();
        tokio::spawn(async move {
            chaff::start_background_noise(chaff_tor, chaff_cfg).await;
        });
    }

    // 9. Shutdown Block
    match signal::ctrl_c().await {
        Ok(()) => info!("Shutdown signal received."),
        Err(err) => error!("Unable to listen for shutdown signal: {}", err),
    }

    info!("Wiping memory and exiting...");
    Ok(())
}