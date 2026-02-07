// src/main.rs

mod config;
mod proxy;
mod dns;
mod chaff;
mod hardening;

use anyhow::{Context, Result};
use clap::Parser;
use std::{fs, sync::Arc};
use tracing::{error, info, warn};

use arti_client::{
    TorClient,
    TorClientConfig,
    config::CfgPath,
};

use rustls::crypto::ring;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run a minimal Tor bootstrap self-check and exit
    #[arg(long)]
    selfcheck: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // ------------------------------------------------------------
    // 0. Install crypto provider (MUST be first)
    // ------------------------------------------------------------
    ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    // ------------------------------------------------------------
    // 1. Logging (stdout only)
    // ------------------------------------------------------------
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stdout)
        .init();

    let args = Args::parse();

    // ------------------------------------------------------------
    // 2. Load configuration
    // ------------------------------------------------------------
    let cfg = config::load();

    // ------------------------------------------------------------
    // 3. Security hardening
    // ------------------------------------------------------------
    if cfg.strict_mode {
        info!("Strict zero-trust mode enabled");

        if let Err(e) = hardening::apply_protections(true) {
            error!("Security hardening failed: {e}");
            panic!("ABORT: strict mode requires hardened kernel");
        }

        if unsafe { libc::geteuid() } == 0 {
            panic!("ABORT: running as root violates zero-trust model");
        }
    } else {
        warn!("DEBUG MODE: Kernel security hardening is DISABLED");
    }

    info!("torrust zero-trust active. Mode: Embedded Arti");

    // ------------------------------------------------------------
    // 4. Prepare tmpfs-backed Tor directories
    // ------------------------------------------------------------
    fs::create_dir_all(&cfg.tor_state_dir)
        .context("Tor state directory must be writable (tmpfs)")?;

    fs::create_dir_all(&cfg.tor_cache_dir)
        .context("Tor cache directory must be writable (tmpfs)")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cfg.tor_state_dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&cfg.tor_cache_dir, fs::Permissions::from_mode(0o700))?;
    }

    // ------------------------------------------------------------
    // 5. Configure embedded Tor (arti-client 0.39)
    // ------------------------------------------------------------
    info!("Configuring in-memory Tor state (tmpfs)");

    let mut tor_cfg = TorClientConfig::builder();

    tor_cfg
        .storage()
        .state_dir(CfgPath::new(cfg.tor_state_dir.clone()))
        .cache_dir(CfgPath::new(cfg.tor_cache_dir.clone()))
        .permissions()
        .dangerously_trust_everyone();

    let tor_cfg = tor_cfg
        .build()
        .context("Failed to build TorClientConfig")?;

    // ------------------------------------------------------------
    // 6. Bootstrap Tor (NEW 0.39 API)
    // ------------------------------------------------------------
    info!("Bootstrapping embedded Tor");

    let tor_client = TorClient::builder()
        .config(tor_cfg)
        .create_bootstrapped()
        .await
        .context("Failed to bootstrap Tor")?;

    let tor_client = Arc::new(tor_client);

    // ------------------------------------------------------------
    // 7. Self-check mode (NO external traffic)
    // ------------------------------------------------------------
    if args.selfcheck {
        info!("Self-check OK: Tor successfully bootstrapped");
        std::process::exit(0);
    }

    info!("Identity shielding active. Starting services");

    // ------------------------------------------------------------
    // 8. SOCKS5 proxy
    // ------------------------------------------------------------
    {
        let tor = tor_client.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = proxy::start_socks_server(tor, cfg).await {
                error!("CRITICAL: SOCKS server crashed: {e}");
            }
        });
    }

    // ------------------------------------------------------------
    // 9. DNS proxy
    // ------------------------------------------------------------
    {
        let tor = tor_client.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = dns::start_dns_server(tor, cfg).await {
                error!("CRITICAL: DNS server crashed: {e}");
            }
        });
    }

    // ------------------------------------------------------------
    // 10. Chaff / traffic shaping (optional)
    // ------------------------------------------------------------
    if cfg.chaff_enabled {
        let tor = tor_client.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            chaff::start_background_noise(tor, cfg).await;
        });
    }

    // ------------------------------------------------------------
    // 11. Shutdown handling
    // ------------------------------------------------------------
    match signal::ctrl_c().await {
        Ok(()) => info!("Shutdown signal received"),
        Err(e) => error!("Failed to listen for shutdown signal: {e}"),
    }

    info!("Shutting down. Ephemeral memory will be wiped by kernel.");
    Ok(())
}
