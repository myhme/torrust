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
    #[arg(long)]
    selfcheck: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // ---- crypto provider ----
    ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // ---- logging ----
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stdout)
        .init();

    let args = Args::parse();
    let cfg = config::load();

    // ---- zero-trust hardening ----
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

    // ---- filesystem hardening ----
    fs::create_dir_all(&cfg.tor_state_dir)
        .context("Tor state dir writable")?;
    fs::create_dir_all(&cfg.tor_cache_dir)
        .context("Tor cache dir writable")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cfg.tor_state_dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&cfg.tor_cache_dir, fs::Permissions::from_mode(0o700))?;
    }

    // ---- Tor configuration ----
    info!("Configuring in-memory Tor state");

    let mut tor_cfg = TorClientConfig::builder();
    tor_cfg
        .storage()
        .state_dir(CfgPath::new(cfg.tor_state_dir.to_string_lossy().into_owned()))
        .cache_dir(CfgPath::new(cfg.tor_cache_dir.to_string_lossy().into_owned()))
        .permissions()
        .dangerously_trust_everyone();

    let tor_cfg = tor_cfg
        .build()
        .context("Failed to build Tor config")?;

    // ---- bootstrap Tor ----
    info!("Bootstrapping embedded Tor");

    let tor_client = TorClient::builder()
        .config(tor_cfg)
        .create_bootstrapped()
        .await
        .context("Failed to bootstrap Tor")?;

    let tor_client = Arc::new(tor_client);

    // ---- selfcheck ----
    if args.selfcheck {
        info!("Self-check OK");
        std::process::exit(0);
    }

    info!("Identity shielding active. Starting services");

    // ---- SOCKS proxy ----
    {
        let tor = tor_client.clone();
        let cfg = cfg.clone();

        tokio::spawn(async move {
            if let Err(e) = proxy::start_socks_server(tor, cfg).await {
                error!("CRITICAL: SOCKS server crashed: {e}");
            }
        });
    }

    // ---- DNS proxy ----
    {
        let tor = tor_client.clone();
        let cfg = cfg.clone();

        tokio::spawn(async move {
            if let Err(e) = dns::start_dns_server(tor, cfg).await {
                error!("CRITICAL: DNS server crashed: {e}");
            }
        });
    }

    // ---- cover traffic (chaff) ----
    if cfg.chaff_enabled {
        // IMPORTANT:
        // This is intentionally NOT async and NOT awaited.
        // It spawns its own background tasks and must be
        // behaviorally independent from user activity.
        chaff::start_background_noise(tor_client.clone());
    }

    // ---- shutdown handling ----
    match signal::ctrl_c().await {
        Ok(()) => info!("Shutdown signal received"),
        Err(e) => error!("Failed to listen for shutdown signal: {e}"),
    }

    info!("Shutting down. Ephemeral memory will be wiped by kernel.");
    Ok(())
}
