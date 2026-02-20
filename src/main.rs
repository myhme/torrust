// src/main.rs
//
// Minimal, Tor-default lifecycle.
// Enforces zero-trust process bounds, memory locking, and environment-driven logging.

mod config;
mod proxy;
mod chaff;
mod hardening;

use anyhow::{Context, Result};
use clap::Parser;
use std::{fs, sync::Arc};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter, prelude::*};

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
    /// Exit immediately after successful startup
    #[arg(long)]
    selfcheck: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // ------------------------------------------------------------
    // Crypto provider (explicit, deterministic)
    // ------------------------------------------------------------
    ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // ------------------------------------------------------------
    // Logging (Respects RUST_LOG environment variable)
    // ------------------------------------------------------------
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).with_writer(std::io::stdout))
        .with(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let cfg = config::load();

    // ------------------------------------------------------------
    // Zero-trust process hardening
    // ------------------------------------------------------------
    if cfg.strict_mode {
        info!("Strict zero-trust mode enabled");

        if let Err(e) = hardening::apply_protections(true) {
            error!("Security hardening failed: {e}");
            panic!("ABORT: strict mode requires hardened kernel");
        }

        // Enforce non-root execution
        if unsafe { libc::geteuid() } == 0 {
            panic!("ABORT: running as root violates zero-trust model");
        }
    } else {
        warn!("DEBUG MODE: Process hardening disabled");
    }

    info!("torrust active (embedded Arti, Tor defaults)");

    // ------------------------------------------------------------
    // Filesystem setup (ephemeral only)
    // ------------------------------------------------------------
    fs::create_dir_all(&cfg.tor_state_dir)
        .context("Tor state dir not writable")?;
    fs::create_dir_all(&cfg.tor_cache_dir)
        .context("Tor cache dir not writable")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cfg.tor_state_dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&cfg.tor_cache_dir, fs::Permissions::from_mode(0o700))?;
    }

    // ------------------------------------------------------------
    // Tor configuration
    // ------------------------------------------------------------
    info!("Configuring Tor client");

    let mut tor_cfg = TorClientConfig::builder();
    tor_cfg
        .storage()
        .state_dir(CfgPath::new(cfg.tor_state_dir.to_string_lossy().into_owned()))
        .cache_dir(CfgPath::new(cfg.tor_cache_dir.to_string_lossy().into_owned()))
        .permissions()
        .dangerously_trust_everyone(); // Safe because directory is in a locked-down container tmpfs

    let tor_cfg = tor_cfg
        .build()
        .context("Failed to build Tor configuration")?;

    // ------------------------------------------------------------
    // Bootstrap Tor fully BEFORE exposing services
    // ------------------------------------------------------------
    info!("Bootstrapping Tor");

    let tor_client = TorClient::builder()
        .config(tor_cfg)
        .create_bootstrapped()
        .await
        .context("Tor bootstrap failed")?;

    let tor_client = Arc::new(tor_client);

    // ------------------------------------------------------------
    // Self-check mode (used by container healthchecks)
    // ------------------------------------------------------------
    if args.selfcheck {
        info!("Self-check OK");
        return Ok(());
    }

    info!("Tor ready. Starting network services");

    // ------------------------------------------------------------
    // SOCKS proxy (primary interface)
    // ------------------------------------------------------------
    {
        let tor = tor_client.clone();
        let cfg = cfg.clone();

        tokio::spawn(async move {
            if let Err(e) = proxy::start_socks_server(tor, cfg).await {
                error!("SOCKS server terminated: {e}");
            }
        });
    }

    // ------------------------------------------------------------
    // Optional cover traffic (independent, boring, non-unique)
    // ------------------------------------------------------------
    if cfg.chaff_enabled {
        chaff::start_background_noise(tor_client.clone());
    }

    // ------------------------------------------------------------
    // Shutdown handling
    // ------------------------------------------------------------
    match signal::ctrl_c().await {
        Ok(()) => info!("Shutdown signal received"),
        Err(e) => error!("Failed to receive shutdown signal: {e}"),
    }

    info!("Shutting down (ephemeral state discarded)");
    Ok(())
}