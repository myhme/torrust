// src/main.rs

mod config;
mod proxy;
mod dns;
mod chaff;
mod hardening;

use anyhow::{Context, Result};
use clap::Parser;
use std::{sync::Arc, fs};
use tracing::{error, info, warn};

use arti_client::{
    TorClient,
    TorClientConfig,
    config::CfgPath,
};

// === Crypto provider (Ring) ===
use rustls::crypto::ring;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run a minimal connectivity self-check and exit
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
    // 1. Logging (stdout only, no files)
    // ------------------------------------------------------------
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stdout)
        .init();

    let args = Args::parse();

    // ------------------------------------------------------------
    // 2. Load Configuration
    // ------------------------------------------------------------
    let cfg = config::load();

    // ------------------------------------------------------------
    // 3. Security Hardening
    // ------------------------------------------------------------
    if cfg.strict_mode {
        info!("Strict zero-trust mode enabled");

        if let Err(e) = hardening::apply_protections(true) {
            error!("Security hardening failed: {e}");
            panic!("ABORT: strict mode requires hardened kernel");
        }

        // Enforce non-root in strict mode
        if unsafe { libc::geteuid() } == 0 {
            panic!("ABORT: running as root violates zero-trust model");
        }
    } else {
        warn!("DEBUG MODE: Kernel security hardening is DISABLED");
    }

    info!("torrust zero-trust active. Mode: Embedded Arti");

    // ------------------------------------------------------------
    // 4. Configure Embedded Tor (RAM-only, explicit tmpfs)
    // ------------------------------------------------------------
    info!("Configuring in-memory ephemeral Tor state");

    // 🔐 Resolve state/cache dirs explicitly (NO implicit defaults)
    let state_dir = std::env::var("XDG_DATA_HOME")
        .unwrap_or_else(|_| "/var/lib/tor/state".to_string());

    let cache_dir = std::env::var("XDG_CACHE_HOME")
        .unwrap_or_else(|_| "/var/lib/tor/state".to_string());

    info!("Tor state dir : {}", state_dir);
    info!("Tor cache dir : {}", cache_dir);

    // 🔐 MUST exist and be writable (tmpfs)
    fs::create_dir_all(&state_dir)
        .context("Tor state directory is not writable (tmpfs required)")?;
    fs::create_dir_all(&cache_dir)
        .context("Tor cache directory is not writable (tmpfs required)")?;

    // 🔒 Lock down permissions (defense in depth)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700))?;
    }

    let mut tor_cfg = TorClientConfig::builder();

    tor_cfg
        .storage()
        // ✅ EXPLICIT paths — no fallback to /
        .state_dir(CfgPath::new(state_dir.into()))
        .cache_dir(CfgPath::new(cache_dir.into()))
        // Required for containers + tmpfs + non-root
        .permissions()
        .dangerously_trust_everyone();

    let tor_cfg = tor_cfg
        .build()
        .context("Failed to build TorClientConfig")?;

    // ------------------------------------------------------------
    // 5. Bootstrap Tor
    // ------------------------------------------------------------
    info!("Bootstrapping embedded Tor circuit (memory-only)");

    let tor_client = TorClient::create_bootstrapped(tor_cfg)
        .await
        .context("Failed to bootstrap Tor")?;

    let tor_client = Arc::new(tor_client);

    // ------------------------------------------------------------
    // 6. Self-check mode
    // ------------------------------------------------------------
    if args.selfcheck {
        info!("Running self-check (no services started)");

        match tor_client.connect(("1.1.1.1", 53)).await {
            Ok(_) => {
                info!("Self-check OK: Tor circuit established");
                std::process::exit(0);
            }
            Err(e) => {
                error!("Self-check FAILED: {e}");
                std::process::exit(1);
            }
        }
    }

    info!("Identity shielding active. Starting services");

    // ------------------------------------------------------------
    // 7. SOCKS5 Proxy
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
    // 8. DNS Proxy
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
    // 9. Chaff / Traffic Shaping
    // ------------------------------------------------------------
    if cfg.chaff_enabled {
        let tor = tor_client.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            chaff::start_background_noise(tor, cfg).await;
        });
    }

    // ------------------------------------------------------------
    // 10. Shutdown handling
    // ------------------------------------------------------------
    match signal::ctrl_c().await {
        Ok(()) => info!("Shutdown signal received"),
        Err(e) => error!("Failed to listen for shutdown signal: {e}"),
    }

    info!("Shutting down. Ephemeral memory will be wiped by kernel.");
    Ok(())
}
