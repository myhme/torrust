// src/config.rs

use std::{env, path::PathBuf};
use dotenvy::dotenv;
use tracing::info;

#[derive(Clone, Debug)]
pub struct Config {
    // Network
    pub socks_port: u16,
    pub dns_port: u16,

    // Security / behavior
    pub strict_mode: bool,
    pub chaff_enabled: bool,
    pub paranoid_traffic_percent: u8,

    // Tor paths (tmpfs only)
    pub tor_state_dir: PathBuf,
    pub tor_cache_dir: PathBuf,
}

pub fn load() -> Config {
    // Load .env if present (ignored in containers)
    let _ = dotenv();

    // ----------------------------
    // Network configuration
    // ----------------------------
    let socks_port = env::var("COMMON_SOCKS_PROXY_PORT")
        .unwrap_or_else(|_| "9150".to_string())
        .parse()
        .expect("Invalid SOCKS port");

    let dns_port = env::var("COMMON_DNS_PROXY_PORT")
        .unwrap_or_else(|_| "5353".to_string())
        .parse()
        .expect("Invalid DNS port");

    // ----------------------------
    // Security & behavior flags
    // ----------------------------
    let strict_mode = env::var("SECMEM_STRICT")
        .map(|v| v == "1")
        .unwrap_or(false);

    let chaff_enabled = env::var("TORGO_ENABLE_CHAFF")
        .map(|v| v == "1")
        .unwrap_or(false);

    let paranoid_traffic_percent = env::var("TORGO_PARANOID_TRAFFIC_PERCENT")
        .unwrap_or_else(|_| "50".to_string())
        .parse()
        .unwrap_or(50);

    // ----------------------------
    // Tor filesystem paths
    //
    // XDG is authoritative.
    // Fallbacks must still be tmpfs-safe.
    // ----------------------------
    let tor_state_dir = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/tor/state"));

    let tor_cache_dir = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| tor_state_dir.clone());

    let cfg = Config {
        socks_port,
        dns_port,
        strict_mode,
        chaff_enabled,
        paranoid_traffic_percent,
        tor_state_dir,
        tor_cache_dir,
    };

    info!(
        "Config Loaded: SOCKS={}, DNS={}, Chaff={}, Paranoid={}%, Strict={}",
        cfg.socks_port,
        cfg.dns_port,
        cfg.chaff_enabled,
        cfg.paranoid_traffic_percent,
        cfg.strict_mode
    );

    info!(
        "Tor paths: state={}, cache={}",
        cfg.tor_state_dir.display(),
        cfg.tor_cache_dir.display()
    );

    cfg
}
