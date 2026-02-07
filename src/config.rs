// src/config.rs

use std::env;
use std::path::PathBuf;
use dotenvy::dotenv;
use tracing::info;

#[derive(Clone, Debug)]
pub struct Config {
    // Network
    pub socks_port: u16,
    pub dns_port: u16,

    // Security / privacy
    pub strict_mode: bool,
    pub chaff_enabled: bool,
    pub paranoid_traffic_percent: u8,

    // Tor storage (tmpfs-backed, ephemeral)
    pub tor_state_dir: PathBuf,
    pub tor_cache_dir: PathBuf,
}

pub fn load() -> Config {
    // Load .env if present (ignored in container usage)
    let _ = dotenv();

    let socks_port = env::var("COMMON_SOCKS_PROXY_PORT")
        .unwrap_or_else(|_| "9150".to_string())
        .parse()
        .expect("Invalid SOCKS port");

    let dns_port = env::var("COMMON_DNS_PROXY_PORT")
        .unwrap_or_else(|_| "5353".to_string())
        .parse()
        .expect("Invalid DNS port");

    let strict_mode = env::var("SECMEM_STRICT").unwrap_or_default() == "1";
    let chaff_enabled = env::var("TORGO_ENABLE_CHAFF").unwrap_or_default() == "1";

    let paranoid_traffic_percent = env::var("TORGO_PARANOID_TRAFFIC_PERCENT")
        .unwrap_or_else(|_| "50".to_string())
        .parse()
        .unwrap_or(50);

    // ------------------------------------------------------------
    // Tor directories (explicit, no fallback magic)
    // ------------------------------------------------------------
    //
    // These paths MUST be:
    // - mounted as tmpfs
    // - writable by the container user
    // - non-persistent
    //
    let tor_state_dir = env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/tor/state"));

    let tor_cache_dir = env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/tor/state"));

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
        "Config loaded: SOCKS={}, DNS={}, Strict={}, Chaff={}, Paranoid={}%",
        cfg.socks_port,
        cfg.dns_port,
        cfg.strict_mode,
        cfg.chaff_enabled,
        cfg.paranoid_traffic_percent,
    );

    cfg
}
