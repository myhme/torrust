// src/config.rs

use std::{env, path::PathBuf};
use dotenvy::dotenv;
use tracing::info;

#[derive(Clone, Debug)]
pub struct Config {
    pub socks_port: u16,
    pub dns_port: u16,
    pub strict_mode: bool,
    pub chaff_enabled: bool,
    // "Paranoid" traffic gets a fresh circuit every request
    pub paranoid_traffic_percent: u8,

    // 🔐 Explicit Tor paths (tmpfs only)
    pub tor_state_dir: PathBuf,
    pub tor_cache_dir: PathBuf,
}

pub fn load() -> Config {
    // Load .env if present (ignored in containers)
    let _ = dotenv();

    // -------------------------------
    // Network
    // -------------------------------
    let socks_port = env::var("COMMON_SOCKS_PROXY_PORT")
        .unwrap_or_else(|_| "9150".to_string())
        .parse()
        .expect("Invalid SOCKS port");

    let dns_port = env::var("COMMON_DNS_PROXY_PORT")
        .unwrap_or_else(|_| "5353".to_string())
        .parse()
        .expect("Invalid DNS port");

    // -------------------------------
    // Security / behavior
    // -------------------------------
    let strict_mode = env::var("SECMEM_STRICT").unwrap_or_default() == "1";
    let chaff_enabled = env::var("TORGO_ENABLE_CHAFF").unwrap_or_default() == "1";

    let paranoid_traffic_percent = env::var("TORGO_PARANOID_TRAFFIC_PERCENT")
        .unwrap_or_else(|_| "50".to_string())
        .parse()
        .unwrap_or(50);

    // -------------------------------
    // 🔐 Tor state & cache (explicit)
    // -------------------------------
    //
    // Priority order:
    // 1. XDG vars (correct, standard, container-safe)
    // 2. Explicit fallback inside tmpfs
    //
    let tor_state_dir = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/tor/state"));

    let tor_cache_dir = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| tor_state_dir.clone());

    let c = Config {
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
        c.socks_port,
        c.dns_port,
        c.chaff_enabled,
        c.paranoid_traffic_percent,
        c.strict_mode
    );

    info!(
        "Tor paths: state={}, cache={}",
        c.tor_state_dir.display(),
        c.tor_cache_dir.display()
    );

    c
}
