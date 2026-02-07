// src/config.rs
//
// Configuration with NO paranoia knobs.
// Designed to match Tor Browser / Arti defaults and avoid uniqueness.

use std::env;
use std::path::PathBuf;
use dotenvy::dotenv;
use tracing::info;

#[derive(Clone, Debug)]
pub struct Config {
    // Network exposure (explicit, minimal)
    pub socks_port: u16,

    // Security posture
    pub strict_mode: bool,

    // Optional cover traffic (OFF by default)
    pub chaff_enabled: bool,

    // Tor storage (tmpfs-backed, ephemeral)
    pub tor_state_dir: PathBuf,
    pub tor_cache_dir: PathBuf,
}

pub fn load() -> Config {
    // Load .env if present (safe; ignored in container-only deployments)
    let _ = dotenv();

    // ------------------------------------------------------------
    // Network ports
    // ------------------------------------------------------------
    let socks_port = env::var("COMMON_SOCKS_PROXY_PORT")
        .unwrap_or_else(|_| "9150".to_string())
        .parse()
        .expect("Invalid SOCKS port");

    // ------------------------------------------------------------
    // Security posture
    // ------------------------------------------------------------
    let strict_mode = env::var("SECMEM_STRICT").unwrap_or_default() == "1";

    // Chaff is OPTIONAL and OFF by default.
    // Tor already pads and rotates circuits; extra traffic is usually unnecessary.
    let chaff_enabled = env::var("TORGO_ENABLE_CHAFF").unwrap_or_default() == "1";

    // ------------------------------------------------------------
    // Tor directories (explicit, no fallback magic)
    // ------------------------------------------------------------
    //
    // These MUST be:
    // - tmpfs-mounted
    // - writable by the container user
    // - non-persistent
    //
    let tor_state_dir = env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/tor/state"));

    let tor_cache_dir = env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/tor/cache"));

    let cfg = Config {
        socks_port,
        strict_mode,
        chaff_enabled,
        tor_state_dir,
        tor_cache_dir,
    };

    // IMPORTANT:
    // Do not log "paranoid", percentages, or behavioral knobs.
    // Logging those alone makes the node unique.
    info!(
        "Config loaded: SOCKS={}, Strict={}, Chaff={}",
        cfg.socks_port,
        cfg.strict_mode,
        cfg.chaff_enabled,
    );

    cfg
}
