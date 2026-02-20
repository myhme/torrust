// src/config.rs

use std::env;
use std::path::PathBuf;
use dotenvy::dotenv;
use tracing::info;

#[derive(Clone, Debug)]
pub struct Config {
    pub socks_port: u16,
    pub strict_mode: bool,
    pub chaff_enabled: bool,
    pub auto_isolate_domains: bool,
    pub tor_state_dir: PathBuf,
    pub tor_cache_dir: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub tls_client_ca_path: PathBuf, // NEW: CA cert for mTLS
}

pub fn load() -> Config {
    let _ = dotenv();

    let socks_port = env::var("COMMON_SOCKS_PROXY_PORT")
        .unwrap_or_else(|_| "9150".to_string())
        .parse()
        .expect("Invalid SOCKS port");

    let strict_mode = env::var("SECMEM_STRICT").unwrap_or_default() == "1";
    let chaff_enabled = env::var("TORGO_ENABLE_CHAFF").unwrap_or_default() == "1";
    let auto_isolate_domains = env::var("AUTO_ISOLATE_DOMAINS").unwrap_or_default() == "1";

    let tor_state_dir = env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/tor/state"));

    let tor_cache_dir = env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/tor/cache"));

    let tls_cert_path = env::var("TLS_CERT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/torrust/certs/tls.crt"));

    let tls_key_path = env::var("TLS_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/torrust/certs/tls.key"));

    // NEW: Load the CA cert path
    let tls_client_ca_path = env::var("TLS_CLIENT_CA_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/torrust/certs/ca.crt"));

    let cfg = Config {
        socks_port,
        strict_mode,
        chaff_enabled,
        auto_isolate_domains,
        tor_state_dir,
        tor_cache_dir,
        tls_cert_path,
        tls_key_path,
        tls_client_ca_path,
    };

    info!(
        "Config loaded: SOCKS={} (mTLS), Strict={}, Auto-Isolate={}",
        cfg.socks_port,
        cfg.strict_mode,
        cfg.auto_isolate_domains
    );

    cfg
}