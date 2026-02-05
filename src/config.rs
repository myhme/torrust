// src/config.rs
use std::env;
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
}

pub fn load() -> Config {
    // Attempt to load .env file, but ignore if missing (Docker usage)
    let _ = dotenv();

    let c = Config {
        socks_port: env::var("COMMON_SOCKS_PROXY_PORT")
            .unwrap_or_else(|_| "9150".to_string())
            .parse()
            .expect("Invalid SOCKS port"),
        
        dns_port: env::var("COMMON_DNS_PROXY_PORT")
            .unwrap_or_else(|_| "5353".to_string())
            .parse()
            .expect("Invalid DNS port"),

        strict_mode: env::var("SECMEM_STRICT").unwrap_or_default() == "1",
        chaff_enabled: env::var("TORGO_ENABLE_CHAFF").unwrap_or_default() == "1",
        
        paranoid_traffic_percent: env::var("TORGO_PARANOID_TRAFFIC_PERCENT")
            .unwrap_or_else(|_| "50".to_string())
            .parse()
            .unwrap_or(50),
    };

    info!("Config Loaded: SOCKS={}, DNS={}, Chaff={}, Paranoid={}%", 
        c.socks_port, c.dns_port, c.chaff_enabled, c.paranoid_traffic_percent);
    c
}