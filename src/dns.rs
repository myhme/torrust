// src/dns.rs
//
// Intentionally minimal.
// Tor Browser does NOT expose a DNS proxy.
// DNS resolution should happen via SOCKS5 remote DNS.
//
// This module exists only to satisfy optional wiring in main.rs.
// It performs no network activity.

use anyhow::Result;
use std::sync::Arc;

use arti_client::TorClient;
use tor_rtcompat::Runtime;

use crate::config::Config;

pub async fn start_dns_server<R: Runtime>(
    _tor: Arc<TorClient<R>>,
    _cfg: Config,
) -> Result<()> {
    // No DNS proxy.
    // Applications must use SOCKS5 remote DNS (socks5h://).
    Ok(())
}
