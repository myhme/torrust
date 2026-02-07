// src/chaff.rs

use rand::{seq::SliceRandom, thread_rng, Rng};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;
use tracing::info;

use arti_client::{TorClient, DataStream};

use crate::config::Config;

/// Small pool of boring, static domains.
/// These are intentionally:
/// - popular
/// - stable
/// - HTTPS only
/// - low JS / redirect complexity
///
/// The goal is NOT to mimic browsing,
/// but to generate non-distinct Tor exit traffic.
const CHAFF_DOMAINS: &[&str] = &[
    "example.com",
    "www.iana.org",
    "www.rfc-editor.org",
    "www.gnu.org",
];

/// Generate low-volume background Tor traffic ("chaff").
///
/// Properties:
/// - Disabled by default
/// - Boot-time randomness only
/// - Very low volume
/// - Wide timing jitter
/// - No retries
/// - No state
///
/// This is NOT meant to hide destinations.
/// It only reduces timing confidence slightly.
pub async fn start_background_noise(
    tor: Arc<TorClient>,
    _cfg: Config,
) {
    info!("Chaff enabled: starting background noise task");

    // ------------------------------------------------------------
    // Boot-time domain selection (stable per run)
    // ------------------------------------------------------------
    let domain = match CHAFF_DOMAINS.choose(&mut thread_rng()) {
        Some(d) => *d,
        None => return, // should never happen
    };

    let host = domain;
    let port = 443;

    loop {
        // ------------------------------------------------------------
        // Wide timing jitter (prevents periodic patterns)
        // ------------------------------------------------------------
        let delay_secs = thread_rng().gen_range(30..120);
        sleep(Duration::from_secs(delay_secs)).await;

        // ------------------------------------------------------------
        // Best-effort Tor connection
        // ------------------------------------------------------------
        let mut stream: DataStream = match tor.connect((host, port)).await {
            Ok(s) => s,
            Err(_) => continue, // chaff must never fail loudly
        };

        // ------------------------------------------------------------
        // Minimal, low-entropy HTTPS request
        // ------------------------------------------------------------
        //
        // - Single request
        // - No cookies
        // - No keep-alive
        // - No redirects followed
        //
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host
        );

        let _ = stream.write_all(request.as_bytes()).await;
        // Intentionally ignore all errors
    }
}
