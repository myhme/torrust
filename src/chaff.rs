// src/chaff.rs

use rand::{thread_rng, Rng};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::time::sleep;
use tracing::info;

use arti_client::{TorClient, DataStream};
use arti_client::runtime::TokioRuntime;

use crate::config::Config;

// -----------------------------------------------------------------------------
// Chaff targets
// -----------------------------------------------------------------------------
//
// Very small pool of boring, globally common, low-complexity HTTPS targets.
// One target is selected ONCE per process lifetime to avoid fingerprinting.
//
const CHAFF_TARGETS: &[(&str, u16, &str)] = &[
    ("example.com", 443, "/"),
    ("example.net", 443, "/"),
    ("iana.org", 443, "/domains/reserved"),
];

fn select_chaff_target() -> (&'static str, u16, &'static str) {
    let mut rng = thread_rng();
    let idx = rng.gen_range(0..CHAFF_TARGETS.len());
    CHAFF_TARGETS[idx]
}

/// Generate low-volume background traffic over Tor.
///
/// SECURITY MODEL:
/// - Optional, disabled by default
/// - No persistence
/// - No retries
/// - No adaptation
/// - No per-request randomness (only timing jitter)
///
/// PURPOSE:
/// - Mask idle periods
/// - Reduce timing confidence
/// - NOT to imitate real browsing
pub async fn start_background_noise(
    tor: Arc<TorClient<TokioRuntime>>,
    _cfg: Config,
) {
    let (host, port, path) = select_chaff_target();

    info!("Chaff enabled: background noise active");

    loop {
        // ---------------------------------------------------------------------
        // Wide timing jitter (prevents periodic signatures)
        // ---------------------------------------------------------------------
        //
        // Chaff must be sparse and irregular.
        // Tight intervals are fingerprintable.
        //
        let delay_secs = thread_rng().gen_range(45..180);
        sleep(Duration::from_secs(delay_secs)).await;

        // ---------------------------------------------------------------------
        // Best-effort Tor connection
        // ---------------------------------------------------------------------
        //
        // Failures are ignored completely.
        // Chaff must never affect availability or shutdown.
        //
        let mut stream: DataStream = match tor.connect((host, port)).await {
            Ok(s) => s,
            Err(_) => continue,
        };

        // ---------------------------------------------------------------------
        // Minimal, static HTTP request
        // ---------------------------------------------------------------------
        //
        // - Fixed headers
        // - No User-Agent
        // - No cookies
        // - No redirects
        // - No JS
        //
        // TLS fingerprinting is handled by Tor itself.
        //
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host
        );

        // Ignore all I/O errors
        let _ = stream.write_all(request.as_bytes()).await;
    }
}
