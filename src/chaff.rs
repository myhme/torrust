//! chaff.rs
//!
//! OPTIONAL constant-rate cover traffic.
//! Designed to be BORING and NON-UNIQUE.
//!
//! Tor already provides padding and circuit rotation.
//! This should only be enabled if you fully understand the tradeoffs.

use std::sync::Arc;
use std::time::Duration;

use arti_client::{TorClient, StreamPrefs};
use arti_client::isolation::IsolationToken;
use tor_rtcompat::Runtime;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

/// Fixed interval between cover connections
/// (Long enough to avoid churn, short enough to avoid idle gaps)
const INTERVAL: Duration = Duration::from_secs(60);

/// Fixed padding size (bytes)
const PAD_SIZE: usize = 1024;

/// Single, stable, popular onion service
/// (No rotation, no weights, no randomness)
const COVER_TARGET: &str =
    "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443";

/// Entry point called from main.rs
pub fn start_background_noise<R: Runtime>(tor: Arc<TorClient<R>>) {
    tokio::spawn(async move {
        loop {
            sleep(INTERVAL).await;

            // New isolation per cover stream
            let mut prefs = StreamPrefs::new();
            prefs.set_isolation(IsolationToken::new());

            let mut stream = match tor.connect_with_prefs(COVER_TARGET, &prefs).await {
                Ok(s) => s,
                Err(_) => continue,
            };

            let mut buf = vec![0u8; PAD_SIZE];

            // Minimal, symmetric I/O
            let _ = stream.write_all(&buf).await;
            let _ = stream.read(&mut buf).await;
        }
    });
}
