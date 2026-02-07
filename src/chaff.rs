// src/chaff.rs

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};
use rand::Rng; // Import Rng trait

use arti_client::TorClient;
use tor_rtcompat::Runtime;

use crate::config::Config;

const CHAFF_TARGETS: &[(&str, u16)] = &[
    ("www.google.com", 80),
    ("www.cloudflare.com", 80),
    ("www.microsoft.com", 80),
    ("1.1.1.1", 80),
];

pub async fn start_background_noise<R: Runtime>(
    tor: Arc<TorClient<R>>, 
    _cfg: Config, 
) {
    info!("Chaff traffic generator active");

    // FIX: Do not create 'rng' here.
    // ThreadRng is !Send and cannot be held across .await points.

    loop {
        // 1. Generate random values immediately (don't hold the handle)
        let sleep_duration = rand::rng().random_range(120..600);
        
        debug!("Chaff: sleeping for {} seconds", sleep_duration);
        
        // The RNG handle is dropped here, so it's safe to await.
        sleep(Duration::from_secs(sleep_duration)).await;

        // 2. Pick a random target
        let target_idx = rand::rng().random_range(0..CHAFF_TARGETS.len());
        let (host, port) = CHAFF_TARGETS[target_idx];

        debug!("Chaff: initiating connection to {}:{}", host, port);

        // 3. Connect and discard
        match tor.connect((host, port)).await {
            Ok(stream) => {
                drop(stream);
                debug!("Chaff: connection success");
            }
            Err(e) => {
                debug!("Chaff: connection failed (this is fine): {}", e);
            }
        }
    }
}