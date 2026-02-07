//! chaff.rs
//!
//! Constant-rate Tor-native cover traffic.
//! Reduces idle-time correlation and traffic-shape fingerprinting.

use std::sync::Arc;
use std::time::Duration;

use arti_client::{TorClient, StreamPrefs};
use arti_client::isolation::IsolationToken;
use tor_rtcompat::Runtime;

use rand::{SeedableRng, random};
use rand::rngs::SmallRng;
use rand_distr::{Poisson, Distribution};
use rand_distr::weighted::WeightedIndex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

/// Number of concurrent cover streams
const COVER_STREAMS: usize = 3;

/// Average Poisson rate (events / second)
const AVG_EVENTS_PER_SEC: f64 = 0.4;

/// Fixed padding size (bytes)
const PAD_SIZE: usize = 1024;

/// Minimum delay to avoid tight retry loops
const MIN_DELAY_SECS: f64 = 0.25;

struct CoverTarget {
    addr: &'static str,
    weight: u8,
}

/// HTTPS-only popular onion services
static COVER_TARGETS: &[CoverTarget] = &[
    CoverTarget {
        addr: "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443",
        weight: 3,
    },
    CoverTarget {
        addr: "protonmail.com.onion:443",
        weight: 3,
    },
    CoverTarget {
        addr: "nytimes3xbfgragh.onion:443",
        weight: 2,
    },
];

/// Entry point called from main.rs
pub fn start_background_noise<R: Runtime>(tor: Arc<TorClient<R>>) {
    let isolation = IsolationToken::new();

    for _ in 0..COVER_STREAMS {
        let tor = Arc::clone(&tor);
        let isolation = isolation.clone();

        tokio::spawn(async move {
            cover_loop(tor, isolation).await;
        });
    }
}

async fn cover_loop<R: Runtime>(
    tor: Arc<TorClient<R>>,
    isolation: IsolationToken,
) {
    let poisson = Poisson::new(AVG_EVENTS_PER_SEC)
        .expect("invalid Poisson rate");

    let weights: Vec<u8> = COVER_TARGETS.iter().map(|t| t.weight).collect();
    let chooser = WeightedIndex::new(&weights)
        .expect("invalid cover target weights");

    loop {
        // ---- RNG (rand 0.9 correct, Send-safe) ----
        let mut rng = SmallRng::seed_from_u64(random::<u64>());

        let delay = poisson.sample(&mut rng).max(MIN_DELAY_SECS);
        let target = COVER_TARGETS[chooser.sample(&mut rng)].addr;

        // ---- timing ----
        sleep(Duration::from_secs_f64(delay)).await;

        let mut prefs = StreamPrefs::new();
        prefs.set_isolation(isolation.clone());

        let mut stream = match tor.connect_with_prefs(target, &prefs).await {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut buf = vec![0u8; PAD_SIZE];
        let _ = stream.write_all(&buf).await;
        let _ = stream.read(&mut buf).await;
    }
}
