// src/chaff.rs
use crate::config::Config;
use anyhow::Result;
use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use rand::Rng;
use rand_distr::{Normal, Distribution};
use tracing::{info, debug};
use tokio::io::AsyncWriteExt;
use chrono::Timelike; 

pub async fn start_background_noise(
    tor: Arc<TorClient<PreferredRuntime>>,
    _cfg: Config
) {
    info!("Chaff: Active. Simulating browser traffic (Circadian/Video/Text).");

    // Explicitly type u16 to avoid type mismatch errors
    let seeds: Vec<(&str, u16)> = vec![
        ("www.bbc.com", 443),
        ("vimeo.com", 443),
        ("news.ycombinator.com", 443),
        ("github.com", 443),
    ];

    let user_agents = vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    ];

    loop {
        // 1. Circadian Rhythm Check
        let hour = chrono::Utc::now().hour();
        if hour >= 2 && hour <= 6 {
            debug!("Chaff: User sleeping (Circadian Night Mode).");
            sleep(Duration::from_secs(1800)).await;
            continue;
        }

        // 2. Pick Persona & Target (SCOPED BLOCK)
        // We create 'rng' here and calculate everything immediately.
        // 'rng' is dropped at the closing brace '}', BEFORE the await.
        let (host, port, ua, is_video) = {
            let mut rng = rand::thread_rng();
            let (h, p) = seeds[rng.gen_range(0..seeds.len())];
            let u = user_agents[rng.gen_range(0..user_agents.len())];
            (h, p, u, h.contains("vimeo"))
        };

        // 3. Connect via Tor
        // Now we can await safely because 'rng' no longer exists.
        debug!("Chaff: Visiting {} (Video: {})", host, is_video);
        match perform_visit(&tor, host, port, ua).await {
            Ok(_) => {
                // 4. Consumption Time
                // We create a NEW rng here for the delay calculation.
                let delay = {
                    let mut rng = rand::thread_rng();
                    let mean = if is_video { 120.0 } else { 30.0 };
                    let std_dev = if is_video { 60.0 } else { 10.0 };
                    let normal = Normal::new(mean, std_dev).unwrap();
                    let sample = normal.sample(&mut rng);
                    f64::max(sample, 5.0)
                };
                
                debug!("Chaff: Reading/Watching for {:.1}s", delay);
                sleep(Duration::from_secs_f64(delay)).await;
            }
            Err(e) => {
                debug!("Chaff: Visit failed: {}", e);
                sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

async fn perform_visit(
    tor: &Arc<TorClient<PreferredRuntime>>,
    host: &str,
    port: u16,
    ua: &str
) -> Result<()> {
    let mut stream = tor.connect((host, port)).await?;

    let request = format!(
        "HEAD / HTTP/1.1\r\n\
        Host: {}\r\n\
        User-Agent: {}\r\n\
        Connection: close\r\n\
        \r\n", 
        host, ua
    );

    stream.write_all(request.as_bytes()).await?;
    Ok(())
}