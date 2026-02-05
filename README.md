# torrust
Multiple tor circuit with rust
torrust/
├── Cargo.toml          # (The Dependencies file)
├── Dockerfile          # (The Build recipe)
└── src/
    ├── main.rs         # (Entry point)
    ├── config.rs       # (Settings loader)
    ├── proxy.rs        # (SOCKS5 Logic)
    ├── dns.rs          # (DNS Logic)
    ├── chaff.rs        # (Cover Traffic Logic)
    └── hardening.rs    # (Memory Security)