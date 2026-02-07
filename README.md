# Torrust — Zero-Trust Tor SOCKS5 & DNS Proxy (Arti)

Torrust is a **minimal, zero-trust Tor proxy** written in Rust using **Arti (Tor in Rust)**.  
It provides:

- SOCKS5 proxy over Tor
- DNS-over-Tor (TCP)
- Optional low-volume chaff traffic
- Memory-only, ephemeral operation
- Hardened container-first deployment

Torrust is designed to be **boring, conservative, and auditable**, prioritizing **anonymity set size and fingerprint resistance** over cleverness.

---

## ✨ Features

- 🔐 **Embedded Tor (Arti)** — no external `tor` daemon
- 🧠 **Zero-trust design**
  - Non-root execution
  - Read-only root filesystem
  - No persistent state
- 🧪 **Memory-only operation**
  - Tor state & cache on `tmpfs`
  - No disk writes
- 🌐 **SOCKS5 proxy**
  - TCP only
  - No UDP leaks
- 🔎 **DNS over Tor**
  - Onion resolver preferred
  - Single clearnet fallback
  - TCP only (RFC 7766)
- 🎭 **Optional chaff traffic**
  - Low-volume
  - Non-deterministic timing
  - Designed to avoid fingerprinting
- 🐳 **Container-ready**
  - Docker & docker-compose friendly
  - AppArmor / seccomp compatible

---

## ❗ Non-Goals (Important)

Torrust **does NOT**:

- Hide browser fingerprints
- Defeat a global passive adversary
- Imitate real user browsing
- Add heavy fake traffic
- Guarantee anonymity on its own

Anonymity depends on **how you use it**.

---

## 🧠 Threat Model (High-Level)

Torrust assumes:

- The host kernel is trusted
- Tor entry guards are not globally compromised
- Exit nodes may be hostile
- Network observers may attempt timing correlation

Defenses focus on:

- Minimizing distinguishability
- Avoiding unique behavior
- Avoiding persistent identifiers
- Keeping behavior common and boring

---

## 🔒 Security & Privacy Design

### Filesystem & Memory
- Root filesystem is **read-only**
- Tor state and cache live on **`tmpfs`**
- No persistent identifiers
- All memory wiped on container exit

### DNS
- DNS queries are forwarded **over Tor**
- Primary: `.onion` DNS resolvers
- Fallback: single clearnet resolver (`1.1.1.1`)
- Resolver chosen **once per boot**
- TCP only (no UDP leaks)
- No DoH (to avoid protocol fingerprinting)

### Chaff (Optional)
- Disabled by default
- Low-volume background HTTPS requests
- Small pool of boring, static domains
- Wide timing jitter
- No attempt to mimic real browsing
- Designed to reduce timing confidence, not hide destinations

---

## 📦 Configuration

Configuration is done via environment variables.

### Network
```env
COMMON_SOCKS_PROXY_PORT=9150
COMMON_DNS_PROXY_PORT=5353
```

## 🔐 Security

```env
SECMEM_STRICT=1          # Enforce strict zero-trust checks
TORGO_ENABLE_CHAFF=0     # Enable background chaff (optional)
```

## 🪵 Logging
RUST_LOG=info
# For debugging only:
# RUST_LOG=debug,arti=debug


⚠️ Do not use debug logging in production.

 ## 🚀 Running with Docker

Example docker-compose snippet:

```
services:
  torrust:
    image: ghcr.io/myhme/torrust:latest
    user: "10001"
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - IPC_LOCK
    tmpfs:
      - /var/lib/tor/state:size=64m,uid=10001,gid=10001,mode=0700
      - /tmp:size=16m,uid=10001,gid=10001,mode=1777
    environment:
      - COMMON_SOCKS_PROXY_PORT=9150
      - COMMON_DNS_PROXY_PORT=5353
      - SECMEM_STRICT=1
      - TORGO_ENABLE_CHAFF=0
    security_opt:
      - no-new-privileges:true
```
🧪 Health Check

Torrust supports a minimal self-check:

/torrust --selfcheck


This verifies Tor bootstrap without starting proxy services.

 ## 🧰 Building from Source
cargo build --release

Static builds (musl)
RUSTFLAGS="-C target-feature=+crt-static" \
cargo build --release --target aarch64-unknown-linux-musl

## ⚠️ Operational Guidance

For best anonymity:

Use a hardened browser (e.g. Tor Browser)

Avoid logging into identifying accounts

Do not install extensions

Avoid long-lived sessions

Do not increase chaff volume

Keep behavior boring

## 🧾 Auditing Notes

Torrust intentionally avoids:

complex heuristics

adaptive behavior

dynamic configuration

protocol diversity

This makes the system easier to audit and reason about.

## 📜 License

Licensed under the MIT License.