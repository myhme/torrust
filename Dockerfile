# syntax=docker/dockerfile:1.7

# ==========================================
# Arguments (Version Control)
# ==========================================
ARG RUST_VERSION=1.93
ARG ALPINE_VERSION=3.23
ARG APP_NAME=torrust
# Target Architecture for your Oracle VPS (ARM64)
ARG TARGET_ARCH=aarch64-unknown-linux-musl

# ==========================================
# Stage 1: The Hardened Builder
# ==========================================
FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS builder

ARG APP_NAME
ARG TARGET_ARCH

# 1. Install Build Dependencies
# musl-dev: Required for static linking
# gcc/build-base: Required for compiling C dependencies of Rust crates
RUN apk add --no-cache musl-dev gcc build-base

# 2. Add the specific architecture target (ARM64 Musl)
RUN rustup target add ${TARGET_ARCH}

WORKDIR /app

# 3. Cache Dependencies (Optimization)
# We copy only the dependency manifests first to cache the build of external crates
COPY Cargo.toml Cargo.lock ./
# Create a dummy main.rs to satisfy the compiler
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (This layer is cached unless Cargo.toml changes)
RUN cargo build --release --target ${TARGET_ARCH}

# 4. Build the Actual Application
COPY src ./src
# Touch main.rs to force a rebuild of the application code
RUN touch src/main.rs

# === SECURITY HARDENING FLAGS ===
# -C relocation-model=pie:         Force Position Independent Executable (ASLR)
# -C link-arg=-static-pie:         Link as a static binary but keep randomization info
# -C link-arg=-Wl,-z,relro,-z,now: Full Read-Only Relocations (Anti-Exploit)
# -C target-feature=+crt-static:   Bundle the C-Runtime statically
RUN RUSTFLAGS="-C relocation-model=pie -C link-arg=-static-pie -C link-arg=-Wl,-z,relro,-z,now -C target-feature=+crt-static" \
    cargo build --release --target ${TARGET_ARCH}

# ==========================================
# Stage 2: The Zero Trust Runtime
# ==========================================
FROM scratch

ARG APP_NAME
ARG TARGET_ARCH

# 1. Copy SSL Certificates 
# Required for Tor to verify Directory Authorities
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# 2. Copy the Hardened Static Binary
COPY --from=builder /app/target/${TARGET_ARCH}/release/${APP_NAME} /torrust

# 3. Security: Run as unprivileged user
# UID 10001 does not exist in the host system map usually, ensuring isolation
USER 10001

# 4. Entrypoint
ENTRYPOINT ["/torrust"]