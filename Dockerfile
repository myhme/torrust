# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.93
ARG ALPINE_VERSION=3.23
ARG APP_NAME=torrust
ARG TARGET_ARCH=aarch64-unknown-linux-musl

# ================================
# STAGE 1: BUILD (STATIC MUSL)
# ================================
FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS builder

# Re-declare ARGs for this stage
ARG APP_NAME
ARG TARGET_ARCH

# Build dependencies only
RUN apk add --no-cache \
    musl-dev \
    gcc \
    build-base

RUN rustup target add ${TARGET_ARCH}

WORKDIR /app

# ---- Dependency cache layer ----
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target ${TARGET_ARCH}

# ---- Build actual app ----
COPY src ./src

# Static, stripped, reproducible
RUN RUSTFLAGS="-C target-feature=+crt-static -C link-args=-fstack-protector-all -C strip=symbols" \
    cargo build --release --target ${TARGET_ARCH}

# ================================
# STAGE 2: RUNTIME (HARDENED)
# ================================
FROM alpine:${ALPINE_VERSION}

# Re-declare ARGs for this stage
ARG APP_NAME
ARG TARGET_ARCH

# ---- Minimal runtime deps ----
# libcap is required to set capabilities on the binary
RUN apk add --no-cache ca-certificates libcap

# ---- Create unprivileged user ----
RUN addgroup -S torrust \
 && adduser  -S -D -H -u 10001 -G torrust torrust

# ---- Pre-create Tor state layout (IMMUTABLE STRUCTURE) ----
RUN mkdir -p /var/lib/tor/state/state \
 && chown -R torrust:torrust /var/lib/tor \
 && chmod 700 /var/lib/tor/state/state

# ---- Copy binary ----
COPY --from=builder /app/target/${TARGET_ARCH}/release/${APP_NAME} /torrust

# ---- Permissions & Capabilities hardening ----
# 1. Ensure the binary is executable
# 2. Grant the binary permission to lock memory (mlockall) even for non-root users
RUN chmod 0555 /torrust \
 && setcap 'cap_ipc_lock=+ep' /torrust

# ---- Drop privileges permanently ----
# The binary now carries the "Effective" and "Permitted" IPC_LOCK capability
USER 10001

# ---- No shell, no args injection ----
ENTRYPOINT ["/torrust"]