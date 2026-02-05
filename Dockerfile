# syntax=docker/dockerfile:1.7
ARG RUST_VERSION=1.93
ARG ALPINE_VERSION=3.23
ARG APP_NAME=torrust
ARG TARGET_ARCH=aarch64-unknown-linux-musl

# === STAGE 1: BUILD ===
FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS builder
ARG APP_NAME
ARG TARGET_ARCH

RUN apk add --no-cache musl-dev gcc build-base
RUN rustup target add ${TARGET_ARCH}

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
# Cache dependencies
RUN cargo build --release --target ${TARGET_ARCH}

# Build App
COPY src ./src
RUN touch src/main.rs

# === [CHANGE 1] SIMPLIFIED BUILD FLAGS ===
# Removed "-C link-arg=-static-pie" which causes Segfaults on some ARM systems.
# We just use standard static linking now.
RUN RUSTFLAGS="-C target-feature=+crt-static -C strip=symbols" \
    cargo build --release --target ${TARGET_ARCH}

# === STAGE 2: DEBUG RUNTIME ===
# === [CHANGE 2] USE ALPINE INSTEAD OF SCRATCH ===
FROM alpine:${ALPINE_VERSION}

ARG APP_NAME
ARG TARGET_ARCH

# Install standard tools for debugging
RUN apk add --no-cache ca-certificates bash curl

# Copy the binary
COPY --from=builder /app/target/${TARGET_ARCH}/release/${APP_NAME} /torrust

# === [CHANGE 3] RUN AS ROOT FOR DEBUGGING ===
# USER 10001 

ENTRYPOINT ["/torrust"]