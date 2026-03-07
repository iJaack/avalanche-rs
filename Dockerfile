# Stage 1: Build
FROM rust:1.75-slim AS builder

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libclang-dev clang llvm-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY proto/ proto/
COPY build.rs ./
COPY src/ src/
COPY benches/ benches/

RUN cargo build --release --features full && \
    strip target/release/avalanche-rs

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -m -s /bin/false avalanche

COPY --from=builder /app/target/release/avalanche-rs /usr/local/bin/avalanche-rs

RUN mkdir -p /data/avalanche-rs && chown avalanche:avalanche /data/avalanche-rs

USER avalanche
WORKDIR /data/avalanche-rs

EXPOSE 9650 9651

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -sf http://localhost:9650/health || exit 1

ENTRYPOINT ["avalanche-rs"]
CMD ["--data-dir", "/data/avalanche-rs"]
