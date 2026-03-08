# Stage 1: Build
FROM rust:1.85-slim AS builder

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
FROM alpine:3.20

RUN apk add --no-cache ca-certificates libstdc++ && \
    adduser -D -H avalanche

COPY --from=builder /app/target/release/avalanche-rs /usr/local/bin/avalanche-rs

RUN mkdir -p /data/avalanche-rs && chown -R avalanche:avalanche /data/avalanche-rs

USER avalanche
WORKDIR /data/avalanche-rs

EXPOSE 9650 9651

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD wget -qO- http://localhost:9650/health >/dev/null 2>&1 || exit 1

ENTRYPOINT ["avalanche-rs"]
CMD ["--data-dir", "/data/avalanche-rs"]
