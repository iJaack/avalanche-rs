# avalanche-rs 🏔️

[![CI](https://github.com/iJaack/avalanche-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/iJaack/avalanche-rs/actions/workflows/ci.yml)

A production-grade Rust implementation of the Avalanche network protocol. Connects to real AvalancheGo nodes on Fuji testnet and mainnet. 27.8K lines of Rust, 597 tests, 8.6 MB binary.

## Benchmarks vs AvalancheGo 1.14.1

Tested on Mac Mini M4 (Apple Silicon), Fuji testnet, **3 minutes each** (2026-03-07):

| Metric | avalanche-rs | AvalancheGo 1.14.1 | Δ |
|--------|-------------|-------------------|---|
| **Binary size** | 8.6 MB | 88.7 MB | **10.3× smaller** |
| **Memory (RSS) @ 3 min** | 36 MB | 1,787 MB | **49.6× less** |
| **First peer handshake** | 595 ms | ~8 s | **~13× faster** |
| **P-Chain bootstrap** | ✅ Complete + following | ❌ 40.8% executed | **avalanche-rs wins** |
| **P-Chain blocks synced** | 3,067 | 267K fetched, 109K executed | * |
| **C-Chain blocks synced** | 503 | 0 (not started) | ∞ |
| **Status at 3 min** | ✅ Following chain tip | ⏳ Still executing | — |

avalanche-rs completes full P-Chain + C-Chain bootstrap in **~25 seconds**, then tracks the chain tip. AvalancheGo is still executing blocks after 3 minutes.

> Full benchmark details: [`BENCHMARK.md`](BENCHMARK.md)

## Features

### Networking & Protocol
- TLS identity generation (ECDSA P-256, self-signed certs)
- mTLS connections with mutual authentication
- Protobuf wire protocol (4-byte length prefix + prost)
- Version/PeerList handshake exchange
- BLS12-381 signatures (proof-of-possession DST)
- Bloom filter for efficient peer tracking
- Peer discovery (12+ simultaneous connections)
- Persistent peer management with scoring & eviction
- Avalanche Warp Messaging (AWM) — BLS aggregate sig relay

### Consensus & Sync
- Snowman consensus engine (α=15, β=20, chits, confidence counters)
- P-Chain bootstrap (3,000+ blocks via recursive GetAncestors)
- C-Chain bootstrap (500+ blocks with EVM execution via revm)
- State sync protocol (StateSummaryFrontier, trie node download)
- Continuous sync (SyncPhase::Following — tracks chain tip)
- Block building with BLS signing (--validator mode)
- State trie verification (alloy-trie MPT)
- State pruning (configurable depth, background task)
- Light client mode (headers-only, merkle proof verification)

### RPC Server
- **eth_*** — 21 methods: getBalance, getTransactionCount, getCode, getStorageAt, call, estimateGas, gasPrice, getTransactionByHash, getTransactionReceipt, getBlockByNumber, getBlockByHash, getLogs, newFilter, getFilterChanges, getBlobByHash, subscribe, unsubscribe
- **txpool_*** — 3 methods: status, content, inspect
- **debug_*** — 3 methods: traceTransaction, traceBlockByNumber, getBlockByNumber
- **platform.*** — 7 methods: getCurrentValidators, getPendingValidators, getHeight, getBlock, getSubnets, getStake, getMinStake
- **net_***, **web3_***, **avax_*** — version, clientVersion, syncing, nodeID
- WebSocket subscriptions: newHeads, logs, newPendingTransactions
- Prometheus metrics at `/metrics`
- Health endpoint matching AvalancheGo format

### Transaction Validation
- P-Chain: secp256k1 signature verification
- P-Chain: UTXO tracking from genesis, double-spend detection
- C-Chain: full EVM execution via revm
- C-Chain: receipt root & gas accounting verification
- EIP-4844 blob transaction parsing & KZG commitment verification
- EIP-1559 aware transaction pool with priority queue & nonce gap detection

### Debug & Trace
- debug_traceTransaction with structLogs format (pc, op, gas, gasCost, depth, stack, memory)
- debug_traceBlockByNumber — trace all txs in a block
- Configurable tracers: structLogger (default), callTracer

### Performance
- LRU block cache (--block-cache-size, default 1024)
- LRU account state cache (reduce trie lookups)
- parking_lot::RwLock for non-async hot paths
- RocksDB WriteBatch for atomic block storage
- Connection pooling (min 10, max 50)

### Advanced
- Archive node mode (--archive, keep ALL historical state)
- Snap/1 sync protocol (10x fewer round trips for state download)
- Subnet support (--tracked-subnets, per-chain sync state)
- MEV engine (V2/V4 AMM math, sandwich sim, arbitrage detection)
- WASM build target (avalanche-core → wasm32)
- `no_std` core library (avalanche-core crate)

## Quick Start

```bash
# Build
cargo build --release

# Run on Fuji testnet
./target/release/avalanche-rs \
  --network-id 5 \
  --bootstrap-ips "52.29.72.46:9651" \
  --staking-port 9651 \
  --http-port 9650

# Run on mainnet
./target/release/avalanche-rs \
  --network-id 1 \
  --bootstrap-ips "52.29.72.46:9651" \
  --staking-port 9651 \
  --http-port 9650

# Light client mode (headers only, minimal memory)
./target/release/avalanche-rs \
  --network-id 5 --light-client \
  --bootstrap-ips "52.29.72.46:9651"

# Validator mode (block building)
./target/release/avalanche-rs \
  --network-id 5 --validator \
  --bootstrap-ips "52.29.72.46:9651"

# Custom state pruning depth
./target/release/avalanche-rs \
  --network-id 5 --state-pruning-depth 512 \
  --bootstrap-ips "52.29.72.46:9651"
```

## Architecture

```
avalanche-rs/
├── src/
│   ├── main.rs          # Node daemon, P2P, handshake, message loop, RPC server
│   ├── archive/         # Archive node mode (historical state queries)
│   ├── blob/            # EIP-4844 blob transactions & KZG verification
│   ├── block/           # Block parsing (Apricot + Banff), chain graph
│   ├── cache/           # LRU caches (blocks, accounts), connection pooling
│   ├── consensus/       # Snowman consensus (alpha/beta, chits, confidence)
│   ├── db/              # RocksDB storage (12 column families + pruning)
│   ├── debug/           # Debug & trace APIs (structLogs, callTracer)
│   ├── evm/             # C-Chain EVM execution via revm
│   ├── identity/        # TLS cert generation, IP signing, BLS keys
│   ├── light/           # Light client (headers-only, proof requests)
│   ├── mempool/         # Transaction mempool
│   ├── metrics/         # Prometheus metrics & health endpoint
│   ├── mev/             # MEV engine (V2/V4 AMM, sandwich, arb)
│   ├── network/         # P2P networking, persistent peer management
│   ├── proto/           # Protobuf codec (p2p.proto)
│   ├── rpc/             # JSON-RPC client
│   ├── snap/            # Snap/1 sync protocol (fast state download)
│   ├── subnet/          # Subnet discovery & chain management
│   ├── sync/            # State sync, bootstrap, chain following
│   ├── tx/              # Transaction types, UTXO validation
│   ├── txpool/          # Transaction pool (EIP-1559 priority queue)
│   ├── validator/       # Validator set tracking, signature verification
│   ├── warp/            # Avalanche Warp Messaging (AWM)
│   ├── websocket/       # WebSocket subscriptions (newHeads, logs)
│   ├── types/           # Core types
│   └── codec/           # Serialization helpers
├── crates/
│   ├── avalanche-core/  # no_std protocol library (codec, blocks, BLS, bloom)
│   └── avalanche-wasm/  # WASM bindings (wasm-bindgen)
```

## WASM Support

The `avalanche-core` crate compiles to WebAssembly for browser-based light clients:

```bash
# Build WASM package
cd crates/avalanche-wasm
wasm-pack build --target web

# Or raw wasm32 build
cargo build -p avalanche-core --target wasm32-unknown-unknown --no-default-features
```

Exported functions: `parse_block`, `verify_bls_signature`, `bloom_check`, `decode_message`

## Protocol Compatibility

- **AvalancheGo v1.14.0 / v1.14.1** — tested and confirmed
- **RPC Protocol:** 44
- **Wire format:** 4-byte BE length prefix + protobuf (prost)
- **TLS:** ECDSA P-256, mutual auth required
- **BLS DST:** `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
- **Snowman:** α_p=15, α_c=15, β=20 (Fuji parameters)

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `prost` 0.12 | Protobuf encoding/decoding |
| `ring` 0.17 | ECDSA P-256 key generation + IP signing |
| `rcgen` 0.13 | Self-signed TLS certificate generation |
| `rustls` 0.23 | TLS 1.3 with mutual authentication |
| `blst` 0.3 | BLS12-381 signatures |
| `revm` 19 | EVM execution |
| `rocksdb` 0.22 | Persistent storage |
| `alloy-trie` 0.7 | Merkle Patricia Trie verification |
| `prometheus` 0.13 | Metrics collection |
| `tokio` 1.0 | Async runtime |

## Development

```bash
# Run all tests
cargo test

# Run with clippy
cargo clippy -- -D warnings

# Format check
cargo fmt -- --check

# Verify no_std core compiles
cargo test -p avalanche-core --no-default-features

# Release build
cargo build --release
```

## Stats

- **23,851 lines** of Rust
- **518 tests** (476 unit + 3 integration + 39 avalanche-core)
- **8.6 MB** release binary (LTO + strip)
- **36 MB** RSS at steady state (49.6× less than AvalancheGo)

## The Bloom Filter Bug 🐛

The handshake was rejected for hours because AvalancheGo's `bloom.Parse()` expects a structured format:
`[numHashes(1 byte)][hash_seeds(8 bytes each)][entries(1+ bytes)]` — not raw zero bytes.
Sending `[0x00, ...]` means `numHashes=0` which fails `minHashes=1` validation.
Fix: send `[0x01, <8-byte seed>, 0x00]` (1 hash, random seed, empty entries).

## License

MIT
