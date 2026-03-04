# avalanche-rs 🏔️

A Rust implementation of the Avalanche P2P protocol. Connects to real AvalancheGo nodes on Fuji testnet and mainnet.

## Status

**Working:** Full P2P handshake with live Avalanche validators.

```
✅ TLS identity generation (ECDSA P-256, self-signed certs)
✅ mTLS connection to bootstrap nodes
✅ Protobuf wire protocol (4-byte length prefix + prost)
✅ Handshake exchange (Version + PeerList)
✅ BLS signatures (blst, proof-of-possession DST)
✅ IP signing with TLS key (ring ECDSA P-256 SHA-256 ASN1)
✅ Bloom filter for known peers
✅ Peer discovery (15+ validators from PeerList)
✅ JSON-RPC server (eth_chainId, eth_blockNumber, avax_getNodeID, etc.)
✅ RocksDB storage (7 column families)
✅ EVM execution via revm
✅ 273 tests passing
```

## Quick Start

```bash
# Build
cargo build --release

# Run on Fuji testnet
./target/release/avalanche-rs \
  --network-id 5 \
  --bootstrap-ips "52.29.72.46:9651,207.229.99.63:9651" \
  --staking-port 9651 \
  --http-port 9650

# Run on mainnet
./target/release/avalanche-rs \
  --network-id 1 \
  --bootstrap-ips "52.29.72.46:9651" \
  --staking-port 9651 \
  --http-port 9650
```

## Architecture

```
src/
├── main.rs          # Node daemon, P2P connect, handshake, message loop
├── identity/        # TLS cert generation, IP signing, BLS keys
├── proto/           # Protobuf codec (p2p.proto from AvalancheGo)
├── network/         # P2P networking, peer management
├── sync/            # Bootstrap state sync (GetAcceptedFrontier, GetAncestors)
├── evm/             # C-Chain EVM execution via revm
├── db/              # RocksDB storage layer
├── rpc/             # JSON-RPC server
├── tx/              # Transaction types and validation
├── types/           # Core types (blocks, headers, vertices)
├── consensus/       # Snowman consensus stubs
├── mempool/         # Transaction mempool
├── mev/             # MEV extraction analysis
└── codec/           # Serialization helpers
```

~14K lines of Rust. Zero unsafe code.

## Protocol Compatibility

- **AvalancheGo v1.14.0 / v1.14.1** — tested and confirmed
- **RPC Protocol:** 44
- **Wire format:** 4-byte BE length prefix + protobuf (prost)
- **TLS:** ECDSA P-256, mutual auth required
- **BLS DST:** `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (proof of possession)
- **Bloom filter:** `[numHashes:1][seeds:8*n][entries:1+]`

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
| `tokio` 1.0 | Async runtime |

## What's Next

- [ ] Ping/Pong keepalive in message loop
- [ ] Connect to discovered peers (PeerList → dial)
- [ ] Bootstrap: GetAcceptedFrontier → GetAccepted → GetAncestors
- [ ] Block validation + chain state
- [ ] Full Snowman consensus participation

## The Bloom Filter Bug 🐛

The handshake was rejected for hours because AvalancheGo's `bloom.Parse()` expects a structured format:
`[numHashes(1 byte)][hash_seeds(8 bytes each)][entries(1+ bytes)]` — not raw zero bytes.
Sending `[0x00, ...]` means `numHashes=0` which fails `minHashes=1` validation.
Fix: send `[0x01, <8-byte seed>, 0x00]` (1 hash, random seed, empty entries).

## License

MIT
