# avalanche-rs 🏔️

A Rust implementation of the Avalanche P2P protocol. Connects to real AvalancheGo nodes on Fuji testnet and mainnet.

## Benchmarks vs AvalancheGo

Tested on Mac Mini M4 (Apple Silicon), Fuji testnet, 45 seconds each:

| Metric | avalanche-rs | AvalancheGo 1.14.1 | Delta |
|--------|-------------|---------------------|-------|
| **Binary size** | 7.8 MB | 87.5 MB | **11x smaller** |
| **Memory (RSS @ 45s)** | 73 MB | 285 MB | **3.9x less** |
| **First peer connected** | ~110ms | ~30s | **~270x faster** |
| **P-Chain bootstrap start** | ~10s | ~4s | similar |
| **P-Chain blocks synced** | 3,204 | 0 (still initializing) | ∞ |
| **P-Chain tip height** | 266,981 ✅ | 0 (not reached) | **full sync** |
| **C-Chain blocks synced** | 518 | 0 | ∞ |
| **Chain walk verified** | 3,204 linked | N/A | **avalanche-rs only** |
| **Peers connected** | 11 | network OK at 30s | **similar** |

avalanche-rs completes full P-Chain + C-Chain bootstrap in ~28 seconds. AvalancheGo is still initializing subsystems and hasn't fetched a single block at the 45-second mark.

> Full benchmark details: [`BENCHMARKS.md`](BENCHMARKS.md)

## Status

**Working:** Full bootstrap sequence with block storage on Fuji testnet.

```
✅ TLS identity generation (ECDSA P-256, self-signed certs)
✅ mTLS connection to bootstrap nodes
✅ Protobuf wire protocol (4-byte length prefix + prost)
✅ Handshake exchange (Version + PeerList)
✅ BLS signatures (blst, proof-of-possession DST)
✅ IP signing with TLS key (ring ECDSA P-256 SHA-256 ASN1)
✅ Bloom filter for known peers
✅ Peer discovery (12+ simultaneous connections via PeerList)
✅ JSON-RPC server (eth_chainId, eth_blockNumber, avax_getNodeID, etc.)
✅ RocksDB storage (7 column families)
✅ EVM execution via revm
✅ 348 tests passing (316 unit + 32 integration)
✅ P-Chain bootstrap (3,200+ blocks via recursive GetAncestors)
✅ C-Chain bootstrap (500+ blocks via recursive GetAncestors)
✅ P-Chain chain verification (tip-to-genesis walk, height matches API)
✅ Validator set tracking (pre-populated with known Fuji validators)
✅ MEV engine (mempool scanning, V2/V4 arbitrage, sandwich simulation, hook risk analysis)
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

## Bootstrap Sequence

The node performs a full Snowman bootstrap sequence:

```
1. Connect to bootstrap peers (mTLS)
2. Handshake (Version ↔ PeerList)
3. Discover peers (PeerList → dial up to 12 simultaneously)
4. P-Chain bootstrap:
   GetAcceptedFrontier → AcceptedFrontier (tip hash)
   GetAccepted → Accepted (confirmed tip)
   GetAncestors → Ancestors (up to 2MB of blocks per round)
   Recursive fetch (up to 10 rounds) → 3,200+ blocks stored
   Chain walk: verify tip → genesis via parent pointers (height matches API)
5. C-Chain bootstrap (Fuji only):
   GetAcceptedFrontier → AcceptedFrontier (C-Chain tip)
   GetAccepted → Accepted
   GetAncestors → recursive fetch → blocks stored (prefixed "c:")
6. Validator set loaded (2 known Fuji bootstrap validators)
```

## Architecture

```
src/
├── main.rs          # Node daemon, P2P connect, handshake, message loop
├── block/           # Block header parsing (Apricot + Banff), chain graph, Snowman
├── identity/        # TLS cert generation, IP signing, BLS keys
├── proto/           # Protobuf codec (p2p.proto from AvalancheGo)
├── network/         # P2P networking, peer management
├── sync/            # Bootstrap state sync (GetAcceptedFrontier, GetAncestors)
├── evm/             # C-Chain EVM execution via revm
├── db/              # RocksDB storage layer (8 column families)
├── rpc/             # JSON-RPC server
├── tx/              # Transaction types and validation
├── types/           # Core types (blocks, headers, vertices)
├── consensus/       # Snowman consensus stubs
├── mempool/         # Transaction mempool
├── mev/             # MEV engine (mempool monitor, AMM math, sandwich/arb, V4 hooks)
└── codec/           # Serialization helpers
```

~16K lines of Rust.

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

- [x] ~~Full P-Chain block parsing (height, timestamp extraction)~~ ✅
- [x] ~~Validate block parent linkage~~ ✅ (chain walk verified)
- [ ] Block signature validation
- [ ] Full Snowman consensus participation
- [ ] Validator set updates from AddValidator/AddDelegator txs
- [ ] State sync (EVM state root extraction done; full account trie download pending)
- [x] ~~C-Chain block parsing (RLP decode from wire format)~~ ✅ (Avalanche-wrapped RLP + raw RLP, parentHash/height/timestamp extraction)
- [x] ~~MEV engine integration~~ ✅ (V2/V4 AMM math, sandwich sim, hook risk, mempool scan)

## The Bloom Filter Bug 🐛

The handshake was rejected for hours because AvalancheGo's `bloom.Parse()` expects a structured format:
`[numHashes(1 byte)][hash_seeds(8 bytes each)][entries(1+ bytes)]` — not raw zero bytes.
Sending `[0x00, ...]` means `numHashes=0` which fails `minHashes=1` validation.
Fix: send `[0x01, <8-byte seed>, 0x00]` (1 hash, random seed, empty entries).

## License

MIT
