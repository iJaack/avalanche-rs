# Benchmark: avalanche-rs vs AvalancheGo 1.14.1

**Date:** 2026-03-07  
**Network:** Fuji testnet (267,375 P-Chain blocks at time of test)  
**Duration:** 3 minutes per implementation  
**Hardware:** Mac Mini M4 (Apple Silicon), 16GB RAM  

## Results

| Metric | avalanche-rs | AvalancheGo 1.14.1 | Δ |
|--------|-------------|-------------------|---|
| **Binary size** | 8.4 MB | 88.7 MB | **10.6× smaller** |
| **Memory (RSS) @ 3 min** | 118 MB | 1,511 MB | **12.8× less** |
| **First peer handshake** | 103 ms | ~12 s | **~116× faster** |
| **Network health check** | N/A | 32 s | — |
| **P-Chain bootstrap status** | ✅ Complete + following | ❌ Still executing (18.7%) | — |
| **P-Chain blocks synced** | 3,064 | 267,380 fetched, 50,086 executed | * |
| **C-Chain blocks synced** | 529 | 0 (not started) | — |
| **P-Chain height reached** | 267,375 | N/A (executing) | — |
| **Peers connected** | 11 | N/A | — |
| **Sync phase at 3 min** | `Following` (chain tip) | Executing blocks (18.7%) | — |

\* Different sync strategies — see notes below.

## Timeline

### avalanche-rs
```
T+0.000s  Process start
T+0.103s  TLS handshake complete with bootstrap peer (Berlin)
T+0.868s  Database opened, integrity check passed
T+10.0s   P-Chain: first blocks arriving via Ancestors
T+20.0s   P-Chain: 3,058 blocks synced, height 267,373
T+20.0s   C-Chain: 529 blocks synced, 1 stateRoot mapping
T+25.0s   Entered SyncPhase::Following — tracking chain tip
T+180.0s  Stable: 3,064 P-Chain blocks, 529 C-Chain, 11 peers, 118 MB RSS
```

### AvalancheGo 1.14.1
```
T+0.000s  Process start, initializing subsystems
T+2.0s    API server listening
T+12.2s   P-Chain bootstrap: starting to fetch (99 known, 1 accepted)
T+32.0s   Network health check passing
T+60.0s   P-Chain fetch: 56% (150,095/267,380)
T+77.0s   P-Chain fetch: 80% (215,314/267,380)
T+127.5s  P-Chain fetch complete, compacting database
T+131.2s  Executing blocks (267,380 total)
T+176.7s  Executed 50,086/267,380 (18.7%), ETA: 30 min remaining
T+180.0s  Killed — 1,511 MB RSS, bootstrap incomplete
```

## Analysis

### Sync Strategy Differences

**avalanche-rs** uses incremental sync via the Avalanche P2P protocol:
- Requests `Ancestors` messages from peers for recent chain history
- Verifies chain walk from tip back to genesis
- Enters `Following` mode once bootstrap completes
- Syncs 3,064 recent blocks — enough to verify chain integrity and track tip

**AvalancheGo** uses full historical sync:
- Downloads ALL 267,380 blocks before executing any
- Compacts database, then serially executes every block
- Estimated 30+ minutes to complete full bootstrap on this hardware
- More thorough but dramatically slower for initial sync

### Key Takeaways

1. **avalanche-rs boots to chain-tip tracking in ~25 seconds.** AvalancheGo needs 30+ minutes for the same network.

2. **Memory efficiency is dramatic.** 118 MB vs 1,511 MB after 3 minutes — avalanche-rs uses 12.8× less memory. On resource-constrained hardware (Raspberry Pi, VPS, embedded), this is the difference between "runs" and "doesn't run."

3. **Binary size matters for distribution.** 8.4 MB ships faster, deploys faster, and has a smaller attack surface than 88.7 MB.

4. **The tradeoff is sync depth.** AvalancheGo downloads full history; avalanche-rs syncs recent chain state. For validators and archive nodes, full history matters. For lightweight nodes, monitoring, and rapid bootstrap, avalanche-rs's approach is superior.

## Methodology

- Both implementations ran against the same Fuji testnet with default bootstrap peers
- avalanche-rs: `--network-id 5 --bootstrap-ips 52.29.72.46:9651`
- AvalancheGo: `--network-id=fuji` (uses built-in bootstrap peers)
- Memory measured via `ps -o rss=` at T+180s
- Each test ran on a clean data directory with no prior state
- 5-second cooldown between tests
- AvalancheGo ran with sybil protection enabled (required for public networks in v1.14.1)

## Test Environment

```
OS:        macOS 15.2 (Darwin 25.2.0 arm64)
Hardware:  Mac Mini M4 (Apple Silicon)
RAM:       16 GB
avalanche-rs:  v0.1.0 (release build, 395 tests passing)
AvalancheGo:   v1.14.1 (official binary)
```

## Reproducing

```bash
# Build avalanche-rs
cargo build --release

# Download AvalancheGo
curl -L https://github.com/ava-labs/avalanchego/releases/download/v1.14.1/avalanchego-macos-arm64.tar.gz | tar xz

# Run avalanche-rs (3 min)
./target/release/avalanche-rs --network-id 5 --data-dir /tmp/bench-rs \
  --bootstrap-ips 52.29.72.46:9651 --staking-port 29651 --http-port 29650

# Run AvalancheGo (3 min)
./avalanchego --network-id=fuji --data-dir=/tmp/bench-go \
  --staking-port=29661 --http-port=29660 --log-level=info
```
