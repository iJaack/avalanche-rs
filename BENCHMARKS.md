# Benchmarks: avalanche-rs vs AvalancheGo

## Test Environment
- **Machine:** Mac Mini M4 (Apple Silicon)
- **Network:** Fuji testnet (network_id=5)
- **Bootstrap:** `52.29.72.46:9651`
- **Duration:** 45 seconds per run
- **Date:** 2026-03-04

## Results — Run 1 (Phase 9: parent-chain linking)

| Metric | avalanche-rs | AvalancheGo | Delta |
|--------|-------------|-------------|-------|
| **Binary size** | 7.9 MB | 97 MB | **12x smaller** |
| **Memory (RSS)** | 71 MB | 316 MB | **4.5x less** |
| **First peer handshake** | 268ms | ~2,040ms | **7.6x faster** |
| **Bootstrap complete** | 11.5s | N/A (still initializing) | — |
| **P-Chain blocks synced** | 3,200 | 0 (not bootstrapped yet) | — |
| **Chain walk** | 3,200 blocks linked | — | — |
| **Peers connected** | 11 | 0 (still initializing) | — |

### Notes
- AvalancheGo spends ~2s just initializing (loading config, registering health checks) before attempting any connections
- avalanche-rs connects to its first peer in 268ms from startup
- AvalancheGo had 0 peers and 0 blocks after 45s — it was still in initialization phase
- avalanche-rs completed full P-Chain bootstrap (3,200 blocks) + chain walk in 11.5s

## Results — Run 2 (Height fix + parent-chain linking)

| Metric | avalanche-rs | AvalancheGo | Delta |
|--------|-------------|-------------|-------|
| **Binary size** | 7.9 MB | 97 MB | **12x smaller** |
| **Memory (RSS)** | 20 MB | 316 MB | **16x less** |
| **First peer handshake** | 196ms | ~2,040ms | **10x faster** |
| **Bootstrap complete** | 11.8s | N/A (still initializing) | — |
| **P-Chain blocks synced** | 3,202 | 0 (not bootstrapped yet) | — |
| **P-Chain tip height** | 266,978 ✅ | 266,978 | **matches** |
| **Chain walk** | 3,202 blocks linked | — | — |
| **Peers connected** | 11 | 0 (still initializing) | — |

### Fixes since Run 1
- Height extraction fixed: was reading timestamp as height (showed 1,772,655,395 instead of 266,978)
- Wire format confirmed: all blocks use parent(32) + timestamp(8) + height(8) regardless of type ID
- Memory dropped from 71MB to 20MB (debug logging removed)
