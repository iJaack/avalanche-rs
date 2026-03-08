# Mainnet Sync Results — March 8, 2026

## Environment
- **Hardware:** Mac Mini M4 (Apple Silicon)
- **Binary:** avalanche-rs v0.1.0 (release build, 8.5 MB)
- **Network:** Mainnet (--network-id 1)
- **Bootstrap nodes:** 24 (synced from AvalancheGo genesis/bootstrappers.json)

## Timeline
| Event | Timestamp | Δ from start |
|-------|-----------|-------------|
| Node started | 10:22:39 | 0s |
| Dialing 24 bootstrap nodes | 10:22:39 | 0s |
| First handshake complete | 10:22:52 | **13s** |
| P-Chain bootstrap complete | 10:22:55 | **16s** |
| Following chain tip | 10:22:55 | 16s |

## P-Chain Bootstrap
- **Blocks fetched:** 7,614
- **Tip height:** 24,593,252
- **Fetch rounds:** 10 (recursive GetAncestors)
- **Data transferred:** ~8.9 MB total
- **Connected peer:** 13.36.28.133:9651 (Paris, AWS eu-west-3)

## Memory
| Metric | Value |
|--------|-------|
| RSS at bootstrap complete | 57.8 MB |
| RSS at 3 min idle | 66.3 MB |
| Binary size | 8.5 MB |

## Comparison vs AvalancheGo 1.14.1

| Metric | avalanche-rs | AvalancheGo | Δ |
|--------|-------------|-------------|---|
| Binary size | 8.5 MB | 88.7 MB | **10.4× smaller** |
| Memory (RSS) | 66.3 MB | 1,787 MB | **26.9× less** |
| First handshake | 13s | ~8s | AvalancheGo faster* |
| P-Chain bootstrap | 16s (7,614 blocks) | Still executing at 3 min | **avalanche-rs wins** |

*AvalancheGo has hardcoded trusted bootstrap NodeIDs which speeds initial TLS verification.
avalanche-rs connects to IPs without pre-shared NodeIDs (pure discovery).

## Status
✅ Mainnet P-Chain sync validated — connects, handshakes, fetches blocks, follows chain tip.
⚠️ C-Chain bootstrap not triggered in this run (needs separate chain ID routing).
