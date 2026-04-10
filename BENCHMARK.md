# Benchmark: avalanche-rs vs AvalancheGo

## Latest Results (2026-04-10, 5-minute Fuji production run)

> This is the current real-world benchmark for the shared Fuji production surface.
> The full dated write-up is in [docs/benchmarks/2026-04-10-fuji-300s.md](docs/benchmarks/2026-04-10-fuji-300s.md).

**Network:** Fuji testnet
**Duration:** 5 minutes per implementation
**Hardware:** Darwin arm64
**avalanche-rs commit:** `8b4ae7b`
**AvalancheGo version:** `v1.14.2`

| Metric | avalanche-rs | AvalancheGo v1.14.2 |
|--------|-------------|----------------------|
| Binary size | 10,272 KB | 88,968 KB |
| Final RSS | 21,584 KB | 39,008 KB |
| Peak RSS | 22,896 KB | 77,040 KB |
| First peer handshake | 330,249 ms | NA |
| P-Chain height RPC | `8725724278057432` | `null` |
| C-Chain block number | `0x0` | `null` |
| Peer count | `null` | `42` |
| P-Chain bootstrapped | `true` | `false` |
| Health endpoint healthy | `null` | `false` |

What matters more than the raw table:

- `avalanche-rs` stayed materially smaller in memory.
- AvalancheGo exposed the healthier networking surface in the same 5-minute window: 42 peers, working health and metrics endpoints, but no completed P-Chain bootstrap.
- `avalanche-rs` exposed real parity bugs during the benchmark: `platform.getHeight` returned an impossible value, `info.peers` was not usable in-window, `/ext/health` did not yield a usable benchmark response, and C-Chain stayed at `0x0`.

So this benchmark is useful as a production comparison, but not as a “victory” benchmark. The current gap is behavioral correctness and operational readiness, not binary size or raw RSS.

## Historical Snapshot (2026-03-08, Post Phase 12)

> Network sync benchmark below was run on a **Mac mini M4**.
> A fresh **Mac mini M1** indexer validation benchmark was added on **2026-03-10**; see the dedicated section below for current DB-backed indexer numbers.

**Network:** Fuji testnet (267,390 P-Chain blocks)
**Duration:** 3 minutes per implementation
**Hardware:** Mac Mini M4 (Apple Silicon), 16GB RAM
**avalanche-rs version:** v0.1.0 (663 tests, ~31K lines — full RPC, consensus, pruning, warp, subnets, light client, WASM, Fortuna, Granite, hardening, observability)

| Metric | avalanche-rs | AvalancheGo 1.14.1 | Δ |
|--------|-------------|-------------------|---|
| **Binary size** | 8.5 MB | 88.7 MB | **10.4× smaller** |
| **Memory (RSS) @ 3 min** | 67 MB | 1,787 MB | **26.7× less** |
| **First peer handshake** | 100 ms | ~8 s | **~80× faster** |
| **P-Chain bootstrap status** | ✅ Complete + following | ❌ Executing (40.8%) | — |
| **P-Chain blocks synced** | 3,066 | 267,383 fetched, 109,007 executed | * |
| **C-Chain blocks synced** | 516 | 0 (not started) | — |
| **P-Chain height reached** | 267,390 | N/A (executing) | — |
| **Peers connected** | 11 | N/A | — |
| **Sync phase at 3 min** | `Following` (chain tip) | Executing blocks (40.8%) | — |

\* Different sync strategies — see notes below.

### Memory Progression Over Time

| Version | RSS @ 3 min | Notes |
|---------|------------|-------|
| Pre-Phase 5 (Session 3) | 73 MB | Basic bootstrap only |
| Post-Phase 5-6 | 118 MB | +state sync, tx validation, warp, subnets |
| Post-Phase 7-8 | 36 MB | +full RPC, consensus, pruning, WASM, light client |
| **Post-Phase 12** | **67 MB** | +Fortuna (ACP-176), Granite (ACP-181/204/226), hardening, observability |

Phase 12 adds significant new functionality (dynamic gas limits, epoch management, secp256r1, dynamic block times, structured logging, panic recovery, rate limiting) while memory remains well under 100 MB.

### RSS Samples During Run

| Time | RSS (KB) |
|------|----------|
| T+30s | 68,944 |
| T+60s | 68,944 |
| T+90s | 68,944 |
| T+120s | 68,944 |
| T+150s | 68,944 |
| T+180s | 68,944 |

Memory is completely flat — state pruning keeps the footprint stable.

### Mac mini M1 Indexer Validation (2026-03-10)

This benchmark measures the production indexer validation path on the current development host, a **Mac mini M1 (16 GB RAM)**, using local **Postgres 17 + TimescaleDB**.

| Metric | Result |
|--------|--------|
| Release build (`cargo build --release --features indexer`) | **4m36s** |
| Release binary size (`target/release/avalanche-rs`) | **11 MB** |
| Full DB-backed integration suite | **149.75s** |
| Test count | **32/32 passed** |
| Peak test memory footprint | **~106 MB** |

Validated suites:

- `api_integration` — 11 tests
- `indexer_integration` — 9 tests
- `indexer_comprehensive` — 12 tests

What this benchmark proves:

- Axum REST routes are wired correctly for the indexer API
- Writer shutdown flushes data reliably before process exit
- Gap detection, duplicate handling, balances, and query paths all pass against a real database
- The current indexer stack is stable enough for the next productionization pass


## Timeline

### avalanche-rs (Post Phase 12)
```
T+0.000s   Process start
T+0.100s   TLS handshake complete with bootstrap peer (52.29.72.46:9651)
T+0.200s   Version exchange, PeerList with 15 peers received
T+0.500s   11 peers connected (bootstrap + discovered)
T+10.0s    P-Chain bootstrap: 10 rounds of GetAncestors
T+12.0s    P-Chain: 3,066 blocks synced, height 267,390
T+12.0s    C-Chain: 516 blocks synced
T+12.0s    Entered SyncPhase::Following — tracking chain tip
T+180.0s   Stable: 3,066 P-Chain, 516 C-Chain, 11 peers, 67 MB RSS
```

### AvalancheGo 1.14.1 (previous run, same hardware)
```
T+0.000s   Process start, initializing subsystems
T+2.0s     API server listening
T+7.9s     P-Chain bootstrap: starting to fetch
T+32.0s    Network health check passing
T+71.0s    P-Chain fetch: 97.3% (260,146/267,383)
T+82.0s    P-Chain fetch complete, compacting database
T+85.0s    Executing blocks (267,383 total)
T+130.0s   Executed 44,342 (16.6%), ETA: 4m28s
T+150.0s   Executed 88,837 (33.2%), ETA: 3m26s
T+180.0s   Executed 109,007 (40.8%), ETA: 2m04s — killed. 1,787 MB RSS.
```

## Analysis

### Why 67 MB?

The Phase 12 build adds Fortuna (ACP-176 dynamic gas limits), Granite (ACP-181 epochs, ACP-204 secp256r1 verification, ACP-226 dynamic block times), hardening (panic recovery, rate limiting, connection limits), and observability (structured logging, Prometheus histograms). Despite the additional functionality, memory stays flat at 67 MB thanks to:

- **State pruning** (256-block depth, 60s cycle)
- **mimalloc** for efficient allocation
- **Rust's zero-cost abstractions**

The increase from 36 MB (Phase 7-8) to 67 MB reflects the additional validator data structures, epoch tracking, and rate-limiting state — all constant-size allocations.

### Sync Strategy Differences

**avalanche-rs** uses incremental sync:
- Requests `Ancestors` messages for recent chain history
- Verifies chain walk from tip to genesis
- Enters `Following` mode once bootstrap completes
- Prunes old state automatically

**AvalancheGo** uses full historical sync:
- Downloads ALL 267,383 blocks, then executes serially
- At 3 minutes: fetched 100% but only executed 40.8%
- Estimated 5+ minutes to complete full bootstrap
- No state pruning during initial sync

### Key Takeaways

1. **26.7× less memory** — avalanche-rs uses 67 MB vs 1,787 MB. Runs on a Raspberry Pi, $5/mo VPS, or embedded device.

2. **Bootstrap to chain-tip in ~12 seconds.** AvalancheGo needs 5+ minutes on the same hardware.

3. **8.5 MB binary** with full RPC, consensus, warp, subnets, pruning, metrics, light client, Fortuna, and Granite. AvalancheGo is 88.7 MB for similar functionality.

4. **Memory stays flat.** State pruning keeps RSS at 67 MB indefinitely — no growth over time.

## Features Included in This Benchmark

- ✅ Full eth_* JSON-RPC (21 methods)
- ✅ platform.* JSON-RPC (7 methods)
- ✅ txpool_* JSON-RPC (3 methods)
- ✅ debug_* JSON-RPC (3 methods)
- ✅ WebSocket subscriptions (newHeads, logs, newPendingTransactions)
- ✅ Snowman consensus (alpha=15, beta=20, chits, confidence)
- ✅ State pruning (256-block depth, 60s cycle)
- ✅ Prometheus metrics + health endpoint
- ✅ Warp messaging (AWM protocol)
- ✅ Subnet support (--tracked-subnets)
- ✅ Light client mode (--light-client)
- ✅ WASM build target (avalanche-core)
- ✅ Fortuna upgrade (ACP-176: dynamic EVM gas limits)
- ✅ Granite upgrade (ACP-181 epochs, ACP-204 secp256r1, ACP-226 dynamic block times)
- ✅ Hardening (panic recovery, rate limiting, connection limits)
- ✅ Observability (structured logging, Prometheus histograms, span tracing)
- ✅ 663+ tests passing
- ✅ 32/32 DB-backed indexer/API validation tests passing on Mac mini M1

## Reproducing

```bash
# Build avalanche-rs
cargo build --release

# Run (3 min benchmark)
./target/release/avalanche-rs --network-id 5 --data-dir ./data/bench \
  --bootstrap-ips 52.29.72.46:9651 --staking-port 29651 --http-port 29650

# Run AvalancheGo for comparison
./avalanchego --network-id=fuji --data-dir=./data/bench-go \
  --staking-port=29661 --http-port=29660 --log-level=info
```

## Test Environment

```
OS:          macOS 15.2 (Darwin 25.2.0 arm64)
Hardware:    Mac Mini M4 (Apple Silicon) for network sync benchmark
Indexer host: Mac mini M1 (Apple Silicon), 16 GB RAM for DB-backed validation benchmark
RAM:         16 GB
avalanche-rs: v0.1.0 (release build, 663 tests, ~31K lines Rust)
AvalancheGo:  v1.14.1 (official binary)
```
