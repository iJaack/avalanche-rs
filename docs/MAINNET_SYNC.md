# Mainnet Sync Test Results

## Test Date: 2026-03-08

### Configuration

```
Binary:     ./target/release/avalanche-rs (8.5 MB, Phase 12 build)
Network:    Mainnet (network-id=1)
Duration:   5 minutes
Hardware:   Mac Mini M4 (Apple Silicon), 16GB RAM
OS:         macOS 15.2 (Darwin 25.2.0 arm64)
```

### Bootstrap IPs Tested

| IP | Port | Result |
|----|------|--------|
| 54.94.43.49 | 9651 | TCP connect timeout after 10s |
| 52.33.32.23 | 9651 | TCP connect timeout after 10s |

### Results

**Status:** Node started successfully but could not connect to mainnet bootstrap peers.

**Blocks synced:** 0 (P-Chain), 0 (C-Chain)
**Sync phase:** Bootstrapping (waiting for peer connection)
**Errors:** `TCP connect timeout to <ip>:9651`
**Final RSS:** 15,744 KB (~15 MB)

### RSS Samples

| Time | RSS (KB) | Notes |
|------|----------|-------|
| T+45s | 15,712 | Waiting for bootstrap connection |
| T+105s | 15,712 | Still waiting |
| T+165s | 15,744 | Minimal growth |
| T+225s | 15,744 | Flat |
| T+300s | 15,744 | Flat — process killed |

### Analysis

The node starts cleanly and listens on both P2P (9651) and HTTP (9650) ports. The mainnet bootstrap IPs tested are no longer reachable — these are known Avalanche mainnet bootstrap nodes but may have been rotated or firewalled.

**Key observations:**

1. **Startup is instant** — Node initializes in <20ms (DB open, TLS cert gen, EVM init)
2. **Idle memory is 15 MB** — Without any peer connections or block data, the node uses only 15 MB RSS
3. **No crashes or panics** — Node ran for the full 5 minutes without any errors beyond the bootstrap timeout
4. **Graceful failure** — Bootstrap timeout is logged as a WARN, node continues running and retrying

### Comparison with Fuji (same build)

| Metric | Mainnet (no peers) | Fuji (11 peers) |
|--------|-------------------|-----------------|
| Startup time | <20ms | <20ms |
| Idle RSS | 15 MB | 67 MB |
| P-Chain blocks | 0 | 3,066 |
| C-Chain blocks | 0 | 516 |
| Sync phase | Bootstrapping | Following |

The 15 MB vs 67 MB difference reflects block storage and peer connection state. Without peers, the node has minimal memory overhead.

### Reproducing

```bash
cargo build --release

# Try mainnet (may need updated bootstrap IPs)
./target/release/avalanche-rs \
  --network-id 1 \
  --bootstrap-ips "54.94.43.49:9651" \
  --data-dir ./data/mainnet-test

# For working mainnet bootstrap, check:
# https://github.com/ava-labs/avalanchego/blob/master/genesis/bootstrappers.go
```

### Next Steps

- Update mainnet bootstrap IPs from AvalancheGo's latest `bootstrappers.go`
- Add DNS-based bootstrap peer discovery (like AvalancheGo's DNS seeding)
- Re-run mainnet sync test once bootstrap peers are updated
