# Benchmark: avalanche-rs vs AvalancheGo v1.14.2

- Date (UTC): 2026-04-15T08:48:07Z
- Network: Fuji testnet
- Configured duration: 300s per implementation
- Hardware: Darwin arm64
- Bootstrap IP: 52.29.72.46:9651
- Bootstrap ID: NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg
- avalanche-rs commit: a0e585e
- AvalancheGo version: v1.14.2

## Run Status

This run is not a clean completed comparison. The `avalanche-rs` side completed the configured 300-second window and final RPC sampling. AvalancheGo exited early at about 242 seconds because its disk-space guard shut the node down:

```text
low on disk space. Shutting down... {"availableDiskBytes": 14426427392, "remainingDiskPercentage": 2, "requiredDiskPercentage": 3}
```

The benchmark harness then hung before writing the AvalancheGo `.env` summary, so the AvalancheGo values below are reconstructed from the captured log and RSS sample files.

## Cold Start Sync

| Metric | avalanche-rs | AvalancheGo v1.14.2 |
|--------|-------------|----------------------|
| Binary size | 10,288 KB | 88,968 KB |
| Run outcome | Completed configured window | Aborted at ~242s |
| First peer handshake | 330,226 ms | NA; bootstrap connection failed |
| Final RSS | 10,720 KB | Not collected |
| Peak sampled RSS | 122,704 KB | 78,144 KB |
| Last sampled RSS | 7,520 KB | 20,768 KB |
| P-Chain height | 273714 | Not collected |
| C-Chain block number | `0x33a03b6` | Not collected |
| Peer count (`info.peers`) | 1 | Not collected |
| P-Chain bootstrapped | true | Not collected |
| Health endpoint healthy | false | Not collected |

## Shared RPC Latency Slice

Average of 3 requests after the `avalanche-rs` run. AvalancheGo latency was not collected because the process had already shut down.

| Endpoint | avalanche-rs | AvalancheGo v1.14.2 |
|----------|-------------|----------------------|
| `eth_blockNumber` | 0.8 ms | NA |
| `eth_chainId` | 0.4 ms | NA |
| `eth_gasPrice` | 0.6 ms | NA |
| `platform.getHeight` | 0.4 ms | NA |
| `GET /ext/health` | 0.6 ms | NA |
| `GET /metrics` | NA | NA |

## Shared RPC Values At End Of Run

| Value | avalanche-rs | AvalancheGo v1.14.2 |
|-------|-------------|----------------------|
| `eth_chainId` | `0xa86a` | Not collected |
| `eth_gasPrice` | `0x60db88400` | Not collected |

## Raw Artifacts

- avalanche-rs log: `./docs/benchmarks/raw/20260415T083331Z-avalanche-rs.log`
- avalanche-rs env summary: `./docs/benchmarks/raw/20260415T083331Z-avalanche-rs.env`
- avalanche-rs RSS samples: `./docs/benchmarks/raw/20260415T083331Z-avalanche-rs-rss.csv`
- AvalancheGo log: `./docs/benchmarks/raw/20260415T083331Z-avalanchego.log`
- AvalancheGo RSS samples: `./docs/benchmarks/raw/20260415T083331Z-avalanchego-rss.csv`

## Notes

- `avalanche-rs` synced P-Chain height 273714 and reported C-Chain block `0x33a03b6` during final collection.
- AvalancheGo logged `failed to connect to bootstrap nodes` after 60 seconds, then exited later due to disk pressure before final RPC collection.
- Host free space after the run was about 13.1 GiB available on `/System/Volumes/Data`, which is below AvalancheGo's 3% required-free-space guard for this volume.
