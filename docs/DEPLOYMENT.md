# Deployment Guide

## Docker

### Quick Start (Fuji Testnet)

```bash
docker compose --profile fuji up -d
```

### Mainnet

```bash
docker compose --profile mainnet up -d
```

### Custom Build

```bash
docker build -t avalanche-rs .
docker run -d --name avalanche-rs \
  -p 9650:9650 -p 9651:9651 \
  -v avalanche-data:/data/avalanche-rs \
  avalanche-rs --network-id=1
```

## Systemd Service

Create `/etc/systemd/system/avalanche-rs.service`:

```ini
[Unit]
Description=Avalanche-RS Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=avalanche
Group=avalanche
ExecStart=/usr/local/bin/avalanche-rs \
    --network-id=1 \
    --data-dir=/var/lib/avalanche-rs \
    --http-port=9650 \
    --staking-port=9651 \
    --log-level=info \
    --log-format=json
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -m -s /bin/false avalanche
sudo mkdir -p /var/lib/avalanche-rs
sudo chown avalanche:avalanche /var/lib/avalanche-rs
sudo systemctl daemon-reload
sudo systemctl enable --now avalanche-rs
```

## Resource Requirements

| Mode | RAM | Disk | CPU |
|------|-----|------|-----|
| Full Node (default) | 2-4 GB | 50 GB SSD | 2+ cores |
| Archive (`--archive`) | 8-16 GB | 500+ GB SSD | 4+ cores |
| Validator (`--validator`) | 4-8 GB | 100 GB SSD | 4+ cores |
| Light Client (`--light-client`) | 256-512 MB | 1 GB | 1 core |
| RPC-only | 2-4 GB | 50 GB SSD | 2+ cores |

## Recommended Flags

### RPC Node

```bash
avalanche-rs \
    --network-id=1 \
    --data-dir=/var/lib/avalanche-rs \
    --http-port=9650 \
    --log-format=json \
    --txpool-size=8192 \
    --block-cache-size=2048
```

### Validator

```bash
avalanche-rs \
    --network-id=1 \
    --data-dir=/var/lib/avalanche-rs \
    --validator \
    --staking-tls-cert-file=/etc/avalanche/staker.crt \
    --staking-tls-key-file=/etc/avalanche/staker.key \
    --log-format=json
```

### Archive Node

```bash
avalanche-rs \
    --network-id=1 \
    --data-dir=/var/lib/avalanche-rs \
    --archive \
    --state-pruning-depth=0 \
    --block-cache-size=4096 \
    --log-format=json
```

### Light Client

```bash
avalanche-rs \
    --network-id=1 \
    --data-dir=/var/lib/avalanche-rs \
    --light-client \
    --log-format=json
```

## Monitoring with Prometheus & Grafana

### Prometheus

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'avalanche-rs'
    static_configs:
      - targets: ['localhost:9650']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Grafana

Import the dashboard from `docs/grafana/dashboard.json`.

Key metrics exposed at `/metrics`:
- `avalanche_blocks_synced` — total blocks synced
- `avalanche_peer_count` — connected peers
- `avalanche_tip_height` — current chain tip
- `avalanche_rpc_requests_total` — RPC request count
- `avalanche_rpc_latency_seconds` — RPC response time histogram

### Health Check

```bash
curl http://localhost:9650/health
```

Returns JSON with database and network health status.

## Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 9650 | TCP | HTTP/WS (JSON-RPC, health, metrics) |
| 9651 | TCP | P2P (staking, consensus) |
