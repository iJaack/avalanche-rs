# Indexer Deployment (Production Path)

This is the operator path for deploying the `avalanche-rs` indexer with TimescaleDB, Prometheus, and Grafana.

## 1) Prepare operator config

```bash
cp .env.example .env
```

Minimum values to verify in `.env`:

- `INDEXER_ENABLED=true`
- `AVAX_NETWORK_ID=1` (mainnet) or `5` (fuji)
- `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`
- `INDEXER_API_PORT=8080`
- `PROMETHEUS_PORT=9090`
- `GRAFANA_PORT=3000`
- `GRAFANA_ADMIN_PASSWORD` set to a non-default secret

`DATABASE_URL` is optional. When unset, compose derives it from `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD`.

## 2) Start indexer topology

```bash
docker compose --profile indexer up -d --build
```

This brings up:

- `indexer-db` (TimescaleDB/PostgreSQL)
- `avalanche-indexer` (node + indexer feature enabled)
- `prometheus` (scraping indexer metrics)
- `grafana` (pre-provisioned Prometheus datasource + dashboard)

## 3) Verify service health

```bash
curl -sf http://127.0.0.1:${INDEXER_API_PORT:-8080}/health
curl -sf http://127.0.0.1:${INDEXER_API_PORT:-8080}/metrics | rg '^indexer_'
curl -sf http://127.0.0.1:${PROMETHEUS_PORT:-9090}/-/healthy
```

Grafana UI: `http://127.0.0.1:${GRAFANA_PORT:-3000}`

- default user: `GRAFANA_ADMIN_USER`
- password: `GRAFANA_ADMIN_PASSWORD`

The dashboard is auto-loaded as **Avalanche-RS Indexer**.

## 4) Key ports and endpoints

- `9650` — node JSON-RPC
- `9651` — node staking/P2P
- `8080` — indexer REST + `/metrics`
- `9090` — Prometheus
- `3000` — Grafana

Common API checks:

```bash
curl -sf http://127.0.0.1:8080/api/blocks/1
curl -sf "http://127.0.0.1:8080/api/logs?limit=5"
```

## 5) Operations notes

- Compose persists data in `indexer-data` and `postgres_data` volumes.
- Alert rules are loaded from `docs/alerts.yml` (baseline node + indexer alerts).
- For alert tuning and failure triage, use `docs/indexer-observability-runbook.md`.
