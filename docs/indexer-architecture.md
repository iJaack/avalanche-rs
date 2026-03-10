# Avalanche Indexer Architecture Note

## Goal
Build a low-cost Avalanche indexing backend that can scale toward billions of transactions without keeping all raw data hot forever in Postgres.

## Current Shape
- **Hot path:** recent raw blocks / transactions / logs in TimescaleDB
- **Compression:** historical chunks compressed in TimescaleDB
- **Rollups:** hourly / daily continuous aggregates for common analytics
- **Balances:** AVAX-only balance snapshots + SQL recomputation path
- **Catchup:** startup gap detection + catchup metrics
- **Observability:** Prometheus metrics for throughput / lag / failures

## Recommended Storage Tiers

### Tier 1 — Hot analytical store
Use TimescaleDB / Postgres for:
- recent raw data
- API-serving reads
- address lookups
- operational metrics
- balance snapshots

Recommended retention in hot storage:
- raw blocks / txs / logs: short-to-medium window
- compressed historical chunks: medium window
- continuous aggregates: long-lived

### Tier 2 — Warm historical archive
Keep compressed historical partitions for data still queried occasionally.
This layer should prioritize:
- cheap disk footprint
- acceptable scan performance
- lower write amplification

### Tier 3 — Cold archive
Move older raw history to object storage in a columnar format when possible.
Suggested long-term direction:
- Parquet in object storage
- partition by chain / date / block range
- reconstruct heavyweight historical analytics outside the hot DB

## Design Principles
- prefer batch writes over row-at-a-time ingestion
- push recomputation into SQL when cheaper than Rust iteration
- keep raw-hot retention finite unless a product requirement forces otherwise
- treat continuous aggregates as the default source for dashboards
- avoid premature ERC-20/token expansion until AVAX-only ingestion is proven

## Product Decision Still Needed
Routescan needs to choose between:
1. **cheap analytics-first backend**
2. **forever-hot raw explorer backend**

Those are different cost profiles.

## Recommended Next Steps
1. validate Timescale-backed tests against a real local DB
2. define hot/warm/cold retention windows explicitly
3. decide whether old raw tx history must remain queryable in Postgres
4. keep AVAX-only first, then expand token indexing only after ingestion proves stable
