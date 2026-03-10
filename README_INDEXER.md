# Indexer & REST API (Optional)

The indexer is an optional module that indexes all blocks, transactions, and logs into PostgreSQL with TimescaleDB for efficient time-series queries. It runs alongside the node and exposes a REST API for analytics workloads.

## Why Use the Indexer?

- **Separate analytics workload**: REST API queries don't compete with JSON-RPC traffic
- **Time-series optimized**: TimescaleDB hypertables for fast block/transaction ranges
- **Full query support**: Blocks by number/hash, transactions, logs with filtering
- **Independent of RPC**: Continues to index while RPC handles other clients

## Setup (One-Time)

### 1. Install PostgreSQL 17 + TimescaleDB

```bash
# macOS with Homebrew
brew install postgresql@17
brew tap timescale/tap
brew install timescaledb

# Start service
brew services start postgresql@17

# Configure TimescaleDB
timescaledb_move.sh
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"
timescaledb-tune --quiet --yes
brew services restart postgresql@17
```

### 2. Create Database & User

```bash
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"

createdb avalanche_indexer

psql -d avalanche_indexer <<SQL
CREATE USER indexer WITH PASSWORD 'indexer_pass';
GRANT ALL PRIVILEGES ON DATABASE avalanche_indexer TO indexer;
GRANT ALL ON SCHEMA public TO indexer;
CREATE EXTENSION IF NOT EXISTS timescaledb;
SQL
```

### 3. Build with Indexer Feature

```bash
cargo build --release --features indexer
```

## Running the Indexer

### Local Development

```bash
cd avalanche-rs

cargo run --features indexer --bin avalanche-rs -- \
  --network-id 5 \
  --indexer-enabled \
  --database-url "postgres://indexer:indexer_pass@localhost/avalanche_indexer"
```

The node will:
1. Start P2P and RPC on ports 9651 / 9650 (as usual)
2. Initialize the indexer and migrate PostgreSQL schema
3. Start REST API on port **8080**
4. Index all finalized blocks to PostgreSQL in the background

### Production Deployment

```bash
./target/release/avalanche-rs \
  --network-id 1 \
  --indexer-enabled \
  --database-url "postgres://indexer:production_password@db.internal:5432/avalanche_indexer" \
  --log-level info
```

## REST API Endpoints

### Health Check
```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

### Blocks
```bash
# Get block by height
curl http://localhost:8080/api/blocks/1

# Get block by hash
curl http://localhost:8080/api/blocks/hash/0x...

# Response
{
  "number": 1,
  "hash": "0x...",
  "parent_hash": "0x...",
  "timestamp": "2021-12-15T19:10:00Z",
  "gas_used": 123456,
  "gas_limit": 15000000,
  "transaction_count": 42,
  "size": 56789
}
```

### Transactions
```bash
# Get transaction by hash
curl http://localhost:8080/api/tx/0x...

# Get all transactions for an address
curl "http://localhost:8080/api/address/0x.../transactions?limit=10&offset=0"

# Response
{
  "hash": "0x...",
  "block_number": 123456,
  "from": "0x...",
  "to": "0x...",
  "value": "1000000000000000000",
  "gas_price": 25000000000,
  "status": 1
}
```

### Event Logs
```bash
# Get logs with filters
curl "http://localhost:8080/api/logs?address=0x...&topic0=0x...&fromBlock=1000&toBlock=2000"

# Response
[
  {
    "address": "0x...",
    "topics": ["0x...", "0x...", null, null],
    "data": "0x...",
    "block_number": 1234,
    "transaction_hash": "0x...",
    "log_index": 0
  }
]
```

## Database Schema

The indexer creates these TimescaleDB hypertables:

- **blocks** — Block headers (number, hash, timestamp, gas metrics)
- **transactions** — Transaction details (hash, from/to, value, gas, status)
- **logs** — Event logs (address, topics, data, indexed by address + topic0)
- **address_balances** — Latest balance snapshot (updated on each block)

All hypertables are partitioned by `timestamp` for efficient time-series queries.

### Example Queries

```sql
-- Get average gas price per day
SELECT DATE_TRUNC('day', timestamp) as day, AVG(gas_price) as avg_price
FROM transactions
WHERE timestamp > NOW() - INTERVAL '30 days'
GROUP BY day
ORDER BY day DESC;

-- Find top callers in last hour
SELECT from_address, COUNT(*) as tx_count
FROM transactions
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY from_address
ORDER BY tx_count DESC
LIMIT 10;

-- Get all logs for a contract in a range
SELECT * FROM logs
WHERE address = '\x...'::bytea
AND timestamp BETWEEN '2026-03-01' AND '2026-03-31'
ORDER BY timestamp DESC;
```

## Performance

- **Indexing rate**: ~500 blocks/sec (depends on PostgreSQL + network)
- **Query latency**: <100ms for standard queries (p50)
- **Database size**: ~10 GB per month (mainnet)
- **Network isolation**: REST API runs independently, doesn't impact RPC

## Troubleshooting

### "cannot create a unique index without the column timestamp"

TimescaleDB requires all PRIMARY KEY constraints in hypertables to include the partitioning column. Make sure you're using the latest migration (Mar 9, 2026 or later).

### "connection refused" on port 8080

The REST API server spawns async — wait 2-3 seconds for initialization. Check node logs for errors:

```bash
grep -i "indexer\|REST\|8080" <logfile>
```

### Database locked

Only one instance of avalanche-rs can use the same RocksDB folder. Ensure you're not running multiple instances pointing to the same `--data-dir`.

## Architecture

```
avalanche-rs (main)
├── P2P (port 9651)
├── JSON-RPC (port 9650)
└── Indexer (conditional)
    ├── Background writer task (batch processing)
    │   └── PostgreSQL (blocks, txs, logs)
    └── Axum REST API server (port 8080)
        ├── Blocks endpoint
        ├── Transactions endpoint
        └── Logs endpoint
```

The indexer runs in the background and doesn't block the main node. If PostgreSQL is unavailable, the node continues to function normally (indexing just pauses).

## Next Steps

- **Deployment**: Docker Compose template with PostgreSQL + pgAdmin
- **Monitoring**: Prometheus metrics and operator runbook in [`docs/indexer-observability-runbook.md`](docs/indexer-observability-runbook.md)
- **Caching**: Redis layer for hot queries
- **GraphQL**: High-level query interface built on REST API
