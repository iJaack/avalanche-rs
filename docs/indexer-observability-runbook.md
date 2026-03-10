# Indexer Observability Runbook

This runbook is for operators running `avalanche-rs` with `--indexer-enabled`.

## Core Prometheus metrics

Prioritize these indexer metrics for dashboards and alerts:

- `indexer_height` — highest block indexed in PostgreSQL.
- `indexer_lag_blocks` — distance from chain tip (`0` means caught up).
- `indexer_catchup_blocks_remaining` — startup/backfill backlog.
- `indexer_catchup_blocks_per_sec` — catchup throughput.
- `indexer_queue_depth` — pending blocks waiting in the writer queue.
- `indexer_batches_flushed_total` — successful batch writes.
- `indexer_batch_write_duration_seconds` — batch write latency histogram.
- `indexer_batch_size` — number of blocks per batch flush histogram.
- `indexer_write_errors_total` — failed batch writes.
- `indexer_blocks_indexed_total`, `indexer_transactions_indexed_total`, `indexer_logs_indexed_total` — ingest counters.

## Suggested alerts

Tune thresholds to your network and hardware profile.

```yaml
groups:
  - name: avalanche-rs-indexer
    rules:
      - alert: IndexerWriteErrors
        expr: increase(indexer_write_errors_total[5m]) > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Indexer write failures detected"
          description: "Indexer write errors increased in the last 5 minutes."

      - alert: IndexerLagGrowing
        expr: indexer_lag_blocks > 5000 and increase(indexer_lag_blocks[10m]) > 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Indexer lag is high and increasing"
          description: "Indexer is falling behind chain tip for 10 minutes."

      - alert: IndexerQueueBackpressure
        expr: indexer_queue_depth > 500
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Indexer queue depth elevated"
          description: "Indexer queue depth has remained high for 10 minutes."

      - alert: IndexerStalled
        expr: increase(indexer_blocks_indexed_total[15m]) == 0 and indexer_lag_blocks > 0
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "Indexer stalled while behind"
          description: "No blocks indexed for 15 minutes while lag remains non-zero."
```

## Operator checks

Use these checks during incident response:

1. **API health and metrics endpoint**
   - `curl -sf http://127.0.0.1:8080/health`
   - `curl -sf http://127.0.0.1:8080/metrics | rg indexer_`
2. **Progress/liveness**
   - Confirm `indexer_blocks_indexed_total` increases over time.
   - Confirm `indexer_queue_depth` trends down after bursts.
3. **Lag and catchup**
   - If `indexer_lag_blocks` is non-zero, check whether `indexer_catchup_blocks_remaining` decreases.
   - If backlog is flat and `indexer_catchup_blocks_per_sec` is near zero, inspect DB health.
4. **Database path**
   - Verify PostgreSQL connectivity and disk headroom.
   - Check long-running transactions/locks and write latency.
5. **Recovery behavior**
   - After restart, confirm `indexer_height` and `indexer_blocks_indexed_total` continue increasing.
   - Confirm no duplicate growth in `address_balances` for replayed blocks (idempotent resume).

## Restart/resume verification checklist

During planned maintenance or after crash recovery:

1. Stop process cleanly and restart with same `--database-url`.
2. Confirm `indexer_state.last_indexed_block` remains monotonic.
3. Confirm replaying recently indexed blocks does not duplicate:
   - `blocks` rows,
   - `transactions` rows,
   - `logs` rows,
   - or `address_balances` deltas.
4. Confirm API correctness on known addresses and block heights.

Use this SQL spot-check after restart:

```sql
SELECT key, value_int, updated_at
FROM indexer_state
WHERE key = 'last_indexed_block';
```
