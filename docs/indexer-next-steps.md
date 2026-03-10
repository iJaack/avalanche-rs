# Indexer Next Steps

## Goal

Move the newly stabilized indexer from locally validated to production-ready deployment and observability.

## Immediate next steps

1. **Production config wiring**
   - add a documented `.env` / deployment example for `INDEXER_ENABLED` and `DATABASE_URL`
   - confirm startup behavior when DB is unavailable
   - document safe retry/backoff expectations

2. **Runtime observability**
   - expose a small set of indexer-specific Prometheus dashboards / alert recommendations
   - track ingest lag, batch flush duration, write failures, catchup backlog, and API latency

3. **Operational hardening**
   - add a smoke test for startup catchup against a seeded DB
   - add a restart / crash-recovery validation pass
   - confirm idempotent resume behavior after partial writes

4. **Scale validation**
   - benchmark larger synthetic datasets focused on batch ingest throughput
   - validate compression and retention behavior over longer time windows
   - measure API query latency on larger block / tx / log tables

5. **Deployment packaging**
   - provide a docker-compose example with Postgres/Timescale tuned for the indexer
   - document required migrations and first-run bootstrap flow
   - add a concise runbook for backup / restore

## Recommended execution order

1. observability + runbook
2. crash/restart validation
3. larger-scale ingest benchmark
4. deployment packaging

## Success criteria

- node starts cleanly with `--indexer-enabled` in a fresh environment
- metrics clearly show lag, failures, and throughput
- restart during catchup does not corrupt state or double-count balances
- API remains correct under larger historical datasets
