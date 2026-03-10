-- Billion-scale cost optimization: compression, continuous aggregates, retention policies
-- TimescaleDB native compression for historical data

-- =============================================================================
-- COMPRESSION POLICIES
-- Compress chunks older than 7 days (hot → warm transition)
-- Achieves 10-20x compression on time-series blockchain data
-- =============================================================================

-- Blocks: compress by timestamp, order by number for range scans
ALTER TABLE blocks SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = '',
    timescaledb.compress_orderby = 'timestamp DESC, number DESC'
);
SELECT add_compression_policy('blocks', INTERVAL '7 days', if_not_exists => TRUE);

-- Transactions: segment by from_address for per-account queries on compressed data
ALTER TABLE transactions SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'from_address',
    timescaledb.compress_orderby = 'timestamp DESC, block_number DESC'
);
SELECT add_compression_policy('transactions', INTERVAL '7 days', if_not_exists => TRUE);

-- Logs: segment by address for contract-level queries
ALTER TABLE logs SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'address',
    timescaledb.compress_orderby = 'timestamp DESC, block_number DESC'
);
SELECT add_compression_policy('logs', INTERVAL '7 days', if_not_exists => TRUE);

-- =============================================================================
-- CONTINUOUS AGGREGATES
-- Pre-compute hourly and daily rollups to avoid full-table scans
-- =============================================================================

-- Hourly block stats (gas usage, block count, tx throughput)
CREATE MATERIALIZED VIEW IF NOT EXISTS blocks_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', timestamp) AS bucket,
    COUNT(*) AS block_count,
    SUM(transaction_count) AS tx_count,
    SUM(gas_used) AS total_gas_used,
    AVG(gas_used)::BIGINT AS avg_gas_used,
    MAX(number) AS max_block_number,
    MIN(number) AS min_block_number,
    SUM(size) AS total_size
FROM blocks
GROUP BY bucket
WITH NO DATA;

-- Refresh policy: keep hourly aggregates updated with 1h lag
SELECT add_continuous_aggregate_policy('blocks_hourly',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- Daily block stats for long-range analytics
CREATE MATERIALIZED VIEW IF NOT EXISTS blocks_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', timestamp) AS bucket,
    COUNT(*) AS block_count,
    SUM(transaction_count) AS tx_count,
    SUM(gas_used) AS total_gas_used,
    AVG(gas_used)::BIGINT AS avg_gas_used,
    MAX(number) AS max_block_number,
    MIN(number) AS min_block_number,
    SUM(size) AS total_size
FROM blocks
GROUP BY bucket
WITH NO DATA;

SELECT add_continuous_aggregate_policy('blocks_daily',
    start_offset => INTERVAL '30 days',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Hourly transaction volume by address (top senders/receivers)
CREATE MATERIALIZED VIEW IF NOT EXISTS tx_volume_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', timestamp) AS bucket,
    from_address,
    COUNT(*) AS tx_count,
    SUM(gas_used) AS total_gas_used
FROM transactions
GROUP BY bucket, from_address
WITH NO DATA;

SELECT add_continuous_aggregate_policy('tx_volume_hourly',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- =============================================================================
-- RETENTION / DOWNSAMPLING
-- Keep raw data for 90 days, aggregates forever
-- Older raw data is dropped — aggregates preserve the analytics
-- =============================================================================

-- Drop raw block chunks older than 90 days (aggregates retained)
SELECT add_retention_policy('blocks', INTERVAL '90 days', if_not_exists => TRUE);

-- Drop raw transaction chunks older than 90 days
SELECT add_retention_policy('transactions', INTERVAL '90 days', if_not_exists => TRUE);

-- Drop raw log chunks older than 90 days
SELECT add_retention_policy('logs', INTERVAL '90 days', if_not_exists => TRUE);

-- =============================================================================
-- INDEXER STATE TABLE
-- Track indexer progress for catchup mode gap detection
-- =============================================================================

CREATE TABLE IF NOT EXISTS indexer_state (
    key TEXT PRIMARY KEY,
    value_int BIGINT,
    value_text TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed initial state
INSERT INTO indexer_state (key, value_int, updated_at)
VALUES ('last_indexed_block', 0, NOW())
ON CONFLICT (key) DO NOTHING;

INSERT INTO indexer_state (key, value_text, updated_at)
VALUES ('indexer_version', '2.0.0', NOW())
ON CONFLICT (key) DO NOTHING;
