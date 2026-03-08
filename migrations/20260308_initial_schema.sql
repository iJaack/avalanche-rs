-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Blocks table
CREATE TABLE blocks (
    number BIGINT NOT NULL,
    hash BYTEA NOT NULL PRIMARY KEY,
    parent_hash BYTEA NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    gas_used BIGINT NOT NULL DEFAULT 0,
    gas_limit BIGINT NOT NULL DEFAULT 0,
    transaction_count INT NOT NULL DEFAULT 0,
    size BIGINT NOT NULL DEFAULT 0
);

-- Convert to hypertable (time-series optimized)
SELECT create_hypertable('blocks', 'timestamp', if_not_exists => TRUE);

-- Indexes
CREATE INDEX idx_blocks_number ON blocks(number);
CREATE INDEX idx_blocks_timestamp ON blocks(timestamp DESC);

-- Transactions table
CREATE TABLE transactions (
    hash BYTEA NOT NULL PRIMARY KEY,
    block_hash BYTEA NOT NULL REFERENCES blocks(hash) ON DELETE CASCADE,
    block_number BIGINT NOT NULL,
    from_address BYTEA NOT NULL,
    to_address BYTEA,
    value NUMERIC(78, 0) NOT NULL DEFAULT 0,
    gas_price BIGINT,
    gas_limit BIGINT,
    gas_used BIGINT,
    input BYTEA,
    nonce BIGINT,
    status SMALLINT, -- 0=failed, 1=success, NULL=pending
    tx_index INT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL
);

SELECT create_hypertable('transactions', 'timestamp', if_not_exists => TRUE);

CREATE INDEX idx_tx_block_number ON transactions(block_number DESC);
CREATE INDEX idx_tx_from_address ON transactions(from_address);
CREATE INDEX idx_tx_to_address ON transactions(to_address) WHERE to_address IS NOT NULL;
CREATE INDEX idx_tx_timestamp ON transactions(timestamp DESC);

-- Event logs table
CREATE TABLE logs (
    id BIGSERIAL PRIMARY KEY,
    transaction_hash BYTEA NOT NULL REFERENCES transactions(hash) ON DELETE CASCADE,
    block_number BIGINT NOT NULL,
    log_index INT NOT NULL,
    address BYTEA NOT NULL,
    topic0 BYTEA,
    topic1 BYTEA,
    topic2 BYTEA,
    topic3 BYTEA,
    data BYTEA,
    timestamp TIMESTAMPTZ NOT NULL,
    UNIQUE(transaction_hash, log_index)
);

SELECT create_hypertable('logs', 'timestamp', if_not_exists => TRUE);

CREATE INDEX idx_logs_address ON logs(address);
CREATE INDEX idx_logs_topic0 ON logs(topic0) WHERE topic0 IS NOT NULL;
CREATE INDEX idx_logs_topic1 ON logs(topic1) WHERE topic1 IS NOT NULL;
CREATE INDEX idx_logs_block_number ON logs(block_number DESC);
CREATE INDEX idx_logs_timestamp ON logs(timestamp DESC);

-- Address balances (snapshot, not time-series)
CREATE TABLE address_balances (
    address BYTEA NOT NULL PRIMARY KEY,
    balance NUMERIC(78, 0) NOT NULL DEFAULT 0,
    nonce BIGINT NOT NULL DEFAULT 0,
    last_updated_block BIGINT NOT NULL,
    last_updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_balances_updated_block ON address_balances(last_updated_block DESC);
