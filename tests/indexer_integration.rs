//! Integration tests for the indexer pipeline.
//!
//! Requires a running TimescaleDB instance:
//!   docker run -d --name tsdb-test -p 5433:5432 \
//!     -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=indexer_test \
//!     timescale/timescaledb:latest-pg16
//!
//! Run with: DATABASE_URL=postgres://test:test@localhost:5433/indexer_test cargo test --features indexer -p avalanche-rs --test indexer_integration

#![cfg(feature = "indexer")]

use std::sync::OnceLock;
use chrono::{TimeZone, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use serial_test::serial;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

static TEST_DB_NAME: OnceLock<String> = OnceLock::new();

fn test_database_name() -> String {
    TEST_DB_NAME
        .get_or_init(|| format!("indexer_integration_{}", std::process::id()))
        .clone()
}

async fn ensure_test_database() {
    let db_name = test_database_name();
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect("postgresql:///postgres")
        .await
        .expect("connect to postgres admin db");

    let exists: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(&db_name)
        .fetch_optional(&admin_pool)
        .await
        .expect("check test database existence");

    if exists.is_none() {
        sqlx::query(&format!("CREATE DATABASE \"{}\"", db_name))
            .execute(&admin_pool)
            .await
            .expect("create test database");
    }

    admin_pool.close().await;
}

fn test_database_url() -> String {
    format!("postgresql:///{}", test_database_name())
}

async fn setup_pool() -> PgPool {
    ensure_test_database().await;
    let url = test_database_url();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("Failed to connect to test database. Is TimescaleDB running?");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    // Clean all tables for a fresh test
    sqlx::query("DELETE FROM logs")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM transactions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM blocks")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM address_balances")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM indexer_state WHERE key NOT IN ('indexer_version')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO indexer_state (key, value_int, updated_at) VALUES ('last_indexed_block', 0, NOW()) ON CONFLICT (key) DO UPDATE SET value_int = 0, updated_at = NOW()")
        .execute(&pool)
        .await
        .unwrap();

    pool
}

fn make_block(number: i64, tx_count: usize) -> avalanche_rs::indexer::IndexedBlock {
    let ts =
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap() + chrono::Duration::seconds(number * 2);
    let hash = {
        let mut h = vec![0u8; 32];
        h[..8].copy_from_slice(&number.to_be_bytes());
        h
    };
    let parent_hash = {
        let mut h = vec![0u8; 32];
        if number > 0 {
            h[..8].copy_from_slice(&(number - 1).to_be_bytes());
        }
        h
    };

    let transactions = (0..tx_count)
        .map(|i| {
            let tx_hash = {
                let mut h = vec![0u8; 32];
                h[..8].copy_from_slice(&number.to_be_bytes());
                h[8..12].copy_from_slice(&(i as u32).to_be_bytes());
                h
            };
            let from = {
                let mut a = vec![0u8; 20];
                a[..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
                a
            };
            let to = {
                let mut a = vec![0u8; 20];
                a[..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
                a
            };

            let logs = vec![avalanche_rs::indexer::IndexedLog {
                transaction_hash: tx_hash.clone(),
                block_number: number,
                log_index: 0,
                address: from.clone(),
                topic0: Some(vec![0xEE; 32]),
                topic1: None,
                topic2: None,
                topic3: None,
                data: Some(vec![0xFF; 64]),
                timestamp: ts,
            }];

            avalanche_rs::indexer::IndexedTransaction {
                hash: tx_hash,
                block_hash: hash.clone(),
                block_number: number,
                from_address: from,
                to_address: Some(to),
                value: "1000000000000000000".to_string(), // 1 AVAX
                gas_price: Some(25_000_000_000),
                gas_limit: Some(21_000),
                gas_used: Some(21_000),
                input: None,
                nonce: Some(i as i64),
                status: Some(1),
                tx_index: i as i32,
                timestamp: ts,
                logs,
            }
        })
        .collect();

    avalanche_rs::indexer::IndexedBlock {
        number,
        hash,
        parent_hash,
        timestamp: ts,
        gas_used: 21_000 * tx_count as i64,
        gas_limit: 8_000_000,
        transaction_count: tx_count as i32,
        size: 1024 + 256 * tx_count as i64,
        transactions,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[serial]
#[tokio::test]
async fn test_write_and_query_single_block() {
    let pool = setup_pool().await;

    // Write a block via IndexerWriter
    let writer = avalanche_rs::indexer::IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    let block = make_block(1, 2);
    writer.index_block(block).await;

    // Give batch processor time to flush
    tokio::time::sleep(Duration::from_secs(6)).await;

    // Query back
    let query = avalanche_rs::indexer::IndexerQuery::new(pool.clone());
    let fetched = query
        .get_block_by_number(1)
        .await
        .expect("query")
        .expect("block should exist");

    assert_eq!(fetched.number, 1);
    assert_eq!(fetched.transaction_count, 2);
    assert_eq!(fetched.gas_used, 42_000);

    // Query transaction
    let tx_hash = {
        let mut h = vec![0u8; 32];
        h[..8].copy_from_slice(&1i64.to_be_bytes());
        h
    };
    let tx = query
        .get_transaction(&tx_hash)
        .await
        .expect("query")
        .expect("tx should exist");
    assert_eq!(tx.block_number, 1);
    assert_eq!(tx.value.to_plain_string(), "1000000000000000000");

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_batch_processing_at_scale() {
    let pool = setup_pool().await;

    let writer = avalanche_rs::indexer::IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    // Send 250 blocks (triggers multiple batch flushes at BATCH_SIZE=100)
    let start = std::time::Instant::now();
    for i in 1..=250 {
        let block = make_block(i, 1);
        writer.index_block(block).await;
    }

    // Wait for all batches to flush
    tokio::time::sleep(Duration::from_secs(8)).await;
    let elapsed = start.elapsed();

    // Verify all blocks were written
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blocks")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 250, "All 250 blocks should be indexed");

    // Verify transactions
    let tx_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transactions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tx_count.0, 250, "250 transactions should be indexed");

    // Verify logs
    let log_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM logs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(log_count.0, 250, "250 logs should be indexed");

    // Performance check: 250 blocks should complete in under 30s
    assert!(
        elapsed.as_secs() < 30,
        "Batch processing took too long: {:?}",
        elapsed
    );

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_idempotent_inserts() {
    let pool = setup_pool().await;

    let writer = avalanche_rs::indexer::IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    // Insert same block twice
    let block = make_block(100, 1);
    writer.index_block(block.clone()).await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    writer.index_block(block).await;
    tokio::time::sleep(Duration::from_secs(6)).await;

    // Should have exactly 1 block
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blocks WHERE number = 100")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1, "Duplicate block should be ignored");

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_restart_resume_preserves_state() {
    let pool = setup_pool().await;

    let writer1 = avalanche_rs::indexer::IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    for number in 1..=3 {
        writer1.index_block(make_block(number, 1)).await;
    }

    // Graceful shutdown should flush queued blocks.
    writer1.close().await;

    let initial_state: (i64,) =
        sqlx::query_as("SELECT value_int FROM indexer_state WHERE key = 'last_indexed_block'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(initial_state.0, 3);

    // Restart and continue forward (no replay of block 3).
    let writer2 = avalanche_rs::indexer::IndexerWriter::new(&test_database_url())
        .await
        .expect("writer restart");

    writer2.index_block(make_block(4, 1)).await;
    writer2.index_block(make_block(5, 1)).await;
    writer2.close().await;

    let final_state: (i64,) =
        sqlx::query_as("SELECT value_int FROM indexer_state WHERE key = 'last_indexed_block'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(final_state.0, 5, "resume should advance state monotonically");

    let block_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blocks")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(block_count.0, 5, "should have 5 unique blocks after restart+resume");

    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_query_address_transactions() {
    let pool = setup_pool().await;

    let writer = avalanche_rs::indexer::IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    for i in 1..=5 {
        writer.index_block(make_block(i, 2)).await;
    }
    tokio::time::sleep(Duration::from_secs(6)).await;

    let query = avalanche_rs::indexer::IndexerQuery::new(pool.clone());

    // Query by from_address
    let from_addr = {
        let mut a = vec![0u8; 20];
        a[..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        a
    };

    let txs = query
        .get_transactions_by_address(&from_addr, 100, 0)
        .await
        .expect("query");
    assert_eq!(txs.len(), 10, "5 blocks * 2 txs each = 10");

    // Test pagination
    let page = query
        .get_transactions_by_address(&from_addr, 3, 0)
        .await
        .expect("query");
    assert_eq!(page.len(), 3);

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_query_logs_with_filters() {
    let pool = setup_pool().await;

    let writer = avalanche_rs::indexer::IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    for i in 1..=10 {
        writer.index_block(make_block(i, 1)).await;
    }
    tokio::time::sleep(Duration::from_secs(6)).await;

    let query = avalanche_rs::indexer::IndexerQuery::new(pool.clone());

    // Query by topic0
    let topic = vec![0xEE; 32];
    let logs = query
        .get_logs(
            None,
            vec![Some(topic.as_slice()), None, None, None],
            None,
            None,
        )
        .await
        .expect("query");
    assert_eq!(logs.len(), 10);

    // Query by block range
    let logs = query
        .get_logs(None, vec![None, None, None, None], Some(3), Some(7))
        .await
        .expect("query");
    assert_eq!(logs.len(), 5);

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_timescaledb_compression_setup() {
    let pool = setup_pool().await;

    // Verify compression policies are configured
    let policies: Vec<(String,)> = sqlx::query_as(
        "SELECT hypertable_name::text FROM timescaledb_information.compression_settings
         WHERE hypertable_name IN ('blocks', 'transactions', 'logs')
         GROUP BY hypertable_name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    let names: Vec<&str> = policies.iter().map(|p| p.0.as_str()).collect();
    assert!(names.contains(&"blocks"), "blocks should have compression");
    assert!(
        names.contains(&"transactions"),
        "transactions should have compression"
    );
    assert!(names.contains(&"logs"), "logs should have compression");

    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_continuous_aggregates_exist() {
    let pool = setup_pool().await;

    // Verify continuous aggregates were created
    let aggs: Vec<(String,)> = sqlx::query_as(
        "SELECT view_name::text FROM timescaledb_information.continuous_aggregates
         WHERE view_name IN ('blocks_hourly', 'blocks_daily', 'tx_volume_hourly')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    let names: Vec<&str> = aggs.iter().map(|a| a.0.as_str()).collect();
    assert!(names.contains(&"blocks_hourly"));
    assert!(names.contains(&"blocks_daily"));
    assert!(names.contains(&"tx_volume_hourly"));

    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_indexer_state_table() {
    let pool = setup_pool().await;

    // Verify indexer_state was created with defaults
    let row: (i64,) =
        sqlx::query_as("SELECT value_int FROM indexer_state WHERE key = 'last_indexed_block'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.0, 0);

    // Update state
    sqlx::query("UPDATE indexer_state SET value_int = 1000, updated_at = NOW() WHERE key = 'last_indexed_block'")
        .execute(&pool)
        .await
        .unwrap();

    let row: (i64,) =
        sqlx::query_as("SELECT value_int FROM indexer_state WHERE key = 'last_indexed_block'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.0, 1000);

    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_retention_policies_configured() {
    let pool = setup_pool().await;

    // Verify retention policies exist
    let policies: Vec<(String,)> = sqlx::query_as(
        "SELECT hypertable_name::text FROM timescaledb_information.jobs
         WHERE proc_name = 'policy_retention'
         AND hypertable_name IN ('blocks', 'transactions', 'logs')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(
        policies.len() >= 3,
        "Should have retention policies for blocks, transactions, logs"
    );

    pool.close().await;
}
