//! API handler integration tests for the indexer REST endpoints.
//!
//! Tests request/response flow, error handling, hex encoding, pagination, and filtering.

#![cfg(feature = "indexer")]

use std::sync::OnceLock;
use avalanche_rs::{
    api::routes,
    indexer::{IndexedBlock, IndexedLog, IndexedTransaction, IndexerQuery, IndexerWriter},
};
use axum::http::StatusCode;
use chrono::{Duration, TimeZone, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration as StdDuration;
use serial_test::serial;
use tower::ServiceExt;

// ============================================================================
// SETUP
// ============================================================================

static TEST_DB_NAME: OnceLock<String> = OnceLock::new();

fn test_database_name() -> String {
    TEST_DB_NAME
        .get_or_init(|| format!("api_integration_{}", std::process::id()))
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
        .acquire_timeout(StdDuration::from_secs(5))
        .connect(&url)
        .await
        .expect("Failed to connect to test DB");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let _ = sqlx::query("DELETE FROM logs").execute(&pool).await;
    let _ = sqlx::query("DELETE FROM transactions").execute(&pool).await;
    let _ = sqlx::query("DELETE FROM blocks").execute(&pool).await;
    let _ = sqlx::query("DELETE FROM address_balances").execute(&pool).await;
    let _ = sqlx::query("DELETE FROM indexer_state WHERE key NOT IN ('indexer_version')").execute(&pool).await;
    let _ = sqlx::query("INSERT INTO indexer_state (key, value_int, updated_at) VALUES ('last_indexed_block', 0, NOW()) ON CONFLICT (key) DO UPDATE SET value_int = 0, updated_at = NOW()").execute(&pool).await;

    pool
}

fn make_block(number: i64, tx_count: usize) -> IndexedBlock {
    let ts = Utc.with_ymd_and_hms(2024, 1, 15, 12, 30, 0).unwrap() + Duration::seconds(number * 10);

    let hash = {
        let mut h = vec![0u8; 32];
        h[0..8].copy_from_slice(&number.to_be_bytes());
        h
    };

    let parent_hash = {
        let mut h = vec![0u8; 32];
        if number > 0 {
            h[0..8].copy_from_slice(&(number - 1).to_be_bytes());
        }
        h
    };

    let transactions = (0..tx_count)
        .map(|i| {
            let tx_hash = {
                let mut h = vec![0u8; 32];
                h[0..8].copy_from_slice(&number.to_be_bytes());
                h[8..12].copy_from_slice(&(i as u32).to_be_bytes());
                h
            };

            let from = {
                let mut a = vec![0u8; 20];
                a[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
                a
            };

            let to = {
                let mut a = vec![0u8; 20];
                a[0..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
                a
            };

            IndexedTransaction {
                hash: tx_hash.clone(),
                block_hash: hash.clone(),
                block_number: number,
                from_address: from.clone(),
                to_address: Some(to),
                value: (1_000_000_000_000_000_000u128 * (i as u128 + 1)).to_string(),
                gas_price: Some(25_000_000_000i64),
                gas_limit: Some(21_000i64),
                gas_used: Some(21_000i64),
                input: None,
                nonce: Some(i as i64),
                status: Some(1),
                tx_index: i as i32,
                timestamp: ts,
                logs: vec![IndexedLog {
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
                }],
            }
        })
        .collect();

    IndexedBlock {
        number,
        hash,
        parent_hash,
        timestamp: ts,
        gas_used: (21_000 * tx_count) as i64,
        gas_limit: 8_000_000i64,
        transaction_count: tx_count as i32,
        size: (1024 + 256 * tx_count) as i64,
        transactions,
    }
}

// ============================================================================
// TEST: Health endpoint
// ============================================================================

#[serial]
#[tokio::test]
async fn test_health_endpoint() {
    let pool = setup_pool().await;
    let query = IndexerQuery::new(pool.clone());
    let app = routes::router(query);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    pool.close().await;
}

// ============================================================================
// TEST: Get block by number
// ============================================================================

#[serial]
#[tokio::test]
async fn test_get_block_by_number() {
    let pool = setup_pool().await;
    let writer = IndexerWriter::new(&test_database_url())
        .await
        .unwrap();

    let block = make_block(42, 2);
    writer.index_block(block).await;

    tokio::time::sleep(StdDuration::from_secs(6)).await;

    let query = IndexerQuery::new(pool.clone());
    let app = routes::router(query);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/blocks/42")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();

    // Response should be valid JSON
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(json["number"], 42);
    assert_eq!(json["transaction_count"], 2);

    writer.close().await;
    pool.close().await;
}

// ============================================================================
// TEST: Get block by hash
// ============================================================================

#[serial]
#[tokio::test]
async fn test_get_block_by_hash() {
    let pool = setup_pool().await;

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .unwrap();

    let block = make_block(100, 1);
    let block_hash = block.hash.clone();
    writer.index_block(block).await;

    tokio::time::sleep(StdDuration::from_secs(6)).await;

    let hash_hex = format!("0x{}", hex::encode(&block_hash));
    let query = IndexerQuery::new(pool.clone());
    let app = routes::router(query);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(&format!("/api/blocks/hash/{}", hash_hex))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    assert_eq!(json["number"], 100);

    writer.close().await;
    pool.close().await;
}

// ============================================================================
// TEST: Get block by invalid hash (400)
// ============================================================================

#[serial]
#[tokio::test]
async fn test_get_block_invalid_hash_format() {
    let pool = setup_pool().await;
    let query = IndexerQuery::new(pool.clone());
    let app = routes::router(query);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/blocks/hash/not_a_hex_string")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    pool.close().await;
}

// ============================================================================
// TEST: Get transaction by hash
// ============================================================================

#[serial]
#[tokio::test]
async fn test_get_transaction_by_hash() {
    let pool = setup_pool().await;

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .unwrap();

    let block = make_block(200, 2);
    let first_tx_hash = block.transactions[0].hash.clone();
    writer.index_block(block).await;

    tokio::time::sleep(StdDuration::from_secs(6)).await;

    let tx_hex = format!("0x{}", hex::encode(&first_tx_hash));
    let query = IndexerQuery::new(pool.clone());
    let app = routes::router(query);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(&format!("/api/tx/{}", tx_hex))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    assert_eq!(json["block_number"], 200);
    // Value should be preserved as numeric string (not truncated)
    assert!(json["value"].is_string());

    writer.close().await;
    pool.close().await;
}

// ============================================================================
// TEST: Get address transactions
// ============================================================================

#[serial]
#[tokio::test]
async fn test_get_address_transactions() {
    let pool = setup_pool().await;

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .unwrap();

    let block = make_block(300, 2);
    let from_addr = block.transactions[0].from_address.clone();
    writer.index_block(block).await;

    tokio::time::sleep(StdDuration::from_secs(6)).await;

    let addr_hex = format!("0x{}", hex::encode(&from_addr));
    let query = IndexerQuery::new(pool.clone());
    let app = routes::router(query);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(&format!("/api/address/{}/transactions?limit=10&offset=0", addr_hex))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    // Should be an array
    assert!(json.is_array());

    writer.close().await;
    pool.close().await;
}

// ============================================================================
// TEST: Get logs with filters
// ============================================================================

#[serial]
#[tokio::test]
async fn test_get_logs_with_address_filter() {
    let pool = setup_pool().await;

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .unwrap();

    let block = make_block(400, 1);
    let log_address = block.transactions[0].logs[0].address.clone();
    writer.index_block(block).await;

    tokio::time::sleep(StdDuration::from_secs(6)).await;

    let addr_hex = format!("0x{}", hex::encode(&log_address));
    let query = IndexerQuery::new(pool.clone());
    let app = routes::router(query);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(&format!("/api/logs?address={}&fromBlock=0&toBlock=500", addr_hex))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    assert!(json.is_array());

    writer.close().await;
    pool.close().await;
}

// ============================================================================
// TEST: Pagination parameters
// ============================================================================

#[serial]
#[tokio::test]
async fn test_pagination_limit_and_offset() {
    let pool = setup_pool().await;

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .unwrap();

    // Create blocks with same sender
    for i in 1..=5 {
        let block = make_block(i, 1);
        writer.index_block(block).await;
    }

    tokio::time::sleep(StdDuration::from_secs(6)).await;

    let from_addr = {
        let mut a = vec![0u8; 20];
        a[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        a
    };
    let addr_hex = format!("0x{}", hex::encode(&from_addr));

    let query = IndexerQuery::new(pool.clone());
    let app = routes::router(query);

    // Request with limit=2, offset=1
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(&format!(
                    "/api/address/{}/transactions?limit=2&offset=1",
                    addr_hex
                ))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    assert!(json.is_array());
    // Should return at most 2 items due to limit
    assert!(json.as_array().unwrap().len() <= 2);

    writer.close().await;
    pool.close().await;
}

// ============================================================================
// TEST: Metrics endpoint
// ============================================================================

#[serial]
#[tokio::test]
async fn test_metrics_endpoint() {
    let pool = setup_pool().await;

    let query = IndexerQuery::new(pool.clone());
    let app = routes::router(query);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();

    // Prometheus format: should contain HELP and TYPE lines
    assert!(text.contains("indexer_blocks_indexed_total"));

    pool.close().await;
}

// ============================================================================
// TEST: 404 Not Found
// ============================================================================

#[serial]
#[tokio::test]
async fn test_nonexistent_block_returns_404() {
    let pool = setup_pool().await;
    let query = IndexerQuery::new(pool.clone());
    let app = routes::router(query);

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/blocks/99999999")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    pool.close().await;
}

// ============================================================================
// TEST: Hex encoding round-trip
// ============================================================================

#[serial]
#[tokio::test]
async fn test_hex_encoding_preserves_data() {
    let pool = setup_pool().await;

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .unwrap();

    let block = make_block(500, 1);
    writer.index_block(block).await;

    tokio::time::sleep(StdDuration::from_secs(6)).await;

    let query = IndexerQuery::new(pool.clone());
    let fetched = query
        .get_block_by_number(500)
        .await
        .unwrap()
        .unwrap();

    // Verify hex encoding didn't truncate or corrupt the data
    assert!(fetched.hash.len() == 32);
    assert!(fetched.parent_hash.len() == 32);

    // API response should have "0x" prefix
    let app = routes::router(IndexerQuery::new(pool.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/blocks/500")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();

    let hash_str = json["hash"].as_str().unwrap();
    assert!(hash_str.starts_with("0x"), "hash should have 0x prefix");
    assert_eq!(hash_str.len(), 2 + 64, "hash should be 66 chars (0x + 64 hex)");

    writer.close().await;
    pool.close().await;
}
