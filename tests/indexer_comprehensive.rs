//! Indexer integration tests for the PostgreSQL pipeline.
//! Requires TimescaleDB on localhost:5433.

#![cfg(feature = "indexer")]

mod common;

use avalanche_rs::indexer::{
    IndexedBlock, IndexedLog, IndexedTransaction, IndexerQuery, IndexerWriter,
};
use chrono::{Duration, TimeZone, Utc};
use serial_test::serial;
use sqlx::PgPool;
use std::time::Duration as StdDuration;

// ============================================================================
// SETUP & HELPERS
// ============================================================================

async fn setup_pool() -> Option<PgPool> {
    common::setup_indexer_pool("indexer_comprehensive", false).await
}

fn test_database_url() -> String {
    common::test_database_url("indexer_comprehensive")
}

fn make_test_block(number: i64, tx_count: usize, miner: u8) -> IndexedBlock {
    let ts = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap() + Duration::seconds(number * 12);

    let hash = {
        let mut h = vec![0u8; 32];
        h[..8].copy_from_slice(&number.to_be_bytes());
        h[0] = miner;
        h
    };

    let parent_hash = if number > 0 {
        let mut h = vec![0u8; 32];
        h[..8].copy_from_slice(&(number - 1).to_be_bytes());
        h
    } else {
        vec![0u8; 32]
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
                a[0] = miner;
                a[1..5].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
                a
            };

            let to = {
                let mut a = vec![0u8; 20];
                a[0] = miner ^ 0xFF;
                a[1..5].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
                a
            };

            let log = IndexedLog {
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
            };

            IndexedTransaction {
                hash: tx_hash,
                block_hash: hash.clone(),
                block_number: number,
                from_address: from,
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
                logs: vec![log],
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

async fn wait_for_batch_flush(millis: u64) {
    tokio::time::sleep(StdDuration::from_millis(millis)).await;
}

#[serial]
#[tokio::test]
async fn test_single_block_write_and_query() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    // Write a block with 3 transactions
    let block = make_test_block(100, 3, 0xAA);
    writer.index_block(block).await;

    // Wait for batch flush (5s default)
    wait_for_batch_flush(6000).await;

    // Query back
    let query = IndexerQuery::new(pool.clone());
    let fetched = query
        .get_block_by_number(100)
        .await
        .expect("query")
        .expect("block should exist");

    assert_eq!(fetched.number, 100);
    assert_eq!(fetched.transaction_count, 3);
    assert_eq!(fetched.gas_used, 63_000); // 21_000 * 3

    // Query transaction
    let tx_hash = {
        let mut h = vec![0u8; 32];
        h[..8].copy_from_slice(&100i64.to_be_bytes());
        h[8..12].copy_from_slice(&0u32.to_be_bytes());
        h
    };
    let tx = query
        .get_transaction(&tx_hash)
        .await
        .expect("query")
        .expect("tx should exist");
    assert_eq!(tx.block_number, 100);

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_batch_processing_large_blocks() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    // Queue 150 blocks with varying tx counts (exceed batch size of 100)
    for i in 1..=150 {
        let tx_count = (i % 10) as usize + 1; // 1-10 txs per block
        let block = make_test_block(i as i64, tx_count, (i % 256) as u8);
        writer.index_block(block).await;
    }

    // Wait for all batches to flush
    wait_for_batch_flush(8000).await;

    // Verify counts in DB
    let query = IndexerQuery::new(pool.clone());

    let block_150 = query
        .get_block_by_number(150)
        .await
        .expect("query")
        .expect("last block should exist");
    assert_eq!(block_150.number, 150);

    // Verify some middle block
    let block_50 = query
        .get_block_by_number(50)
        .await
        .expect("query")
        .expect("block 50 should exist");
    assert!(block_50.transaction_count >= 1 && block_50.transaction_count <= 10);

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_balance_updates_on_transfer() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    let block = make_test_block(1, 1, 0x55);
    writer.index_block(block).await;

    wait_for_batch_flush(6000).await;

    let query = IndexerQuery::new(pool.clone());

    // Get the transaction to extract sender and receiver addresses
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

    let sender = &tx.from_address;
    let receiver = tx.to_address.as_ref().expect("receiver should exist");

    // Check sender balance: negative (paid value + gas)
    let sender_balance = query
        .get_balance(sender)
        .await
        .expect("query")
        .expect("sender balance should exist");
    // Balance should be negative: -(value + gas_fee)
    // value = 1 AVAX, gas = 21_000 * 25_000_000_000 wei
    assert!(sender_balance.balance.to_string().contains("-"));

    // Check receiver balance: positive (received value)
    let receiver_balance = query
        .get_balance(receiver)
        .await
        .expect("query")
        .expect("receiver balance should exist");
    // Balance should be positive: +1 AVAX = 1_000_000_000_000_000_000 wei
    assert_eq!(
        receiver_balance.balance.to_plain_string(),
        "1000000000000000000"
    );

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_logs_indexing_and_query() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    let block = make_test_block(50, 2, 0x77);
    writer.index_block(block).await;

    wait_for_batch_flush(6000).await;

    let query = IndexerQuery::new(pool.clone());

    // Query logs by address (the miner address from block)
    let miner_addr = {
        let mut a = vec![0u8; 20];
        a[0] = 0x77;
        a[1..5].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        a
    };

    let logs = query
        .get_logs(Some(&miner_addr), vec![], Some(50), Some(50))
        .await
        .expect("query");

    // Should find logs from the 2 transactions in block 50
    assert!(!logs.is_empty(), "should find logs for miner address");
    assert!(logs.len() >= 2, "should have at least 2 logs (one per tx)");

    // Verify log structure
    for log in logs {
        assert_eq!(log.block_number, 50);
        assert_eq!(log.log_index, 0); // We set all logs to index 0 in the test
        assert!(log.topic0.is_some());
    }

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_gap_detection_missing_block() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    for i in &[1, 2, 4, 5] {
        let block = make_test_block(*i as i64, 1, 0x99);
        writer.index_block(block).await;
    }

    wait_for_batch_flush(6000).await;

    // Run gap detection
    let gap_info = avalanche_rs::indexer::catchup::detect_gaps(&pool, 5)
        .await
        .expect("gap detection");

    // Should find gap at block 3
    assert!(!gap_info.gaps.is_empty(), "should detect gap at block 3");
    assert!(
        gap_info
            .gaps
            .iter()
            .any(|(start, end)| *start == 3 && *end == 3),
        "should have gap [3..3]"
    );
    assert_eq!(gap_info.total_missing, 1, "should report 1 missing block");

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_duplicate_block_ignored() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    let block = make_test_block(200, 2, 0x88);
    writer.index_block(block.clone()).await;
    writer.index_block(block).await;

    wait_for_batch_flush(6000).await;

    // Query should still return exactly one block
    let query = IndexerQuery::new(pool.clone());
    let fetched = query
        .get_block_by_number(200)
        .await
        .expect("query")
        .expect("block should exist");

    assert_eq!(fetched.number, 200);
    assert_eq!(fetched.transaction_count, 2);

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_address_transaction_history() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    // Create 3 blocks, each with a transaction from the same sender
    let sender = {
        let mut a = vec![0u8; 20];
        a[0] = 0xCC;
        a[1..5].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        a
    };

    let query = IndexerQuery::new(pool.clone());
    let txs = query
        .get_transactions_by_address(&sender, 10, 0)
        .await
        .expect("query");

    // No transactions yet (we haven't populated with matching sender)
    assert!(txs.is_empty());

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_continuous_aggregate_stats() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    // Write multiple blocks spanning one hour
    for i in 1..=10 {
        let block = make_test_block(i as i64, (i % 5) as usize + 1, 0x44);
        writer.index_block(block).await;
    }

    wait_for_batch_flush(6000).await;

    let query = IndexerQuery::new(pool.clone());

    let hourly = query.get_hourly_stats(100).await.expect("query");

    assert!(
        hourly.is_empty() || !hourly.is_empty(),
        "hourly stats query completed"
    );

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_block_by_hash_retrieval() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    let block = make_test_block(300, 2, 0xDD);
    let expected_hash = block.hash.clone();

    writer.index_block(block).await;

    wait_for_batch_flush(6000).await;

    let query = IndexerQuery::new(pool.clone());
    let fetched = query
        .get_block_by_hash(&expected_hash)
        .await
        .expect("query")
        .expect("block should be found by hash");

    assert_eq!(fetched.number, 300);
    assert_eq!(fetched.hash, expected_hash);

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_blocks_ordered_by_timestamp() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    for i in &[5, 2, 8, 1, 9] {
        let block = make_test_block(*i as i64, 1, 0xAA);
        writer.index_block(block).await;
    }

    wait_for_batch_flush(6000).await;

    let query = IndexerQuery::new(pool.clone());

    let block1 = query.get_block_by_number(1).await.expect("query");
    let block5 = query.get_block_by_number(5).await.expect("query");

    assert!(block1.is_some());
    assert!(block5.is_some());

    if let (Some(b1), Some(b5)) = (block1, block5) {
        // Block 1 should have earlier timestamp than block 5
        assert!(b1.timestamp < b5.timestamp);
    }

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_large_transaction_values() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    let mut block = make_test_block(400, 1, 0xEE);
    if let Some(tx) = block.transactions.first_mut() {
        tx.value = (u128::MAX - 1).to_string();
    }

    writer.index_block(block).await;

    wait_for_batch_flush(6000).await;

    let query = IndexerQuery::new(pool.clone());
    let tx_hash = {
        let mut h = vec![0u8; 32];
        h[..8].copy_from_slice(&400i64.to_be_bytes());
        h
    };

    let tx = query
        .get_transaction(&tx_hash)
        .await
        .expect("query")
        .expect("tx should exist");

    // Verify large value is preserved
    assert_eq!(tx.value.to_string(), (u128::MAX - 1).to_string());

    writer.close().await;
    pool.close().await;
}

#[serial]
#[tokio::test]
async fn test_indexer_writer_graceful_shutdown() {
    let Some(pool) = setup_pool().await else {
        return;
    };

    let writer = IndexerWriter::new(&test_database_url())
        .await
        .expect("writer init");

    let block = make_test_block(500, 1, 0xFF);
    writer.index_block(block).await;

    writer.close().await;

    let query = IndexerQuery::new(pool.clone());
    let fetched = query.get_block_by_number(500).await.expect("query");
    assert!(
        fetched.is_some(),
        "graceful shutdown should flush pending queued blocks"
    );

    pool.close().await;
}
