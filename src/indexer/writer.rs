use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info};

use super::metrics::IndexerMetrics;

/// Data types for indexing — mapped from core types to DB schema.

#[derive(Debug, Clone)]
pub struct IndexedBlock {
    pub number: i64,
    pub hash: Vec<u8>,
    pub parent_hash: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub gas_used: i64,
    pub gas_limit: i64,
    pub transaction_count: i32,
    pub size: i64,
    pub transactions: Vec<IndexedTransaction>,
}

#[derive(Debug, Clone)]
pub struct IndexedTransaction {
    pub hash: Vec<u8>,
    pub block_hash: Vec<u8>,
    pub block_number: i64,
    pub from_address: Vec<u8>,
    pub to_address: Option<Vec<u8>>,
    pub value: String, // NUMERIC(78,0) as string
    pub gas_price: Option<i64>,
    pub gas_limit: Option<i64>,
    pub gas_used: Option<i64>,
    pub input: Option<Vec<u8>>,
    pub nonce: Option<i64>,
    pub status: Option<i16>,
    pub tx_index: i32,
    pub timestamp: DateTime<Utc>,
    pub logs: Vec<IndexedLog>,
}

#[derive(Debug, Clone)]
pub struct IndexedLog {
    pub transaction_hash: Vec<u8>,
    pub block_number: i64,
    pub log_index: i32,
    pub address: Vec<u8>,
    pub topic0: Option<Vec<u8>>,
    pub topic1: Option<Vec<u8>>,
    pub topic2: Option<Vec<u8>>,
    pub topic3: Option<Vec<u8>>,
    pub data: Option<Vec<u8>>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct BalanceUpdate {
    pub address: Vec<u8>,
    pub balance: String, // NUMERIC(78,0) as string
    pub nonce: i64,
    pub block_number: i64,
    pub updated_at: DateTime<Utc>,
}

const BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

pub struct IndexerWriter {
    pool: PgPool,
    tx: mpsc::Sender<IndexedBlock>,
    handle: JoinHandle<()>,
}

impl IndexerWriter {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .min_connections(5)
            .max_connections(20)
            .acquire_timeout(Duration::from_secs(10))
            .connect(database_url)
            .await?;

        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await?;

        let (tx, rx) = mpsc::channel::<IndexedBlock>(1024);

        // Spawn background batch processor
        let bg_pool = pool.clone();
        let handle = tokio::spawn(batch_processor(bg_pool, rx));
        info!("Indexer batch processor started");

        Ok(Self { pool, tx, handle })
    }

    /// Send a block to the indexing queue. Non-blocking.
    pub async fn index_block(&self, block: IndexedBlock) {
        let metrics = IndexerMetrics::global();
        debug!(
            "Indexer: enqueuing block #{} (hash={:02x}{:02x}{:02x}{:02x}..., {} txs)",
            block.number,
            block.hash.get(0).unwrap_or(&0),
            block.hash.get(1).unwrap_or(&0),
            block.hash.get(2).unwrap_or(&0),
            block.hash.get(3).unwrap_or(&0),
            block.transactions.len()
        );
        if let Err(e) = self.tx.send(block).await {
            error!("Failed to enqueue block for indexing: {}", e);
        }
        let queued_blocks = self.tx.max_capacity().saturating_sub(self.tx.capacity()) as i64;
        metrics.queue_depth.set(queued_blocks);
    }

    /// Get a clone of the connection pool (for IndexerQuery).
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    pub async fn close(self) {
        drop(self.tx); // signal shutdown to batch processor
        let _ = self.handle.await;
        self.pool.close().await;
    }
}

async fn batch_processor(pool: PgPool, mut rx: mpsc::Receiver<IndexedBlock>) {
    let metrics = IndexerMetrics::global();
    let mut batch: Vec<IndexedBlock> = Vec::with_capacity(BATCH_SIZE);
    let mut flush_interval = tokio::time::interval(FLUSH_INTERVAL);
    flush_interval.tick().await; // skip immediate tick

    info!("Indexer batch processor: waiting for blocks...");

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(block) => {
                        debug!("Batch processor: received block #{}", block.number);
                        batch.push(block);
                        metrics.queue_depth.set(rx.len() as i64);
                        if batch.len() >= BATCH_SIZE {
                            info!("Batch processor: reached {} blocks, flushing...", batch.len());
                            flush_batch(&pool, &mut batch).await;
                            metrics.queue_depth.set(rx.len() as i64);
                        }
                    }
                    None => {
                        // Channel closed — flush remaining and exit
                        if !batch.is_empty() {
                            info!("Batch processor: channel closed, flushing {} remaining blocks", batch.len());
                            flush_batch(&pool, &mut batch).await;
                        }
                        metrics.queue_depth.set(0);
                        info!("Indexer batch processor shutting down");
                        return;
                    }
                }
            }
            _ = flush_interval.tick() => {
                if !batch.is_empty() {
                    info!("Batch processor: {} blocks pending, flushing on timer...", batch.len());
                    flush_batch(&pool, &mut batch).await;
                }
                metrics.queue_depth.set(rx.len() as i64);
            }
        }
    }
}

async fn flush_batch(pool: &PgPool, batch: &mut Vec<IndexedBlock>) {
    let count = batch.len();
    let first_num = batch.first().map(|b| b.number).unwrap_or(0);
    let last_num = batch.last().map(|b| b.number).unwrap_or(0);
    let metrics = IndexerMetrics::global();

    debug!(
        "Flushing batch of {} blocks (#{} to #{})",
        count, first_num, last_num
    );

    let start = std::time::Instant::now();
    match write_batch(pool, batch).await {
        Ok(stats) => {
            let elapsed = start.elapsed();
            metrics.batches_flushed.inc();
            metrics.batch_size.observe(count as f64);
            metrics.batch_write_duration.observe(elapsed.as_secs_f64());
            metrics.blocks_indexed.inc_by(stats.blocks as u64);
            metrics.transactions_indexed.inc_by(stats.txs as u64);
            metrics.logs_indexed.inc_by(stats.logs as u64);
            metrics.indexer_height.set(last_num);
            // Update indexer_state for catchup gap detection
            if let Err(e) = super::catchup::update_indexer_state(pool, last_num).await {
                debug!("Failed to update indexer_state: {}", e);
            }
            info!(
                "Indexed batch of {} blocks (#{} to #{}) in {:.1}ms",
                count,
                first_num,
                last_num,
                elapsed.as_secs_f64() * 1000.0
            );
        }
        Err(e) => {
            metrics.write_errors.inc();
            error!("Failed to write batch of {} blocks: {}", count, e);
        }
    }
    batch.clear();
}

struct BatchStats {
    blocks: usize,
    txs: usize,
    logs: usize,
}

async fn write_batch(pool: &PgPool, blocks: &[IndexedBlock]) -> Result<BatchStats, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let mut blocks_inserted = 0;
    let mut txs_inserted = 0;
    let mut logs_inserted = 0;

    for block in blocks {
        // 1. Insert block (ON CONFLICT with both hash AND timestamp for TimescaleDB)
        let result = sqlx::query(
            "INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, size)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (hash, timestamp) DO NOTHING",
        )
        .bind(block.number)
        .bind(&block.hash)
        .bind(&block.parent_hash)
        .bind(block.timestamp)
        .bind(block.gas_used)
        .bind(block.gas_limit)
        .bind(block.transaction_count)
        .bind(block.size)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() > 0 {
            blocks_inserted += 1;
        }

        // 2. Insert transactions
        for txn in &block.transactions {
            let result = sqlx::query(
                "INSERT INTO transactions (hash, block_hash, block_number, from_address, to_address, value, gas_price, gas_limit, gas_used, input, nonce, status, tx_index, timestamp)
                 VALUES ($1, $2, $3, $4, $5, $6::numeric, $7, $8, $9, $10, $11, $12, $13, $14)
                 ON CONFLICT (hash, timestamp) DO NOTHING",
            )
            .bind(&txn.hash)
            .bind(&txn.block_hash)
            .bind(txn.block_number)
            .bind(&txn.from_address)
            .bind(&txn.to_address)
            .bind(&txn.value)
            .bind(txn.gas_price)
            .bind(txn.gas_limit)
            .bind(txn.gas_used)
            .bind(&txn.input)
            .bind(txn.nonce)
            .bind(txn.status)
            .bind(txn.tx_index)
            .bind(txn.timestamp)
            .execute(&mut *tx)
            .await?;

            let txn_inserted = result.rows_affected() > 0;
            if txn_inserted {
                txs_inserted += 1;
                super::balance::apply_transaction_balance_update(&mut tx, txn).await?;
            }

            // 3. Insert logs
            for log in &txn.logs {
                let result = sqlx::query(
                    "INSERT INTO logs (transaction_hash, block_number, log_index, address, topic0, topic1, topic2, topic3, data, timestamp)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                     ON CONFLICT (transaction_hash, log_index, timestamp) DO NOTHING",
                )
                .bind(&log.transaction_hash)
                .bind(log.block_number)
                .bind(log.log_index)
                .bind(&log.address)
                .bind(&log.topic0)
                .bind(&log.topic1)
                .bind(&log.topic2)
                .bind(&log.topic3)
                .bind(&log.data)
                .bind(log.timestamp)
                .execute(&mut *tx)
                .await?;

                if result.rows_affected() > 0 {
                    logs_inserted += 1;
                }
            }
        }
    }

    tx.commit().await?;
    debug!(
        "DB write complete: {} blocks, {} txs, {} logs inserted",
        blocks_inserted, txs_inserted, logs_inserted
    );
    Ok(BatchStats {
        blocks: blocks_inserted,
        txs: txs_inserted,
        logs: logs_inserted,
    })
}
