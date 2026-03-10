use chrono::{DateTime, Utc};
use sqlx::types::BigDecimal;
use sqlx::PgPool;

/// Row types returned from queries, matching the DB schema.

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct BlockRow {
    pub number: i64,
    pub hash: Vec<u8>,
    pub parent_hash: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub gas_used: i64,
    pub gas_limit: i64,
    pub transaction_count: i32,
    pub size: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TransactionRow {
    pub hash: Vec<u8>,
    pub block_hash: Vec<u8>,
    pub block_number: i64,
    pub from_address: Vec<u8>,
    pub to_address: Option<Vec<u8>>,
    pub value: sqlx::types::BigDecimal,
    pub gas_price: Option<i64>,
    pub gas_limit: Option<i64>,
    pub gas_used: Option<i64>,
    pub input: Option<Vec<u8>>,
    pub nonce: Option<i64>,
    pub status: Option<i16>,
    pub tx_index: i32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct LogRow {
    pub id: i64,
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

pub struct IndexerQuery {
    pool: PgPool,
}

impl IndexerQuery {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_block_by_number(&self, number: u64) -> Result<Option<BlockRow>, sqlx::Error> {
        sqlx::query_as::<_, BlockRow>(
            "SELECT number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, size
             FROM blocks WHERE number = $1 LIMIT 1",
        )
        .bind(number as i64)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn get_block_by_hash(&self, hash: &[u8]) -> Result<Option<BlockRow>, sqlx::Error> {
        sqlx::query_as::<_, BlockRow>(
            "SELECT number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, size
             FROM blocks WHERE hash = $1 LIMIT 1",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn get_transaction(
        &self,
        hash: &[u8],
    ) -> Result<Option<TransactionRow>, sqlx::Error> {
        sqlx::query_as::<_, TransactionRow>(
            "SELECT hash, block_hash, block_number, from_address, to_address, value, gas_price, gas_limit, gas_used, input, nonce, status, tx_index, timestamp
             FROM transactions WHERE hash = $1 LIMIT 1",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn get_transactions_by_address(
        &self,
        addr: &[u8],
        limit: usize,
        offset: usize,
    ) -> Result<Vec<TransactionRow>, sqlx::Error> {
        sqlx::query_as::<_, TransactionRow>(
            "SELECT hash, block_hash, block_number, from_address, to_address, value, gas_price, gas_limit, gas_used, input, nonce, status, tx_index, timestamp
             FROM transactions
             WHERE from_address = $1 OR to_address = $1
             ORDER BY block_number DESC, tx_index DESC
             LIMIT $2 OFFSET $3",
        )
        .bind(addr)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_logs(
        &self,
        address: Option<&[u8]>,
        topics: Vec<Option<&[u8]>>,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<LogRow>, sqlx::Error> {
        // Build dynamic query with optional filters
        let mut query = String::from(
            "SELECT id, transaction_hash, block_number, log_index, address, topic0, topic1, topic2, topic3, data, timestamp FROM logs WHERE 1=1",
        );
        let mut param_idx = 1u32;

        if address.is_some() {
            query.push_str(&format!(" AND address = ${}", param_idx));
            param_idx += 1;
        }

        // topic filters: topics[0] = topic0, topics[1] = topic1, etc.
        let topic_columns = ["topic0", "topic1", "topic2", "topic3"];
        let mut topic_bind_indices = Vec::new();
        for (i, topic) in topics.iter().enumerate() {
            if i >= 4 {
                break;
            }
            if topic.is_some() {
                query.push_str(&format!(" AND {} = ${}", topic_columns[i], param_idx));
                topic_bind_indices.push((i, param_idx));
                param_idx += 1;
            }
        }

        if from_block.is_some() {
            query.push_str(&format!(" AND block_number >= ${}", param_idx));
            param_idx += 1;
        }
        if to_block.is_some() {
            query.push_str(&format!(" AND block_number <= ${}", param_idx));
            #[allow(unused_assignments)]
            {
                param_idx += 1;
            }
        }

        query.push_str(" ORDER BY block_number DESC, log_index ASC LIMIT 1000");

        // Use sqlx::query_as with dynamic bindings
        let mut q = sqlx::query_as::<_, LogRow>(&query);

        if let Some(addr) = address {
            q = q.bind(addr.to_vec());
        }
        for (i, _) in &topic_bind_indices {
            if let Some(Some(topic_data)) = topics.get(*i) {
                q = q.bind(topic_data.to_vec());
            }
        }
        if let Some(from) = from_block {
            q = q.bind(from as i64);
        }
        if let Some(to) = to_block {
            q = q.bind(to as i64);
        }

        q.fetch_all(&self.pool).await
    }

    // -----------------------------------------------------------------------
    // Continuous aggregate queries
    // -----------------------------------------------------------------------

    pub async fn get_hourly_stats(&self, limit: usize) -> Result<Vec<HourlyStatsRow>, sqlx::Error> {
        sqlx::query_as::<_, HourlyStatsRow>(
            "SELECT bucket, block_count, tx_count, total_gas_used, avg_gas_used, total_size
             FROM blocks_hourly
             ORDER BY bucket DESC
             LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_daily_stats(&self, limit: usize) -> Result<Vec<HourlyStatsRow>, sqlx::Error> {
        sqlx::query_as::<_, HourlyStatsRow>(
            "SELECT bucket, block_count, tx_count, total_gas_used, avg_gas_used, total_size
             FROM blocks_daily
             ORDER BY bucket DESC
             LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
    }

    // -----------------------------------------------------------------------
    // Balance queries
    // -----------------------------------------------------------------------

    pub async fn get_balance(&self, address: &[u8]) -> Result<Option<BalanceRow>, sqlx::Error> {
        sqlx::query_as::<_, BalanceRow>(
            "SELECT address, balance, nonce, last_updated_block, last_updated_at
             FROM address_balances WHERE address = $1",
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await
    }

    // -----------------------------------------------------------------------
    // Indexer state (for catchup)
    // -----------------------------------------------------------------------

    pub async fn get_last_indexed_block(&self) -> Result<i64, sqlx::Error> {
        let row: Option<(Option<i64>,)> = sqlx::query_as(
            "SELECT value_int FROM indexer_state WHERE key = 'last_indexed_block'",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.0).unwrap_or(0))
    }

    pub async fn get_max_block_number(&self) -> Result<i64, sqlx::Error> {
        let row: (Option<i64>,) =
            sqlx::query_as("SELECT MAX(number) FROM blocks")
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0.unwrap_or(0))
    }
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct HourlyStatsRow {
    pub bucket: DateTime<Utc>,
    pub block_count: i64,
    pub tx_count: i64,
    pub total_gas_used: i64,
    pub avg_gas_used: i64,
    pub total_size: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BalanceRow {
    pub address: Vec<u8>,
    pub balance: BigDecimal,
    pub nonce: i64,
    pub last_updated_block: i64,
    pub last_updated_at: DateTime<Utc>,
}
