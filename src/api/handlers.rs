use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use super::AppState;

// ---------------------------------------------------------------------------
// Response types (hex-encoded for JSON)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct BlockJson {
    pub number: i64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: String,
    pub gas_used: i64,
    pub gas_limit: i64,
    pub transaction_count: i32,
    pub size: i64,
}

#[derive(Serialize)]
pub struct TransactionJson {
    pub hash: String,
    pub block_hash: String,
    pub block_number: i64,
    pub from_address: String,
    pub to_address: Option<String>,
    pub value: String,
    pub gas_price: Option<i64>,
    pub gas_limit: Option<i64>,
    pub gas_used: Option<i64>,
    pub nonce: Option<i64>,
    pub status: Option<i16>,
    pub tx_index: i32,
    pub timestamp: String,
}

#[derive(Serialize)]
pub struct LogJson {
    pub id: i64,
    pub transaction_hash: String,
    pub block_number: i64,
    pub log_index: i32,
    pub address: String,
    pub topic0: Option<String>,
    pub topic1: Option<String>,
    pub topic2: Option<String>,
    pub topic3: Option<String>,
    pub data: Option<String>,
    pub timestamp: String,
}

fn hex(bytes: &[u8]) -> String {
    format!("0x{}", faster_hex::hex_string(bytes))
}

fn hex_opt(bytes: &Option<Vec<u8>>) -> Option<String> {
    bytes.as_ref().map(|b| hex(b))
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

impl From<crate::indexer::query::BlockRow> for BlockJson {
    fn from(b: crate::indexer::query::BlockRow) -> Self {
        Self {
            number: b.number,
            hash: hex(&b.hash),
            parent_hash: hex(&b.parent_hash),
            timestamp: b.timestamp.to_rfc3339(),
            gas_used: b.gas_used,
            gas_limit: b.gas_limit,
            transaction_count: b.transaction_count,
            size: b.size,
        }
    }
}

impl From<crate::indexer::query::TransactionRow> for TransactionJson {
    fn from(t: crate::indexer::query::TransactionRow) -> Self {
        Self {
            hash: hex(&t.hash),
            block_hash: hex(&t.block_hash),
            block_number: t.block_number,
            from_address: hex(&t.from_address),
            to_address: t.to_address.as_ref().map(|a| hex(a)),
            value: t.value.to_plain_string(),
            gas_price: t.gas_price,
            gas_limit: t.gas_limit,
            gas_used: t.gas_used,
            nonce: t.nonce,
            status: t.status,
            tx_index: t.tx_index,
            timestamp: t.timestamp.to_rfc3339(),
        }
    }
}

impl From<crate::indexer::query::LogRow> for LogJson {
    fn from(l: crate::indexer::query::LogRow) -> Self {
        Self {
            id: l.id,
            transaction_hash: hex(&l.transaction_hash),
            block_number: l.block_number,
            log_index: l.log_index,
            address: hex(&l.address),
            topic0: hex_opt(&l.topic0),
            topic1: hex_opt(&l.topic1),
            topic2: hex_opt(&l.topic2),
            topic3: hex_opt(&l.topic3),
            data: hex_opt(&l.data),
            timestamp: l.timestamp.to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

pub async fn get_block_by_number(
    State(query): State<AppState>,
    Path(number): Path<u64>,
) -> impl IntoResponse {
    match query.get_block_by_number(number).await {
        Ok(Some(block)) => {
            Json(serde_json::to_value(BlockJson::from(block)).unwrap()).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn get_block_by_hash(
    State(query): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let bytes = match parse_hex(&hash) {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, "Invalid hex hash").into_response(),
    };
    match query.get_block_by_hash(&bytes).await {
        Ok(Some(block)) => {
            Json(serde_json::to_value(BlockJson::from(block)).unwrap()).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn get_transaction(
    State(query): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let bytes = match parse_hex(&hash) {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, "Invalid hex hash").into_response(),
    };
    match query.get_transaction(&bytes).await {
        Ok(Some(tx)) => {
            Json(serde_json::to_value(TransactionJson::from(tx)).unwrap()).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct PaginationParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn get_address_transactions(
    State(query): State<AppState>,
    Path(addr): Path<String>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let bytes = match parse_hex(&addr) {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, "Invalid hex address").into_response(),
    };
    let limit = params.limit.unwrap_or(10).min(100);
    let offset = params.offset.unwrap_or(0);

    match query
        .get_transactions_by_address(&bytes, limit, offset)
        .await
    {
        Ok(txs) => {
            let json_txs: Vec<TransactionJson> = txs.into_iter().map(Into::into).collect();
            Json(serde_json::to_value(json_txs).unwrap()).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct LogFilterParams {
    pub address: Option<String>,
    pub topic0: Option<String>,
    pub topic1: Option<String>,
    pub topic2: Option<String>,
    pub topic3: Option<String>,
    #[serde(alias = "fromBlock")]
    pub from_block: Option<u64>,
    #[serde(alias = "toBlock")]
    pub to_block: Option<u64>,
}

pub async fn get_logs(
    State(query): State<AppState>,
    Query(params): Query<LogFilterParams>,
) -> impl IntoResponse {
    let address_bytes = params.address.as_ref().and_then(|a| parse_hex(a));
    let topic0_bytes = params.topic0.as_ref().and_then(|t| parse_hex(t));
    let topic1_bytes = params.topic1.as_ref().and_then(|t| parse_hex(t));
    let topic2_bytes = params.topic2.as_ref().and_then(|t| parse_hex(t));
    let topic3_bytes = params.topic3.as_ref().and_then(|t| parse_hex(t));

    let topics: Vec<Option<&[u8]>> = vec![
        topic0_bytes.as_deref(),
        topic1_bytes.as_deref(),
        topic2_bytes.as_deref(),
        topic3_bytes.as_deref(),
    ];

    match query
        .get_logs(
            address_bytes.as_deref(),
            topics,
            params.from_block,
            params.to_block,
        )
        .await
    {
        Ok(logs) => {
            let json_logs: Vec<LogJson> = logs.into_iter().map(Into::into).collect();
            Json(serde_json::to_value(json_logs).unwrap()).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub async fn prometheus_metrics() -> impl IntoResponse {
    let metrics = crate::indexer::IndexerMetrics::global();
    let mut buffer = String::new();
    buffer.push_str(&format!(
        "# HELP indexer_blocks_indexed_total Total blocks written to PostgreSQL\n\
         # TYPE indexer_blocks_indexed_total counter\n\
         indexer_blocks_indexed_total {}\n",
        metrics.blocks_indexed.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_transactions_indexed_total Total transactions written\n\
         # TYPE indexer_transactions_indexed_total counter\n\
         indexer_transactions_indexed_total {}\n",
        metrics.transactions_indexed.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_logs_indexed_total Total event logs written\n\
         # TYPE indexer_logs_indexed_total counter\n\
         indexer_logs_indexed_total {}\n",
        metrics.logs_indexed.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_batches_flushed_total Total batch flushes\n\
         # TYPE indexer_batches_flushed_total counter\n\
         indexer_batches_flushed_total {}\n",
        metrics.batches_flushed.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_height Highest block number indexed\n\
         # TYPE indexer_height gauge\n\
         indexer_height {}\n",
        metrics.indexer_height.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_lag_blocks Blocks behind chain tip (0 = caught up)\n\
         # TYPE indexer_lag_blocks gauge\n\
         indexer_lag_blocks {}\n",
        metrics.indexer_lag_blocks.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_queue_depth Blocks waiting in the indexer channel\n\
         # TYPE indexer_queue_depth gauge\n\
         indexer_queue_depth {}\n",
        metrics.queue_depth.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_write_errors_total Total batch write failures\n\
         # TYPE indexer_write_errors_total counter\n\
         indexer_write_errors_total {}\n",
        metrics.write_errors.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_catchup_blocks_remaining Blocks remaining in catchup sync\n\
         # TYPE indexer_catchup_blocks_remaining gauge\n\
         indexer_catchup_blocks_remaining {}\n",
        metrics.catchup_blocks_remaining.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_catchup_blocks_per_sec Catchup sync throughput\n\
         # TYPE indexer_catchup_blocks_per_sec gauge\n\
         indexer_catchup_blocks_per_sec {}\n",
        metrics.catchup_blocks_per_sec.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_storage_bytes_estimate Estimated storage usage in bytes\n\
         # TYPE indexer_storage_bytes_estimate gauge\n\
         indexer_storage_bytes_estimate {}\n",
        metrics.storage_bytes_estimate.get()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_batch_size_count Total observed batch size samples\n\
         # TYPE indexer_batch_size_count counter\n\
         indexer_batch_size_count {}\n",
        metrics.batch_size.get_sample_count()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_batch_size_sum Sum of observed blocks per batch\n\
         # TYPE indexer_batch_size_sum gauge\n\
         indexer_batch_size_sum {}\n",
        metrics.batch_size.get_sample_sum()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_batch_write_duration_seconds_count Total observed batch write duration samples\n\
         # TYPE indexer_batch_write_duration_seconds_count counter\n\
         indexer_batch_write_duration_seconds_count {}\n",
        metrics.batch_write_duration.get_sample_count()
    ));
    buffer.push_str(&format!(
        "# HELP indexer_batch_write_duration_seconds_sum Sum of batch write durations in seconds\n\
         # TYPE indexer_batch_write_duration_seconds_sum gauge\n\
         indexer_batch_write_duration_seconds_sum {}\n",
        metrics.batch_write_duration.get_sample_sum()
    ));
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        buffer,
    )
}

#[derive(Serialize)]
pub struct HourlyStatsJson {
    pub bucket: String,
    pub block_count: i64,
    pub tx_count: i64,
    pub total_gas_used: i64,
    pub avg_gas_used: i64,
    pub total_size: i64,
}

pub async fn get_hourly_stats(
    State(query): State<AppState>,
    Query(params): Query<StatsParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(24).min(168); // max 7 days hourly
    match query.get_hourly_stats(limit).await {
        Ok(rows) => Json(serde_json::to_value(rows).unwrap()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn get_daily_stats(
    State(query): State<AppState>,
    Query(params): Query<StatsParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(30).min(365);
    match query.get_daily_stats(limit).await {
        Ok(rows) => Json(serde_json::to_value(rows).unwrap()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct StatsParams {
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct BalanceJson {
    pub address: String,
    pub balance: String,
    pub nonce: i64,
    pub last_updated_block: i64,
}

pub async fn get_address_balance(
    State(query): State<AppState>,
    Path(addr): Path<String>,
) -> impl IntoResponse {
    let bytes = match parse_hex(&addr) {
        Some(b) => b,
        None => return (StatusCode::BAD_REQUEST, "Invalid hex address").into_response(),
    };
    match query.get_balance(&bytes).await {
        Ok(Some(row)) => {
            let json = BalanceJson {
                address: hex(&bytes),
                balance: row.balance.to_plain_string(),
                nonce: row.nonce,
                last_updated_block: row.last_updated_block,
            };
            Json(serde_json::to_value(json).unwrap()).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).ok()
}
