use axum::{routing::get, Router};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

use crate::indexer::IndexerQuery;

use super::{handlers, AppState};

/// Build the Axum router with all REST endpoints.
pub fn router(query: IndexerQuery) -> Router {
    let state: AppState = Arc::new(query);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(handlers::health))
        .route("/metrics", get(handlers::prometheus_metrics))
        .route("/api/blocks/hash/:hash", get(handlers::get_block_by_hash))
        .route("/api/blocks/:number", get(handlers::get_block_by_number))
        .route("/api/tx/:hash", get(handlers::get_transaction))
        .route(
            "/api/address/:addr/transactions",
            get(handlers::get_address_transactions),
        )
        .route("/api/logs", get(handlers::get_logs))
        .route("/api/stats/hourly", get(handlers::get_hourly_stats))
        .route("/api/stats/daily", get(handlers::get_daily_stats))
        .route(
            "/api/address/:addr/balance",
            get(handlers::get_address_balance),
        )
        .layer(cors)
        .with_state(state)
}
