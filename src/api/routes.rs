use axum::{routing::get, Router};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

use crate::indexer::IndexerQuery;

use super::handlers;

/// Shared state for API handlers.
pub type AppState = Arc<IndexerQuery>;

/// Build the Axum router with all REST endpoints.
pub fn router(query: IndexerQuery) -> Router {
    let state: AppState = Arc::new(query);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(handlers::health))
        .route("/api/blocks/{number}", get(handlers::get_block_by_number))
        .route("/api/blocks/hash/{hash}", get(handlers::get_block_by_hash))
        .route("/api/tx/{hash}", get(handlers::get_transaction))
        .route(
            "/api/address/{addr}/transactions",
            get(handlers::get_address_transactions),
        )
        .route("/api/logs", get(handlers::get_logs))
        .layer(cors)
        .with_state(state)
}
