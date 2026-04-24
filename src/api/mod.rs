pub mod handlers;
pub mod routes;

use std::sync::Arc;

use crate::indexer::IndexerQuery;

/// Shared state for API handlers.
pub type AppState = Arc<IndexerQuery>;

pub use routes::router;
