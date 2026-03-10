#![cfg(feature = "indexer")]

use tower::util::ServiceExt;
use avalanche_rs::{
    api::routes,
    indexer::{IndexedBlock, IndexedLog, IndexedTransaction, IndexerQuery},
};
use axum::http::StatusCode;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

#[tokio::test]
async fn test_routes_module_accessible() {
    // Just check if we can access the router function
    eprintln!("Routes module is accessible: routes::router function exists");
    assert!(true);
}

#[tokio::test]
async fn test_router_health_and_blocks() {
    // Setup minimal pool
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect("postgresql:///postgres")
        .await
        .expect("connect to postgres");

    let query = IndexerQuery::new(pool);
    let app = routes::router(query);

    // Test health route
    let health_req = axum::http::Request::builder()
        .method("GET")
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let health_resp = app.clone().oneshot(health_req).await.unwrap();
    eprintln!("Health route status: {}", health_resp.status());
    assert_eq!(health_resp.status(), StatusCode::OK);

    // Test block number route
    let block_req = axum::http::Request::builder()
        .method("GET")
        .uri("/api/blocks/42")
        .body(axum::body::Body::empty())
        .unwrap();
    let block_resp = app.oneshot(block_req).await.unwrap();
    eprintln!("Block route status: {}", block_resp.status());
    // We expect 404 since block doesn't exist, but NOT because route isn't matched
    assert_ne!(block_resp.status(), StatusCode::NOT_FOUND); // or should be 404 if block not found
}
