//! avalanche-rs - Production Rust client for the Avalanche network
//!
//! A fast, type-safe, async client for interacting with Avalanche blockchains.

#![allow(missing_docs)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::overly_complex_bool_expr,
    clippy::assertions_on_constants,
    clippy::if_same_then_else,
    clippy::large_enum_variant,
    clippy::match_like_matches_macro,
    clippy::module_inception,
    clippy::single_match,
    clippy::unnecessary_sort_by,
    clippy::vec_init_then_push,
    clippy::while_let_loop,
    clippy::doc_lazy_continuation,
    clippy::too_many_arguments
)]
#![warn(rust_2018_idioms)]
// We need unsafe for RocksDB FFI bindings and revm's EVM internals
// #![forbid(unsafe_code)]

pub mod archive;
pub mod codec;
pub mod consensus;
#[macro_use]
mod fixed_bytes;
pub mod mempool;
pub mod mev;
#[cfg(feature = "p2p")]
pub mod network;
#[cfg(feature = "rpc")]
pub mod rpc;
pub mod tx;
pub mod txpool;
pub mod types;

// Production node modules
pub mod blob;
pub mod block;
pub mod cache;
pub mod db;
pub mod debug;
pub mod evm;
pub mod fortuna;
pub mod granite;
pub mod hardening;
pub mod identity;
pub mod light;
pub mod metrics;
pub mod observability;
pub mod pchain;
pub mod proto;
pub mod snap;
pub mod staking;
pub mod subnet;
pub mod sync;
pub mod validator;
pub mod warp;
pub mod websocket;

#[cfg(feature = "indexer")]
pub mod api;
#[cfg(feature = "indexer")]
pub mod indexer;

// Re-export common types for convenience
pub use types::{
    AvalancheError, Block, BlockID, ChainID, NodeID, Result, Transaction, TransactionID, ID, UTXO,
};

#[cfg(feature = "rpc")]
pub use rpc::RpcClient;

// Network module exports peer management, consensus, and message types
// Use: avalanche_rs::network::{Peer, PeerManager, NetworkMessage, ...}
