//! avalanche-rs - Production Rust client for the Avalanche network
//!
//! A fast, type-safe, async client for interacting with Avalanche blockchains.

#![allow(missing_docs)]
#![warn(rust_2018_idioms)]
// We need unsafe for RocksDB FFI bindings and revm's EVM internals
// #![forbid(unsafe_code)]

pub mod types;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(feature = "p2p")]
pub mod network;
pub mod codec;
pub mod consensus;
pub mod mev;
pub mod tx;
pub mod mempool;

// Production node modules
pub mod proto;
pub mod identity;
pub mod evm;
pub mod db;
pub mod sync;
pub mod block;
pub mod validator;
pub mod metrics;
pub mod warp;
pub mod subnet;
pub mod light;

// Re-export common types for convenience
pub use types::{AvalancheError, Result, ID, NodeID, BlockID, TransactionID, ChainID, Block, Transaction, UTXO};

#[cfg(feature = "rpc")]
pub use rpc::RpcClient;

// Network module exports peer management, consensus, and message types
// Use: avalanche_rs::network::{Peer, PeerManager, NetworkMessage, ...}
