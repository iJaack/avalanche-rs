//! avalanche-core: no_std compatible core types for the Avalanche network.
//!
//! This crate provides fundamental types (IDs, blocks, transactions, codec)
//! that can be used in embedded, WASM, or other no_std environments.
//!
//! Enable the `std` feature (default) for standard library support.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod block;
pub mod bloom;
pub mod codec;
pub mod types;
