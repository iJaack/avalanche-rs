//! Avalanche Rust Client - Core Types & Codec Module
//! Production-ready implementation of types and serialization for Avalanche blockchain
//!
//! This module provides:
//! - ID types (NodeID, BlockID, TransactionID, ChainID)
//! - Core data structures (Block, Transaction, UTXO)
//! - Error handling (thiserror)
//! - Serialization (serde + custom codecs)
//! - Comprehensive unit tests

use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use std::fmt;

// ============================================================================
// MODULE: errors.rs - Error Types
// ============================================================================

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum AvalancheError {
    #[error("invalid hex string: {0}")]
    InvalidHex(String),

    #[error("invalid id length: expected {expected}, got {actual}")]
    InvalidIdLength { expected: usize, actual: usize },

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("deserialization error: {0}")]
    DeserializationError(String),

    #[error("invalid chain id: {0}")]
    InvalidChainId(String),

    #[error("invalid block: {0}")]
    InvalidBlock(String),

    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("invalid utxo: {0}")]
    InvalidUtxo(String),

    #[error("json encoding error: {0}")]
    JsonError(String),

    #[error("hash mismatch")]
    HashMismatch,
}

impl From<serde_json::Error> for AvalancheError {
    fn from(err: serde_json::Error) -> Self {
        AvalancheError::JsonError(err.to_string())
    }
}

impl From<hex::FromHexError> for AvalancheError {
    fn from(err: hex::FromHexError) -> Self {
        AvalancheError::InvalidHex(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AvalancheError>;

// ============================================================================
// MODULE: types/mod.rs - Core Types & Data Structures
// ============================================================================

/// A fixed 32-byte identifier, typically used for hashes
/// This is the base for NodeID, BlockID, TransactionID, and ChainID
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID([u8; 32]);

impl ID {
    /// Create an ID from a fixed 32-byte array
    pub fn new(bytes: [u8; 32]) -> Self {
        ID(bytes)
    }

    /// Create an ID from a vector, returning error if length != 32
    pub fn from_vec(vec: Vec<u8>) -> Result<Self> {
        if vec.len() != 32 {
            return Err(AvalancheError::InvalidIdLength {
                expected: 32,
                actual: vec.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&vec);
        Ok(ID(bytes))
    }

    /// Decode from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)?;
        Self::from_vec(bytes)
    }

    /// Encode to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the underlying byte array
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute SHA256 hash of data
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        ID(bytes)
    }
}

/// Parse ID from CB58 (base58check) string — Avalanche's standard format
impl std::str::FromStr for ID {
    type Err = AvalancheError;

    fn from_str(s: &str) -> Result<Self> {
        // Try CB58 decode (base58 with 4-byte checksum)
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|e| AvalancheError::InvalidHex(format!("Invalid CB58: {}", e)))?;

        if decoded.len() < 4 {
            return Err(AvalancheError::InvalidHex("CB58 too short".to_string()));
        }

        // Last 4 bytes are checksum
        let payload = &decoded[..decoded.len() - 4];

        if payload.len() != 32 {
            return Err(AvalancheError::InvalidIdLength {
                expected: 32,
                actual: payload.len(),
            });
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(payload);
        Ok(ID(bytes))
    }
}

/// Create ID from a byte slice
impl ID {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_vec(bytes.to_vec())
    }
}

impl fmt::Debug for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ID({})", self.to_hex())
    }
}

impl fmt::Display for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

impl Serialize for ID {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ID {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        ID::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

// Specialized ID types for type safety
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeID(pub ID);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockID(pub ID);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionID(pub ID);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainID(pub ID);

// Blockchain ID constants
pub const BLOCKCHAIN_X: &str = "2oYMBNV4eNHyqk2fjjV5nVQLDbtrnNJR5k6Gfc2KTKY51gPt3Z";
pub const BLOCKCHAIN_C: &str = "C";
pub const BLOCKCHAIN_P: &str = "P";

/// Represents a single transaction on the Avalanche network
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Transaction {
    /// X-Chain (exchange) transaction
    XChain {
        id: TransactionID,
        /// Inputs are UTXOs being spent
        inputs: Vec<UTXO>,
        /// Outputs are new UTXOs being created
        outputs: Vec<UTXO>,
    },
    /// C-Chain (contract) transaction
    CChain {
        id: TransactionID,
        /// Ethereum-style transaction data
        nonce: u64,
        gas_price: u64,
        gas_limit: u64,
        to: Option<String>,
        value: u64,
        data: Vec<u8>,
    },
    /// P-Chain (platform) transaction
    PChain {
        id: TransactionID,
        /// Platform chain operations (staking, delegation, etc.)
        operation: String,
        params: Vec<u8>,
    },
}

impl Transaction {
    pub fn id(&self) -> TransactionID {
        match self {
            Transaction::XChain { id, .. } => *id,
            Transaction::CChain { id, .. } => *id,
            Transaction::PChain { id, .. } => *id,
        }
    }

    pub fn chain_type(&self) -> &str {
        match self {
            Transaction::XChain { .. } => "X",
            Transaction::CChain { .. } => "C",
            Transaction::PChain { .. } => "P",
        }
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Transaction {{ id: {}, chain: {} }}", self.id().0, self.chain_type())
    }
}

/// Unspent Transaction Output (UTXO) - represents spendable output
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UTXO {
    /// Transaction ID that created this output
    pub txid: TransactionID,
    /// Output index within the transaction
    pub output_index: u32,
    /// Asset ID (usually AVAX)
    pub asset_id: ID,
    /// Amount (in nanoAVAX, where 1 AVAX = 10^9 nanoAVAX)
    pub amount: u64,
    /// Owner/recipient address
    pub owner: String,
    /// Whether this UTXO has been locked (for staking)
    pub locked: bool,
}

impl UTXO {
    pub fn new(
        txid: TransactionID,
        output_index: u32,
        asset_id: ID,
        amount: u64,
        owner: String,
    ) -> Self {
        UTXO {
            txid,
            output_index,
            asset_id,
            amount,
            owner,
            locked: false,
        }
    }

    pub fn lock(mut self) -> Self {
        self.locked = true;
        self
    }
}

impl fmt::Display for UTXO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UTXO {{ txid: {}, index: {}, amount: {} }}",
            self.txid.0, self.output_index, self.amount
        )
    }
}

/// A block in the Avalanche blockchain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    /// The block ID (hash of block contents)
    pub id: BlockID,
    /// Parent block ID (for chain continuity)
    pub parent_id: BlockID,
    /// Block height in the chain
    pub height: u64,
    /// Timestamp (Unix epoch in milliseconds)
    pub timestamp: u64,
    /// Transactions in this block
    pub txs: Vec<Transaction>,
    /// State root hash
    pub state_root: ID,
}

impl Block {
    pub fn new(
        id: BlockID,
        parent_id: BlockID,
        height: u64,
        timestamp: u64,
        txs: Vec<Transaction>,
        state_root: ID,
    ) -> Result<Self> {
        if height == 0 && parent_id != BlockID(ID::new([0u8; 32])) {
            return Err(AvalancheError::InvalidBlock(
                "Genesis block must have zero parent_id".to_string(),
            ));
        }
        Ok(Block {
            id,
            parent_id,
            height,
            timestamp,
            txs,
            state_root,
        })
    }

    /// Genesis block factory
    pub fn genesis(state_root: ID) -> Self {
        Block {
            id: BlockID(ID::new([0u8; 32])),
            parent_id: BlockID(ID::new([0u8; 32])),
            height: 0,
            timestamp: 0,
            txs: vec![],
            state_root,
        }
    }

    /// Verify block integrity (check if id matches contents)
    pub fn verify_id(&self) -> Result<()> {
        let computed_id = self.compute_id();
        if computed_id == self.id {
            Ok(())
        } else {
            Err(AvalancheError::HashMismatch)
        }
    }

    /// Compute the block ID from block contents
    pub fn compute_id(&self) -> BlockID {
        let data = serde_json::to_vec(&BlockContent {
            parent_id: self.parent_id,
            height: self.height,
            timestamp: self.timestamp,
            state_root: self.state_root,
            tx_count: self.txs.len() as u32,
        })
        .expect("serialization of block content should not fail"); // Safe: we control the struct

        BlockID(ID::hash(&data))
    }

    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block {{ id: {}, height: {}, txs: {} }}",
            self.id.0,
            self.height,
            self.tx_count()
        )
    }
}

// Internal struct for consistent ID computation
#[derive(Serialize)]
struct BlockContent {
    parent_id: BlockID,
    height: u64,
    timestamp: u64,
    state_root: ID,
    tx_count: u32,
}

// ============================================================================
// MODULE: codec/mod.rs - Serialization/Deserialization
// ============================================================================

/// JSON codec for RPC messages and external communication
pub struct JsonCodec;

impl JsonCodec {
    /// Encode a value to JSON bytes
    pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
        serde_json::to_vec(value).map_err(|e| AvalancheError::JsonError(e.to_string()))
    }

    /// Encode a value to pretty-printed JSON string
    pub fn encode_pretty<T: Serialize>(value: &T) -> Result<String> {
        serde_json::to_string_pretty(value).map_err(|e| AvalancheError::JsonError(e.to_string()))
    }

    /// Decode JSON bytes to a value
    pub fn decode<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T> {
        serde_json::from_slice(data).map_err(|e| AvalancheError::JsonError(e.to_string()))
    }

    /// Decode JSON string to a value
    pub fn decode_str<T: for<'de> Deserialize<'de>>(json_str: &str) -> Result<T> {
        serde_json::from_str(json_str).map_err(|e| AvalancheError::JsonError(e.to_string()))
    }
}

/// Hex codec for ID serialization
pub struct HexCodec;

impl HexCodec {
    /// Encode ID to hex string
    pub fn encode(id: &ID) -> String {
        id.to_hex()
    }

    /// Decode hex string to ID
    pub fn decode(hex_str: &str) -> Result<ID> {
        ID::from_hex(hex_str)
    }

    /// Encode bytes to hex
    pub fn encode_bytes(data: &[u8]) -> String {
        hex::encode(data)
    }

    /// Decode hex to bytes
    pub fn decode_bytes(hex_str: &str) -> Result<Vec<u8>> {
        hex::decode(hex_str).map_err(|e| AvalancheError::InvalidHex(e.to_string()))
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ID Tests
    #[test]
    fn test_id_creation() {
        let bytes = [1u8; 32];
        let id = ID::new(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn test_id_from_vec() {
        let vec = vec![42u8; 32];
        let id = ID::from_vec(vec).unwrap();
        assert_eq!(id.0[0], 42);
    }

    #[test]
    fn test_id_from_vec_wrong_length() {
        let vec = vec![42u8; 16];
        assert!(ID::from_vec(vec).is_err());
    }

    #[test]
    fn test_id_hex_roundtrip() {
        let mut arr = [0u8; 32];
        arr[0] = 0x12; arr[1] = 0x34; arr[2] = 0x56; arr[3] = 0x78;
        arr[4] = 0xab; arr[5] = 0xcd; arr[6] = 0xef; arr[7] = 0x00;
        let original = ID::new(arr);
        let hex = original.to_hex();
        let decoded = ID::from_hex(&hex).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_id_hash() {
        let data1 = b"test data";
        let data2 = b"test data";
        let data3 = b"other data";

        let hash1 = ID::hash(data1);
        let hash2 = ID::hash(data2);
        let hash3 = ID::hash(data3);

        assert_eq!(hash1, hash2, "same data should produce same hash");
        assert_ne!(hash1, hash3, "different data should produce different hash");
    }

    #[test]
    fn test_id_display() {
        let id = ID::new([0xff; 32]);
        let display = format!("{}", id);
        assert_eq!(display.len(), 16, "display should show first 16 hex chars");
    }

    // NodeID, BlockID, TransactionID Tests
    #[test]
    fn test_typed_ids() {
        let id = ID::new([1u8; 32]);
        let node_id = NodeID(id);
        let block_id = BlockID(id);
        let tx_id = TransactionID(id);

        assert_eq!(node_id.0, id);
        assert_eq!(block_id.0, id);
        assert_eq!(tx_id.0, id);
    }

    // Transaction Tests
    #[test]
    fn test_transaction_x_chain() {
        let tx = Transaction::XChain {
            id: TransactionID(ID::new([1u8; 32])),
            inputs: vec![],
            outputs: vec![],
        };
        assert_eq!(tx.chain_type(), "X");
    }

    #[test]
    fn test_transaction_c_chain() {
        let tx = Transaction::CChain {
            id: TransactionID(ID::new([2u8; 32])),
            nonce: 0,
            gas_price: 1000,
            gas_limit: 21000,
            to: Some("0x123".to_string()),
            value: 0,
            data: vec![],
        };
        assert_eq!(tx.chain_type(), "C");
    }

    #[test]
    fn test_transaction_p_chain() {
        let tx = Transaction::PChain {
            id: TransactionID(ID::new([3u8; 32])),
            operation: "AddValidator".to_string(),
            params: vec![],
        };
        assert_eq!(tx.chain_type(), "P");
    }

    // UTXO Tests
    #[test]
    fn test_utxo_creation() {
        let txid = TransactionID(ID::new([1u8; 32]));
        let asset_id = ID::new([2u8; 32]);
        let utxo = UTXO::new(txid, 0, asset_id, 1000000, "user1".to_string());

        assert_eq!(utxo.txid, txid);
        assert_eq!(utxo.amount, 1000000);
        assert!(!utxo.locked);
    }

    #[test]
    fn test_utxo_lock() {
        let txid = TransactionID(ID::new([1u8; 32]));
        let asset_id = ID::new([2u8; 32]);
        let utxo = UTXO::new(txid, 0, asset_id, 1000000, "user1".to_string()).lock();

        assert!(utxo.locked);
    }

    // Block Tests
    #[test]
    fn test_block_genesis() {
        let state_root = ID::new([5u8; 32]);
        let block = Block::genesis(state_root);

        assert_eq!(block.height, 0);
        assert_eq!(block.tx_count(), 0);
        assert_eq!(block.state_root, state_root);
    }

    #[test]
    fn test_block_creation() {
        let block = Block::new(
            BlockID(ID::new([1u8; 32])),
            BlockID(ID::new([2u8; 32])),
            1,
            1000,
            vec![],
            ID::new([3u8; 32]),
        )
        .unwrap();

        assert_eq!(block.height, 1);
        assert_eq!(block.timestamp, 1000);
    }

    #[test]
    fn test_block_invalid_genesis() {
        let result = Block::new(
            BlockID(ID::new([1u8; 32])),
            BlockID(ID::new([2u8; 32])), // non-zero parent for height 0
            0,
            1000,
            vec![],
            ID::new([3u8; 32]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_block_compute_id() {
        let block = Block::new(
            BlockID(ID::new([1u8; 32])),
            BlockID(ID::new([2u8; 32])),
            1,
            1000,
            vec![],
            ID::new([3u8; 32]),
        )
        .unwrap();

        let computed_id = block.compute_id();
        let recomputed_id = block.compute_id();
        assert_eq!(computed_id, recomputed_id, "compute_id should be deterministic");
    }

    // Serialization Tests
    #[test]
    fn test_id_json_roundtrip() {
        let original = ID::new([42u8; 32]);
        let json = serde_json::to_string(&original).unwrap();
        let decoded: ID = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_block_json_roundtrip() {
        let block = Block::new(
            BlockID(ID::new([1u8; 32])),
            BlockID(ID::new([2u8; 32])),
            1,
            1000,
            vec![],
            ID::new([3u8; 32]),
        )
        .unwrap();

        let json = serde_json::to_string(&block).unwrap();
        let decoded: Block = serde_json::from_str(&json).unwrap();
        assert_eq!(block, decoded);
    }

    #[test]
    fn test_transaction_json_roundtrip() {
        let tx = Transaction::XChain {
            id: TransactionID(ID::new([1u8; 32])),
            inputs: vec![],
            outputs: vec![],
        };

        let json = serde_json::to_string(&tx).unwrap();
        let decoded: Transaction = serde_json::from_str(&json).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn test_utxo_json_roundtrip() {
        let utxo = UTXO::new(
            TransactionID(ID::new([1u8; 32])),
            0,
            ID::new([2u8; 32]),
            1000000,
            "user1".to_string(),
        );

        let json = serde_json::to_string(&utxo).unwrap();
        let decoded: UTXO = serde_json::from_str(&json).unwrap();
        assert_eq!(utxo, decoded);
    }

    // Codec Tests
    #[test]
    fn test_json_codec_encode_decode() {
        let block = Block::new(
            BlockID(ID::new([1u8; 32])),
            BlockID(ID::new([2u8; 32])),
            5,
            2000,
            vec![],
            ID::new([3u8; 32]),
        )
        .unwrap();

        let encoded = JsonCodec::encode(&block).unwrap();
        let decoded: Block = JsonCodec::decode(&encoded).unwrap();
        assert_eq!(block, decoded);
    }

    #[test]
    fn test_hex_codec_encode_decode() {
        let mut arr = [0u8; 32];
        arr[0] = 0x12; arr[1] = 0x34; arr[2] = 0x56; arr[3] = 0x78;
        arr[4] = 0xab; arr[5] = 0xcd; arr[6] = 0xef; arr[7] = 0x00;
        let id = ID::new(arr);
        let hex = HexCodec::encode(&id);
        let decoded = HexCodec::decode(&hex).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_hex_codec_bytes() {
        let data = b"test data";
        let hex = HexCodec::encode_bytes(data);
        let decoded = HexCodec::decode_bytes(&hex).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    // Error Tests
    #[test]
    fn test_error_invalid_hex() {
        let result = ID::from_hex("not_valid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_serialization() {
        let err = AvalancheError::SerializationError("test".to_string());
        assert_eq!(err.to_string(), "serialization error: test");
    }
}

// ============================================================================
// EXPORTS & RE-EXPORTS FOR EASY IMPORTING
// ============================================================================

pub mod errors {
    pub use super::{AvalancheError, Result};
}

pub mod types {
    pub use super::{ID, NodeID, BlockID, TransactionID, ChainID, Transaction, UTXO, Block};
    pub use super::{BLOCKCHAIN_X, BLOCKCHAIN_C, BLOCKCHAIN_P};
}

pub mod codec {
    pub use super::{JsonCodec, HexCodec};
}
