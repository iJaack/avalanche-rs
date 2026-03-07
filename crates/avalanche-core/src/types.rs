//! Core Avalanche types, compatible with no_std.
//!
//! Provides ID types (32-byte identifiers), NodeID (20-byte), and basic
//! block/transaction structures.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A 32-byte identifier used throughout Avalanche.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Id(pub [u8; 32]);

impl Id {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Compute the SHA-256 hash of the given data and return as an ID.
    pub fn from_sha256(data: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        Self(arr)
    }
}

impl Default for Id {
    fn default() -> Self {
        Self::ZERO
    }
}

/// A 20-byte node identifier.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 20]);

impl NodeId {
    pub const ZERO: Self = Self([0u8; 20]);

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Type-safe block ID.
pub type BlockId = Id;

/// Type-safe transaction ID.
pub type TransactionId = Id;

/// Type-safe chain ID.
pub type ChainId = Id;

/// A minimal block header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub id: BlockId,
    pub parent_id: BlockId,
    pub height: u64,
    pub timestamp: u64,
}

impl BlockHeader {
    pub fn is_genesis(&self) -> bool {
        self.parent_id.is_zero()
    }
}

/// A minimal transaction envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TransactionId,
    pub chain_id: ChainId,
    pub payload: Vec<u8>,
}

/// A UTXO (unspent transaction output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub tx_id: TransactionId,
    pub output_index: u32,
    pub amount: u64,
    pub owner: [u8; 20],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_zero() {
        let id = Id::ZERO;
        assert!(id.is_zero());
    }

    #[test]
    fn test_id_from_bytes() {
        let id = Id::from_bytes(&[0xAA; 32]).unwrap();
        assert_eq!(id.0, [0xAA; 32]);
        assert!(!id.is_zero());
    }

    #[test]
    fn test_id_from_bytes_wrong_len() {
        assert!(Id::from_bytes(&[0; 31]).is_none());
        assert!(Id::from_bytes(&[0; 33]).is_none());
    }

    #[test]
    fn test_id_from_sha256() {
        let id1 = Id::from_sha256(b"hello");
        let id2 = Id::from_sha256(b"hello");
        assert_eq!(id1, id2);
        assert!(!id1.is_zero());

        let id3 = Id::from_sha256(b"world");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_node_id() {
        let nid = NodeId::from_bytes(&[0xBB; 20]).unwrap();
        assert_eq!(nid.0, [0xBB; 20]);
        assert!(!nid.is_zero());
    }

    #[test]
    fn test_block_header_genesis() {
        let genesis = BlockHeader {
            id: Id::from_sha256(b"genesis"),
            parent_id: Id::ZERO,
            height: 0,
            timestamp: 0,
        };
        assert!(genesis.is_genesis());

        let block = BlockHeader {
            id: Id::from_sha256(b"block1"),
            parent_id: Id::from_sha256(b"genesis"),
            height: 1,
            timestamp: 100,
        };
        assert!(!block.is_genesis());
    }
}
