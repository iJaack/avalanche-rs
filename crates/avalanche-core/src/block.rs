//! Block type definitions, compatible with no_std.

use serde::{Deserialize, Serialize};
use crate::types::{BlockId, Id};

/// Avalanche block types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockType {
    /// Apricot Proposal block (typeID 0)
    ApricotProposal,
    /// Apricot Abort block (typeID 1)
    ApricotAbort,
    /// Apricot Commit block (typeID 2)
    ApricotCommit,
    /// Apricot Standard block (typeID 3)
    ApricotStandard,
    /// Apricot Atomic block (typeID 4)
    ApricotAtomic,
    /// Banff Proposal block (typeID 29)
    BanffProposal,
    /// Banff Abort block (typeID 30)
    BanffAbort,
    /// Banff Commit block (typeID 31)
    BanffCommit,
    /// Banff Standard block (typeID 32)
    BanffStandard,
    /// Unknown block type
    Unknown(u32),
}

impl BlockType {
    /// Parse a block type from its typeID.
    pub fn from_type_id(id: u32) -> Self {
        match id {
            0 => Self::ApricotProposal,
            1 => Self::ApricotAbort,
            2 => Self::ApricotCommit,
            3 => Self::ApricotStandard,
            4 => Self::ApricotAtomic,
            29 => Self::BanffProposal,
            30 => Self::BanffAbort,
            31 => Self::BanffCommit,
            32 => Self::BanffStandard,
            other => Self::Unknown(other),
        }
    }

    /// Get the typeID for this block type.
    pub fn type_id(&self) -> u32 {
        match self {
            Self::ApricotProposal => 0,
            Self::ApricotAbort => 1,
            Self::ApricotCommit => 2,
            Self::ApricotStandard => 3,
            Self::ApricotAtomic => 4,
            Self::BanffProposal => 29,
            Self::BanffAbort => 30,
            Self::BanffCommit => 31,
            Self::BanffStandard => 32,
            Self::Unknown(id) => *id,
        }
    }

    /// Whether this is a Banff-era block.
    pub fn is_banff(&self) -> bool {
        matches!(
            self,
            Self::BanffProposal | Self::BanffAbort | Self::BanffCommit | Self::BanffStandard
        )
    }

    /// Get the byte offset where the parent ID starts for this block type.
    pub fn parent_id_offset(&self) -> usize {
        match self {
            Self::BanffProposal => 18,
            Self::BanffAbort | Self::BanffCommit | Self::BanffStandard => 14,
            _ => 6, // Apricot blocks
        }
    }
}

/// Compute the block ID (SHA-256 hash of raw block bytes).
pub fn compute_block_id(raw: &[u8]) -> BlockId {
    Id::from_sha256(raw)
}

/// Extract the parent block ID from raw block bytes.
pub fn extract_parent_id(raw: &[u8], block_type: BlockType) -> Option<BlockId> {
    let offset = block_type.parent_id_offset();
    if raw.len() < offset + 32 {
        return None;
    }
    let mut parent = [0u8; 32];
    parent.copy_from_slice(&raw[offset..offset + 32]);
    Some(Id(parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_type_from_type_id() {
        assert_eq!(BlockType::from_type_id(0), BlockType::ApricotProposal);
        assert_eq!(BlockType::from_type_id(29), BlockType::BanffProposal);
        assert_eq!(BlockType::from_type_id(32), BlockType::BanffStandard);
        assert!(matches!(BlockType::from_type_id(99), BlockType::Unknown(99)));
    }

    #[test]
    fn test_block_type_roundtrip() {
        let types = [0, 1, 2, 3, 4, 29, 30, 31, 32];
        for type_id in types {
            let bt = BlockType::from_type_id(type_id);
            assert_eq!(bt.type_id(), type_id);
        }
    }

    #[test]
    fn test_block_type_is_banff() {
        assert!(BlockType::BanffProposal.is_banff());
        assert!(BlockType::BanffStandard.is_banff());
        assert!(!BlockType::ApricotStandard.is_banff());
    }

    #[test]
    fn test_compute_block_id_deterministic() {
        let data = b"block data";
        let id1 = compute_block_id(data);
        let id2 = compute_block_id(data);
        assert_eq!(id1, id2);
        assert!(!id1.is_zero());
    }

    #[test]
    fn test_compute_block_id_varies() {
        let id1 = compute_block_id(b"block A");
        let id2 = compute_block_id(b"block B");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_extract_parent_id_apricot() {
        let mut raw = vec![0u8; 50];
        raw[6..38].copy_from_slice(&[0xAA; 32]);
        let parent = extract_parent_id(&raw, BlockType::ApricotStandard).unwrap();
        assert_eq!(parent.0, [0xAA; 32]);
    }

    #[test]
    fn test_extract_parent_id_banff() {
        let mut raw = vec![0u8; 60];
        raw[18..50].copy_from_slice(&[0xBB; 32]);
        let parent = extract_parent_id(&raw, BlockType::BanffProposal).unwrap();
        assert_eq!(parent.0, [0xBB; 32]);
    }

    #[test]
    fn test_extract_parent_id_too_short() {
        let raw = vec![0u8; 10];
        assert!(extract_parent_id(&raw, BlockType::ApricotStandard).is_none());
    }

    #[test]
    fn test_parent_id_offsets() {
        assert_eq!(BlockType::ApricotStandard.parent_id_offset(), 6);
        assert_eq!(BlockType::BanffProposal.parent_id_offset(), 18);
        assert_eq!(BlockType::BanffAbort.parent_id_offset(), 14);
    }
}
