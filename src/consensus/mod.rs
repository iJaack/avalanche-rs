//! Consensus module for Snowman and DAG-based consensus simulation.
//!
//! Provides consensus state tracking, block validation, and finality detection.

use crate::types::{Block, BlockID};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Original Snowman (retained for compatibility)
// ---------------------------------------------------------------------------

/// Snowman consensus state machine (simple voting model).
#[derive(Debug, Clone)]
pub struct Snowman {
    /// Current preferred block
    preferred: Option<BlockID>,
    /// Blocks seen so far (tracked for future block queries)
    _blocks: HashMap<BlockID, Block>,
    /// Voting confidence counter
    confidence: u64,
    /// Finality threshold
    beta: u64,
}

impl Snowman {
    /// Create a new Snowman instance with default parameters.
    pub fn new() -> Self {
        Snowman {
            preferred: None,
            _blocks: HashMap::new(),
            confidence: 0,
            beta: 20,
        }
    }

    /// Record a vote for a block.
    pub fn vote(&mut self, block_id: BlockID) {
        if Some(block_id) == self.preferred {
            self.confidence += 1;
        } else {
            self.preferred = Some(block_id);
            self.confidence = 1;
        }
    }

    /// Check if we have reached finality.
    pub fn is_finalized(&self) -> bool {
        self.confidence >= self.beta
    }

    /// Get the currently preferred block.
    pub fn preferred_block(&self) -> Option<BlockID> {
        self.preferred
    }
}

impl Default for Snowman {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SnowmanConsensus — production-oriented consensus tracker
// ---------------------------------------------------------------------------

use crate::block::BlockHeader;

/// Production Snowman consensus state.
///
/// Tracks the preferred chain tip, the last accepted (finalized) block,
/// and pending blocks not yet accepted.
#[derive(Debug, Default)]
pub struct SnowmanConsensus {
    /// Current preferred tip (may not be finalized yet).
    preferred: Option<[u8; 32]>,
    /// Last accepted (finalized) block ID.
    last_accepted: Option<[u8; 32]>,
    /// Height of `last_accepted`.
    pub last_accepted_height: u64,
    /// Blocks that have been seen but not yet accepted.
    pending: HashMap<[u8; 32], BlockHeader>,
    /// Count of accepted blocks.
    accepted_count: u64,
}

impl SnowmanConsensus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a block, advancing `last_accepted` and clearing it from pending.
    pub fn accept_block(&mut self, header: &BlockHeader) {
        self.last_accepted = Some(header.id);
        self.last_accepted_height = header.height;
        self.preferred = Some(header.id);
        self.pending.remove(&header.id);
        self.accepted_count += 1;
    }

    /// Update the preferred tip (without finalizing).
    pub fn set_preferred(&mut self, id: [u8; 32]) {
        self.preferred = Some(id);
    }

    /// Returns true if the given block ID is the current preferred tip.
    pub fn is_preferred(&self, id: &[u8; 32]) -> bool {
        self.preferred.as_ref() == Some(id)
    }

    /// Add a block to the pending set (seen but not accepted).
    pub fn add_pending(&mut self, header: BlockHeader) {
        self.pending.insert(header.id, header);
    }

    /// Returns the last accepted block ID.
    pub fn last_accepted(&self) -> Option<[u8; 32]> {
        self.last_accepted
    }

    /// Returns the current preferred tip.
    pub fn preferred(&self) -> Option<[u8; 32]> {
        self.preferred
    }

    /// Total number of accepted blocks.
    pub fn accepted_count(&self) -> u64 {
        self.accepted_count
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snowman_voting() {
        let mut snowman = Snowman::new();
        let block_id = BlockID(crate::types::ID::new([1u8; 32]));

        snowman.vote(block_id);
        assert_eq!(snowman.preferred_block(), Some(block_id));
        assert_eq!(snowman.confidence, 1);
    }

    fn make_header(id: [u8; 32], parent: [u8; 32], height: u64) -> BlockHeader {
        BlockHeader {
            id,
            parent_id: parent,
            height,
            timestamp: 0,
            block_type: crate::block::BlockType::PChainStandard,
            raw_size: 54,
        }
    }

    #[test]
    fn test_snowman_consensus_accept() {
        let mut sc = SnowmanConsensus::new();
        assert!(sc.last_accepted().is_none());

        let h0 = make_header([0u8; 32], [0u8; 32], 0);
        sc.accept_block(&h0);
        assert_eq!(sc.last_accepted(), Some([0u8; 32]));
        assert_eq!(sc.last_accepted_height, 0);
        assert_eq!(sc.accepted_count(), 1);
        assert!(sc.is_preferred(&[0u8; 32]));
    }

    #[test]
    fn test_snowman_consensus_accept_chain() {
        let mut sc = SnowmanConsensus::new();

        let headers: Vec<BlockHeader> = (0u64..5)
            .map(|h| make_header([h as u8; 32], if h == 0 { [0u8; 32] } else { [(h - 1) as u8; 32] }, h))
            .collect();

        for h in &headers {
            sc.accept_block(h);
        }

        assert_eq!(sc.accepted_count(), 5);
        assert_eq!(sc.last_accepted_height, 4);
        assert_eq!(sc.last_accepted(), Some([4u8; 32]));
    }

    #[test]
    fn test_snowman_consensus_pending() {
        let mut sc = SnowmanConsensus::new();
        let h = make_header([1u8; 32], [0u8; 32], 1);
        sc.add_pending(h.clone());
        assert_eq!(sc.pending.len(), 1);

        sc.accept_block(&h);
        assert_eq!(sc.pending.len(), 0); // cleared on accept
    }

    #[test]
    fn test_snowman_consensus_set_preferred() {
        let mut sc = SnowmanConsensus::new();
        sc.set_preferred([0xAAu8; 32]);
        assert!(sc.is_preferred(&[0xAAu8; 32]));
        assert!(!sc.is_preferred(&[0u8; 32]));
    }
}
