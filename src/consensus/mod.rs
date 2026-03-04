//! Consensus module for Snowman and DAG-based consensus simulation
//!
//! Provides consensus state tracking, block validation, and finality detection.

use crate::types::{BlockID, Block};
use std::collections::HashMap;

/// Snowman consensus state machine
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
    /// Create a new Snowman instance with default parameters
    pub fn new() -> Self {
        Snowman {
            preferred: None,
            _blocks: HashMap::new(),
            confidence: 0,
            beta: 20,
        }
    }

    /// Record a vote for a block
    pub fn vote(&mut self, block_id: BlockID) {
        if Some(block_id) == self.preferred {
            self.confidence += 1;
        } else {
            self.preferred = Some(block_id);
            self.confidence = 1;
        }
    }

    /// Check if we have reached finality
    pub fn is_finalized(&self) -> bool {
        self.confidence >= self.beta
    }

    /// Get the currently preferred block
    pub fn preferred_block(&self) -> Option<BlockID> {
        self.preferred
    }
}

impl Default for Snowman {
    fn default() -> Self {
        Self::new()
    }
}

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
}
