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

/// Block decision status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    /// Block is processing (not yet decided).
    Processing,
    /// Block was accepted (finalized).
    Accepted,
    /// Block was rejected (conflicting block accepted).
    Rejected,
}

/// Confidence tracker for a single block.
#[derive(Debug, Clone, Default)]
pub struct BlockConfidence {
    /// Consecutive rounds this block has been preferred.
    pub consecutive: u32,
    /// Total votes received across all rounds.
    pub total_votes: u32,
}

/// Production Snowman consensus state.
///
/// Tracks the preferred chain tip, the last accepted (finalized) block,
/// and pending blocks not yet accepted. Implements voting and finality detection
/// with configurable alpha (quorum) and beta (confidence threshold) parameters.
#[derive(Debug)]
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
    /// Vote count per block (for finality detection)
    votes: HashMap<[u8; 32], u32>,
    /// Confidence counters per block.
    confidence: HashMap<[u8; 32], BlockConfidence>,
    /// Decision status for blocks.
    decisions: HashMap<[u8; 32], BlockStatus>,
    /// The decided frontier: set of accepted block IDs at the tip.
    decided_frontier: Vec<[u8; 32]>,
    /// Alpha: quorum size — minimum votes in a round to count as successful poll.
    pub alpha: u32,
    /// Beta: finality threshold — consecutive successful polls needed for acceptance.
    pub beta: u32,
}

impl Default for SnowmanConsensus {
    fn default() -> Self {
        Self {
            preferred: None,
            last_accepted: None,
            last_accepted_height: 0,
            pending: HashMap::new(),
            accepted_count: 0,
            votes: HashMap::new(),
            confidence: HashMap::new(),
            decisions: HashMap::new(),
            decided_frontier: Vec::new(),
            alpha: 15,
            beta: 20,
        }
    }
}

impl SnowmanConsensus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom alpha/beta parameters.
    pub fn with_params(alpha: u32, beta: u32) -> Self {
        Self { alpha, beta, ..Default::default() }
    }

    /// Accept a block, advancing `last_accepted` and clearing it from pending.
    pub fn accept_block(&mut self, header: &BlockHeader) {
        self.last_accepted = Some(header.id);
        self.last_accepted_height = header.height;
        self.preferred = Some(header.id);
        self.pending.remove(&header.id);
        self.votes.remove(&header.id);
        self.confidence.remove(&header.id);
        self.decisions.insert(header.id, BlockStatus::Accepted);
        self.accepted_count += 1;

        // Update decided frontier: remove parent, add this block
        self.decided_frontier.retain(|id| *id != header.parent_id);
        self.decided_frontier.push(header.id);
    }

    /// Reject a block (conflicting block was accepted).
    pub fn reject_block(&mut self, block_id: [u8; 32]) {
        self.pending.remove(&block_id);
        self.votes.remove(&block_id);
        self.confidence.remove(&block_id);
        self.decisions.insert(block_id, BlockStatus::Rejected);
    }

    /// Get the decision status of a block.
    pub fn block_status(&self, block_id: &[u8; 32]) -> BlockStatus {
        self.decisions.get(block_id).copied().unwrap_or(
            if self.pending.contains_key(block_id) {
                BlockStatus::Processing
            } else {
                BlockStatus::Processing
            }
        )
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
        self.decisions.insert(header.id, BlockStatus::Processing);
        self.pending.insert(header.id, header);
    }

    /// Process chits (votes) from a single peer for a round.
    ///
    /// `voted_ids` contains the block IDs this peer voted for.
    /// Returns a list of block IDs that were accepted in this round.
    pub fn process_chits(&mut self, voted_ids: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let mut accepted = Vec::new();

        // Count votes per block in this round
        let mut round_votes: HashMap<[u8; 32], u32> = HashMap::new();
        for id in voted_ids {
            *round_votes.entry(*id).or_insert(0) += 1;
        }

        for (block_id, count) in &round_votes {
            // Accumulate total votes
            let vote_count = self.votes.entry(*block_id).or_insert(0);
            *vote_count += count;

            let conf = self.confidence.entry(*block_id).or_default();
            conf.total_votes += count;

            // Check if this round's votes meet the alpha quorum
            if *count >= self.alpha {
                conf.consecutive += 1;
                let new_consecutive = conf.consecutive;

                // Update preference: block with most consecutive polls wins
                let should_update = if let Some(current_pref) = self.preferred {
                    if current_pref == *block_id {
                        false // already preferred
                    } else {
                        let current_conf = self.confidence.get(&current_pref)
                            .map(|c| c.consecutive)
                            .unwrap_or(0);
                        new_consecutive > current_conf
                    }
                } else {
                    true
                };
                if should_update {
                    self.preferred = Some(*block_id);
                }

                // Check beta threshold for finality
                if new_consecutive >= self.beta {
                    let header = self.pending.get(block_id).cloned().unwrap_or_else(|| {
                        BlockHeader {
                            id: *block_id,
                            parent_id: [0u8; 32],
                            height: 0,
                            timestamp: 0,
                            block_type: crate::block::BlockType::Unknown(0),
                            raw_size: 0,
                            raw_bytes: Vec::new(),
                        }
                    });
                    self.accept_block(&header);
                    accepted.push(*block_id);
                }
            } else {
                // Failed poll — reset consecutive counter
                if let Some(conf) = self.confidence.get_mut(block_id) {
                    conf.consecutive = 0;
                }
            }
        }

        accepted
    }

    /// Record a vote for a block (from Chits message).
    /// Returns true if the block reaches finality (votes >= beta).
    pub fn record_vote(&mut self, block_id: [u8; 32]) -> bool {
        let vote_count = self.votes.entry(block_id).or_insert(0);
        *vote_count += 1;

        if *vote_count >= self.beta {
            self.accept_block(&self.pending.get(&block_id).cloned().unwrap_or_else(|| {
                BlockHeader {
                    id: block_id,
                    parent_id: [0u8; 32],
                    height: 0,
                    timestamp: 0,
                    block_type: crate::block::BlockType::Unknown(0),
                    raw_size: 0,
                    raw_bytes: Vec::new(),
                }
            }));
            true
        } else {
            false
        }
    }

    /// Get current vote count for a block
    pub fn vote_count(&self, block_id: &[u8; 32]) -> u32 {
        *self.votes.get(block_id).unwrap_or(&0)
    }

    /// Get confidence counter for a block
    pub fn block_confidence(&self, block_id: &[u8; 32]) -> Option<&BlockConfidence> {
        self.confidence.get(block_id)
    }

    /// Check if block has reached finality
    pub fn is_finalized(&self, block_id: &[u8; 32]) -> bool {
        self.vote_count(block_id) >= self.beta
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

    /// Get all pending blocks
    pub fn pending_blocks(&self) -> Vec<BlockHeader> {
        self.pending.values().cloned().collect()
    }

    /// Get the decided frontier (accepted tips).
    pub fn decided_frontier(&self) -> &[[u8; 32]] {
        &self.decided_frontier
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
            block_type: crate::block::BlockType::BanffStandard,
            raw_size: 54,
            raw_bytes: Vec::new(),
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

    #[test]
    fn test_snowman_consensus_vote_tallying() {
        let mut consensus = SnowmanConsensus::new();
        let block_id = [0xBBu8; 32];

        // Record votes - should not finalize until beta (20) votes
        let header = make_header(block_id, [0u8; 32], 1);
        consensus.add_pending(header.clone());

        for _i in 0..19 {
            assert!(!consensus.record_vote(block_id)); // build up to 19 votes
        }
        
        // 20th vote should trigger finality
        assert!(consensus.record_vote(block_id));
        // After acceptance, the block is no longer in pending but should be last_accepted
        assert_eq!(consensus.last_accepted(), Some(block_id));
        assert_eq!(consensus.accepted_count(), 1);
    }

    #[test]
    fn test_snowman_consensus_multiple_blocks() {
        let mut consensus = SnowmanConsensus::new();
        let block1 = [0x11u8; 32];
        let block2 = [0x22u8; 32];

        consensus.record_vote(block1);
        consensus.record_vote(block2);
        consensus.record_vote(block1);

        assert_eq!(consensus.vote_count(&block1), 2);
        assert_eq!(consensus.vote_count(&block2), 1);
    }

    // --- Enhanced consensus tests ---

    #[test]
    fn test_consensus_default_params() {
        let sc = SnowmanConsensus::new();
        assert_eq!(sc.alpha, 15);
        assert_eq!(sc.beta, 20);
    }

    #[test]
    fn test_consensus_custom_params() {
        let sc = SnowmanConsensus::with_params(10, 15);
        assert_eq!(sc.alpha, 10);
        assert_eq!(sc.beta, 15);
    }

    #[test]
    fn test_block_rejection() {
        let mut sc = SnowmanConsensus::new();
        let block_id = [0xCC; 32];
        let h = make_header(block_id, [0u8; 32], 1);
        sc.add_pending(h);
        assert_eq!(sc.block_status(&block_id), BlockStatus::Processing);

        sc.reject_block(block_id);
        assert_eq!(sc.block_status(&block_id), BlockStatus::Rejected);
        assert!(sc.pending_blocks().is_empty());
    }

    #[test]
    fn test_block_acceptance_status() {
        let mut sc = SnowmanConsensus::new();
        let block_id = [0xDD; 32];
        let h = make_header(block_id, [0u8; 32], 1);
        sc.accept_block(&h);
        assert_eq!(sc.block_status(&block_id), BlockStatus::Accepted);
    }

    #[test]
    fn test_decided_frontier() {
        let mut sc = SnowmanConsensus::new();

        let genesis = make_header([0u8; 32], [0u8; 32], 0);
        sc.accept_block(&genesis);
        assert_eq!(sc.decided_frontier().len(), 1);
        assert_eq!(sc.decided_frontier()[0], [0u8; 32]);

        // Accept child — should replace parent in frontier
        let child = make_header([1u8; 32], [0u8; 32], 1);
        sc.accept_block(&child);
        assert_eq!(sc.decided_frontier().len(), 1);
        assert_eq!(sc.decided_frontier()[0], [1u8; 32]);
    }

    #[test]
    fn test_process_chits_with_quorum() {
        // Use small alpha/beta for testability
        let mut sc = SnowmanConsensus::with_params(2, 3);
        let block_id = [0xEE; 32];
        let h = make_header(block_id, [0u8; 32], 1);
        sc.add_pending(h);

        // Round 1: 2 votes (meets alpha=2)
        let accepted = sc.process_chits(&[block_id, block_id]);
        assert!(accepted.is_empty()); // only 1 consecutive round

        // Round 2: 2 votes again
        let accepted = sc.process_chits(&[block_id, block_id]);
        assert!(accepted.is_empty()); // 2 consecutive rounds

        // Round 3: 2 votes — should reach beta=3
        let accepted = sc.process_chits(&[block_id, block_id]);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0], block_id);
        assert_eq!(sc.last_accepted(), Some(block_id));
    }

    #[test]
    fn test_process_chits_confidence_reset() {
        let mut sc = SnowmanConsensus::with_params(2, 3);
        let block_id = [0xFF; 32];
        let h = make_header(block_id, [0u8; 32], 1);
        sc.add_pending(h);

        // Round 1: quorum met
        sc.process_chits(&[block_id, block_id]);
        assert_eq!(sc.block_confidence(&block_id).unwrap().consecutive, 1);

        // Round 2: quorum NOT met (only 1 vote, need 2)
        sc.process_chits(&[block_id]);
        assert_eq!(sc.block_confidence(&block_id).unwrap().consecutive, 0);

        // Round 3: quorum met again — consecutive resets to 1
        sc.process_chits(&[block_id, block_id]);
        assert_eq!(sc.block_confidence(&block_id).unwrap().consecutive, 1);
    }

    #[test]
    fn test_process_chits_preference_switching() {
        let mut sc = SnowmanConsensus::with_params(2, 100); // high beta so nothing finalizes
        let block_a = [0xAA; 32];
        let block_b = [0xBB; 32];
        sc.add_pending(make_header(block_a, [0u8; 32], 1));
        sc.add_pending(make_header(block_b, [0u8; 32], 1));

        // Round 1: A gets quorum → A preferred with consecutive=1
        sc.process_chits(&[block_a, block_a]);
        assert!(sc.is_preferred(&block_a));

        // Round 2: only B gets quorum → B consecutive=1, A consecutive stays 1 (not polled)
        // But A's consecutive isn't reset since it wasn't polled with < alpha votes
        // B consecutive == A consecutive, so preference doesn't switch
        // We need to also vote for A below quorum to reset it
        sc.process_chits(&[block_b, block_b, block_a]); // A gets 1 vote (< alpha=2), B gets 2
        // A consecutive reset to 0, B consecutive = 1 → B preferred
        assert!(sc.is_preferred(&block_b));
    }

    #[test]
    fn test_mock_voting_simulation() {
        // Simulate 20 peers voting for the same block across rounds
        let mut sc = SnowmanConsensus::with_params(15, 20);
        let block_id = [0x42; 32];
        sc.add_pending(make_header(block_id, [0u8; 32], 1));

        // 20 rounds of 15 votes each should finalize
        for round in 0..20 {
            let votes: Vec<[u8; 32]> = (0..15).map(|_| block_id).collect();
            let accepted = sc.process_chits(&votes);
            if round == 19 {
                assert_eq!(accepted.len(), 1, "should finalize on round 20");
            } else {
                assert!(accepted.is_empty(), "should not finalize before round 20");
            }
        }

        assert_eq!(sc.last_accepted(), Some(block_id));
        assert_eq!(sc.block_status(&block_id), BlockStatus::Accepted);
    }
}
