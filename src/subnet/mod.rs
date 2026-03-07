//! Subnet support for avalanche-rs.
//!
//! Phase 7: Track and bootstrap multiple subnets.
//! Implements:
//! - --tracked-subnets CLI parsing
//! - Subnet validator set discovery
//! - Per-chain sync state management
//! - Multi-chain connection tracking
//! - Dynamic subnet/chain add/remove

use crate::network::{ChainId, NodeId};
use crate::sync::SyncPhase;
use crate::validator::ValidatorSet;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Subnet Identifiers
// ---------------------------------------------------------------------------

/// A subnet identifier (32 bytes, same as a ChainId).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SubnetId(pub [u8; 32]);

impl SubnetId {
    /// The Primary Network subnet ID (all zeros).
    pub fn primary_network() -> Self {
        Self([0u8; 32])
    }

    /// Parse from hex string.
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for SubnetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Subnet-{}", &self.to_hex()[..16])
    }
}

// ---------------------------------------------------------------------------
// Chain Configuration
// ---------------------------------------------------------------------------

/// Configuration for a chain within a subnet.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Chain ID
    pub chain_id: ChainId,
    /// Subnet this chain belongs to
    pub subnet_id: SubnetId,
    /// Human-readable name (e.g., "P-Chain", "C-Chain", "X-Chain")
    pub name: String,
    /// VM type (e.g., "platformvm", "evm", "avm")
    pub vm_type: String,
}

// ---------------------------------------------------------------------------
// Subnet Tracker
// ---------------------------------------------------------------------------

/// Per-chain sync state.
#[derive(Debug, Clone)]
pub struct ChainSyncState {
    /// Chain configuration
    pub config: ChainConfig,
    /// Current sync phase
    pub phase: SyncPhase,
    /// Last synced height
    pub height: u64,
    /// Target height
    pub target_height: u64,
    /// Connected peers tracking this chain
    pub peers: Vec<NodeId>,
}

impl ChainSyncState {
    fn new(config: ChainConfig) -> Self {
        Self {
            config,
            phase: SyncPhase::Idle,
            height: 0,
            target_height: 0,
            peers: Vec::new(),
        }
    }

    /// Progress percentage.
    pub fn progress_pct(&self) -> f64 {
        if self.target_height == 0 {
            return 0.0;
        }
        (self.height as f64 / self.target_height as f64 * 100.0).min(100.0)
    }

    /// Whether this chain is fully synced.
    pub fn is_synced(&self) -> bool {
        matches!(self.phase, SyncPhase::Synced | SyncPhase::Following)
    }
}

/// Tracks all subnets and their chains.
pub struct SubnetTracker {
    /// All tracked subnets
    subnets: HashMap<SubnetId, SubnetState>,
    /// Chain ID → subnet ID mapping for quick lookup
    chain_to_subnet: HashMap<[u8; 32], SubnetId>,
}

/// State for a single subnet.
#[derive(Debug)]
pub struct SubnetState {
    /// Subnet identifier
    pub id: SubnetId,
    /// Validator set for this subnet
    pub validators: ValidatorSet,
    /// Chains in this subnet
    pub chains: HashMap<[u8; 32], ChainSyncState>,
}

impl SubnetTracker {
    /// Create a new subnet tracker.
    pub fn new() -> Self {
        Self {
            subnets: HashMap::new(),
            chain_to_subnet: HashMap::new(),
        }
    }

    /// Parse --tracked-subnets CLI argument (comma-separated hex subnet IDs).
    pub fn parse_tracked_subnets(cli_arg: &str) -> Vec<SubnetId> {
        if cli_arg.is_empty() {
            return vec![];
        }
        cli_arg
            .split(',')
            .filter_map(|s| SubnetId::from_hex(s.trim()))
            .collect()
    }

    /// Add a subnet to track.
    pub fn add_subnet(&mut self, subnet_id: SubnetId) {
        self.subnets
            .entry(subnet_id.clone())
            .or_insert_with(|| SubnetState {
                id: subnet_id,
                validators: ValidatorSet::new(),
                chains: HashMap::new(),
            });
    }

    /// Add a chain to a subnet.
    pub fn add_chain(&mut self, config: ChainConfig) -> bool {
        let subnet_id = config.subnet_id.clone();
        let chain_id_bytes = config.chain_id.0;

        if let Some(subnet) = self.subnets.get_mut(&subnet_id) {
            let state = ChainSyncState::new(config);
            subnet.chains.insert(chain_id_bytes, state);
            self.chain_to_subnet.insert(chain_id_bytes, subnet_id);
            true
        } else {
            false
        }
    }

    /// Remove a chain from tracking.
    pub fn remove_chain(&mut self, chain_id: &ChainId) -> bool {
        if let Some(subnet_id) = self.chain_to_subnet.remove(&chain_id.0) {
            if let Some(subnet) = self.subnets.get_mut(&subnet_id) {
                subnet.chains.remove(&chain_id.0);
                return true;
            }
        }
        false
    }

    /// Get the sync state for a chain.
    pub fn chain_state(&self, chain_id: &ChainId) -> Option<&ChainSyncState> {
        let subnet_id = self.chain_to_subnet.get(&chain_id.0)?;
        let subnet = self.subnets.get(subnet_id)?;
        subnet.chains.get(&chain_id.0)
    }

    /// Get mutable sync state for a chain.
    pub fn chain_state_mut(&mut self, chain_id: &ChainId) -> Option<&mut ChainSyncState> {
        let subnet_id = self.chain_to_subnet.get(&chain_id.0)?.clone();
        let subnet = self.subnets.get_mut(&subnet_id)?;
        subnet.chains.get_mut(&chain_id.0)
    }

    /// Update sync phase for a chain.
    pub fn set_chain_phase(&mut self, chain_id: &ChainId, phase: SyncPhase) {
        if let Some(state) = self.chain_state_mut(chain_id) {
            state.phase = phase;
        }
    }

    /// Update sync height for a chain.
    pub fn set_chain_height(&mut self, chain_id: &ChainId, height: u64) {
        if let Some(state) = self.chain_state_mut(chain_id) {
            state.height = height;
        }
    }

    /// Add a peer to a chain's peer list.
    pub fn add_chain_peer(&mut self, chain_id: &ChainId, peer: NodeId) {
        if let Some(state) = self.chain_state_mut(chain_id) {
            if !state.peers.contains(&peer) {
                state.peers.push(peer);
            }
        }
    }

    /// Get the validator set for a subnet.
    pub fn subnet_validators(&self, subnet_id: &SubnetId) -> Option<&ValidatorSet> {
        self.subnets.get(subnet_id).map(|s| &s.validators)
    }

    /// Get mutable validator set for a subnet.
    pub fn subnet_validators_mut(&mut self, subnet_id: &SubnetId) -> Option<&mut ValidatorSet> {
        self.subnets.get_mut(subnet_id).map(|s| &mut s.validators)
    }

    /// Get all tracked subnet IDs.
    pub fn tracked_subnets(&self) -> Vec<SubnetId> {
        self.subnets.keys().cloned().collect()
    }

    /// Get all chains across all subnets.
    pub fn all_chains(&self) -> Vec<&ChainSyncState> {
        self.subnets
            .values()
            .flat_map(|s| s.chains.values())
            .collect()
    }

    /// Number of tracked subnets.
    pub fn subnet_count(&self) -> usize {
        self.subnets.len()
    }

    /// Total number of tracked chains.
    pub fn chain_count(&self) -> usize {
        self.chain_to_subnet.len()
    }

    /// Whether all chains are synced.
    pub fn all_synced(&self) -> bool {
        self.all_chains().iter().all(|c| c.is_synced())
    }

    /// Summary of sync status for all chains.
    pub fn sync_summary(&self) -> Vec<(String, SyncPhase, f64)> {
        self.all_chains()
            .iter()
            .map(|c| (c.config.name.clone(), c.phase.clone(), c.progress_pct()))
            .collect()
    }
}

impl Default for SubnetTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chain(name: &str, subnet: &SubnetId) -> ChainConfig {
        let mut chain_id = [0u8; 32];
        for (i, b) in name.bytes().enumerate() {
            if i < 32 {
                chain_id[i] = b;
            }
        }
        ChainConfig {
            chain_id: ChainId(chain_id),
            subnet_id: subnet.clone(),
            name: name.to_string(),
            vm_type: "evm".to_string(),
        }
    }

    #[test]
    fn test_subnet_id_primary_network() {
        let primary = SubnetId::primary_network();
        assert_eq!(primary.0, [0u8; 32]);
    }

    #[test]
    fn test_subnet_id_from_hex() {
        let hex = "aa".repeat(32);
        let id = SubnetId::from_hex(&hex).unwrap();
        assert_eq!(id.0, [0xAA; 32]);
    }

    #[test]
    fn test_subnet_id_from_hex_invalid() {
        assert!(SubnetId::from_hex("too_short").is_none());
        assert!(SubnetId::from_hex("not_hex_gg").is_none());
    }

    #[test]
    fn test_subnet_id_display() {
        let id = SubnetId([0xBB; 32]);
        let s = format!("{}", id);
        assert!(s.starts_with("Subnet-"));
    }

    #[test]
    fn test_parse_tracked_subnets() {
        let hex = "aa".repeat(32);
        let hex2 = "bb".repeat(32);
        let arg = format!("{},{}", hex, hex2);
        let subnets = SubnetTracker::parse_tracked_subnets(&arg);
        assert_eq!(subnets.len(), 2);
        assert_eq!(subnets[0].0, [0xAA; 32]);
        assert_eq!(subnets[1].0, [0xBB; 32]);
    }

    #[test]
    fn test_parse_tracked_subnets_empty() {
        let subnets = SubnetTracker::parse_tracked_subnets("");
        assert!(subnets.is_empty());
    }

    #[test]
    fn test_subnet_tracker_add_subnet_and_chain() {
        let mut tracker = SubnetTracker::new();
        let subnet = SubnetId::primary_network();
        tracker.add_subnet(subnet.clone());

        let chain = make_chain("C-Chain", &subnet);
        let chain_id = chain.chain_id.clone();
        assert!(tracker.add_chain(chain));

        assert_eq!(tracker.subnet_count(), 1);
        assert_eq!(tracker.chain_count(), 1);

        let state = tracker.chain_state(&chain_id).unwrap();
        assert_eq!(state.config.name, "C-Chain");
        assert_eq!(state.phase, SyncPhase::Idle);
    }

    #[test]
    fn test_subnet_tracker_add_chain_no_subnet() {
        let mut tracker = SubnetTracker::new();
        let chain = make_chain("orphan", &SubnetId([0xFF; 32]));
        assert!(!tracker.add_chain(chain));
    }

    #[test]
    fn test_subnet_tracker_remove_chain() {
        let mut tracker = SubnetTracker::new();
        let subnet = SubnetId::primary_network();
        tracker.add_subnet(subnet.clone());

        let chain = make_chain("X-Chain", &subnet);
        let chain_id = chain.chain_id.clone();
        tracker.add_chain(chain);

        assert!(tracker.remove_chain(&chain_id));
        assert_eq!(tracker.chain_count(), 0);
        assert!(tracker.chain_state(&chain_id).is_none());
    }

    #[test]
    fn test_subnet_tracker_set_phase_and_height() {
        let mut tracker = SubnetTracker::new();
        let subnet = SubnetId::primary_network();
        tracker.add_subnet(subnet.clone());

        let chain = make_chain("P-Chain", &subnet);
        let chain_id = chain.chain_id.clone();
        tracker.add_chain(chain);

        tracker.set_chain_phase(&chain_id, SyncPhase::Fetching);
        tracker.set_chain_height(&chain_id, 1000);

        let state = tracker.chain_state(&chain_id).unwrap();
        assert_eq!(state.phase, SyncPhase::Fetching);
        assert_eq!(state.height, 1000);
    }

    #[test]
    fn test_subnet_tracker_add_peer() {
        let mut tracker = SubnetTracker::new();
        let subnet = SubnetId::primary_network();
        tracker.add_subnet(subnet.clone());

        let chain = make_chain("C-Chain", &subnet);
        let chain_id = chain.chain_id.clone();
        tracker.add_chain(chain);

        let peer = NodeId([0x11; 20]);
        tracker.add_chain_peer(&chain_id, peer.clone());
        tracker.add_chain_peer(&chain_id, peer.clone()); // duplicate

        let state = tracker.chain_state(&chain_id).unwrap();
        assert_eq!(state.peers.len(), 1); // no duplicate
    }

    #[test]
    fn test_subnet_tracker_all_synced() {
        let mut tracker = SubnetTracker::new();
        let subnet = SubnetId::primary_network();
        tracker.add_subnet(subnet.clone());

        let chain1 = make_chain("P-Chain", &subnet);
        let chain2 = make_chain("C-Chain", &subnet);
        let cid1 = chain1.chain_id.clone();
        let cid2 = chain2.chain_id.clone();
        tracker.add_chain(chain1);
        tracker.add_chain(chain2);

        assert!(!tracker.all_synced());

        tracker.set_chain_phase(&cid1, SyncPhase::Synced);
        assert!(!tracker.all_synced());

        tracker.set_chain_phase(&cid2, SyncPhase::Following);
        assert!(tracker.all_synced());
    }

    #[test]
    fn test_chain_sync_state_progress() {
        let config = make_chain("test", &SubnetId::primary_network());
        let mut state = ChainSyncState::new(config);
        state.target_height = 1000;
        state.height = 500;
        assert_eq!(state.progress_pct(), 50.0);
    }

    #[test]
    fn test_sync_summary() {
        let mut tracker = SubnetTracker::new();
        let subnet = SubnetId::primary_network();
        tracker.add_subnet(subnet.clone());

        let chain = make_chain("C-Chain", &subnet);
        let chain_id = chain.chain_id.clone();
        tracker.add_chain(chain);
        tracker.set_chain_phase(&chain_id, SyncPhase::Fetching);

        let summary = tracker.sync_summary();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].0, "C-Chain");
        assert_eq!(summary[0].1, SyncPhase::Fetching);
    }

    #[test]
    fn test_subnet_validators() {
        let mut tracker = SubnetTracker::new();
        let subnet = SubnetId([0x11; 32]);
        tracker.add_subnet(subnet.clone());

        let vs = tracker.subnet_validators(&subnet);
        assert!(vs.is_some());
        assert_eq!(vs.unwrap().count(), 0);
    }

    #[test]
    fn test_multiple_subnets() {
        let mut tracker = SubnetTracker::new();
        let sub1 = SubnetId::primary_network();
        let sub2 = SubnetId([0x22; 32]);
        tracker.add_subnet(sub1.clone());
        tracker.add_subnet(sub2.clone());

        tracker.add_chain(make_chain("P", &sub1));
        tracker.add_chain(make_chain("C", &sub1));
        tracker.add_chain(make_chain("CustomVM", &sub2));

        assert_eq!(tracker.subnet_count(), 2);
        assert_eq!(tracker.chain_count(), 3);
        assert_eq!(tracker.all_chains().len(), 3);
    }
}
