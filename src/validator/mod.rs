//! P-Chain validator set management and transaction parsing.
//!
//! Tracks active validators and their stake weights, parsed from P-Chain
//! AddValidator and AddDelegator transactions.

use std::collections::HashMap;
use crate::network::NodeId;

/// Information about a validator
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorInfo {
    /// The validator's NodeID
    pub node_id: NodeId,
    /// Stake weight in AVAX nanoAVAX (1 AVAX = 10^9 nanoAVAX)
    pub weight: u64,
    /// Unix timestamp when validator starts
    pub start_time: u64,
    /// Unix timestamp when validator ends
    pub end_time: u64,
}

impl ValidatorInfo {
    /// Check if this validator is currently active at the given timestamp
    pub fn is_active(&self, now: u64) -> bool {
        now >= self.start_time && now < self.end_time
    }
}

/// Active validator set for P-Chain
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    /// Map of NodeID -> ValidatorInfo
    validators: HashMap<[u8; 20], ValidatorInfo>,
    /// Total stake weight of all active validators
    total_weight: u64,
}

impl ValidatorSet {
    /// Create a new empty validator set
    pub fn new() -> Self {
        ValidatorSet {
            validators: HashMap::new(),
            total_weight: 0,
        }
    }

    /// Add or update a validator
    pub fn add_validator(&mut self, info: ValidatorInfo) {
        let bytes = info.node_id.0;
        
        // Subtract old weight if replacing existing validator
        if let Some(old) = self.validators.get(&bytes) {
            self.total_weight = self.total_weight.saturating_sub(old.weight);
        }
        
        // Add new weight
        self.total_weight = self.total_weight.saturating_add(info.weight);
        self.validators.insert(bytes, info);
    }

    /// Remove a validator by NodeID
    pub fn remove_validator(&self, node_id: &NodeId) -> Option<ValidatorInfo> {
        self.validators.get(&node_id.0).cloned()
    }

    /// Get validator info by NodeID
    pub fn get_validator(&self, node_id: &NodeId) -> Option<&ValidatorInfo> {
        self.validators.get(&node_id.0)
    }

    /// Get all validators
    pub fn all_validators(&self) -> Vec<ValidatorInfo> {
        self.validators.values().cloned().collect()
    }

    /// Get active validators at given timestamp
    pub fn active_validators(&self, now: u64) -> Vec<ValidatorInfo> {
        self.validators
            .values()
            .filter(|v| v.is_active(now))
            .cloned()
            .collect()
    }

    /// Get total weight of all validators
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Get count of validators
    pub fn count(&self) -> usize {
        self.validators.len()
    }
}

impl Default for ValidatorSet {
    fn default() -> Self {
        Self::new()
    }
}

/// P-Chain transaction types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PChainTxType {
    /// BaseTransaction (typeID 0)
    Base,
    /// AddValidatorTx (typeID 0x0C = 12)
    AddValidator,
    /// AddDelegatorTx (typeID 0x0E = 14)
    AddDelegator,
    /// RemoveSubnetValidatorTx (typeID 0x11 = 17)
    RemoveSubnetValidator,
    /// Unknown typeID
    Unknown(u32),
}

impl PChainTxType {
    /// Parse typeID to PChainTxType
    pub fn from_id(id: u32) -> Self {
        match id {
            0 => PChainTxType::Base,
            0x0C => PChainTxType::AddValidator,
            0x0E => PChainTxType::AddDelegator,
            0x11 => PChainTxType::RemoveSubnetValidator,
            unknown => PChainTxType::Unknown(unknown),
        }
    }
}

/// Parsed AddValidator transaction
#[derive(Debug, Clone)]
pub struct AddValidatorTx {
    /// Validator's NodeID (20 bytes)
    pub node_id: [u8; 20],
    /// Start time (Unix seconds)
    pub start_time: u64,
    /// End time (Unix seconds)
    pub end_time: u64,
    /// Stake weight (nanoAVAX)
    pub weight: u64,
}

impl AddValidatorTx {
    /// Parse an AddValidator transaction from bytes
    /// Format (post-codec header):
    /// - NodeID: 20 bytes
    /// - StartTime: u64 BE
    /// - EndTime: u64 BE
    /// - Weight: u64 BE
    /// - (more fields for reward address, delegation fee, etc. - omitted for now)
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 20 + 8 + 8 + 8 {
            return Err(format!(
                "AddValidatorTx too short: {} bytes (need ≥44)",
                raw.len()
            ));
        }

        let mut node_id = [0u8; 20];
        node_id.copy_from_slice(&raw[0..20]);

        let start_time = u64::from_be_bytes(raw[20..28].try_into().unwrap());
        let end_time = u64::from_be_bytes(raw[28..36].try_into().unwrap());
        let weight = u64::from_be_bytes(raw[36..44].try_into().unwrap());

        if start_time >= end_time {
            return Err("start_time must be before end_time".to_string());
        }

        Ok(AddValidatorTx {
            node_id,
            start_time,
            end_time,
            weight,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_set_add() {
        let mut vs = ValidatorSet::new();
        let info = ValidatorInfo {
            node_id: NodeId([0xAAu8; 20]),
            weight: 1000,
            start_time: 100,
            end_time: 200,
        };
        vs.add_validator(info.clone());
        assert_eq!(vs.count(), 1);
        assert_eq!(vs.total_weight(), 1000);
        assert_eq!(vs.get_validator(&NodeId([0xAAu8; 20])), Some(&info));
    }

    #[test]
    fn test_validator_set_active_at_time() {
        let mut vs = ValidatorSet::new();
        let info = ValidatorInfo {
            node_id: NodeId([0xBBu8; 20]),
            weight: 500,
            start_time: 100,
            end_time: 200,
        };
        vs.add_validator(info);
        
        assert_eq!(vs.active_validators(50).len(), 0);  // Before start
        assert_eq!(vs.active_validators(150).len(), 1); // During active
        assert_eq!(vs.active_validators(250).len(), 0); // After end
    }

    #[test]
    fn test_add_validator_tx_parse() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&[0xCCu8; 20]);  // NodeID
        raw.extend_from_slice(&(100u64).to_be_bytes()); // StartTime
        raw.extend_from_slice(&(200u64).to_be_bytes()); // EndTime
        raw.extend_from_slice(&(1000u64).to_be_bytes()); // Weight

        let tx = AddValidatorTx::parse(&raw).unwrap();
        assert_eq!(tx.node_id, [0xCCu8; 20]);
        assert_eq!(tx.start_time, 100);
        assert_eq!(tx.end_time, 200);
        assert_eq!(tx.weight, 1000);
    }

    #[test]
    fn test_add_validator_tx_parse_too_short() {
        let raw = vec![0u8; 20];
        assert!(AddValidatorTx::parse(&raw).is_err());
    }

    #[test]
    fn test_add_validator_tx_invalid_times() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&[0xDDu8; 20]);  // NodeID
        raw.extend_from_slice(&(200u64).to_be_bytes()); // StartTime (AFTER end)
        raw.extend_from_slice(&(100u64).to_be_bytes()); // EndTime (BEFORE start)
        raw.extend_from_slice(&(1000u64).to_be_bytes()); // Weight

        assert!(AddValidatorTx::parse(&raw).is_err());
    }

    #[test]
    fn test_validator_set_total_weight() {
        let mut vs = ValidatorSet::new();
        for i in 0..3 {
            let mut node_id_bytes = [0u8; 20];
            node_id_bytes[0] = i;
            vs.add_validator(ValidatorInfo {
                node_id: NodeId(node_id_bytes),
                weight: 100 * (i as u64 + 1),
                start_time: 0,
                end_time: 1000,
            });
        }
        assert_eq!(vs.total_weight(), 600); // 100 + 200 + 300
    }
}
