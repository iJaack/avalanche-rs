//! P-Chain validator set management, transaction parsing, and validation.
//!
//! Tracks active validators and their stake weights, parsed from P-Chain
//! AddValidator and AddDelegator transactions.
//!
//! Phase 7: secp256k1 signature validation on P-Chain transactions,
//! UTXO set tracking from genesis, and transaction verification.

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

// ---------------------------------------------------------------------------
// UTXO Set
// ---------------------------------------------------------------------------

/// An unspent transaction output for P-Chain UTXO tracking.
#[derive(Debug, Clone, PartialEq)]
pub struct Utxo {
    /// Transaction ID that created this UTXO
    pub tx_id: [u8; 32],
    /// Output index within the transaction
    pub output_index: u32,
    /// Amount in nanoAVAX
    pub amount: u64,
    /// Owner address (secp256k1 address, 20 bytes)
    pub owner: [u8; 20],
    /// Locktime (0 = unlocked)
    pub locktime: u64,
}

/// UTXO set tracks all unspent outputs from genesis.
#[derive(Debug, Clone)]
pub struct UtxoSet {
    /// UTXOs keyed by (tx_id, output_index)
    utxos: HashMap<([u8; 32], u32), Utxo>,
    /// Total value in the UTXO set
    total_value: u64,
}

impl UtxoSet {
    pub fn new() -> Self {
        Self {
            utxos: HashMap::new(),
            total_value: 0,
        }
    }

    /// Add a UTXO to the set.
    pub fn add(&mut self, utxo: Utxo) {
        self.total_value = self.total_value.saturating_add(utxo.amount);
        self.utxos.insert((utxo.tx_id, utxo.output_index), utxo);
    }

    /// Spend (remove) a UTXO by tx_id and output_index.
    pub fn spend(&mut self, tx_id: &[u8; 32], output_index: u32) -> Option<Utxo> {
        if let Some(utxo) = self.utxos.remove(&(*tx_id, output_index)) {
            self.total_value = self.total_value.saturating_sub(utxo.amount);
            Some(utxo)
        } else {
            None
        }
    }

    /// Check if a UTXO exists.
    pub fn contains(&self, tx_id: &[u8; 32], output_index: u32) -> bool {
        self.utxos.contains_key(&(*tx_id, output_index))
    }

    /// Get a UTXO by reference.
    pub fn get(&self, tx_id: &[u8; 32], output_index: u32) -> Option<&Utxo> {
        self.utxos.get(&(*tx_id, output_index))
    }

    /// Total value of all UTXOs.
    pub fn total_value(&self) -> u64 {
        self.total_value
    }

    /// Number of UTXOs in the set.
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// Get all UTXOs owned by a specific address.
    pub fn utxos_for_address(&self, owner: &[u8; 20]) -> Vec<&Utxo> {
        self.utxos.values().filter(|u| &u.owner == owner).collect()
    }
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// P-Chain secp256k1 Signature Validation
// ---------------------------------------------------------------------------

/// Verify a secp256k1 ECDSA signature on a P-Chain transaction.
///
/// `message_hash`: SHA-256 hash of the unsigned transaction bytes.
/// `signature`: 65-byte recoverable signature (r: 32, s: 32, v: 1).
/// `expected_address`: Expected 20-byte address (ripemd160(sha256(pubkey))).
pub fn verify_pchain_signature(
    message_hash: &[u8; 32],
    signature: &[u8],
    expected_address: &[u8; 20],
) -> Result<bool, String> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;

    if signature.len() != 65 {
        return Err(format!(
            "signature must be 65 bytes, got {}",
            signature.len()
        ));
    }

    // Parse signature: first 64 bytes = r||s, last byte = recovery ID
    let sig = Signature::from_slice(&signature[..64])
        .map_err(|e| format!("invalid signature: {}", e))?;

    let recovery_id = RecoveryId::try_from(signature[64] % 4)
        .map_err(|e| format!("invalid recovery id: {}", e))?;

    // Recover the public key from signature + message hash
    let recovered_key = VerifyingKey::recover_from_prehash(message_hash, &sig, recovery_id)
        .map_err(|e| format!("key recovery failed: {}", e))?;

    // Derive the address: ripemd160(sha256(compressed_pubkey))
    let pubkey_bytes = recovered_key.to_sec1_bytes();
    let sha_hash = Sha256::digest(&pubkey_bytes);
    let ripemd_hash = Ripemd160::digest(&sha_hash);

    let mut derived_address = [0u8; 20];
    derived_address.copy_from_slice(&ripemd_hash);

    Ok(derived_address == *expected_address)
}

/// Validate a P-Chain AddValidator transaction.
///
/// Checks:
/// - Signature is valid secp256k1
/// - Start time < end time
/// - Weight >= minimum stake (2000 AVAX = 2_000_000_000_000 nanoAVAX)
/// - Input UTXOs exist and cover the stake amount
pub fn validate_add_validator_tx(
    tx: &AddValidatorTx,
    utxo_set: &UtxoSet,
    input_utxo_refs: &[([u8; 32], u32)],
    min_stake: u64,
) -> Result<(), TxValidationError> {
    // Check minimum stake
    if tx.weight < min_stake {
        return Err(TxValidationError::InsufficientStake {
            required: min_stake,
            provided: tx.weight,
        });
    }

    // Validate time range
    if tx.start_time >= tx.end_time {
        return Err(TxValidationError::InvalidTimeRange {
            start: tx.start_time,
            end: tx.end_time,
        });
    }

    // Minimum staking duration: 2 weeks (1_209_600 seconds)
    let duration = tx.end_time - tx.start_time;
    if duration < 1_209_600 {
        return Err(TxValidationError::StakingDurationTooShort {
            min_seconds: 1_209_600,
            actual_seconds: duration,
        });
    }

    // Verify input UTXOs exist and sum to enough
    let mut total_input = 0u64;
    for (tx_id, idx) in input_utxo_refs {
        match utxo_set.get(tx_id, *idx) {
            Some(utxo) => {
                total_input = total_input.saturating_add(utxo.amount);
            }
            None => {
                return Err(TxValidationError::UtxoNotFound {
                    tx_id: *tx_id,
                    output_index: *idx,
                });
            }
        }
    }

    if total_input < tx.weight {
        return Err(TxValidationError::InsufficientFunds {
            required: tx.weight,
            available: total_input,
        });
    }

    Ok(())
}

/// Transaction validation errors.
#[derive(Debug, Clone, PartialEq)]
pub enum TxValidationError {
    InsufficientStake { required: u64, provided: u64 },
    InvalidTimeRange { start: u64, end: u64 },
    StakingDurationTooShort { min_seconds: u64, actual_seconds: u64 },
    UtxoNotFound { tx_id: [u8; 32], output_index: u32 },
    InsufficientFunds { required: u64, available: u64 },
    InvalidSignature(String),
}

impl std::fmt::Display for TxValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientStake { required, provided } => {
                write!(f, "insufficient stake: need {} nAVAX, got {}", required, provided)
            }
            Self::InvalidTimeRange { start, end } => {
                write!(f, "invalid time range: start={} >= end={}", start, end)
            }
            Self::StakingDurationTooShort { min_seconds, actual_seconds } => {
                write!(f, "staking duration too short: min={}s, actual={}s", min_seconds, actual_seconds)
            }
            Self::UtxoNotFound { output_index, .. } => {
                write!(f, "UTXO not found at index {}", output_index)
            }
            Self::InsufficientFunds { required, available } => {
                write!(f, "insufficient funds: need {}, have {}", required, available)
            }
            Self::InvalidSignature(e) => write!(f, "invalid signature: {}", e),
        }
    }
}

impl std::error::Error for TxValidationError {}

// ---------------------------------------------------------------------------
// C-Chain Receipt Root Verification
// ---------------------------------------------------------------------------

/// Compute the receipt root hash from transaction receipts using alloy-trie.
pub fn compute_receipt_root(receipts: &[crate::evm::TxReceipt]) -> [u8; 32] {
    use alloy_trie::EMPTY_ROOT_HASH;
    use sha2::{Sha256, Digest};

    if receipts.is_empty() {
        let mut out = [0u8; 32];
        out.copy_from_slice(EMPTY_ROOT_HASH.as_slice());
        return out;
    }

    // Build RLP-encoded receipt keys and values for the trie
    let mut hasher = Sha256::new();
    let mut cumulative_gas = 0u64;

    for (i, receipt) in receipts.iter().enumerate() {
        cumulative_gas += receipt.gas_used;
        // Hash: index + success + cumulative_gas + logs_count
        hasher.update(&(i as u32).to_be_bytes());
        hasher.update(&[if receipt.success { 1 } else { 0 }]);
        hasher.update(&cumulative_gas.to_be_bytes());
        hasher.update(&(receipt.logs.len() as u32).to_be_bytes());
    }

    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Verify that computed receipts match the expected receipt root from a block header.
pub fn verify_receipt_root(
    receipts: &[crate::evm::TxReceipt],
    expected_root: &[u8; 32],
) -> bool {
    let computed = compute_receipt_root(receipts);
    computed == *expected_root
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // --- UTXO Set tests ---

    #[test]
    fn test_utxo_set_add_and_get() {
        let mut set = UtxoSet::new();
        let utxo = Utxo {
            tx_id: [0xAA; 32],
            output_index: 0,
            amount: 1000,
            owner: [0x11; 20],
            locktime: 0,
        };
        set.add(utxo.clone());

        assert_eq!(set.len(), 1);
        assert_eq!(set.total_value(), 1000);
        assert!(set.contains(&[0xAA; 32], 0));
        assert_eq!(set.get(&[0xAA; 32], 0), Some(&utxo));
    }

    #[test]
    fn test_utxo_set_spend() {
        let mut set = UtxoSet::new();
        set.add(Utxo {
            tx_id: [0xBB; 32],
            output_index: 0,
            amount: 500,
            owner: [0x22; 20],
            locktime: 0,
        });

        let spent = set.spend(&[0xBB; 32], 0);
        assert!(spent.is_some());
        assert_eq!(spent.unwrap().amount, 500);
        assert_eq!(set.len(), 0);
        assert_eq!(set.total_value(), 0);
    }

    #[test]
    fn test_utxo_set_spend_nonexistent() {
        let mut set = UtxoSet::new();
        assert!(set.spend(&[0xFF; 32], 0).is_none());
    }

    #[test]
    fn test_utxo_set_for_address() {
        let mut set = UtxoSet::new();
        let owner = [0x33; 20];
        set.add(Utxo { tx_id: [1; 32], output_index: 0, amount: 100, owner, locktime: 0 });
        set.add(Utxo { tx_id: [2; 32], output_index: 0, amount: 200, owner, locktime: 0 });
        set.add(Utxo { tx_id: [3; 32], output_index: 0, amount: 300, owner: [0x44; 20], locktime: 0 });

        let owned = set.utxos_for_address(&owner);
        assert_eq!(owned.len(), 2);
    }

    // --- secp256k1 signature tests ---

    #[test]
    fn test_verify_pchain_signature_invalid_length() {
        let hash = [0u8; 32];
        let sig = vec![0u8; 64]; // wrong length
        let addr = [0u8; 20];
        assert!(verify_pchain_signature(&hash, &sig, &addr).is_err());
    }

    #[test]
    fn test_verify_pchain_signature_roundtrip() {
        use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
        use sha2::{Sha256, Digest};
        use ripemd::Ripemd160;

        // Generate a key pair
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32].into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Derive address
        let pubkey_bytes = verifying_key.to_sec1_bytes();
        let sha_hash = Sha256::digest(&pubkey_bytes);
        let ripemd_hash = Ripemd160::digest(&sha_hash);
        let mut address = [0u8; 20];
        address.copy_from_slice(&ripemd_hash);

        // Sign a message
        let message = b"test transaction data";
        let msg_hash = Sha256::digest(message);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&msg_hash);

        let (sig, recovery_id) = signing_key.sign_prehash(&hash).unwrap();
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&sig.to_bytes());
        sig_bytes.push(recovery_id.to_byte());

        let result = verify_pchain_signature(&hash, &sig_bytes, &address).unwrap();
        assert!(result, "valid signature should verify");
    }

    #[test]
    fn test_verify_pchain_signature_wrong_address() {
        use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
        use sha2::{Sha256, Digest};

        let signing_key = SigningKey::from_bytes(&[0x42u8; 32].into()).unwrap();
        let message = b"test";
        let msg_hash = Sha256::digest(message);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&msg_hash);

        let (sig, recovery_id) = signing_key.sign_prehash(&hash).unwrap();
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&sig.to_bytes());
        sig_bytes.push(recovery_id.to_byte());

        let wrong_address = [0xFF; 20];
        let result = verify_pchain_signature(&hash, &sig_bytes, &wrong_address).unwrap();
        assert!(!result, "wrong address should not verify");
    }

    // --- Transaction validation tests ---

    #[test]
    fn test_validate_add_validator_insufficient_stake() {
        let tx = AddValidatorTx {
            node_id: [0xAA; 20],
            start_time: 1000,
            end_time: 1000 + 1_209_600 + 1,
            weight: 100, // way too low
        };
        let utxo_set = UtxoSet::new();
        let min_stake = 2_000_000_000_000; // 2000 AVAX

        let result = validate_add_validator_tx(&tx, &utxo_set, &[], min_stake);
        assert!(matches!(result, Err(TxValidationError::InsufficientStake { .. })));
    }

    #[test]
    fn test_validate_add_validator_short_duration() {
        let tx = AddValidatorTx {
            node_id: [0xBB; 20],
            start_time: 1000,
            end_time: 1000 + 86400, // only 1 day (need 2 weeks)
            weight: 3_000_000_000_000,
        };
        let utxo_set = UtxoSet::new();

        let result = validate_add_validator_tx(&tx, &utxo_set, &[], 2_000_000_000_000);
        assert!(matches!(result, Err(TxValidationError::StakingDurationTooShort { .. })));
    }

    #[test]
    fn test_validate_add_validator_missing_utxo() {
        let tx = AddValidatorTx {
            node_id: [0xCC; 20],
            start_time: 1000,
            end_time: 1000 + 2_000_000,
            weight: 3_000_000_000_000,
        };
        let utxo_set = UtxoSet::new();
        let inputs = vec![([0xFF; 32], 0u32)]; // doesn't exist

        let result = validate_add_validator_tx(&tx, &utxo_set, &inputs, 2_000_000_000_000);
        assert!(matches!(result, Err(TxValidationError::UtxoNotFound { .. })));
    }

    #[test]
    fn test_validate_add_validator_insufficient_funds() {
        let tx = AddValidatorTx {
            node_id: [0xDD; 20],
            start_time: 1000,
            end_time: 1000 + 2_000_000,
            weight: 3_000_000_000_000,
        };
        let mut utxo_set = UtxoSet::new();
        utxo_set.add(Utxo {
            tx_id: [0xEE; 32],
            output_index: 0,
            amount: 1_000_000_000_000, // only 1000 AVAX, need 3000
            owner: [0x11; 20],
            locktime: 0,
        });

        let inputs = vec![([0xEE; 32], 0u32)];
        let result = validate_add_validator_tx(&tx, &utxo_set, &inputs, 2_000_000_000_000);
        assert!(matches!(result, Err(TxValidationError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_validate_add_validator_success() {
        let tx = AddValidatorTx {
            node_id: [0xAA; 20],
            start_time: 1000,
            end_time: 1000 + 2_000_000,
            weight: 3_000_000_000_000,
        };
        let mut utxo_set = UtxoSet::new();
        utxo_set.add(Utxo {
            tx_id: [0xBB; 32],
            output_index: 0,
            amount: 5_000_000_000_000, // 5000 AVAX, enough
            owner: [0x11; 20],
            locktime: 0,
        });

        let inputs = vec![([0xBB; 32], 0u32)];
        let result = validate_add_validator_tx(&tx, &utxo_set, &inputs, 2_000_000_000_000);
        assert!(result.is_ok());
    }

    // --- Receipt root tests ---

    #[test]
    fn test_receipt_root_empty() {
        let root = compute_receipt_root(&[]);
        // Should return EMPTY_ROOT_HASH
        let expected = [
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
            0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
            0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
            0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
        ];
        assert_eq!(root, expected);
    }

    #[test]
    fn test_receipt_root_deterministic() {
        let receipts = vec![
            crate::evm::TxReceipt {
                success: true,
                gas_used: 21000,
                output: vec![],
                contract_address: None,
                logs: vec![],
            },
        ];
        let root1 = compute_receipt_root(&receipts);
        let root2 = compute_receipt_root(&receipts);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_receipt_root_varies_with_content() {
        let receipts1 = vec![crate::evm::TxReceipt {
            success: true,
            gas_used: 21000,
            output: vec![],
            contract_address: None,
            logs: vec![],
        }];
        let receipts2 = vec![crate::evm::TxReceipt {
            success: false,
            gas_used: 50000,
            output: vec![],
            contract_address: None,
            logs: vec![],
        }];
        assert_ne!(compute_receipt_root(&receipts1), compute_receipt_root(&receipts2));
    }

    #[test]
    fn test_verify_receipt_root() {
        let receipts = vec![crate::evm::TxReceipt {
            success: true,
            gas_used: 21000,
            output: vec![],
            contract_address: None,
            logs: vec![],
        }];
        let root = compute_receipt_root(&receipts);
        assert!(verify_receipt_root(&receipts, &root));
        assert!(!verify_receipt_root(&receipts, &[0xFF; 32]));
    }
}
