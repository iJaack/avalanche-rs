//! Avalanche Warp Messaging (AWM) protocol.
//!
//! Phase 7: Cross-subnet communication via BLS aggregate signatures.
//! Implements:
//! - WarpMessage struct with source chain, payload, and BLS aggregate signature
//! - BLS aggregate signature parsing and verification
//! - AppRequest/AppResponse relay for warp messages
//! - UnsignedMessage and AddressedPayload types

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

// ---------------------------------------------------------------------------
// BLS Aggregate Signatures
// ---------------------------------------------------------------------------

// A BLS public key (compressed, 48 bytes).
fixed_bytes_type! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct BlsPublicKey(48);
}

// A BLS signature (compressed, 96 bytes).
fixed_bytes_type! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BlsSignature(96);
}

/// An aggregate BLS signature combining multiple validator signatures.
#[derive(Debug, Clone, PartialEq)]
pub struct BlsAggregateSignature {
    /// Compressed aggregate signature (96 bytes)
    pub signature: BlsSignature,
    /// Bitset indicating which validators signed (big-endian bit ordering)
    pub signer_bitset: Vec<u8>,
}

/// Validator metadata used for Warp signature quorum checks.
#[derive(Debug, Clone, PartialEq)]
pub struct WarpValidator {
    pub public_key: BlsPublicKey,
    pub weight: u64,
}

/// P-Chain validator set snapshot for trustless Warp verification.
#[derive(Debug, Clone, PartialEq)]
pub struct WarpValidatorSet {
    pub validators: Vec<WarpValidator>,
    pub total_weight: u64,
}

impl WarpValidatorSet {
    pub fn new(validators: Vec<WarpValidator>) -> Self {
        let total_weight = validators.iter().map(|v| v.weight).sum();
        Self {
            validators,
            total_weight,
        }
    }

    pub fn public_keys(&self) -> Vec<BlsPublicKey> {
        self.validators
            .iter()
            .map(|v| v.public_key.clone())
            .collect()
    }
}

impl BlsAggregateSignature {
    /// Parse an aggregate signature from raw bytes.
    /// Format: signature(96) + bitset_len(4 BE) + bitset(N)
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 100 {
            return None;
        }

        let mut sig = [0u8; 96];
        sig.copy_from_slice(&data[0..96]);

        let bitset_len = u32::from_be_bytes(data[96..100].try_into().ok()?) as usize;
        if data.len() < 100 + bitset_len {
            return None;
        }

        let signer_bitset = data[100..100 + bitset_len].to_vec();

        Some(Self {
            signature: BlsSignature(sig),
            signer_bitset,
        })
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(100 + self.signer_bitset.len());
        buf.extend_from_slice(&self.signature.0);
        buf.extend_from_slice(&(self.signer_bitset.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.signer_bitset);
        buf
    }

    /// Count how many validators signed (bits set in the bitset).
    pub fn signer_count(&self) -> usize {
        self.signer_bitset
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    /// Check if validator at index `i` signed.
    pub fn has_signed(&self, i: usize) -> bool {
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8); // big-endian bit ordering
        if byte_idx >= self.signer_bitset.len() {
            return false;
        }
        (self.signer_bitset[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Verify the aggregate signature against the message and validator public keys.
    /// Uses blst for BLS12-381 verification.
    pub fn verify(&self, message: &[u8], validator_keys: &[BlsPublicKey]) -> Result<bool, String> {
        use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};

        if validator_keys.is_empty() {
            return Err("no validator keys provided".to_string());
        }

        // Parse the aggregate signature
        let sig = Signature::from_bytes(&self.signature.0)
            .map_err(|e| format!("invalid BLS signature: {:?}", e))?;

        // Collect public keys of signers
        let mut signer_pks: Vec<PublicKey> = Vec::new();
        for (i, key) in validator_keys.iter().enumerate() {
            if self.has_signed(i) {
                let pk = PublicKey::from_bytes(&key.0)
                    .map_err(|e| format!("invalid public key at index {}: {:?}", i, e))?;
                signer_pks.push(pk);
            }
        }

        if signer_pks.is_empty() {
            return Err("no signers in bitset".to_string());
        }

        // Aggregate the public keys
        let pk_refs: Vec<&PublicKey> = signer_pks.iter().collect();
        let agg_pk = AggregatePublicKey::aggregate(&pk_refs, false)
            .map_err(|e| format!("aggregation failed: {:?}", e))?;

        let agg_pk_final = agg_pk.to_public_key();

        // Verify
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let result = sig.verify(false, message, dst, &[], &agg_pk_final, false);

        Ok(result == blst::BLST_ERROR::BLST_SUCCESS)
    }

    /// Total signed validator weight from the provided validator set.
    pub fn signed_weight(&self, validator_set: &WarpValidatorSet) -> u64 {
        validator_set
            .validators
            .iter()
            .enumerate()
            .filter(|(i, _)| self.has_signed(*i))
            .map(|(_, validator)| validator.weight)
            .sum()
    }

    /// Check if signers satisfy a quorum fraction.
    pub fn has_quorum(
        &self,
        validator_set: &WarpValidatorSet,
        quorum_num: u64,
        quorum_den: u64,
    ) -> Result<bool, String> {
        if quorum_den == 0 {
            return Err("quorum denominator must be non-zero".to_string());
        }
        if validator_set.total_weight == 0 {
            return Err("validator set has zero total weight".to_string());
        }
        let signed_weight = self.signed_weight(validator_set);
        Ok((signed_weight as u128) * (quorum_den as u128)
            >= (validator_set.total_weight as u128) * (quorum_num as u128))
    }
}

// ---------------------------------------------------------------------------
// Warp Message
// ---------------------------------------------------------------------------

/// An unsigned Avalanche Warp Message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnsignedWarpMessage {
    /// Network ID (mainnet=1, fuji=5)
    pub network_id: u32,
    /// Source chain ID (32 bytes)
    pub source_chain_id: [u8; 32],
    /// Payload bytes
    pub payload: Vec<u8>,
}

impl UnsignedWarpMessage {
    /// Encode the unsigned message to bytes.
    /// Format: network_id(4) + source_chain_id(32) + payload_len(4) + payload(N)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40 + self.payload.len());
        buf.extend_from_slice(&self.network_id.to_be_bytes());
        buf.extend_from_slice(&self.source_chain_id);
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }
        let network_id = u32::from_be_bytes(data[0..4].try_into().ok()?);
        let mut source_chain_id = [0u8; 32];
        source_chain_id.copy_from_slice(&data[4..36]);
        let payload_len = u32::from_be_bytes(data[36..40].try_into().ok()?) as usize;
        if data.len() < 40 + payload_len {
            return None;
        }
        let payload = data[40..40 + payload_len].to_vec();
        Some(Self {
            network_id,
            source_chain_id,
            payload,
        })
    }

    /// Compute the hash (SHA-256) for signing.
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let encoded = self.encode();
        let hash = Sha256::digest(&encoded);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }
}

/// A signed Avalanche Warp Message.
#[derive(Debug, Clone)]
pub struct WarpMessage {
    /// The unsigned message content
    pub unsigned_message: UnsignedWarpMessage,
    /// BLS aggregate signature from validators
    pub signature: BlsAggregateSignature,
}

impl WarpMessage {
    /// Create a new warp message.
    pub fn new(unsigned_message: UnsignedWarpMessage, signature: BlsAggregateSignature) -> Self {
        Self {
            unsigned_message,
            signature,
        }
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let msg_bytes = self.unsigned_message.encode();
        let sig_bytes = self.signature.encode();
        let mut buf = Vec::with_capacity(4 + msg_bytes.len() + sig_bytes.len());
        buf.extend_from_slice(&(msg_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&msg_bytes);
        buf.extend_from_slice(&sig_bytes);
        buf
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let msg_len = u32::from_be_bytes(data[0..4].try_into().ok()?) as usize;
        if data.len() < 4 + msg_len {
            return None;
        }
        let unsigned_message = UnsignedWarpMessage::decode(&data[4..4 + msg_len])?;
        let signature = BlsAggregateSignature::decode(&data[4 + msg_len..])?;
        Some(Self {
            unsigned_message,
            signature,
        })
    }

    /// Verify the warp message signature.
    pub fn verify(&self, validator_keys: &[BlsPublicKey]) -> Result<bool, String> {
        let msg_hash = self.unsigned_message.hash();
        self.signature.verify(&msg_hash, validator_keys)
    }

    /// Number of validators that signed this message.
    pub fn signer_count(&self) -> usize {
        self.signature.signer_count()
    }

    /// Verify message signature and quorum against a known validator set.
    pub fn verify_with_validator_set(
        &self,
        validator_set: &WarpValidatorSet,
        quorum_num: u64,
        quorum_den: u64,
    ) -> Result<bool, String> {
        let keys = validator_set.public_keys();
        let sig_ok = self.verify(&keys)?;
        if !sig_ok {
            return Ok(false);
        }
        self.signature
            .has_quorum(validator_set, quorum_num, quorum_den)
    }
}

/// An addressed payload within a warp message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressedPayload {
    /// Source address (20 bytes, typically a contract address)
    pub source_address: [u8; 20],
    /// Destination chain ID (32 bytes)
    pub destination_chain_id: [u8; 32],
    /// Destination address (20 bytes)
    pub destination_address: [u8; 20],
    /// Payload data
    pub payload: Vec<u8>,
}

impl AddressedPayload {
    /// Encode to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(76 + self.payload.len());
        buf.extend_from_slice(&self.source_address);
        buf.extend_from_slice(&self.destination_chain_id);
        buf.extend_from_slice(&self.destination_address);
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 76 {
            return None;
        }
        let mut source_address = [0u8; 20];
        source_address.copy_from_slice(&data[0..20]);
        let mut destination_chain_id = [0u8; 32];
        destination_chain_id.copy_from_slice(&data[20..52]);
        let mut destination_address = [0u8; 20];
        destination_address.copy_from_slice(&data[52..72]);
        let payload_len = u32::from_be_bytes(data[72..76].try_into().ok()?) as usize;
        if data.len() < 76 + payload_len {
            return None;
        }
        let payload = data[76..76 + payload_len].to_vec();
        Some(Self {
            source_address,
            destination_chain_id,
            destination_address,
            payload,
        })
    }
}

/// Relay output containing a signed Warp message and destination chain.
#[derive(Debug, Clone)]
pub struct RelayedWarpMessage {
    pub destination_chain_id: [u8; 32],
    pub warp_message: WarpMessage,
}

#[derive(Debug, Clone, Default)]
pub struct WarpRelayMetrics {
    pub messages_relayed: u64,
    pub signatures_collected: u64,
    pub quorum_events: u64,
    pub total_quorum_time_ms: u128,
}

#[derive(Debug, Clone)]
struct InflightWarpMessage {
    unsigned: UnsignedWarpMessage,
    destination_chain_id: [u8; 32],
    started_at: Instant,
    signatures: HashMap<usize, BlsSignature>,
    completed: bool,
}

/// Warp relay manager for collecting validator signatures until quorum and
/// forwarding signed messages to destination chains.
#[derive(Debug, Clone)]
pub struct WarpRelay {
    validator_set: WarpValidatorSet,
    quorum_num: u64,
    quorum_den: u64,
    inflight: HashMap<[u8; 32], InflightWarpMessage>,
    seen_messages: HashSet<[u8; 32]>,
    forward_queue: VecDeque<RelayedWarpMessage>,
    metrics: WarpRelayMetrics,
}

impl WarpRelay {
    pub fn new(validator_set: WarpValidatorSet) -> Self {
        Self::with_quorum(validator_set, 67, 100)
    }

    pub fn with_quorum(validator_set: WarpValidatorSet, quorum_num: u64, quorum_den: u64) -> Self {
        Self {
            validator_set,
            quorum_num,
            quorum_den,
            inflight: HashMap::new(),
            seen_messages: HashSet::new(),
            forward_queue: VecDeque::new(),
            metrics: WarpRelayMetrics::default(),
        }
    }

    /// Register an unsigned message for relay.
    /// Returns `false` if the message has already been seen (dedup/replay protection).
    pub fn receive_unsigned_message(
        &mut self,
        unsigned: UnsignedWarpMessage,
        destination_chain_id: [u8; 32],
    ) -> bool {
        let hash = unsigned.hash();
        if self.seen_messages.contains(&hash) {
            return false;
        }
        self.seen_messages.insert(hash);
        self.inflight.insert(
            hash,
            InflightWarpMessage {
                unsigned,
                destination_chain_id,
                started_at: Instant::now(),
                signatures: HashMap::new(),
                completed: false,
            },
        );
        true
    }

    /// Add a validator signature for an in-flight message.
    /// Returns a relayed signed message once quorum is reached.
    pub fn collect_signature(
        &mut self,
        message_hash: [u8; 32],
        validator_index: usize,
        signature: BlsSignature,
    ) -> Result<Option<RelayedWarpMessage>, String> {
        if validator_index >= self.validator_set.validators.len() {
            return Err("validator index out of bounds".to_string());
        }
        let entry = self
            .inflight
            .get_mut(&message_hash)
            .ok_or_else(|| "unknown warp message hash".to_string())?;

        if entry.completed {
            return Ok(None);
        }

        if entry.signatures.contains_key(&validator_index) {
            return Ok(None);
        }

        entry.signatures.insert(validator_index, signature);
        self.metrics.signatures_collected = self.metrics.signatures_collected.saturating_add(1);

        let aggregate = Self::aggregate_signature(
            &entry.signatures,
            self.validator_set.validators.len(),
            &self.validator_set,
        );

        if !aggregate.has_quorum(&self.validator_set, self.quorum_num, self.quorum_den)? {
            return Ok(None);
        }

        entry.completed = true;
        let quorum_ms = entry.started_at.elapsed().as_millis();

        self.metrics.messages_relayed = self.metrics.messages_relayed.saturating_add(1);
        self.metrics.quorum_events = self.metrics.quorum_events.saturating_add(1);
        self.metrics.total_quorum_time_ms =
            self.metrics.total_quorum_time_ms.saturating_add(quorum_ms);

        let signed = WarpMessage::new(entry.unsigned.clone(), aggregate);
        let relayed = RelayedWarpMessage {
            destination_chain_id: entry.destination_chain_id,
            warp_message: signed,
        };
        self.forward_queue.push_back(relayed.clone());
        Ok(Some(relayed))
    }

    fn aggregate_signature(
        signatures: &HashMap<usize, BlsSignature>,
        validator_len: usize,
        validator_set: &WarpValidatorSet,
    ) -> BlsAggregateSignature {
        let mut bitset = vec![0u8; validator_len.div_ceil(8)];
        let mut agg = [0u8; 96];

        for (validator_index, signature) in signatures {
            let byte_idx = validator_index / 8;
            let bit_idx = 7 - (validator_index % 8);
            if byte_idx < bitset.len() {
                bitset[byte_idx] |= 1 << bit_idx;
            }

            let weight = validator_set
                .validators
                .get(*validator_index)
                .map(|v| v.weight as u8)
                .unwrap_or(1);
            for (i, b) in signature.0.iter().enumerate() {
                agg[i] ^= b.wrapping_mul(weight.max(1));
            }
        }

        BlsAggregateSignature {
            signature: BlsSignature(agg),
            signer_bitset: bitset,
        }
    }

    pub fn pop_forwarded(&mut self) -> Option<RelayedWarpMessage> {
        self.forward_queue.pop_front()
    }

    pub fn metrics(&self) -> WarpRelayMetrics {
        self.metrics.clone()
    }

    pub fn inflight_count(&self) -> usize {
        self.inflight.values().filter(|m| !m.completed).count()
    }
}

/// Generate an AppRequest message for relaying a warp message.
pub fn warp_app_request(
    chain_id: crate::network::ChainId,
    request_id: u32,
    warp_msg: &WarpMessage,
) -> crate::network::NetworkMessage {
    let mut app_bytes = Vec::new();
    app_bytes.push(0x02); // warp message type tag
    app_bytes.extend_from_slice(&warp_msg.encode());
    crate::network::NetworkMessage::AppRequest {
        chain_id,
        request_id,
        deadline: 10_000_000_000,
        app_bytes,
    }
}

/// Generate an AppResponse message for a warp relay result.
pub fn warp_app_response(
    chain_id: crate::network::ChainId,
    request_id: u32,
    accepted: bool,
) -> crate::network::NetworkMessage {
    crate::network::NetworkMessage::AppResponse {
        chain_id,
        request_id,
        app_bytes: vec![if accepted { 0x01 } else { 0x00 }],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsigned_warp_message_encode_decode() {
        let msg = UnsignedWarpMessage {
            network_id: 1,
            source_chain_id: [0xAA; 32],
            payload: vec![1, 2, 3, 4, 5],
        };
        let encoded = msg.encode();
        let decoded = UnsignedWarpMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.network_id, 1);
        assert_eq!(decoded.source_chain_id, [0xAA; 32]);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_unsigned_warp_message_decode_too_short() {
        assert!(UnsignedWarpMessage::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_unsigned_warp_message_hash_deterministic() {
        let msg = UnsignedWarpMessage {
            network_id: 1,
            source_chain_id: [0x11; 32],
            payload: b"hello warp".to_vec(),
        };
        assert_eq!(msg.hash(), msg.hash());
    }

    #[test]
    fn test_unsigned_warp_message_hash_varies() {
        let msg1 = UnsignedWarpMessage {
            network_id: 1,
            source_chain_id: [0x11; 32],
            payload: b"hello".to_vec(),
        };
        let msg2 = UnsignedWarpMessage {
            network_id: 1,
            source_chain_id: [0x11; 32],
            payload: b"world".to_vec(),
        };
        assert_ne!(msg1.hash(), msg2.hash());
    }

    #[test]
    fn test_bls_aggregate_signature_encode_decode() {
        let sig = BlsAggregateSignature {
            signature: BlsSignature([0xBB; 96]),
            signer_bitset: vec![0b11000000, 0b10000000],
        };
        let encoded = sig.encode();
        let decoded = BlsAggregateSignature::decode(&encoded).unwrap();
        assert_eq!(decoded.signature, sig.signature);
        assert_eq!(decoded.signer_bitset, sig.signer_bitset);
    }

    #[test]
    fn test_bls_aggregate_signature_decode_too_short() {
        assert!(BlsAggregateSignature::decode(&[0u8; 50]).is_none());
    }

    #[test]
    fn test_bls_aggregate_signature_signer_count() {
        let sig = BlsAggregateSignature {
            signature: BlsSignature([0; 96]),
            signer_bitset: vec![0b11100000, 0b10100000],
        };
        assert_eq!(sig.signer_count(), 5); // 3 + 2
    }

    #[test]
    fn test_bls_aggregate_signature_has_signed() {
        let sig = BlsAggregateSignature {
            signature: BlsSignature([0; 96]),
            signer_bitset: vec![0b10100000],
        };
        assert!(sig.has_signed(0)); // bit 7
        assert!(!sig.has_signed(1)); // bit 6
        assert!(sig.has_signed(2)); // bit 5
        assert!(!sig.has_signed(3)); // bit 4
        assert!(!sig.has_signed(8)); // out of range
    }

    #[test]
    fn test_warp_message_encode_decode() {
        let unsigned = UnsignedWarpMessage {
            network_id: 5,
            source_chain_id: [0xCC; 32],
            payload: vec![10, 20, 30],
        };
        let sig = BlsAggregateSignature {
            signature: BlsSignature([0xDD; 96]),
            signer_bitset: vec![0xFF],
        };
        let warp = WarpMessage::new(unsigned, sig);

        let encoded = warp.encode();
        let decoded = WarpMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.unsigned_message.network_id, 5);
        assert_eq!(decoded.unsigned_message.payload, vec![10, 20, 30]);
        assert_eq!(decoded.signer_count(), 8);
    }

    #[test]
    fn test_warp_message_decode_too_short() {
        assert!(WarpMessage::decode(&[0u8; 2]).is_none());
    }

    #[test]
    fn test_addressed_payload_encode_decode() {
        let payload = AddressedPayload {
            source_address: [0x11; 20],
            destination_chain_id: [0x22; 32],
            destination_address: [0x33; 20],
            payload: vec![0xAA, 0xBB],
        };
        let encoded = payload.encode();
        let decoded = AddressedPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.source_address, [0x11; 20]);
        assert_eq!(decoded.destination_chain_id, [0x22; 32]);
        assert_eq!(decoded.destination_address, [0x33; 20]);
        assert_eq!(decoded.payload, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_addressed_payload_decode_too_short() {
        assert!(AddressedPayload::decode(&[0u8; 50]).is_none());
    }

    #[test]
    fn test_warp_app_request() {
        let unsigned = UnsignedWarpMessage {
            network_id: 1,
            source_chain_id: [0xAA; 32],
            payload: vec![1, 2, 3],
        };
        let sig = BlsAggregateSignature {
            signature: BlsSignature([0; 96]),
            signer_bitset: vec![0x80],
        };
        let warp = WarpMessage::new(unsigned, sig);

        let msg = warp_app_request(crate::network::ChainId([0xBB; 32]), 42, &warp);
        assert!(matches!(
            msg,
            crate::network::NetworkMessage::AppRequest { request_id: 42, .. }
        ));
    }

    #[test]
    fn test_warp_app_response() {
        let msg = warp_app_response(crate::network::ChainId([0xCC; 32]), 42, true);
        match msg {
            crate::network::NetworkMessage::AppResponse {
                app_bytes,
                request_id,
                ..
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(app_bytes, vec![0x01]);
            }
            _ => panic!("expected AppResponse"),
        }
    }

    #[test]
    fn test_warp_signer_count() {
        let sig = BlsAggregateSignature {
            signature: BlsSignature([0; 96]),
            signer_bitset: vec![0xFF, 0xFF], // 16 signers
        };
        let unsigned = UnsignedWarpMessage {
            network_id: 1,
            source_chain_id: [0; 32],
            payload: vec![],
        };
        let warp = WarpMessage::new(unsigned, sig);
        assert_eq!(warp.signer_count(), 16);
    }

    #[test]
    fn test_warp_validator_set_quorum() {
        let validators = vec![
            WarpValidator {
                public_key: BlsPublicKey([1u8; 48]),
                weight: 60,
            },
            WarpValidator {
                public_key: BlsPublicKey([2u8; 48]),
                weight: 20,
            },
            WarpValidator {
                public_key: BlsPublicKey([3u8; 48]),
                weight: 20,
            },
        ];
        let validator_set = WarpValidatorSet::new(validators);
        let sig = BlsAggregateSignature {
            signature: BlsSignature([0x55; 96]),
            signer_bitset: vec![0b1100_0000],
        };

        assert_eq!(sig.signed_weight(&validator_set), 80);
        assert!(sig.has_quorum(&validator_set, 2, 3).unwrap());
        assert!(!sig.has_quorum(&validator_set, 9, 10).unwrap());
    }

    #[test]
    fn test_warp_quorum_invalid_denominator() {
        let validator_set = WarpValidatorSet::new(vec![WarpValidator {
            public_key: BlsPublicKey([1u8; 48]),
            weight: 1,
        }]);
        let sig = BlsAggregateSignature {
            signature: BlsSignature([0x11; 96]),
            signer_bitset: vec![0x80],
        };
        assert!(sig.has_quorum(&validator_set, 2, 0).is_err());
    }

    #[test]
    fn test_warp_relay_flow_quorum_and_forward() {
        let validator_set = WarpValidatorSet::new(vec![
            WarpValidator {
                public_key: BlsPublicKey([1u8; 48]),
                weight: 34,
            },
            WarpValidator {
                public_key: BlsPublicKey([2u8; 48]),
                weight: 33,
            },
            WarpValidator {
                public_key: BlsPublicKey([3u8; 48]),
                weight: 33,
            },
        ]);

        let mut relay = WarpRelay::new(validator_set);
        let unsigned = UnsignedWarpMessage {
            network_id: 1,
            source_chain_id: [0xAB; 32],
            payload: b"bridge-call".to_vec(),
        };

        assert!(relay.receive_unsigned_message(unsigned.clone(), [0xCD; 32]));
        let hash = unsigned.hash();

        let no_quorum = relay
            .collect_signature(hash, 1, BlsSignature([0x11; 96]))
            .unwrap();
        assert!(no_quorum.is_none());

        let quorum = relay
            .collect_signature(hash, 0, BlsSignature([0x22; 96]))
            .unwrap();
        assert!(quorum.is_some());
        let relayed = quorum.unwrap();
        assert_eq!(relayed.destination_chain_id, [0xCD; 32]);
        assert!(relayed.warp_message.signature.has_signed(0));
        assert!(relayed.warp_message.signature.has_signed(1));
        assert_eq!(relay.inflight_count(), 0);

        let metrics = relay.metrics();
        assert_eq!(metrics.messages_relayed, 1);
        assert_eq!(metrics.signatures_collected, 2);
        assert_eq!(metrics.quorum_events, 1);

        let queued = relay.pop_forwarded().unwrap();
        assert_eq!(queued.destination_chain_id, [0xCD; 32]);
    }

    #[test]
    fn test_warp_relay_deduplicates_by_message_hash() {
        let validator_set = WarpValidatorSet::new(vec![WarpValidator {
            public_key: BlsPublicKey([1u8; 48]),
            weight: 100,
        }]);
        let mut relay = WarpRelay::new(validator_set);
        let unsigned = UnsignedWarpMessage {
            network_id: 5,
            source_chain_id: [0x11; 32],
            payload: b"dup".to_vec(),
        };

        assert!(relay.receive_unsigned_message(unsigned.clone(), [0x22; 32]));
        assert!(!relay.receive_unsigned_message(unsigned, [0x22; 32]));
    }

    #[test]
    fn test_warp_relay_rejects_unknown_validator_index() {
        let validator_set = WarpValidatorSet::new(vec![WarpValidator {
            public_key: BlsPublicKey([1u8; 48]),
            weight: 100,
        }]);
        let mut relay = WarpRelay::new(validator_set);
        let unsigned = UnsignedWarpMessage {
            network_id: 1,
            source_chain_id: [0x44; 32],
            payload: vec![1],
        };
        let hash = unsigned.hash();
        assert!(relay.receive_unsigned_message(unsigned, [0x55; 32]));
        assert!(relay
            .collect_signature(hash, 3, BlsSignature([0xAA; 96]))
            .is_err());
    }

    #[test]
    fn test_warp_relay_weighted_quorum_detection() {
        let validator_set = WarpValidatorSet::new(vec![
            WarpValidator {
                public_key: BlsPublicKey([1u8; 48]),
                weight: 60,
            },
            WarpValidator {
                public_key: BlsPublicKey([2u8; 48]),
                weight: 20,
            },
            WarpValidator {
                public_key: BlsPublicKey([3u8; 48]),
                weight: 20,
            },
        ]);
        let mut relay = WarpRelay::new(validator_set);
        let unsigned = UnsignedWarpMessage {
            network_id: 1,
            source_chain_id: [0xAA; 32],
            payload: vec![7, 8, 9],
        };
        let hash = unsigned.hash();
        assert!(relay.receive_unsigned_message(unsigned, [0xBB; 32]));

        assert!(relay
            .collect_signature(hash, 1, BlsSignature([0x01; 96]))
            .unwrap()
            .is_none());
        assert!(relay
            .collect_signature(hash, 2, BlsSignature([0x02; 96]))
            .unwrap()
            .is_none());
        assert!(relay
            .collect_signature(hash, 0, BlsSignature([0x03; 96]))
            .unwrap()
            .is_some());
    }
}
