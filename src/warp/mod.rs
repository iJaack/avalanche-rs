//! Avalanche Warp Messaging (AWM) protocol.
//!
//! Phase 7: Cross-subnet communication via BLS aggregate signatures.
//! Implements:
//! - WarpMessage struct with source chain, payload, and BLS aggregate signature
//! - BLS aggregate signature parsing and verification
//! - AppRequest/AppResponse relay for warp messages
//! - UnsignedMessage and AddressedPayload types

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// BLS Aggregate Signatures
// ---------------------------------------------------------------------------

/// A BLS public key (compressed, 48 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlsPublicKey(pub [u8; 48]);

/// A BLS signature (compressed, 96 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsSignature(pub [u8; 96]);

/// An aggregate BLS signature combining multiple validator signatures.
#[derive(Debug, Clone, PartialEq)]
pub struct BlsAggregateSignature {
    /// Compressed aggregate signature (96 bytes)
    pub signature: BlsSignature,
    /// Bitset indicating which validators signed (big-endian bit ordering)
    pub signer_bitset: Vec<u8>,
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
}
