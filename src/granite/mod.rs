//! Granite upgrade — ACP-181, ACP-204, ACP-226 (AvalancheGo v1.14.0).
//!
//! Three protocol changes activated together:
//!   - ACP-181: P-Chain Epoched Views (5-minute epochs)
//!   - ACP-204: secp256r1 (P-256) signature verification precompile
//!   - ACP-226: Dynamic minimum block times for L1s/subnets
//!
//! Activation:
//!   - Fuji:    2025-10-29T15:00:00Z
//!   - Mainnet: 2025-11-19T16:00:00Z

// ---------------------------------------------------------------------------
// Activation timestamps
// ---------------------------------------------------------------------------

/// Granite activation on Fuji: 2025-10-29T15:00:00Z
pub const GRANITE_FUJI_TIMESTAMP: u64 = 1761750000;

/// Granite activation on Mainnet: 2025-11-19T16:00:00Z
pub const GRANITE_MAINNET_TIMESTAMP: u64 = 1763568000;

/// Check if Granite is active at the given timestamp for the given network.
pub fn is_granite_active(network_id: u32, timestamp: u64) -> bool {
    let activation = match network_id {
        1 => GRANITE_MAINNET_TIMESTAMP,
        5 => GRANITE_FUJI_TIMESTAMP,
        _ => return false,
    };
    timestamp >= activation
}

// ---------------------------------------------------------------------------
// ACP-181: P-Chain Epoched Views
// ---------------------------------------------------------------------------

/// Duration of one epoch in seconds (5 minutes).
pub const EPOCH_DURATION_SECS: u64 = 300;

/// Information about a P-Chain epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochInfo {
    /// The epoch number (0-indexed from Granite activation).
    pub epoch_number: u64,
    /// The P-Chain height that anchors this epoch.
    pub epoch_p_chain_height: u64,
    /// Unix timestamp when this epoch started.
    pub epoch_start_time: u64,
}

/// Calculate the epoch for a given block timestamp.
///
/// The first epoch E_0 starts at the block *before* Granite activation.
/// Returns `None` if Granite is not yet active on this network.
pub fn calculate_epoch(
    network_id: u32,
    block_timestamp: u64,
    activation_block_timestamp: u64,
    activation_p_chain_height: u64,
) -> Option<EpochInfo> {
    if !is_granite_active(network_id, block_timestamp) {
        return None;
    }

    let elapsed = block_timestamp.saturating_sub(activation_block_timestamp);
    let epoch_number = elapsed / EPOCH_DURATION_SECS;

    // Each epoch advances the P-Chain height by 1 from the activation height
    let epoch_p_chain_height = activation_p_chain_height + epoch_number;

    let epoch_start_time = activation_block_timestamp + epoch_number * EPOCH_DURATION_SECS;

    Some(EpochInfo {
        epoch_number,
        epoch_p_chain_height,
        epoch_start_time,
    })
}

// ---------------------------------------------------------------------------
// ACP-204: secp256r1 (P-256) Precompile
// ---------------------------------------------------------------------------

/// Verify a secp256r1 (NIST P-256) ECDSA signature.
///
/// - `message_hash`: 32-byte SHA-256 digest of the message
/// - `sig`: DER or fixed-size (r || s, 64 bytes) encoded signature
/// - `pubkey`: SEC1-encoded public key (compressed 33 bytes or uncompressed 65 bytes)
pub fn verify_secp256r1(
    message_hash: &[u8; 32],
    sig: &[u8],
    pubkey: &[u8],
) -> Result<bool, String> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let vk = VerifyingKey::from_sec1_bytes(pubkey)
        .map_err(|e| format!("invalid P-256 public key: {e}"))?;

    let signature = if sig.len() == 64 {
        Signature::from_slice(sig).map_err(|e| format!("invalid P-256 signature: {e}"))?
    } else {
        Signature::from_der(sig).map_err(|e| format!("invalid P-256 DER signature: {e}"))?
    };

    Ok(vk.verify(message_hash, &signature).is_ok())
}

// ---------------------------------------------------------------------------
// ACP-226: Dynamic Minimum Block Times
// ---------------------------------------------------------------------------

/// Pre-Granite fixed minimum block time (milliseconds).
pub const PRE_GRANITE_MIN_BLOCK_TIME_MS: u64 = 2000;

/// Primary Network ID (Mainnet).
pub const PRIMARY_NETWORK_SUBNET_ID: u32 = 0;

/// Dynamic block timing configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicBlockTiming {
    /// Minimum block time in milliseconds.
    pub min_block_time_ms: u64,
    /// Whether this is on the Primary Network (keeps 2s minimum).
    pub is_primary_network: bool,
}

/// Determine the minimum block time for a given chain.
///
/// - Pre-Granite: all chains use 2000ms.
/// - Post-Granite: Primary Network keeps 2000ms; L1s/subnets can configure
///   lower values (down to 0ms via `--proposervm-min-block-duration`).
pub fn min_block_time(
    network_id: u32,
    subnet_id: u32,
    timestamp: u64,
    configured_min_ms: u64,
) -> DynamicBlockTiming {
    let is_primary = subnet_id == PRIMARY_NETWORK_SUBNET_ID;

    if !is_granite_active(network_id, timestamp) {
        return DynamicBlockTiming {
            min_block_time_ms: PRE_GRANITE_MIN_BLOCK_TIME_MS,
            is_primary_network: is_primary,
        };
    }

    let min_block_time_ms = if is_primary {
        PRE_GRANITE_MIN_BLOCK_TIME_MS
    } else {
        configured_min_ms
    };

    DynamicBlockTiming {
        min_block_time_ms,
        is_primary_network: is_primary,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    // --- Activation ---

    #[test]
    fn test_activation_timestamps() {
        assert_eq!(GRANITE_FUJI_TIMESTAMP, 1761750000);
        assert_eq!(GRANITE_MAINNET_TIMESTAMP, 1763568000);
        assert!(GRANITE_MAINNET_TIMESTAMP > GRANITE_FUJI_TIMESTAMP);
    }

    #[test]
    fn test_is_granite_active() {
        assert!(is_granite_active(5, GRANITE_FUJI_TIMESTAMP));
        assert!(is_granite_active(5, GRANITE_FUJI_TIMESTAMP + 1));
        assert!(!is_granite_active(5, GRANITE_FUJI_TIMESTAMP - 1));
        assert!(is_granite_active(1, GRANITE_MAINNET_TIMESTAMP));
        assert!(!is_granite_active(1, GRANITE_MAINNET_TIMESTAMP - 1));
        assert!(!is_granite_active(999, u64::MAX));
    }

    #[test]
    fn test_fuji_activates_before_mainnet() {
        let between = GRANITE_FUJI_TIMESTAMP + 1;
        assert!(is_granite_active(5, between));
        assert!(!is_granite_active(1, between));
    }

    // --- ACP-181: Epoched Views ---

    #[test]
    fn test_epoch_not_active() {
        let result = calculate_epoch(1, GRANITE_MAINNET_TIMESTAMP - 1, 0, 100);
        assert!(result.is_none());
    }

    #[test]
    fn test_epoch_zero_at_activation() {
        let info = calculate_epoch(1, GRANITE_MAINNET_TIMESTAMP, GRANITE_MAINNET_TIMESTAMP, 100)
            .expect("should be active");
        assert_eq!(info.epoch_number, 0);
        assert_eq!(info.epoch_p_chain_height, 100);
        assert_eq!(info.epoch_start_time, GRANITE_MAINNET_TIMESTAMP);
    }

    #[test]
    fn test_epoch_advances_every_5_minutes() {
        let activation = GRANITE_FUJI_TIMESTAMP;
        let p_height = 500;

        // 4m59s → still epoch 0
        let info = calculate_epoch(5, activation + 299, activation, p_height).unwrap();
        assert_eq!(info.epoch_number, 0);

        // 5m00s → epoch 1
        let info = calculate_epoch(5, activation + 300, activation, p_height).unwrap();
        assert_eq!(info.epoch_number, 1);
        assert_eq!(info.epoch_p_chain_height, p_height + 1);
        assert_eq!(info.epoch_start_time, activation + 300);

        // 10m → epoch 2
        let info = calculate_epoch(5, activation + 600, activation, p_height).unwrap();
        assert_eq!(info.epoch_number, 2);
        assert_eq!(info.epoch_p_chain_height, p_height + 2);
    }

    #[test]
    fn test_epoch_large_elapsed() {
        let activation = GRANITE_MAINNET_TIMESTAMP;
        // 1 hour = 3600s = 12 epochs
        let info = calculate_epoch(1, activation + 3600, activation, 1000).unwrap();
        assert_eq!(info.epoch_number, 12);
        assert_eq!(info.epoch_p_chain_height, 1012);
    }

    #[test]
    fn test_epoch_unknown_network() {
        let result = calculate_epoch(999, GRANITE_MAINNET_TIMESTAMP + 1000, 0, 100);
        assert!(result.is_none());
    }

    // --- ACP-204: secp256r1 ---

    #[test]
    fn test_verify_secp256r1_sign_and_verify() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let sk = SigningKey::random(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let pubkey = vk.to_sec1_bytes();

        let message_hash: [u8; 32] = sha2::Sha256::digest(b"hello granite").into();
        let sig: p256::ecdsa::Signature = sk.sign(&message_hash);
        let sig_bytes = sig.to_bytes();

        let result = verify_secp256r1(&message_hash, &sig_bytes, &pubkey);
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_secp256r1_wrong_message() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let sk = SigningKey::random(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let pubkey = vk.to_sec1_bytes();

        let msg1: [u8; 32] = sha2::Sha256::digest(b"correct message").into();
        let msg2: [u8; 32] = sha2::Sha256::digest(b"wrong message").into();
        let sig: p256::ecdsa::Signature = sk.sign(&msg1);

        let result = verify_secp256r1(&msg2, &sig.to_bytes(), &pubkey);
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_secp256r1_invalid_pubkey() {
        let message_hash = [0u8; 32];
        let sig = [0u8; 64];
        let bad_pubkey = [0u8; 10];

        let result = verify_secp256r1(&message_hash, &sig, &bad_pubkey);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_secp256r1_invalid_signature() {
        use p256::ecdsa::SigningKey;

        let sk = SigningKey::random(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let pubkey = vk.to_sec1_bytes();

        let message_hash = [0xABu8; 32];
        let bad_sig = [0xFFu8; 64];

        let result = verify_secp256r1(&message_hash, &bad_sig, &pubkey);
        // Either returns Err (can't parse) or Ok(false) (doesn't verify)
        match result {
            Ok(valid) => assert!(!valid),
            Err(_) => {} // also acceptable
        }
    }

    #[test]
    fn test_verify_secp256r1_der_signature() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let sk = SigningKey::random(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let pubkey = vk.to_sec1_bytes();

        let message_hash: [u8; 32] = sha2::Sha256::digest(b"der test").into();
        let sig: p256::ecdsa::Signature = sk.sign(&message_hash);
        let der_bytes = sig.to_der();

        let result = verify_secp256r1(&message_hash, der_bytes.as_bytes(), &pubkey);
        assert!(result.unwrap());
    }

    // --- ACP-226: Dynamic Block Times ---

    #[test]
    fn test_pre_granite_always_2s() {
        let timing = min_block_time(1, 0, GRANITE_MAINNET_TIMESTAMP - 1, 500);
        assert_eq!(timing.min_block_time_ms, PRE_GRANITE_MIN_BLOCK_TIME_MS);
        assert!(timing.is_primary_network);

        let timing = min_block_time(1, 42, GRANITE_MAINNET_TIMESTAMP - 1, 500);
        assert_eq!(timing.min_block_time_ms, PRE_GRANITE_MIN_BLOCK_TIME_MS);
        assert!(!timing.is_primary_network);
    }

    #[test]
    fn test_post_granite_primary_keeps_2s() {
        let timing = min_block_time(1, 0, GRANITE_MAINNET_TIMESTAMP, 0);
        assert_eq!(timing.min_block_time_ms, PRE_GRANITE_MIN_BLOCK_TIME_MS);
        assert!(timing.is_primary_network);
    }

    #[test]
    fn test_post_granite_subnet_custom_min() {
        let timing = min_block_time(1, 42, GRANITE_MAINNET_TIMESTAMP, 500);
        assert_eq!(timing.min_block_time_ms, 500);
        assert!(!timing.is_primary_network);
    }

    #[test]
    fn test_post_granite_subnet_zero_min() {
        let timing = min_block_time(5, 1, GRANITE_FUJI_TIMESTAMP, 0);
        assert_eq!(timing.min_block_time_ms, 0);
        assert!(!timing.is_primary_network);
    }
}
