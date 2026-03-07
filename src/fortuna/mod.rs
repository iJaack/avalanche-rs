//! Fortuna upgrade compatibility (ACP-181, ACP-204, ACP-226).
//!
//! Activated on both mainnet and fuji on 2025-03-13T15:00:00Z.

use sha2::{Digest, Sha256};

// Fortuna activation: 2025-03-13T15:00:00Z = 1741878000
pub const FORTUNA_MAINNET_TIMESTAMP: u64 = 1741878000;
pub const FORTUNA_FUJI_TIMESTAMP: u64 = 1741878000;

// Previous upgrade timestamps for reference
pub const GRANITE_MAINNET_TIMESTAMP: u64 = 1765296000;
pub const GRANITE_FUJI_TIMESTAMP: u64 = 1761750000;

/// Returns the latest activated upgrade timestamp for a given network.
/// This is sent in the Handshake to prove compatibility.
pub fn latest_upgrade_time(network_id: u32) -> u64 {
    match network_id {
        1 => GRANITE_MAINNET_TIMESTAMP, // Granite is later than Fortuna
        5 => GRANITE_FUJI_TIMESTAMP,
        _ => 0,
    }
}

/// Check if Fortuna is active at the given timestamp for the given network.
pub fn is_fortuna_active(network_id: u32, timestamp: u64) -> bool {
    let activation = match network_id {
        1 => FORTUNA_MAINNET_TIMESTAMP,
        5 => FORTUNA_FUJI_TIMESTAMP,
        _ => return false,
    };
    timestamp >= activation
}

// ---------------------------------------------------------------------------
// ACP-181: Epoched P-Chain views
// ---------------------------------------------------------------------------

/// Default epoch duration in seconds (6 hours).
pub const EPOCH_DURATION_SECS: u64 = 6 * 3600;

/// Epoch metadata for P-Chain blocks under ACP-181.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochInfo {
    /// Epoch number (0-indexed from Fortuna activation).
    pub epoch_number: u64,
    /// P-Chain height at the start of this epoch.
    pub epoch_p_chain_height: u64,
    /// Timestamp when this epoch started.
    pub epoch_start_time: u64,
}

/// Calculate the epoch for a block given its timestamp.
/// Returns None if Fortuna is not yet active.
pub fn calculate_epoch(network_id: u32, block_timestamp: u64, p_chain_height: u64) -> Option<EpochInfo> {
    if !is_fortuna_active(network_id, block_timestamp) {
        return None;
    }

    let activation = match network_id {
        1 => FORTUNA_MAINNET_TIMESTAMP,
        5 => FORTUNA_FUJI_TIMESTAMP,
        _ => return None,
    };

    let elapsed = block_timestamp.saturating_sub(activation);
    let epoch_number = elapsed / EPOCH_DURATION_SECS;
    let epoch_start_time = activation + epoch_number * EPOCH_DURATION_SECS;

    Some(EpochInfo {
        epoch_number,
        epoch_p_chain_height: p_chain_height,
        epoch_start_time,
    })
}

// ---------------------------------------------------------------------------
// ACP-204: secp256r1 (P-256) signature verification
// ---------------------------------------------------------------------------

/// Verify a secp256r1 (P-256/NIST) signature.
/// Used by the Fortuna precompile for WebAuthn/passkey support.
pub fn verify_secp256r1(
    message_hash: &[u8; 32],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<bool, String> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    if signature_bytes.len() != 64 {
        return Err(format!(
            "invalid signature length: {} (expected 64)",
            signature_bytes.len()
        ));
    }

    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| format!("invalid signature: {}", e))?;

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|e| format!("invalid public key: {}", e))?;

    Ok(verifying_key.verify(message_hash, &signature).is_ok())
}

// ---------------------------------------------------------------------------
// ACP-226: Dynamic minimum block times
// ---------------------------------------------------------------------------

/// Pre-Fortuna minimum block time (2 seconds).
pub const PRE_FORTUNA_MIN_BLOCK_TIME_MS: u64 = 2000;

/// Post-Fortuna minimum block time can be dynamic based on network load.
/// Range: 250ms (high load) to 2000ms (low load).
pub const FORTUNA_MIN_BLOCK_TIME_MS: u64 = 250;
pub const FORTUNA_MAX_BLOCK_TIME_MS: u64 = 2000;

/// Target gas utilization for dynamic block time calculation.
pub const TARGET_GAS_UTILIZATION: f64 = 0.5; // 50%

/// Calculate the minimum block time based on recent gas usage.
/// Under ACP-226, the block time is dynamically adjusted based on gas utilization.
pub fn dynamic_min_block_time(
    network_id: u32,
    current_timestamp: u64,
    gas_used: u64,
    gas_limit: u64,
) -> u64 {
    if !is_fortuna_active(network_id, current_timestamp) {
        return PRE_FORTUNA_MIN_BLOCK_TIME_MS;
    }

    if gas_limit == 0 {
        return FORTUNA_MAX_BLOCK_TIME_MS;
    }

    let utilization = gas_used as f64 / gas_limit as f64;

    if utilization >= TARGET_GAS_UTILIZATION {
        // High load: shorter block times
        let ratio = (utilization - TARGET_GAS_UTILIZATION) / (1.0 - TARGET_GAS_UTILIZATION);
        let range = FORTUNA_MAX_BLOCK_TIME_MS - FORTUNA_MIN_BLOCK_TIME_MS;
        let reduction = (ratio * range as f64) as u64;
        FORTUNA_MAX_BLOCK_TIME_MS.saturating_sub(reduction)
    } else {
        // Low load: keep max block time
        FORTUNA_MAX_BLOCK_TIME_MS
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fortuna_activation_timestamps() {
        // Fortuna: 2025-03-13T15:00:00Z
        assert_eq!(FORTUNA_MAINNET_TIMESTAMP, 1741878000);
        assert_eq!(FORTUNA_FUJI_TIMESTAMP, 1741878000);
    }

    #[test]
    fn test_is_fortuna_active() {
        // Before activation
        assert!(!is_fortuna_active(1, 1741877999));
        // At activation
        assert!(is_fortuna_active(1, 1741878000));
        // After activation
        assert!(is_fortuna_active(1, 1741878001));
        // Fuji same timestamp
        assert!(is_fortuna_active(5, 1741878000));
        // Unknown network
        assert!(!is_fortuna_active(999, 1741878000));
    }

    #[test]
    fn test_latest_upgrade_time() {
        assert_eq!(latest_upgrade_time(1), GRANITE_MAINNET_TIMESTAMP);
        assert_eq!(latest_upgrade_time(5), GRANITE_FUJI_TIMESTAMP);
        assert_eq!(latest_upgrade_time(999), 0);
    }

    #[test]
    fn test_epoch_calculation() {
        // Before Fortuna — no epoch
        assert!(calculate_epoch(1, 1741877999, 100).is_none());

        // At Fortuna activation — epoch 0
        let info = calculate_epoch(1, 1741878000, 100).unwrap();
        assert_eq!(info.epoch_number, 0);
        assert_eq!(info.epoch_start_time, 1741878000);
        assert_eq!(info.epoch_p_chain_height, 100);

        // 1 hour after activation — still epoch 0
        let info = calculate_epoch(1, 1741878000 + 3600, 105).unwrap();
        assert_eq!(info.epoch_number, 0);

        // 6 hours after activation — epoch 1
        let info = calculate_epoch(1, 1741878000 + 6 * 3600, 200).unwrap();
        assert_eq!(info.epoch_number, 1);
        assert_eq!(info.epoch_start_time, 1741878000 + 6 * 3600);

        // 12 hours after — epoch 2
        let info = calculate_epoch(1, 1741878000 + 12 * 3600, 300).unwrap();
        assert_eq!(info.epoch_number, 2);
    }

    #[test]
    fn test_epoch_same_epoch_share_info() {
        // Two blocks in the same epoch should have the same epoch_number and epoch_start_time
        let info1 = calculate_epoch(1, 1741878000 + 100, 100).unwrap();
        let info2 = calculate_epoch(1, 1741878000 + 200, 105).unwrap();
        assert_eq!(info1.epoch_number, info2.epoch_number);
        assert_eq!(info1.epoch_start_time, info2.epoch_start_time);
    }

    #[test]
    fn test_secp256r1_verify() {
        use p256::ecdsa::{signature::Signer, SigningKey};
        use rand::rngs::OsRng;

        // Generate a test key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_key_bytes = verifying_key.to_sec1_bytes();

        // Sign a message
        let message_hash = sha2::Sha256::digest(b"test message");
        let message_hash: [u8; 32] = message_hash.into();
        let (signature, _) = signing_key.sign(&message_hash);
        let sig_bytes = signature.to_bytes();

        // Verify — should succeed
        let result = verify_secp256r1(&message_hash, &sig_bytes, &pub_key_bytes).unwrap();
        assert!(result);

        // Verify with wrong message — should fail
        let wrong_hash = [0xFFu8; 32];
        let result = verify_secp256r1(&wrong_hash, &sig_bytes, &pub_key_bytes).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_secp256r1_invalid_signature() {
        let hash = [0u8; 32];
        // Wrong length
        let result = verify_secp256r1(&hash, &[0u8; 63], &[0u8; 33]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dynamic_block_time_pre_fortuna() {
        // Before Fortuna, always 2000ms
        let time = dynamic_min_block_time(1, 1741877999, 5_000_000, 10_000_000);
        assert_eq!(time, PRE_FORTUNA_MIN_BLOCK_TIME_MS);
    }

    #[test]
    fn test_dynamic_block_time_low_load() {
        // Low gas usage — max block time
        let time = dynamic_min_block_time(1, 1741878000 + 100, 1_000_000, 10_000_000);
        assert_eq!(time, FORTUNA_MAX_BLOCK_TIME_MS);
    }

    #[test]
    fn test_dynamic_block_time_high_load() {
        // 100% gas usage — min block time
        let time = dynamic_min_block_time(1, 1741878000 + 100, 10_000_000, 10_000_000);
        assert_eq!(time, FORTUNA_MIN_BLOCK_TIME_MS);
    }

    #[test]
    fn test_dynamic_block_time_medium_load() {
        // 75% gas usage — between min and max
        let time = dynamic_min_block_time(1, 1741878000 + 100, 7_500_000, 10_000_000);
        assert!(time > FORTUNA_MIN_BLOCK_TIME_MS);
        assert!(time < FORTUNA_MAX_BLOCK_TIME_MS);
    }

    #[test]
    fn test_dynamic_block_time_zero_gas_limit() {
        let time = dynamic_min_block_time(1, 1741878000 + 100, 0, 0);
        assert_eq!(time, FORTUNA_MAX_BLOCK_TIME_MS);
    }
}
