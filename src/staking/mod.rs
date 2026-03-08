//! P-Chain staking helpers for validator/delegator transaction construction.

use k256::ecdsa::SigningKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub const NANO_AVAX: u64 = 1_000_000_000;
pub const MIN_VALIDATOR_STAKE: u64 = 2_000 * NANO_AVAX;
pub const MIN_DELEGATOR_STAKE: u64 = 25 * NANO_AVAX;
pub const MIN_STAKING_PERIOD_DAYS: u16 = 14;
pub const MAX_STAKING_PERIOD_DAYS: u16 = 365;
const SECONDS_PER_DAY: u64 = 86_400;
const SECONDS_PER_YEAR: u64 = 365 * SECONDS_PER_DAY;
const DEFAULT_ANNUAL_REWARD_BPS: u64 = 1_000; // 10%

#[derive(Debug, Clone, PartialEq)]
pub struct StakingConfig {
    pub amount: u64,
    pub duration: u16,
    pub fee: f64,
    pub reward_address: [u8; 20],
}

#[derive(Debug, Clone, PartialEq)]
pub struct StakeInfo {
    pub validator_id: [u8; 20],
    pub amount: u64,
    pub start_time: u64,
    pub end_time: u64,
    pub reward_address: [u8; 20],
}

#[derive(Debug, Clone, PartialEq)]
pub struct DelegationInfo {
    pub delegator: [u8; 20],
    pub validator: [u8; 20],
    pub amount: u64,
    pub fee: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakingTxType {
    AddValidator,
    AddDelegator,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnsignedStakingTx {
    pub tx_type: StakingTxType,
    pub validator_id: [u8; 20],
    pub amount: u64,
    pub start_time: u64,
    pub end_time: u64,
    pub delegation_fee_bps: u16,
    pub reward_address: [u8; 20],
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedStakingTx {
    pub unsigned: UnsignedStakingTx,
    pub signature: [u8; 65],
    pub signer_address: [u8; 20],
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnstakeResult {
    pub validator_id: [u8; 20],
    pub reward_address: [u8; 20],
    pub stake_returned: u64,
    pub reward_paid: u64,
    pub total_paid: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StakingError {
    StakeAmountTooLow { min: u64, provided: u64 },
    InvalidDelegationFee { min_percent: f64, provided: f64 },
    InvalidStakingPeriod { min_days: u16, max_days: u16, provided: u16 },
    StakeNotMatured { end_time: u64, current_time: u64 },
    SignatureFailed(String),
}

impl std::fmt::Display for StakingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StakeAmountTooLow { min, provided } => {
                write!(f, "stake amount too low: min={}, provided={}", min, provided)
            }
            Self::InvalidDelegationFee {
                min_percent,
                provided,
            } => {
                write!(
                    f,
                    "invalid delegation fee: min={}%, provided={} %",
                    min_percent, provided
                )
            }
            Self::InvalidStakingPeriod {
                min_days,
                max_days,
                provided,
            } => {
                write!(
                    f,
                    "invalid staking period: {} days (min={}, max={})",
                    provided, min_days, max_days
                )
            }
            Self::StakeNotMatured {
                end_time,
                current_time,
            } => {
                write!(
                    f,
                    "stake not matured: end_time={}, current_time={}",
                    end_time, current_time
                )
            }
            Self::SignatureFailed(reason) => write!(f, "staking tx signing failed: {}", reason),
        }
    }
}

impl std::error::Error for StakingError {}

pub fn validate_validator_stake(amount: u64) -> Result<(), StakingError> {
    if amount < MIN_VALIDATOR_STAKE {
        return Err(StakingError::StakeAmountTooLow {
            min: MIN_VALIDATOR_STAKE,
            provided: amount,
        });
    }
    Ok(())
}

pub fn validate_delegator_stake(amount: u64) -> Result<(), StakingError> {
    if amount < MIN_DELEGATOR_STAKE {
        return Err(StakingError::StakeAmountTooLow {
            min: MIN_DELEGATOR_STAKE,
            provided: amount,
        });
    }
    Ok(())
}

pub fn validate_staking_period_days(duration_days: u16) -> Result<(), StakingError> {
    if !(MIN_STAKING_PERIOD_DAYS..=MAX_STAKING_PERIOD_DAYS).contains(&duration_days) {
        return Err(StakingError::InvalidStakingPeriod {
            min_days: MIN_STAKING_PERIOD_DAYS,
            max_days: MAX_STAKING_PERIOD_DAYS,
            provided: duration_days,
        });
    }
    Ok(())
}

pub fn validate_delegation_fee_percent(fee_percent: f64) -> Result<(), StakingError> {
    if fee_percent < 2.0 {
        return Err(StakingError::InvalidDelegationFee {
            min_percent: 2.0,
            provided: fee_percent,
        });
    }
    Ok(())
}

pub fn compute_delegation_fee(amount: u64, fee_percent: f64) -> Result<u64, StakingError> {
    validate_delegation_fee_percent(fee_percent)?;
    let fee = (amount as f64 * (fee_percent / 100.0)).floor() as u64;
    Ok(fee)
}

pub fn expected_reward(amount: u64, duration_seconds: u64, uptime_ratio: f64) -> u64 {
    let capped_uptime = uptime_ratio.clamp(0.0, 1.0);
    let annual_reward = amount as f64 * (DEFAULT_ANNUAL_REWARD_BPS as f64 / 10_000.0);
    let duration_fraction = duration_seconds as f64 / SECONDS_PER_YEAR as f64;
    (annual_reward * duration_fraction * capped_uptime).floor() as u64
}

pub fn build_add_validator_tx(
    validator_id: [u8; 20],
    config: &StakingConfig,
    start_time: u64,
) -> Result<UnsignedStakingTx, StakingError> {
    validate_validator_stake(config.amount)?;
    validate_staking_period_days(config.duration)?;
    validate_delegation_fee_percent(config.fee)?;

    let duration_secs = config.duration as u64 * SECONDS_PER_DAY;
    Ok(UnsignedStakingTx {
        tx_type: StakingTxType::AddValidator,
        validator_id,
        amount: config.amount,
        start_time,
        end_time: start_time + duration_secs,
        delegation_fee_bps: (config.fee * 100.0).round() as u16,
        reward_address: config.reward_address,
    })
}

pub fn build_add_delegator_tx(
    validator_id: [u8; 20],
    delegator: [u8; 20],
    config: &StakingConfig,
    start_time: u64,
) -> Result<(UnsignedStakingTx, DelegationInfo), StakingError> {
    validate_delegator_stake(config.amount)?;
    validate_staking_period_days(config.duration)?;
    validate_delegation_fee_percent(config.fee)?;

    let duration_secs = config.duration as u64 * SECONDS_PER_DAY;
    let delegation_info = DelegationInfo {
        delegator,
        validator: validator_id,
        amount: config.amount,
        fee: config.fee,
    };

    Ok((
        UnsignedStakingTx {
            tx_type: StakingTxType::AddDelegator,
            validator_id,
            amount: config.amount,
            start_time,
            end_time: start_time + duration_secs,
            delegation_fee_bps: (config.fee * 100.0).round() as u16,
            reward_address: config.reward_address,
        },
        delegation_info,
    ))
}

pub fn serialize_unsigned_staking_tx(tx: &UnsignedStakingTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(match tx.tx_type {
        StakingTxType::AddValidator => 0x0C,
        StakingTxType::AddDelegator => 0x0E,
    });
    out.extend_from_slice(&tx.validator_id);
    out.extend_from_slice(&tx.amount.to_be_bytes());
    out.extend_from_slice(&tx.start_time.to_be_bytes());
    out.extend_from_slice(&tx.end_time.to_be_bytes());
    out.extend_from_slice(&tx.delegation_fee_bps.to_be_bytes());
    out.extend_from_slice(&tx.reward_address);
    out
}

pub fn sign_staking_tx(
    unsigned_tx: &UnsignedStakingTx,
    signer: &SigningKey,
) -> Result<SignedStakingTx, StakingError> {
    let tx_bytes = serialize_unsigned_staking_tx(unsigned_tx);
    let digest = Sha256::new_with_prefix(&tx_bytes);

    let (signature, recovery_id) = signer
        .sign_digest_recoverable(digest)
        .map_err(|e| StakingError::SignatureFailed(e.to_string()))?;

    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&signature.to_bytes());
    sig_bytes[64] = recovery_id.to_byte();

    Ok(SignedStakingTx {
        unsigned: unsigned_tx.clone(),
        signature: sig_bytes,
        signer_address: pchain_address_from_signer(signer),
    })
}

pub fn pchain_address_from_signer(signer: &SigningKey) -> [u8; 20] {
    let verifying_key = signer.verifying_key();
    let pubkey_bytes = verifying_key.to_sec1_bytes();
    let sha = Sha256::digest(pubkey_bytes);
    let ripemd = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripemd);
    out
}

pub fn unstake(
    stake: &StakeInfo,
    current_time: u64,
    observed_uptime: f64,
) -> Result<UnstakeResult, StakingError> {
    if current_time < stake.end_time {
        return Err(StakingError::StakeNotMatured {
            end_time: stake.end_time,
            current_time,
        });
    }

    let duration_seconds = stake.end_time.saturating_sub(stake.start_time);
    let reward_paid = expected_reward(stake.amount, duration_seconds, observed_uptime);
    Ok(UnstakeResult {
        validator_id: stake.validator_id,
        reward_address: stake.reward_address,
        stake_returned: stake.amount,
        reward_paid,
        total_paid: stake.amount.saturating_add(reward_paid),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::verify_pchain_signature;

    #[test]
    fn test_minimum_stake_validation() {
        assert!(validate_validator_stake(MIN_VALIDATOR_STAKE).is_ok());
        assert!(validate_validator_stake(MIN_VALIDATOR_STAKE - 1).is_err());
        assert!(validate_delegator_stake(MIN_DELEGATOR_STAKE).is_ok());
        assert!(validate_delegator_stake(MIN_DELEGATOR_STAKE - 1).is_err());
    }

    #[test]
    fn test_reward_calculation_accuracy() {
        let amount = 2_000 * NANO_AVAX;
        let duration = 30 * SECONDS_PER_DAY;
        let reward = expected_reward(amount, duration, 0.95);
        assert_eq!(reward, 15_616_438_356);
    }

    #[test]
    fn test_staking_period_bounds() {
        assert!(validate_staking_period_days(MIN_STAKING_PERIOD_DAYS).is_ok());
        assert!(validate_staking_period_days(MAX_STAKING_PERIOD_DAYS).is_ok());
        assert!(validate_staking_period_days(MIN_STAKING_PERIOD_DAYS - 1).is_err());
        assert!(validate_staking_period_days(MAX_STAKING_PERIOD_DAYS + 1).is_err());
    }

    #[test]
    fn test_delegation_fee_computation() {
        let amount = 100 * NANO_AVAX;
        let fee = compute_delegation_fee(amount, 2.5).unwrap();
        assert_eq!(fee, 2_500_000_000);
        assert!(compute_delegation_fee(amount, 1.99).is_err());
    }

    #[test]
    fn test_transaction_construction_and_signing() {
        let signer = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let config = StakingConfig {
            amount: MIN_VALIDATOR_STAKE,
            duration: 30,
            fee: 2.0,
            reward_address: [0x11; 20],
        };

        let unsigned = build_add_validator_tx([0x22; 20], &config, 1_700_000_000).unwrap();
        let signed = sign_staking_tx(&unsigned, &signer).unwrap();

        assert_eq!(signed.unsigned.tx_type, StakingTxType::AddValidator);
        assert_eq!(signed.signature.len(), 65);

        let message_hash: [u8; 32] = Sha256::digest(serialize_unsigned_staking_tx(&unsigned)).into();
        let verified =
            verify_pchain_signature(&message_hash, &signed.signature, &signed.signer_address)
                .unwrap();
        assert!(verified);
    }
}
