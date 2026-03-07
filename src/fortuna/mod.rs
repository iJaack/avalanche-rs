//! Fortuna upgrade compatibility — ACP-176: Dynamic EVM Gas Limits and Price Discovery.
//!
//! Replaces the static gas target + windowed EIP-1559 mechanism with a dynamic
//! fee model (based on ACP-103) where validators can adjust the target gas
//! consumption rate over time via a per-block `q` parameter.
//!
//! Activation:
//!   - Fuji:    2025-03-13T15:00:00Z
//!   - Mainnet: 2025-04-08T15:00:00Z

// ---------------------------------------------------------------------------
// Activation timestamps
// ---------------------------------------------------------------------------

/// Fortuna activation on Fuji: 2025-03-13T15:00:00Z
pub const FORTUNA_FUJI_TIMESTAMP: u64 = 1741878000;

/// Fortuna activation on Mainnet: 2025-04-08T15:00:00Z
pub const FORTUNA_MAINNET_TIMESTAMP: u64 = 1744127600;

/// Granite activation timestamps (for latest-upgrade handshake).
pub const GRANITE_MAINNET_TIMESTAMP: u64 = 1765296000;
pub const GRANITE_FUJI_TIMESTAMP: u64 = 1761750000;

/// Returns the latest activated upgrade timestamp for a given network.
/// Used in the P2P Handshake to prove compatibility.
pub fn latest_upgrade_time(network_id: u32) -> u64 {
    match network_id {
        1 => GRANITE_MAINNET_TIMESTAMP,
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
// ACP-176: Dynamic gas target parameters
// ---------------------------------------------------------------------------

/// Global minimum target gas consumption rate (gas/second).
/// P in the spec — floor that validators cannot go below.
pub const MIN_TARGET_GAS_RATE: u64 = 1_500_000; // 15M gas / 10s

/// Gas price update constant divisor relative to T: K = 87 * T.
pub const GAS_PRICE_UPDATE_K_FACTOR: u64 = 87;

/// Maximum gas capacity relative to T: C = 10 * T.
pub const GAS_CAPACITY_FACTOR: u64 = 10;

/// Gas capacity added per second relative to T: R = 2 * T.
pub const GAS_REFILL_FACTOR: u64 = 2;

/// Maximum per-block change to q.
pub const MAX_Q_CHANGE: i64 = 8;

/// D constant controlling rate of change of target gas consumption.
/// T = P * e^(q/D), so larger D = slower adjustment.
pub const D_CONSTANT: f64 = 48.0;

/// Minimum base fee (25 nAVAX = 25 gwei).
pub const MIN_BASE_FEE: u64 = 25_000_000_000;

/// Pre-Fortuna static gas target per 10-second window.
pub const PRE_FORTUNA_GAS_TARGET: u64 = 15_000_000;

// ---------------------------------------------------------------------------
// Dynamic gas state
// ---------------------------------------------------------------------------

/// State tracked across blocks for the ACP-176 dynamic fee mechanism.
#[derive(Debug, Clone, PartialEq)]
pub struct DynamicGasState {
    /// The q parameter controlling target gas rate: T = P * e^(q/D).
    pub q: i64,
    /// Current target gas per second (derived from q).
    pub target_gas_rate: u64,
    /// Gas price update constant K = 87 * T.
    pub k: u64,
    /// Maximum gas capacity C = 10 * T.
    pub capacity: u64,
    /// Gas capacity added per second R = 2 * T.
    pub refill_rate: u64,
    /// Excess gas consumption (for base fee calculation, from ACP-103).
    pub excess_gas: u64,
    /// Remaining gas capacity at end of previous block.
    pub remaining_capacity: u64,
}

impl DynamicGasState {
    /// Create the initial state at Fortuna activation (q = 0).
    pub fn genesis() -> Self {
        let t = MIN_TARGET_GAS_RATE;
        Self {
            q: 0,
            target_gas_rate: t,
            k: GAS_PRICE_UPDATE_K_FACTOR * t,
            capacity: GAS_CAPACITY_FACTOR * t,
            refill_rate: GAS_REFILL_FACTOR * t,
            excess_gas: 0,
            remaining_capacity: GAS_CAPACITY_FACTOR * t,
        }
    }

    /// Compute the target gas rate from q: T = P * e^(q/D).
    pub fn target_rate_from_q(q: i64) -> u64 {
        let exponent = q as f64 / D_CONSTANT;
        let t = MIN_TARGET_GAS_RATE as f64 * exponent.exp();
        t.round().max(MIN_TARGET_GAS_RATE as f64) as u64
    }

    /// Compute the desired q for a validator's desired target gas rate.
    /// q_desired = D * ln(T_desired / P)
    pub fn q_for_target_rate(desired_rate: u64) -> i64 {
        if desired_rate <= MIN_TARGET_GAS_RATE {
            return 0;
        }
        let ratio = desired_rate as f64 / MIN_TARGET_GAS_RATE as f64;
        let q = D_CONSTANT * ratio.ln();
        q.round() as i64
    }

    /// Calculate the gas limit for a new block given elapsed time since parent.
    /// gasLimit = min(remaining + R * dt, C)
    pub fn gas_limit(&self, elapsed_secs: u64) -> u64 {
        let added = self.refill_rate.saturating_mul(elapsed_secs);
        let available = self.remaining_capacity.saturating_add(added);
        available.min(self.capacity)
    }

    /// Calculate the base fee using the ACP-103 mechanism.
    /// baseFee = M * e^(excess_gas / K), floored at MIN_BASE_FEE.
    pub fn base_fee(&self) -> u64 {
        if self.k == 0 {
            return MIN_BASE_FEE;
        }
        let exponent = self.excess_gas as f64 / self.k as f64;
        let fee = (MIN_BASE_FEE as f64 * exponent.exp()).round() as u64;
        fee.max(MIN_BASE_FEE)
    }

    /// Apply a block: consume gas, update q, recalculate derived params.
    ///
    /// - `gas_used`: gas consumed by the block's transactions.
    /// - `delta_q`: the block builder's proposed change to q (clamped to ±MAX_Q_CHANGE).
    /// - `elapsed_secs`: time since parent block.
    ///
    /// Returns the updated state (q and derived values change take effect next block).
    pub fn apply_block(&self, gas_used: u64, delta_q: i64, elapsed_secs: u64) -> Self {
        // 1. Clamp delta_q
        let clamped_dq = delta_q.clamp(-MAX_Q_CHANGE, MAX_Q_CHANGE);

        // 2. Update remaining capacity after gas consumption
        let limit = self.gas_limit(elapsed_secs);
        let consumed = gas_used.min(limit);
        let new_remaining = limit.saturating_sub(consumed);

        // 3. Update excess gas (ACP-103 style)
        let target_for_period = self.target_gas_rate.saturating_mul(elapsed_secs.max(1));
        let new_excess = if consumed > target_for_period {
            self.excess_gas.saturating_add(consumed - target_for_period)
        } else {
            self.excess_gas
                .saturating_sub(target_for_period - consumed)
        };

        // 4. Update q and derive new T, K, C, R
        let new_q = self.q + clamped_dq;
        let new_t = Self::target_rate_from_q(new_q);
        let new_k = GAS_PRICE_UPDATE_K_FACTOR * new_t;
        let old_k = self.k.max(1);

        // 5. Scale excess gas proportionally to K change: x' = x * K_new / K_old
        let scaled_excess = if old_k > 0 {
            ((new_excess as u128 * new_k as u128) / old_k as u128) as u64
        } else {
            new_excess
        };

        Self {
            q: new_q,
            target_gas_rate: new_t,
            k: new_k,
            capacity: GAS_CAPACITY_FACTOR * new_t,
            refill_rate: GAS_REFILL_FACTOR * new_t,
            excess_gas: scaled_excess,
            remaining_capacity: new_remaining,
        }
    }

    /// Calculate the next preferred q for a block builder given a desired target rate.
    pub fn calc_next_q(q_current: i64, q_desired: i64) -> i64 {
        if q_desired > q_current {
            q_current + (q_desired - q_current).min(MAX_Q_CHANGE)
        } else {
            q_current - (q_current - q_desired).min(MAX_Q_CHANGE)
        }
    }
}

// ---------------------------------------------------------------------------
// Pre-Fortuna legacy fee calculation (for blocks before activation)
// ---------------------------------------------------------------------------

/// Legacy windowed EIP-1559 base fee calculation (pre-Fortuna).
/// Uses a 10-second rolling window with a static 15M gas target.
pub fn legacy_base_fee(parent_base_fee: u64, gas_used: u64, gas_target: u64) -> u64 {
    if gas_target == 0 {
        return parent_base_fee;
    }

    if gas_used > gas_target {
        let delta = parent_base_fee * (gas_used - gas_target) / gas_target / 8;
        parent_base_fee + delta.max(1)
    } else if gas_used < gas_target {
        let delta = parent_base_fee * (gas_target - gas_used) / gas_target / 8;
        let new_fee = parent_base_fee.saturating_sub(delta);
        new_fee.max(MIN_BASE_FEE)
    } else {
        parent_base_fee
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activation_timestamps() {
        // Fuji: 2025-03-13T15:00:00Z
        assert_eq!(FORTUNA_FUJI_TIMESTAMP, 1741878000);
        // Mainnet: 2025-04-08T15:00:00Z
        assert_eq!(FORTUNA_MAINNET_TIMESTAMP, 1744127600);
        // Mainnet is later than Fuji
        assert!(FORTUNA_MAINNET_TIMESTAMP > FORTUNA_FUJI_TIMESTAMP);
    }

    #[test]
    fn test_is_fortuna_active() {
        // Fuji: active at activation
        assert!(is_fortuna_active(5, FORTUNA_FUJI_TIMESTAMP));
        assert!(!is_fortuna_active(5, FORTUNA_FUJI_TIMESTAMP - 1));
        // Mainnet: different timestamp
        assert!(!is_fortuna_active(1, FORTUNA_FUJI_TIMESTAMP));
        assert!(is_fortuna_active(1, FORTUNA_MAINNET_TIMESTAMP));
        // Unknown network
        assert!(!is_fortuna_active(999, FORTUNA_MAINNET_TIMESTAMP));
    }

    #[test]
    fn test_latest_upgrade_time() {
        assert_eq!(latest_upgrade_time(1), GRANITE_MAINNET_TIMESTAMP);
        assert_eq!(latest_upgrade_time(5), GRANITE_FUJI_TIMESTAMP);
        assert_eq!(latest_upgrade_time(999), 0);
    }

    #[test]
    fn test_genesis_state() {
        let state = DynamicGasState::genesis();
        assert_eq!(state.q, 0);
        assert_eq!(state.target_gas_rate, MIN_TARGET_GAS_RATE);
        assert_eq!(state.k, GAS_PRICE_UPDATE_K_FACTOR * MIN_TARGET_GAS_RATE);
        assert_eq!(state.capacity, GAS_CAPACITY_FACTOR * MIN_TARGET_GAS_RATE);
        assert_eq!(state.refill_rate, GAS_REFILL_FACTOR * MIN_TARGET_GAS_RATE);
        assert_eq!(state.excess_gas, 0);
    }

    #[test]
    fn test_target_rate_from_q() {
        // q=0 → T = P * e^0 = P
        assert_eq!(DynamicGasState::target_rate_from_q(0), MIN_TARGET_GAS_RATE);

        // q>0 → T > P
        let t_pos = DynamicGasState::target_rate_from_q(48);
        assert!(t_pos > MIN_TARGET_GAS_RATE);
        // q=48 with D=48 → T = P * e^1 ≈ P * 2.718
        let expected = (MIN_TARGET_GAS_RATE as f64 * std::f64::consts::E).round() as u64;
        assert_eq!(t_pos, expected);

        // q<0 → T >= P (floored)
        let t_neg = DynamicGasState::target_rate_from_q(-100);
        assert_eq!(t_neg, MIN_TARGET_GAS_RATE);
    }

    #[test]
    fn test_q_for_target_rate() {
        // At minimum rate, q = 0
        assert_eq!(DynamicGasState::q_for_target_rate(MIN_TARGET_GAS_RATE), 0);
        // Below minimum, q = 0
        assert_eq!(DynamicGasState::q_for_target_rate(100), 0);
        // Double the rate: q = D * ln(2) ≈ 48 * 0.693 ≈ 33
        let q = DynamicGasState::q_for_target_rate(MIN_TARGET_GAS_RATE * 2);
        assert_eq!(q, 33);
    }

    #[test]
    fn test_gas_limit() {
        let state = DynamicGasState::genesis();
        // At t=0, gas_limit = remaining (= capacity at genesis)
        assert_eq!(state.gas_limit(0), state.capacity);
        // At t=1, gas_limit = remaining + R*1, capped at C
        assert_eq!(state.gas_limit(1), state.capacity); // already at capacity
    }

    #[test]
    fn test_gas_limit_after_consumption() {
        let mut state = DynamicGasState::genesis();
        // Simulate consuming half the capacity
        state.remaining_capacity = state.capacity / 2;
        // After 1 second, should refill by R
        let limit = state.gas_limit(1);
        assert_eq!(limit, state.capacity / 2 + state.refill_rate);
        // After 5 seconds, should be back at full capacity (C = 10*T, R = 2*T, so 5s fills it)
        let limit = state.gas_limit(5);
        assert_eq!(limit, state.capacity);
    }

    #[test]
    fn test_base_fee_at_genesis() {
        let state = DynamicGasState::genesis();
        // excess_gas = 0 → baseFee = M * e^0 = M
        assert_eq!(state.base_fee(), MIN_BASE_FEE);
    }

    #[test]
    fn test_base_fee_increases_with_excess() {
        let mut state = DynamicGasState::genesis();
        let base0 = state.base_fee();
        state.excess_gas = state.k; // excess = K → baseFee = M * e^1
        let base1 = state.base_fee();
        assert!(base1 > base0);
        // Should be approximately M * e ≈ M * 2.718
        let expected = (MIN_BASE_FEE as f64 * std::f64::consts::E).round() as u64;
        assert_eq!(base1, expected);
    }

    #[test]
    fn test_apply_block_no_change() {
        let state = DynamicGasState::genesis();
        // Empty block, no q change, 2 seconds elapsed
        let next = state.apply_block(0, 0, 2);
        assert_eq!(next.q, 0);
        assert_eq!(next.target_gas_rate, MIN_TARGET_GAS_RATE);
        // excess should decrease (consumed < target)
        assert_eq!(next.excess_gas, 0); // was already 0
    }

    #[test]
    fn test_apply_block_increases_q() {
        let state = DynamicGasState::genesis();
        // Builder wants to increase gas target
        let next = state.apply_block(1_000_000, 5, 2);
        assert_eq!(next.q, 5);
        assert!(next.target_gas_rate > MIN_TARGET_GAS_RATE);
        assert!(next.k > state.k);
    }

    #[test]
    fn test_apply_block_clamps_delta_q() {
        let state = DynamicGasState::genesis();
        // Try to change q by 100 — should clamp to MAX_Q_CHANGE
        let next = state.apply_block(0, 100, 1);
        assert_eq!(next.q, MAX_Q_CHANGE as i64);
        // Negative clamping
        let next = state.apply_block(0, -100, 1);
        assert_eq!(next.q, -(MAX_Q_CHANGE as i64));
    }

    #[test]
    fn test_calc_next_q() {
        // Moving toward desired, clamped
        assert_eq!(DynamicGasState::calc_next_q(0, 20), MAX_Q_CHANGE as i64);
        assert_eq!(DynamicGasState::calc_next_q(0, -20), -(MAX_Q_CHANGE as i64));
        // Already at desired
        assert_eq!(DynamicGasState::calc_next_q(5, 5), 5);
        // Small step
        assert_eq!(DynamicGasState::calc_next_q(0, 3), 3);
    }

    #[test]
    fn test_excess_gas_scales_with_k() {
        let mut state = DynamicGasState::genesis();
        state.excess_gas = 100_000_000; // large excess
        let old_k = state.k;
        // Consume at-target gas so excess doesn't change from consumption,
        // but increase q so K changes → excess should scale.
        let gas_for_2s = state.target_gas_rate * 2;
        let next = state.apply_block(gas_for_2s, MAX_Q_CHANGE, 2);
        assert!(next.k > old_k);
        // Excess was scaled by new_k / old_k
        let ratio = next.k as f64 / old_k as f64;
        let expected = (100_000_000.0 * ratio).round() as u64;
        assert!((next.excess_gas as i64 - expected as i64).unsigned_abs() < 1000);
    }

    #[test]
    fn test_legacy_base_fee() {
        let base = 25_000_000_000u64;
        // At target → same fee
        assert_eq!(legacy_base_fee(base, 15_000_000, 15_000_000), base);
        // Above target → fee increases
        let higher = legacy_base_fee(base, 20_000_000, 15_000_000);
        assert!(higher > base);
        // Below target → fee decreases, floored at MIN_BASE_FEE.
        // Since base == MIN_BASE_FEE (25 gwei), it can't go lower.
        let lower = legacy_base_fee(base, 5_000_000, 15_000_000);
        assert_eq!(lower, MIN_BASE_FEE);
        // With a higher starting fee, it should decrease
        let high_base = 100_000_000_000u64; // 100 gwei
        let decreased = legacy_base_fee(high_base, 5_000_000, 15_000_000);
        assert!(decreased < high_base);
        assert!(decreased >= MIN_BASE_FEE);
    }

    #[test]
    fn test_legacy_base_fee_floor() {
        // Very low fee can't go below minimum
        assert_eq!(
            legacy_base_fee(MIN_BASE_FEE, 0, 15_000_000),
            MIN_BASE_FEE
        );
    }

    #[test]
    fn test_convergence_over_blocks() {
        // Simulate 10 blocks where validator wants 2x the minimum target rate
        let desired_rate = MIN_TARGET_GAS_RATE * 2;
        let q_desired = DynamicGasState::q_for_target_rate(desired_rate);
        let mut state = DynamicGasState::genesis();

        for _ in 0..10 {
            let next_q = DynamicGasState::calc_next_q(state.q, q_desired);
            let delta = next_q - state.q;
            state = state.apply_block(state.target_gas_rate * 2, delta, 2);
        }

        // After 10 blocks, q should have converged toward q_desired (33)
        // With MAX_Q_CHANGE=8, after 5 blocks we'd reach 33 (5*8=40 > 33)
        assert_eq!(state.q, q_desired);
        // Target rate should be approximately 2x minimum
        let ratio = state.target_gas_rate as f64 / MIN_TARGET_GAS_RATE as f64;
        assert!((ratio - 2.0).abs() < 0.1);
    }
}
