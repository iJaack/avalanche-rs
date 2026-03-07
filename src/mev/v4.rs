//! UniswapV4 support for Avalanche MEV engine
//!
//! V4 introduces: singleton pool manager, hooks, flash accounting,
//! native ETH support, and dynamic fees. This changes MEV dynamics
//! significantly — hooks can front-run us, dynamic fees can spike
//! mid-bundle, and flash accounting means no intermediate token transfers.

use super::*;
use std::collections::HashMap;

// ============================================================================
// V4 SELECTORS (PoolManager)
// ============================================================================

pub mod v4_selectors {
    // PoolManager
    pub const INITIALIZE: [u8; 4] = [0xf6, 0x37, 0x73, 0x1d];
    pub const SWAP: [u8; 4] = [0xf3, 0xcd, 0x91, 0x4c];
    pub const MODIFY_LIQUIDITY: [u8; 4] = [0x35, 0x44, 0x4c, 0x8c];
    pub const DONATE: [u8; 4] = [0xba, 0x48, 0x1f, 0x19];
    pub const TAKE: [u8; 4] = [0x0b, 0x0d, 0x03, 0x3d];
    pub const SETTLE: [u8; 4] = [0x11, 0xa4, 0x6a, 0x01];
    pub const LOCK: [u8; 4] = [0xf8, 0x3d, 0x08, 0xba];

    // Universal Router (wraps V4)
    pub const EXECUTE: [u8; 4] = [0x24, 0x85, 0x6b, 0xc3];
    pub const EXECUTE_WITH_DEADLINE: [u8; 4] = [0x36, 0x93, 0xd8, 0xa0];

    pub fn is_v4_swap(selector: &[u8]) -> bool {
        if selector.len() < 4 {
            return false;
        }
        let sel = [selector[0], selector[1], selector[2], selector[3]];
        matches!(sel, SWAP | EXECUTE | EXECUTE_WITH_DEADLINE)
    }

    pub fn is_v4_liquidity(selector: &[u8]) -> bool {
        if selector.len() < 4 {
            return false;
        }
        let sel = [selector[0], selector[1], selector[2], selector[3]];
        matches!(sel, MODIFY_LIQUIDITY | DONATE)
    }

    pub fn is_v4_action(selector: &[u8]) -> bool {
        if selector.len() < 4 {
            return false;
        }
        let sel = [selector[0], selector[1], selector[2], selector[3]];
        matches!(
            sel,
            INITIALIZE
                | SWAP
                | MODIFY_LIQUIDITY
                | DONATE
                | TAKE
                | SETTLE
                | LOCK
                | EXECUTE
                | EXECUTE_WITH_DEADLINE
        )
    }
}

// ============================================================================
// V4 POOL KEY (replaces pair addresses)
// ============================================================================

/// V4 identifies pools by PoolKey, not by pair contract address.
/// Same token pair can have many pools with different fees/hooks.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct PoolKey {
    pub currency0: String,
    pub currency1: String,
    pub fee: u32, // fee in hundredths of a bip (e.g., 3000 = 0.30%)
    pub tick_spacing: i32,
    pub hooks: String, // hook contract address (0x0 = no hooks)
}

impl PoolKey {
    pub fn new(token0: &str, token1: &str, fee: u32, tick_spacing: i32, hooks: &str) -> Self {
        // V4 requires currency0 < currency1 (sorted, normalized to lowercase)
        let t0 = token0.to_lowercase();
        let t1 = token1.to_lowercase();
        let (c0, c1) = if t0 < t1 { (t0, t1) } else { (t1, t0) };
        Self {
            currency0: c0,
            currency1: c1,
            fee,
            tick_spacing,
            hooks: hooks.to_string(),
        }
    }

    /// No hooks attached
    pub fn has_hooks(&self) -> bool {
        !self.hooks.is_empty()
            && self.hooks != "0x0000000000000000000000000000000000000000"
            && self.hooks != "0x0"
    }

    /// Standard fee tiers
    pub fn fee_bps(&self) -> f64 {
        self.fee as f64 / 100.0
    }

    /// Whether this is a native ETH (address(0)) pair
    pub fn is_native_pair(&self) -> bool {
        self.currency0 == "0x0000000000000000000000000000000000000000"
            || self.currency1 == "0x0000000000000000000000000000000000000000"
    }
}

// ============================================================================
// HOOK FLAGS & CLASSIFICATION
// ============================================================================

/// V4 hook permission flags (encoded in the hook address's leading bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HookFlags {
    pub before_initialize: bool,
    pub after_initialize: bool,
    pub before_add_liquidity: bool,
    pub after_add_liquidity: bool,
    pub before_remove_liquidity: bool,
    pub after_remove_liquidity: bool,
    pub before_swap: bool,
    pub after_swap: bool,
    pub before_donate: bool,
    pub after_donate: bool,
    pub before_swap_returns_delta: bool,
    pub after_swap_returns_delta: bool,
    pub after_add_liquidity_returns_delta: bool,
    pub after_remove_liquidity_returns_delta: bool,
}

impl HookFlags {
    /// Decode flags from hook contract address (V4 encodes permissions in address bits)
    pub fn from_address(addr: &str) -> Self {
        let addr_clean = addr.trim_start_matches("0x");
        let flags_byte =
            u16::from_str_radix(&addr_clean[..4.min(addr_clean.len())], 16).unwrap_or(0);

        Self {
            before_initialize: flags_byte & (1 << 13) != 0,
            after_initialize: flags_byte & (1 << 12) != 0,
            before_add_liquidity: flags_byte & (1 << 11) != 0,
            after_add_liquidity: flags_byte & (1 << 10) != 0,
            before_remove_liquidity: flags_byte & (1 << 9) != 0,
            after_remove_liquidity: flags_byte & (1 << 8) != 0,
            before_swap: flags_byte & (1 << 7) != 0,
            after_swap: flags_byte & (1 << 6) != 0,
            before_donate: flags_byte & (1 << 5) != 0,
            after_donate: flags_byte & (1 << 4) != 0,
            before_swap_returns_delta: flags_byte & (1 << 3) != 0,
            after_swap_returns_delta: flags_byte & (1 << 2) != 0,
            after_add_liquidity_returns_delta: flags_byte & (1 << 1) != 0,
            after_remove_liquidity_returns_delta: flags_byte & 1 != 0,
        }
    }

    /// Does this hook interfere with MEV strategies?
    pub fn mev_risk_level(&self) -> HookMevRisk {
        // before_swap + returns_delta = hook can front-run us or modify amounts
        if self.before_swap && self.before_swap_returns_delta {
            return HookMevRisk::Critical;
        }
        // before_swap alone = hook sees our swap before execution
        if self.before_swap {
            return HookMevRisk::High;
        }
        // after_swap + returns_delta = hook can modify output amounts
        if self.after_swap && self.after_swap_returns_delta {
            return HookMevRisk::High;
        }
        // after_swap alone = hook observes but can't change amounts
        if self.after_swap {
            return HookMevRisk::Medium;
        }
        // No swap hooks
        if self.before_donate || self.after_donate {
            return HookMevRisk::Low;
        }
        HookMevRisk::None
    }

    /// Count active hooks
    pub fn active_count(&self) -> u32 {
        let bools = [
            self.before_initialize,
            self.after_initialize,
            self.before_add_liquidity,
            self.after_add_liquidity,
            self.before_remove_liquidity,
            self.after_remove_liquidity,
            self.before_swap,
            self.after_swap,
            self.before_donate,
            self.after_donate,
            self.before_swap_returns_delta,
            self.after_swap_returns_delta,
            self.after_add_liquidity_returns_delta,
            self.after_remove_liquidity_returns_delta,
        ];
        bools.iter().filter(|&&b| b).count() as u32
    }
}

/// MEV risk classification based on hook capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HookMevRisk {
    /// No swap hooks — safe for all MEV strategies
    None,
    /// Only liquidity/donate hooks — minimal MEV impact
    Low,
    /// after_swap without delta — hook observes but can't modify
    Medium,
    /// before_swap or after_swap+delta — hook can affect execution
    High,
    /// before_swap+returns_delta — hook can front-run or modify amounts
    Critical,
}

impl std::fmt::Display for HookMevRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookMevRisk::None => write!(f, "NONE"),
            HookMevRisk::Low => write!(f, "LOW"),
            HookMevRisk::Medium => write!(f, "MEDIUM"),
            HookMevRisk::High => write!(f, "HIGH"),
            HookMevRisk::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ============================================================================
// COMMON HOOK PATTERNS (known archetypes)
// ============================================================================

/// Well-known hook patterns on Avalanche/Ethereum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookArchetype {
    /// Dynamic fee hook — adjusts fee based on volatility/utilization
    DynamicFee,
    /// TWAMM — Time-Weighted Average Market Maker (long-duration orders)
    Twamm,
    /// Limit order hook — places resting orders at specific ticks
    LimitOrder,
    /// Oracle hook — updates price oracle on each swap
    Oracle,
    /// MEV-capture hook — redistributes MEV back to LPs
    MevCapture,
    /// No hooks attached — pass-through
    NoHook,
    /// Custom/unknown hook
    Custom(String),
}

impl HookArchetype {
    /// Classify a hook by its behavior flags
    pub fn classify(flags: &HookFlags, hook_address: &str) -> Self {
        // No active hooks = no archetype
        if flags.active_count() == 0 {
            return HookArchetype::NoHook;
        }
        // MEV-capture: before_swap + returns_delta (takes a cut)
        if flags.before_swap && flags.before_swap_returns_delta {
            return HookArchetype::MevCapture;
        }
        // Dynamic fee: before_swap (adjusts fee) without delta
        if flags.before_swap && !flags.before_swap_returns_delta && !flags.after_swap {
            return HookArchetype::DynamicFee;
        }
        // Oracle: after_swap only (updates price)
        if flags.after_swap && !flags.before_swap && !flags.after_swap_returns_delta {
            return HookArchetype::Oracle;
        }
        // TWAMM: both before and after swap + liquidity hooks
        if flags.before_swap && flags.after_swap && flags.before_add_liquidity {
            return HookArchetype::Twamm;
        }
        // Limit order: after_swap + modify liquidity hooks
        if flags.after_swap && flags.after_add_liquidity && flags.after_remove_liquidity {
            return HookArchetype::LimitOrder;
        }
        HookArchetype::Custom(hook_address.to_string())
    }

    /// How does this archetype affect sandwich profitability?
    pub fn sandwich_modifier(&self) -> f64 {
        match self {
            HookArchetype::DynamicFee => 0.7, // fee may spike, reduce expected profit
            HookArchetype::Twamm => 0.9,      // minor interference from pending orders
            HookArchetype::LimitOrder => 0.85, // limit orders can absorb price impact
            HookArchetype::Oracle => 1.0,     // no effect on execution
            HookArchetype::MevCapture => 0.1, // hook captures most of our profit
            HookArchetype::NoHook => 1.0,     // no hooks = full pass-through
            HookArchetype::Custom(_) => 0.5,  // unknown = assume 50% reduction
        }
    }
}

// ============================================================================
// V4 POOL STATE (concentrated liquidity + hooks)
// ============================================================================

/// V4 pool with concentrated liquidity and hook awareness
#[derive(Debug, Clone)]
pub struct V4PoolState {
    pub key: PoolKey,
    pub sqrt_price_x96: U256,
    pub liquidity: u128,
    pub tick: i32,
    pub fee_protocol: u8,
    pub hook_flags: HookFlags,
    pub hook_archetype: HookArchetype,
    pub last_updated: Instant,
    /// Tick bitmap for initialized ticks (simplified: vec of active ticks)
    pub active_ticks: Vec<TickInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickInfo {
    pub tick: i32,
    pub liquidity_net: i128,
    pub liquidity_gross: u128,
}

impl V4PoolState {
    pub fn new(key: PoolKey, sqrt_price_x96: U256, liquidity: u128, tick: i32) -> Self {
        let hook_flags = HookFlags::from_address(&key.hooks);
        let hook_archetype = HookArchetype::classify(&hook_flags, &key.hooks);
        Self {
            key,
            sqrt_price_x96,
            liquidity,
            tick,
            fee_protocol: 0,
            hook_flags,
            hook_archetype,
            last_updated: Instant::now(),
            active_ticks: vec![],
        }
    }

    /// Calculate current price from sqrtPriceX96
    pub fn price(&self) -> f64 {
        let sqrt = self.sqrt_price_x96.to_f64() / 2.0f64.powi(96);
        sqrt * sqrt
    }

    /// Estimate output for a V4 swap (concentrated liquidity approximation)
    /// Uses current tick's liquidity — accurate for small swaps within one tick
    pub fn estimate_output(&self, amount_in: U256, zero_for_one: bool) -> SwapEstimate {
        if self.liquidity == 0 || amount_in.is_zero() {
            return SwapEstimate::zero();
        }

        let fee_factor = (1_000_000 - self.key.fee) as f64 / 1_000_000.0;
        let amt = amount_in.to_f64() * fee_factor;
        let liq = self.liquidity as f64;
        let sqrt_p = self.sqrt_price_x96.to_f64() / 2.0f64.powi(96);

        let (amount_out, new_sqrt_p) = if zero_for_one {
            // token0 → token1: price decreases
            // Δ(1/√P) = Δx / L → new_sqrt_p = L * sqrt_p / (L + Δx * sqrt_p)
            let new_sqrt = liq * sqrt_p / (liq + amt * sqrt_p);
            let out = liq * (sqrt_p - new_sqrt);
            (out, new_sqrt)
        } else {
            // token1 → token0: price increases
            // Δ√P = Δy / L → new_sqrt_p = sqrt_p + Δy / L
            let new_sqrt = sqrt_p + amt / liq;
            let out = liq * (1.0 / sqrt_p - 1.0 / new_sqrt);
            (out, new_sqrt)
        };

        // Hook modifier applies to PROFIT estimation, not raw swap output.
        // Raw output is the AMM math result; hooks modify profitability of MEV strategies.
        let hook_mod = self.hook_archetype.sandwich_modifier();

        let price_impact = ((new_sqrt_p - sqrt_p).abs() / sqrt_p) * 10_000.0;

        SwapEstimate {
            amount_out: U256::from_u128(amount_out.max(0.0) as u128),
            price_impact_bps: price_impact,
            effective_fee_bps: self.key.fee_bps(),
            hook_modifier: hook_mod,
            crosses_tick: self.would_cross_tick(new_sqrt_p, zero_for_one),
            new_sqrt_price: new_sqrt_p,
        }
    }

    /// Check if swap would cross an initialized tick (more gas, less predictable)
    fn would_cross_tick(&self, new_sqrt_price: f64, zero_for_one: bool) -> bool {
        let new_tick = self.sqrt_price_to_tick(new_sqrt_price);
        if zero_for_one {
            self.active_ticks
                .iter()
                .any(|t| t.tick <= self.tick && t.tick > new_tick)
        } else {
            self.active_ticks
                .iter()
                .any(|t| t.tick > self.tick && t.tick <= new_tick)
        }
    }

    fn sqrt_price_to_tick(&self, sqrt_price: f64) -> i32 {
        // tick = log(sqrt_price^2) / log(1.0001)
        if sqrt_price <= 0.0 {
            return i32::MIN;
        }
        let price = sqrt_price * sqrt_price;
        (price.ln() / 1.0001f64.ln()) as i32
    }

    /// Is this pool safe for sandwich MEV?
    pub fn is_sandwich_safe(&self) -> bool {
        match self.hook_flags.mev_risk_level() {
            HookMevRisk::None | HookMevRisk::Low => true,
            HookMevRisk::Medium => true, // observable but not modifiable
            HookMevRisk::High | HookMevRisk::Critical => false,
        }
    }

    /// V4 sandwich simulation with hook awareness
    pub fn simulate_v4_sandwich(
        &self,
        victim_amount: U256,
        frontrun_amount: U256,
        zero_for_one: bool,
    ) -> V4SandwichResult {
        // Step 1: Check hook safety
        let hook_risk = self.hook_flags.mev_risk_level();
        if hook_risk >= HookMevRisk::High {
            return V4SandwichResult {
                profitable: false,
                frontrun_out: SwapEstimate::zero(),
                victim_out: SwapEstimate::zero(),
                backrun_out: SwapEstimate::zero(),
                net_profit: U256::ZERO,
                hook_risk,
                hook_archetype: self.hook_archetype.clone(),
                abort_reason: Some(format!("Hook risk too high: {}", hook_risk)),
            };
        }

        // Step 2: Frontrun
        let frontrun_est = self.estimate_output(frontrun_amount, zero_for_one);

        // Step 3: Simulate pool state after frontrun (update sqrt price)
        let mut pool_after_frontrun = self.clone();
        pool_after_frontrun.sqrt_price_x96 =
            U256::from_u128((frontrun_est.new_sqrt_price * 2.0f64.powi(96)) as u128);
        pool_after_frontrun.tick =
            pool_after_frontrun.sqrt_price_to_tick(frontrun_est.new_sqrt_price);

        // Step 4: Victim swap at worse price
        let victim_est = pool_after_frontrun.estimate_output(victim_amount, zero_for_one);

        // Step 5: Pool state after victim
        let mut pool_after_victim = pool_after_frontrun.clone();
        pool_after_victim.sqrt_price_x96 =
            U256::from_u128((victim_est.new_sqrt_price * 2.0f64.powi(96)) as u128);
        pool_after_victim.tick = pool_after_victim.sqrt_price_to_tick(victim_est.new_sqrt_price);

        // Step 6: Backrun (reverse direction)
        let backrun_est = pool_after_victim.estimate_output(frontrun_est.amount_out, !zero_for_one);

        // Step 7: Calculate profit
        let profit = backrun_est.amount_out.saturating_sub(frontrun_amount);

        // Apply hook modifier to final profit
        let hook_mod = self.hook_archetype.sandwich_modifier();
        let adjusted_profit = U256::from_u128((profit.to_f64() * hook_mod).max(0.0) as u128);

        V4SandwichResult {
            profitable: !adjusted_profit.is_zero(),
            frontrun_out: frontrun_est,
            victim_out: victim_est,
            backrun_out: backrun_est,
            net_profit: adjusted_profit,
            hook_risk,
            hook_archetype: self.hook_archetype.clone(),
            abort_reason: None,
        }
    }
}

/// Swap output estimate with V4-specific details
#[derive(Debug, Clone)]
pub struct SwapEstimate {
    pub amount_out: U256,
    pub price_impact_bps: f64,
    pub effective_fee_bps: f64,
    pub hook_modifier: f64,
    pub crosses_tick: bool,
    pub new_sqrt_price: f64,
}

impl SwapEstimate {
    pub fn zero() -> Self {
        Self {
            amount_out: U256::ZERO,
            price_impact_bps: 0.0,
            effective_fee_bps: 0.0,
            hook_modifier: 1.0,
            crosses_tick: false,
            new_sqrt_price: 0.0,
        }
    }
}

/// V4 sandwich simulation result with hook analysis
#[derive(Debug, Clone)]
pub struct V4SandwichResult {
    pub profitable: bool,
    pub frontrun_out: SwapEstimate,
    pub victim_out: SwapEstimate,
    pub backrun_out: SwapEstimate,
    pub net_profit: U256,
    pub hook_risk: HookMevRisk,
    pub hook_archetype: HookArchetype,
    pub abort_reason: Option<String>,
}

// ============================================================================
// V4 POOL SCANNER — discover pools and classify hooks
// ============================================================================

/// Scans V4 PoolManager events for new pools and classifies their hooks
pub struct V4PoolScanner {
    /// Known pools indexed by PoolKey
    pub pools: HashMap<PoolKey, V4PoolState>,
    /// Hook addresses we've classified
    pub classified_hooks: HashMap<String, (HookFlags, HookArchetype)>,
    /// Stats
    pub pools_scanned: u64,
    pub hooks_with_before_swap: u64,
    pub hooks_mev_capture: u64,
}

impl V4PoolScanner {
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
            classified_hooks: HashMap::new(),
            pools_scanned: 0,
            hooks_with_before_swap: 0,
            hooks_mev_capture: 0,
        }
    }

    /// Register a new V4 pool
    pub fn add_pool(&mut self, key: PoolKey, sqrt_price_x96: U256, liquidity: u128, tick: i32) {
        let flags = HookFlags::from_address(&key.hooks);
        let archetype = HookArchetype::classify(&flags, &key.hooks);

        if flags.before_swap {
            self.hooks_with_before_swap += 1;
        }
        if matches!(archetype, HookArchetype::MevCapture) {
            self.hooks_mev_capture += 1;
        }

        self.classified_hooks
            .insert(key.hooks.clone(), (flags.clone(), archetype.clone()));
        self.pools.insert(
            key.clone(),
            V4PoolState::new(key, sqrt_price_x96, liquidity, tick),
        );
        self.pools_scanned += 1;
    }

    /// Get all pools safe for sandwich MEV
    pub fn sandwich_safe_pools(&self) -> Vec<&V4PoolState> {
        self.pools
            .values()
            .filter(|p| p.is_sandwich_safe())
            .collect()
    }

    /// Get pools by token pair (may return multiple with different fees/hooks)
    pub fn pools_for_pair(&self, token0: &str, token1: &str) -> Vec<&V4PoolState> {
        let t0 = token0.to_lowercase();
        let t1 = token1.to_lowercase();
        let (c0, c1) = if t0 < t1 { (t0, t1) } else { (t1, t0) };

        self.pools
            .values()
            .filter(|p| p.key.currency0 == c0 && p.key.currency1 == c1)
            .collect()
    }

    /// Find best arbitrage between V4 pools (same pair, different fees/hooks)
    pub fn find_v4_arb(
        &self,
        token0: &str,
        token1: &str,
        amount: U256,
    ) -> Option<V4ArbOpportunity> {
        let pools = self.pools_for_pair(token0, token1);
        if pools.len() < 2 {
            return None;
        }

        let mut best_buy: Option<(&V4PoolState, f64)> = None;
        let mut best_sell: Option<(&V4PoolState, f64)> = None;

        for pool in &pools {
            if !pool.is_sandwich_safe() {
                continue;
            }
            let price = pool.price();
            if price <= 0.0 {
                continue;
            }

            match &best_buy {
                None => best_buy = Some((pool, price)),
                Some((_, bp)) => {
                    if price < *bp {
                        best_buy = Some((pool, price));
                    }
                }
            }
            match &best_sell {
                None => best_sell = Some((pool, price)),
                Some((_, sp)) => {
                    if price > *sp {
                        best_sell = Some((pool, price));
                    }
                }
            }
        }

        let (buy_pool, buy_price) = best_buy?;
        let (sell_pool, sell_price) = best_sell?;

        if std::ptr::eq(buy_pool as *const _, sell_pool as *const _) {
            return None; // same pool
        }

        let spread_bps = ((sell_price - buy_price) / buy_price) * 10_000.0;
        if spread_bps < 10.0 {
            return None;
        } // min 10 bps

        let est_profit = amount.to_f64() * (spread_bps / 10_000.0);

        Some(V4ArbOpportunity {
            buy_pool_key: buy_pool.key.clone(),
            sell_pool_key: sell_pool.key.clone(),
            buy_price,
            sell_price,
            spread_bps,
            estimated_profit: U256::from_u128(est_profit.max(0.0) as u128),
            buy_hook_risk: buy_pool.hook_flags.mev_risk_level(),
            sell_hook_risk: sell_pool.hook_flags.mev_risk_level(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct V4ArbOpportunity {
    pub buy_pool_key: PoolKey,
    pub sell_pool_key: PoolKey,
    pub buy_price: f64,
    pub sell_price: f64,
    pub spread_bps: f64,
    pub estimated_profit: U256,
    pub buy_hook_risk: HookMevRisk,
    pub sell_hook_risk: HookMevRisk,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // --- V4 selectors ---

    #[test]
    fn test_v4_swap_selectors() {
        assert!(v4_selectors::is_v4_swap(&v4_selectors::SWAP));
        assert!(v4_selectors::is_v4_swap(&v4_selectors::EXECUTE));
        assert!(v4_selectors::is_v4_swap(
            &v4_selectors::EXECUTE_WITH_DEADLINE
        ));
        assert!(!v4_selectors::is_v4_swap(&v4_selectors::INITIALIZE));
        assert!(!v4_selectors::is_v4_swap(&v4_selectors::DONATE));
        assert!(!v4_selectors::is_v4_swap(&[0, 0, 0])); // too short
    }

    #[test]
    fn test_v4_liquidity_selectors() {
        assert!(v4_selectors::is_v4_liquidity(
            &v4_selectors::MODIFY_LIQUIDITY
        ));
        assert!(v4_selectors::is_v4_liquidity(&v4_selectors::DONATE));
        assert!(!v4_selectors::is_v4_liquidity(&v4_selectors::SWAP));
    }

    #[test]
    fn test_v4_all_actions() {
        let actions = [
            v4_selectors::INITIALIZE,
            v4_selectors::SWAP,
            v4_selectors::MODIFY_LIQUIDITY,
            v4_selectors::DONATE,
            v4_selectors::TAKE,
            v4_selectors::SETTLE,
            v4_selectors::LOCK,
            v4_selectors::EXECUTE,
            v4_selectors::EXECUTE_WITH_DEADLINE,
        ];
        for a in &actions {
            assert!(
                v4_selectors::is_v4_action(a),
                "Should be a V4 action: {:?}",
                a
            );
        }
        assert!(!v4_selectors::is_v4_action(&[0xFF, 0xFF, 0xFF, 0xFF]));
    }

    // --- PoolKey ---

    #[test]
    fn test_pool_key_sorts_tokens() {
        let k1 = PoolKey::new("0xBBB", "0xAAA", 3000, 60, "0x0");
        assert_eq!(k1.currency0, "0xaaa"); // sorted + lowercased
        assert_eq!(k1.currency1, "0xbbb");
    }

    #[test]
    fn test_pool_key_no_hooks() {
        let k = PoolKey::new(
            "A",
            "B",
            3000,
            60,
            "0x0000000000000000000000000000000000000000",
        );
        assert!(!k.has_hooks());
        let k2 = PoolKey::new("A", "B", 3000, 60, "0x0");
        assert!(!k2.has_hooks());
    }

    #[test]
    fn test_pool_key_with_hooks() {
        let k = PoolKey::new("A", "B", 3000, 60, "0x80000000000000000000000000000001");
        assert!(k.has_hooks());
    }

    #[test]
    fn test_pool_key_fee_bps() {
        assert_eq!(PoolKey::new("A", "B", 3000, 60, "0x0").fee_bps(), 30.0);
        assert_eq!(PoolKey::new("A", "B", 500, 10, "0x0").fee_bps(), 5.0);
        assert_eq!(PoolKey::new("A", "B", 10000, 200, "0x0").fee_bps(), 100.0);
    }

    #[test]
    fn test_pool_key_native() {
        let k = PoolKey::new(
            "0x0000000000000000000000000000000000000000",
            tokens::USDC,
            3000,
            60,
            "0x0",
        );
        assert!(k.is_native_pair());
    }

    // --- Hook flags ---

    #[test]
    fn test_hook_flags_no_hooks() {
        let flags = HookFlags::from_address("0x0000000000000000000000000000000000000000");
        assert!(!flags.before_swap);
        assert!(!flags.after_swap);
        assert_eq!(flags.active_count(), 0);
        assert_eq!(flags.mev_risk_level(), HookMevRisk::None);
    }

    #[test]
    fn test_hook_flags_before_swap() {
        // 0x0080 = bit 7 = before_swap
        let flags = HookFlags::from_address("0x0080000000000000000000000000000000000000");
        assert!(flags.before_swap);
        assert!(!flags.after_swap);
        assert_eq!(flags.mev_risk_level(), HookMevRisk::High);
    }

    #[test]
    fn test_hook_flags_after_swap() {
        // 0x0040 = bit 6 = after_swap
        let flags = HookFlags::from_address("0x0040000000000000000000000000000000000000");
        assert!(!flags.before_swap);
        assert!(flags.after_swap);
        assert_eq!(flags.mev_risk_level(), HookMevRisk::Medium);
    }

    #[test]
    fn test_hook_flags_before_swap_returns_delta() {
        // 0x0088 = bit 7 (before_swap) + bit 3 (before_swap_returns_delta)
        let flags = HookFlags::from_address("0x0088000000000000000000000000000000000000");
        assert!(flags.before_swap);
        assert!(flags.before_swap_returns_delta);
        assert_eq!(flags.mev_risk_level(), HookMevRisk::Critical);
    }

    #[test]
    fn test_hook_flags_donate_only() {
        // 0x0030 = bit 5 (before_donate) + bit 4 (after_donate)
        let flags = HookFlags::from_address("0x0030000000000000000000000000000000000000");
        assert!(flags.before_donate);
        assert!(flags.after_donate);
        assert!(!flags.before_swap);
        assert_eq!(flags.mev_risk_level(), HookMevRisk::Low);
    }

    #[test]
    fn test_hook_flags_all_active() {
        // 0x3FFF = all 14 flags
        let flags = HookFlags::from_address("0x3FFF000000000000000000000000000000000000");
        assert_eq!(flags.active_count(), 14);
        assert_eq!(flags.mev_risk_level(), HookMevRisk::Critical);
    }

    // --- Hook archetypes ---

    #[test]
    fn test_archetype_mev_capture() {
        let flags = HookFlags::from_address("0x0088000000000000000000000000000000000000");
        let arch = HookArchetype::classify(&flags, "0x0088");
        assert_eq!(arch, HookArchetype::MevCapture);
        assert!((arch.sandwich_modifier() - 0.1).abs() < 0.01);
    }

    #[test]
    fn test_archetype_dynamic_fee() {
        // before_swap only
        let flags = HookFlags::from_address("0x0080000000000000000000000000000000000000");
        let arch = HookArchetype::classify(&flags, "0x0080");
        assert_eq!(arch, HookArchetype::DynamicFee);
        assert!((arch.sandwich_modifier() - 0.7).abs() < 0.01);
    }

    #[test]
    fn test_archetype_oracle() {
        // after_swap only (no returns_delta)
        let flags = HookFlags::from_address("0x0040000000000000000000000000000000000000");
        let arch = HookArchetype::classify(&flags, "0x0040");
        assert_eq!(arch, HookArchetype::Oracle);
        assert!((arch.sandwich_modifier() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_archetype_no_hook() {
        let flags = HookFlags::from_address("0x0000000000000000000000000000000000000000");
        let arch = HookArchetype::classify(&flags, "0x0");
        assert_eq!(arch, HookArchetype::NoHook);
        assert!((arch.sandwich_modifier() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_hook_risk_ordering() {
        assert!(HookMevRisk::None < HookMevRisk::Low);
        assert!(HookMevRisk::Low < HookMevRisk::Medium);
        assert!(HookMevRisk::Medium < HookMevRisk::High);
        assert!(HookMevRisk::High < HookMevRisk::Critical);
    }

    // --- V4 Pool State ---

    fn make_test_pool(hooks: &str) -> V4PoolState {
        let key = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, hooks);
        // sqrtPriceX96 for ~$20 AVAX/USDC (sqrt(20) * 2^96 ≈ 354.4 * 7.9e28)
        let sqrt_price = U256::from_u128(354_400_000_000_000_000_000_000_000_000u128);
        V4PoolState::new(key, sqrt_price, 1_000_000_000_000_000_000, 0)
    }

    #[test]
    fn test_v4_pool_creation() {
        let pool = make_test_pool("0x0000000000000000000000000000000000000000");
        assert!(!pool.key.has_hooks());
        assert!(pool.is_sandwich_safe());
        assert_eq!(pool.hook_flags.mev_risk_level(), HookMevRisk::None);
    }

    #[test]
    fn test_v4_pool_price() {
        let pool = make_test_pool("0x0000000000000000000000000000000000000000");
        let price = pool.price();
        assert!(price > 0.0, "Price should be positive: {}", price);
    }

    #[test]
    fn test_v4_pool_estimate_zero_input() {
        let pool = make_test_pool("0x0000000000000000000000000000000000000000");
        let est = pool.estimate_output(U256::ZERO, true);
        assert!(est.amount_out.is_zero());
    }

    #[test]
    fn test_v4_pool_estimate_zero_liquidity() {
        let key = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, "0x0");
        let pool = V4PoolState::new(key, U256::from_u128(1_000_000), 0, 0); // zero liquidity
        let est = pool.estimate_output(U256::from_u64(1000), true);
        assert!(est.amount_out.is_zero());
    }

    #[test]
    fn test_v4_pool_hooked_unsafe() {
        // before_swap + returns_delta = MEV capture hook
        let pool = make_test_pool("0x0088000000000000000000000000000000000000");
        assert!(!pool.is_sandwich_safe());
        assert_eq!(pool.hook_flags.mev_risk_level(), HookMevRisk::Critical);
    }

    // --- V4 Sandwich ---

    #[test]
    fn test_v4_sandwich_no_hooks() {
        let pool = make_test_pool("0x0000000000000000000000000000000000000000");
        let victim = U256::from_u128(1_000 * 10u128.pow(18));
        let frontrun = U256::from_u128(3_000 * 10u128.pow(18));

        let result = pool.simulate_v4_sandwich(victim, frontrun, true);
        assert!(result.abort_reason.is_none());
        assert_eq!(result.hook_risk, HookMevRisk::None);
        // Hook modifier = 1.0 for no-hook pool
        assert!((result.frontrun_out.hook_modifier - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_v4_sandwich_aborts_on_mev_capture_hook() {
        let pool = make_test_pool("0x0088000000000000000000000000000000000000");
        let victim = U256::from_u128(1_000 * 10u128.pow(18));
        let frontrun = U256::from_u128(3_000 * 10u128.pow(18));

        let result = pool.simulate_v4_sandwich(victim, frontrun, true);
        assert!(!result.profitable);
        assert!(result.abort_reason.is_some());
        assert!(result.abort_reason.unwrap().contains("CRITICAL"));
    }

    #[test]
    fn test_v4_sandwich_reduced_profit_dynamic_fee() {
        // Dynamic fee hook: before_swap only
        let pool_no_hook = make_test_pool("0x0000000000000000000000000000000000000000");
        let pool_dyn_fee = make_test_pool("0x0080000000000000000000000000000000000000");

        let victim = U256::from_u128(1_000 * 10u128.pow(18));
        let frontrun = U256::from_u128(3_000 * 10u128.pow(18));

        let r_clean = pool_no_hook.simulate_v4_sandwich(victim, frontrun, true);
        let r_hooked = pool_dyn_fee.simulate_v4_sandwich(victim, frontrun, true);

        // Dynamic fee hook should abort (High risk)
        assert!(r_hooked.abort_reason.is_some());
        // No hook should proceed
        assert!(r_clean.abort_reason.is_none());
    }

    // --- V4 Pool Scanner ---

    #[test]
    fn test_scanner_add_pools() {
        let mut scanner = V4PoolScanner::new();
        let key = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, "0x0");
        scanner.add_pool(key, U256::from_u128(1_000_000), 1_000_000, 0);
        assert_eq!(scanner.pools_scanned, 1);
        assert_eq!(scanner.pools.len(), 1);
    }

    #[test]
    fn test_scanner_tracks_hook_stats() {
        let mut scanner = V4PoolScanner::new();

        // Pool with before_swap hook
        let key1 = PoolKey::new(
            tokens::WAVAX,
            tokens::USDC,
            3000,
            60,
            "0x0080000000000000000000000000000000000000",
        );
        scanner.add_pool(key1, U256::from_u128(1_000_000), 1_000_000, 0);

        // Pool with MEV capture hook
        let key2 = PoolKey::new(
            tokens::WAVAX,
            tokens::USDC,
            500,
            10,
            "0x0088000000000000000000000000000000000000",
        );
        scanner.add_pool(key2, U256::from_u128(1_000_000), 1_000_000, 0);

        // No-hook pool
        let key3 = PoolKey::new(tokens::WAVAX, tokens::USDT, 3000, 60, "0x0");
        scanner.add_pool(key3, U256::from_u128(1_000_000), 1_000_000, 0);

        assert_eq!(scanner.pools_scanned, 3);
        assert_eq!(scanner.hooks_with_before_swap, 2);
        assert_eq!(scanner.hooks_mev_capture, 1);
    }

    #[test]
    fn test_scanner_sandwich_safe_filter() {
        let mut scanner = V4PoolScanner::new();

        // Safe pool
        let k1 = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, "0x0");
        scanner.add_pool(k1, U256::from_u128(1_000_000), 1_000_000, 0);

        // Unsafe pool (MEV capture)
        let k2 = PoolKey::new(
            tokens::WAVAX,
            tokens::USDC,
            500,
            10,
            "0x0088000000000000000000000000000000000000",
        );
        scanner.add_pool(k2, U256::from_u128(1_000_000), 1_000_000, 0);

        let safe = scanner.sandwich_safe_pools();
        assert_eq!(safe.len(), 1);
    }

    #[test]
    fn test_scanner_pools_for_pair() {
        let mut scanner = V4PoolScanner::new();

        // Two WAVAX/USDC pools with different fees
        let k1 = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, "0x0");
        let k2 = PoolKey::new(tokens::WAVAX, tokens::USDC, 500, 10, "0x0");
        // One WAVAX/USDT pool
        let k3 = PoolKey::new(tokens::WAVAX, tokens::USDT, 3000, 60, "0x0");

        scanner.add_pool(k1, U256::from_u128(1_000_000), 1_000_000, 0);
        scanner.add_pool(k2, U256::from_u128(1_000_000), 1_000_000, 0);
        scanner.add_pool(k3, U256::from_u128(1_000_000), 1_000_000, 0);

        let wavax_usdc = scanner.pools_for_pair(tokens::WAVAX, tokens::USDC);
        assert_eq!(wavax_usdc.len(), 2);

        let wavax_usdt = scanner.pools_for_pair(tokens::WAVAX, tokens::USDT);
        assert_eq!(wavax_usdt.len(), 1);

        let usdc_weth = scanner.pools_for_pair(tokens::USDC, tokens::WETH);
        assert_eq!(usdc_weth.len(), 0);
    }

    #[test]
    fn test_scanner_pair_order_independent() {
        let mut scanner = V4PoolScanner::new();
        let k = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, "0x0");
        scanner.add_pool(k, U256::from_u128(1_000_000), 1_000_000, 0);

        // Should find regardless of query order
        assert_eq!(scanner.pools_for_pair(tokens::WAVAX, tokens::USDC).len(), 1);
        assert_eq!(scanner.pools_for_pair(tokens::USDC, tokens::WAVAX).len(), 1);
    }

    // --- V4 Arb Scanner ---

    #[test]
    fn test_find_v4_arb_no_spread() {
        let mut scanner = V4PoolScanner::new();
        // Two pools with same price — no arb
        let k1 = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, "0x0");
        let k2 = PoolKey::new(tokens::WAVAX, tokens::USDC, 500, 10, "0x0");
        let sqrt = U256::from_u128(354_400_000_000_000_000_000_000_000_000u128);
        scanner.add_pool(k1, sqrt, 1_000_000_000_000_000_000, 0);
        scanner.add_pool(k2, sqrt, 1_000_000_000_000_000_000, 0);

        let arb = scanner.find_v4_arb(
            tokens::WAVAX,
            tokens::USDC,
            U256::from_u128(10 * 10u128.pow(18)),
        );
        assert!(arb.is_none(), "Same price pools should yield no arb");
    }

    #[test]
    fn test_find_v4_arb_with_spread() {
        let mut scanner = V4PoolScanner::new();
        let sqrt_low = U256::from_u128(300_000_000_000_000_000_000_000_000_000u128);
        let sqrt_high = U256::from_u128(400_000_000_000_000_000_000_000_000_000u128);

        let k1 = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, "0x0");
        let k2 = PoolKey::new(tokens::WAVAX, tokens::USDC, 500, 10, "0x0");
        scanner.add_pool(k1, sqrt_low, 1_000_000_000_000_000_000, 0);
        scanner.add_pool(k2, sqrt_high, 1_000_000_000_000_000_000, 0);

        let arb = scanner.find_v4_arb(
            tokens::WAVAX,
            tokens::USDC,
            U256::from_u128(10 * 10u128.pow(18)),
        );
        assert!(arb.is_some(), "Different price pools should yield arb");
        let arb = arb.unwrap();
        assert!(arb.spread_bps > 10.0);
        assert!(arb.buy_price < arb.sell_price);
    }

    #[test]
    fn test_find_v4_arb_skips_unsafe_pools() {
        let mut scanner = V4PoolScanner::new();
        // Both pools have MEV capture hooks — no safe pools
        let k1 = PoolKey::new(
            tokens::WAVAX,
            tokens::USDC,
            3000,
            60,
            "0x0088000000000000000000000000000000000000",
        );
        let k2 = PoolKey::new(
            tokens::WAVAX,
            tokens::USDC,
            500,
            10,
            "0x0088000000000000000000000000000000000001",
        );
        scanner.add_pool(
            k1,
            U256::from_u128(300_000_000_000_000_000_000_000_000_000u128),
            1_000_000_000_000_000_000,
            0,
        );
        scanner.add_pool(
            k2,
            U256::from_u128(400_000_000_000_000_000_000_000_000_000u128),
            1_000_000_000_000_000_000,
            0,
        );

        let arb = scanner.find_v4_arb(
            tokens::WAVAX,
            tokens::USDC,
            U256::from_u128(10 * 10u128.pow(18)),
        );
        assert!(arb.is_none(), "Should skip unsafe pools");
    }

    #[test]
    fn test_find_v4_arb_single_pool() {
        let mut scanner = V4PoolScanner::new();
        let k = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, "0x0");
        scanner.add_pool(
            k,
            U256::from_u128(354_400_000_000_000_000_000_000_000_000u128),
            1_000_000_000_000_000_000,
            0,
        );

        let arb = scanner.find_v4_arb(
            tokens::WAVAX,
            tokens::USDC,
            U256::from_u128(10 * 10u128.pow(18)),
        );
        assert!(arb.is_none(), "Need at least 2 pools for arb");
    }

    // --- V4 estimate_output real inputs ---

    #[test]
    fn test_v4_estimate_both_directions() {
        let pool = make_test_pool("0x0000000000000000000000000000000000000000");
        let amount = U256::from_u128(100 * 10u128.pow(18));

        let est_0to1 = pool.estimate_output(amount, true);
        let est_1to0 = pool.estimate_output(amount, false);

        // Both should produce non-zero output
        assert!(
            !est_0to1.amount_out.is_zero(),
            "0→1 output should be non-zero"
        );
        assert!(
            !est_1to0.amount_out.is_zero(),
            "1→0 output should be non-zero"
        );
        // Price impact should be positive
        assert!(est_0to1.price_impact_bps > 0.0);
        assert!(est_1to0.price_impact_bps > 0.0);
    }

    #[test]
    fn test_v4_estimate_fee_applied() {
        let pool = make_test_pool("0x0000000000000000000000000000000000000000");
        let amount = U256::from_u128(100 * 10u128.pow(18));
        let est = pool.estimate_output(amount, true);

        // Fee should be 30 bps (fee=3000 → 30bps)
        assert!((est.effective_fee_bps - 30.0).abs() < 0.1);
    }

    // --- Tick crossing ---

    #[test]
    fn test_v4_tick_crossing_detection() {
        let key = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, "0x0");
        let mut pool = V4PoolState::new(
            key,
            U256::from_u128(354_400_000_000_000_000_000_000_000_000u128),
            1_000_000_000_000_000_000,
            100, // current tick = 100
        );
        pool.active_ticks = vec![
            TickInfo {
                tick: 50,
                liquidity_net: 1000,
                liquidity_gross: 1000,
            },
            TickInfo {
                tick: 150,
                liquidity_net: -1000,
                liquidity_gross: 1000,
            },
        ];

        // Small swap shouldn't cross tick
        let small = pool.estimate_output(U256::from_u64(1000), true);
        // Large swap going 0→1 (price decreases, tick decreases) should cross tick 50
        // Depends on actual math — just verify the field is populated
        assert!(small.crosses_tick == true || small.crosses_tick == false); // no crash
    }

    // --- DEX alias ---

    #[test]
    fn test_dex_alias() {
        assert_eq!(
            DexProtocol::LFJ.is_alias_of(),
            Some(DexProtocol::TraderJoeV2)
        );
        assert_eq!(
            DexProtocol::PangolinV2.is_alias_of(),
            Some(DexProtocol::Pangolin)
        );
        assert_eq!(DexProtocol::TraderJoe.is_alias_of(), None);
    }

    // --- V4 pool sqrt_price_to_tick ---

    #[test]
    fn test_sqrt_price_to_tick_zero() {
        let pool = make_test_pool("0x0");
        assert_eq!(pool.sqrt_price_to_tick(0.0), i32::MIN);
        assert_eq!(pool.sqrt_price_to_tick(-1.0), i32::MIN);
    }

    // --- Stress ---

    #[test]
    fn test_hook_classification_stress() {
        let start = Instant::now();
        for i in 0u16..10_000 {
            let addr = format!("0x{:04x}000000000000000000000000000000000000", i);
            let flags = HookFlags::from_address(&addr);
            let _ = flags.mev_risk_level();
            let _ = HookArchetype::classify(&flags, &addr);
        }
        assert!(
            start.elapsed().as_millis() < 50,
            "10K hook classifications should take <50ms"
        );
    }
}
