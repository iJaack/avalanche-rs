//! MEV (Maximal Extractable Value) engine for Avalanche C-Chain
//!
//! Sub-second finality on Avalanche means MEV is pure latency game.
//! This module provides: mempool monitoring, arbitrage detection,
//! sandwich construction, liquidation scanning, and bundle submission.

pub mod v4;

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use serde::{Serialize, Deserialize};

// ============================================================================
// CORE TYPES
// ============================================================================

/// Raw pending transaction from mempool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTx {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: U256,
    pub gas_price: U256,
    pub gas_limit: u64,
    pub input: Vec<u8>,
    pub nonce: u64,
    pub timestamp: u64,
}

/// Simplified U256 for MEV calculations (wraps u128 pair)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct U256 {
    pub high: u128,
    pub low: u128,
}

impl U256 {
    pub const ZERO: Self = Self { high: 0, low: 0 };

    pub fn from_u128(v: u128) -> Self {
        Self { high: 0, low: v }
    }

    pub fn from_u64(v: u64) -> Self {
        Self { high: 0, low: v as u128 }
    }

    pub fn is_zero(&self) -> bool {
        self.high == 0 && self.low == 0
    }

    /// Parse from hex string (0x-prefixed or not)
    pub fn from_hex(s: &str) -> std::result::Result<Self, MevError> {
        let s = s.trim_start_matches("0x");
        if s.is_empty() { return Ok(Self::ZERO); }
        if s.len() > 64 {
            return Err(MevError::ParseError("U256 hex too long".into()));
        }
        if s.len() <= 32 {
            let v = u128::from_str_radix(s, 16)
                .map_err(|e| MevError::ParseError(e.to_string()))?;
            Ok(Self { high: 0, low: v })
        } else {
            let split = s.len() - 32;
            let high = u128::from_str_radix(&s[..split], 16)
                .map_err(|e| MevError::ParseError(e.to_string()))?;
            let low = u128::from_str_radix(&s[split..], 16)
                .map_err(|e| MevError::ParseError(e.to_string()))?;
            Ok(Self { high, low })
        }
    }

    pub fn to_f64(&self) -> f64 {
        (self.high as f64) * 2.0f64.powi(128) + (self.low as f64)
    }

    /// Convert to AVAX (18 decimals)
    pub fn to_avax(&self) -> f64 {
        self.to_f64() / 1e18
    }

    /// Convert to token amount with given decimals
    pub fn to_token(&self, decimals: u8) -> f64 {
        self.to_f64() / 10f64.powi(decimals as i32)
    }

    /// Saturating addition
    pub fn saturating_add(self, other: Self) -> Self {
        let (low, carry) = self.low.overflowing_add(other.low);
        let high = self.high.saturating_add(other.high).saturating_add(carry as u128);
        Self { high, low }
    }

    /// Saturating subtraction
    pub fn saturating_sub(self, other: Self) -> Self {
        if self < other { return Self::ZERO; }
        let (low, borrow) = self.low.overflowing_sub(other.low);
        let high = self.high.wrapping_sub(other.high).wrapping_sub(borrow as u128);
        Self { high, low }
    }
}

impl std::fmt::Display for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.high == 0 {
            write!(f, "0x{:x}", self.low)
        } else {
            write!(f, "0x{:x}{:032x}", self.high, self.low)
        }
    }
}

// ============================================================================
// DEX TYPES
// ============================================================================

/// Known DEX routers on Avalanche C-Chain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DexProtocol {
    TraderJoe,
    TraderJoeV2,
    Pangolin,
    PangolinV2,
    SushiSwap,
    Platypus,
    GMX,
    WooFi,
    Curve,
    Pharaoh,
    LFJ,
    Unknown,
}

impl DexProtocol {
    /// Get router address for this DEX
    pub fn router_address(&self) -> &'static str {
        match self {
            DexProtocol::TraderJoe => "0x60aE616a2155Ee3d9A68541Ba4544862310933d4",
            DexProtocol::TraderJoeV2 => "0xb4315e873dBcf96Ffd0acd8EA43f689D8c20fB30",
            DexProtocol::Pangolin => "0xE54Ca86531e17Ef3616d22Ca28b0D458b6C89106",
            DexProtocol::PangolinV2 => "0xE54Ca86531e17Ef3616d22Ca28b0D458b6C89106", // same as V1 on Avalanche
            DexProtocol::SushiSwap => "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506",
            DexProtocol::Platypus => "0x73256EC7575D999C360c1EeC118ECbEFd8DA7D12",
            DexProtocol::GMX => "0x5F719c2F1095F7B9996269653516B7aAdE5eCAd8",
            DexProtocol::WooFi => "0xC22FBb3133dF781E6C25ea6acebe2D2Bb8CeA2f9",
            DexProtocol::Curve => "0x7f90122BF0700F9E7e1F688fe926940E8839F353",
            DexProtocol::Pharaoh => "0xAAA45c8F5ef92a000a121d102F4e89278a711Faa",
            DexProtocol::LFJ => "0xb4315e873dBcf96Ffd0acd8EA43f689D8c20fB30",
            DexProtocol::Unknown => "0x0000000000000000000000000000000000000000",
        }
    }

    /// Identify DEX from router address
    pub fn from_address(addr: &str) -> Self {
        let addr_lower = addr.to_lowercase();
        match addr_lower.as_str() {
            "0x60ae616a2155ee3d9a68541ba4544862310933d4" => DexProtocol::TraderJoe,
            "0xb4315e873dbcf96ffd0acd8ea43f689d8c20fb30" => DexProtocol::TraderJoeV2, // also LFJ
            "0xe54ca86531e17ef3616d22ca28b0d458b6c89106" => DexProtocol::Pangolin, // also PangolinV2
            "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506" => DexProtocol::SushiSwap,
            "0x73256ec7575d999c360c1eec118ecbefd8da7d12" => DexProtocol::Platypus,
            "0x5f719c2f1095f7b9996269653516b7aade5ecad8" => DexProtocol::GMX,
            "0xc22fbb3133df781e6c25ea6acebe2d2bb8cea2f9" => DexProtocol::WooFi,
            "0x7f90122bf0700f9e7e1f688fe926940e8839f353" => DexProtocol::Curve,
            "0xaaa45c8f5ef92a000a121d102f4e89278a711faa" => DexProtocol::Pharaoh,
            _ => DexProtocol::Unknown,
        }
    }

    /// Check if this is an alias for another protocol (shared router address)
    pub fn is_alias_of(&self) -> Option<DexProtocol> {
        match self {
            DexProtocol::LFJ => Some(DexProtocol::TraderJoeV2),
            DexProtocol::PangolinV2 => Some(DexProtocol::Pangolin),
            _ => None,
        }
    }
}

/// ERC-20 function selectors (first 4 bytes of keccak256)
pub mod selectors {
    // UniswapV2-style
    pub const SWAP_EXACT_TOKENS_FOR_TOKENS: [u8; 4] = [0x38, 0xed, 0x17, 0x39];
    pub const SWAP_TOKENS_FOR_EXACT_TOKENS: [u8; 4] = [0x88, 0x03, 0xdb, 0xee];
    pub const SWAP_EXACT_ETH_FOR_TOKENS: [u8; 4] = [0x7f, 0xf3, 0x6a, 0xb5];
    pub const SWAP_TOKENS_FOR_EXACT_ETH: [u8; 4] = [0x4a, 0x25, 0xd9, 0x4a];
    pub const SWAP_EXACT_TOKENS_FOR_ETH: [u8; 4] = [0x18, 0xcb, 0xaf, 0xe5];
    pub const SWAP_ETH_FOR_EXACT_TOKENS: [u8; 4] = [0xfb, 0x3b, 0xdb, 0x41];

    // UniswapV3-style multicall
    pub const MULTICALL: [u8; 4] = [0xac, 0x96, 0x50, 0xd8];
    pub const EXACT_INPUT_SINGLE: [u8; 4] = [0x41, 0x4b, 0xf3, 0x89];
    pub const EXACT_INPUT: [u8; 4] = [0xc0, 0x4b, 0x8d, 0x59];
    pub const EXACT_OUTPUT_SINGLE: [u8; 4] = [0xdb, 0x3e, 0x21, 0x98];
    pub const EXACT_OUTPUT: [u8; 4] = [0xf2, 0x8c, 0x05, 0x98];

    // ERC-20
    pub const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    pub const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

    pub fn is_swap(selector: &[u8]) -> bool {
        if selector.len() < 4 { return false; }
        let sel = [selector[0], selector[1], selector[2], selector[3]];
        matches!(sel,
            SWAP_EXACT_TOKENS_FOR_TOKENS |
            SWAP_TOKENS_FOR_EXACT_TOKENS |
            SWAP_EXACT_ETH_FOR_TOKENS |
            SWAP_TOKENS_FOR_EXACT_ETH |
            SWAP_EXACT_TOKENS_FOR_ETH |
            SWAP_ETH_FOR_EXACT_TOKENS |
            EXACT_INPUT_SINGLE |
            EXACT_INPUT |
            EXACT_OUTPUT_SINGLE |
            EXACT_OUTPUT |
            MULTICALL
        )
    }
}

/// Decoded swap from mempool transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedSwap {
    pub tx_hash: String,
    pub dex: DexProtocol,
    pub token_in: String,
    pub token_out: String,
    pub amount_in: U256,
    pub amount_out_min: U256,
    pub path: Vec<String>,
    pub recipient: String,
    pub deadline: u64,
    pub gas_price: U256,
    pub is_exact_input: bool,
}

/// Known Avalanche C-Chain tokens
pub mod tokens {
    pub const WAVAX: &str = "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7";
    pub const USDC: &str = "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E";
    pub const USDT: &str = "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7";
    pub const WETH: &str = "0x49D5c2BdFfac6CE2BFdB6640F4F80f226bc10bAB";
    pub const WBTC: &str = "0x50b7545627a5162F82A992c33b87aDc75187B218";
    pub const DAI: &str = "0xd586E7F844cEa2F87f50152665BCbc2C279D8d70";
    pub const JOE: &str = "0x6e84a6216eA6dACC71eE8E6b0a5B7322EEbC0fDd";
    pub const PNG: &str = "0x60781C2586D68229fde47564546784ab3fACA982";
    pub const SAVAX: &str = "0x2b2C81e08f1Af8835a78Bb2A90AE924ACE0eA4bE";
    pub const AVAX_DECIMALS: u8 = 18;
    pub const USDC_DECIMALS: u8 = 6;
    pub const USDT_DECIMALS: u8 = 6;

    pub fn name(addr: &str) -> &'static str {
        let addr_lower = addr.to_lowercase();
        match addr_lower.as_str() {
            "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7" => "WAVAX",
            "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e" => "USDC",
            "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7" => "USDT",
            "0x49d5c2bdffac6ce2bfdb6640f4f80f226bc10bab" => "WETH.e",
            "0x50b7545627a5162f82a992c33b87adc75187b218" => "WBTC.e",
            "0xd586e7f844cea2f87f50152665bcbc2c279d8d70" => "DAI.e",
            "0x6e84a6216ea6dacc71ee8e6b0a5b7322eebc0fdd" => "JOE",
            "0x60781c2586d68229fde47564546784ab3faca982" => "PNG",
            "0x2b2c81e08f1af8835a78bb2a90ae924ace0ea4be" => "sAVAX",
            _ => "???",
        }
    }

    pub fn decimals(addr: &str) -> u8 {
        let addr_lower = addr.to_lowercase();
        match addr_lower.as_str() {
            "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e" => 6,  // USDC
            "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7" => 6,  // USDT
            _ => 18,
        }
    }
}

// ============================================================================
// MEV OPPORTUNITIES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MevOpportunity {
    /// Arbitrage between two DEXes
    Arbitrage {
        token_a: String,
        token_b: String,
        buy_dex: DexProtocol,
        sell_dex: DexProtocol,
        buy_price: f64,
        sell_price: f64,
        spread_bps: f64,
        estimated_profit: U256,
        gas_cost: U256,
        net_profit: U256,
    },
    /// Sandwich a large swap
    Sandwich {
        victim_tx: String,
        victim_swap: DecodedSwap,
        frontrun_amount: U256,
        backrun_amount: U256,
        estimated_profit: U256,
        gas_cost: U256,
        net_profit: U256,
        slippage_tolerance_bps: u64,
    },
    /// Liquidation opportunity
    Liquidation {
        protocol: String,
        borrower: String,
        debt_token: String,
        collateral_token: String,
        debt_amount: U256,
        collateral_amount: U256,
        bonus_bps: u64,
        estimated_profit: U256,
    },
    /// JIT (Just-In-Time) liquidity
    JitLiquidity {
        pool: String,
        dex: DexProtocol,
        victim_tx: String,
        tick_lower: i32,
        tick_upper: i32,
        liquidity_amount: U256,
        estimated_fees: U256,
    },
}

impl MevOpportunity {
    pub fn net_profit(&self) -> U256 {
        match self {
            MevOpportunity::Arbitrage { net_profit, .. } => *net_profit,
            MevOpportunity::Sandwich { net_profit, .. } => *net_profit,
            MevOpportunity::Liquidation { estimated_profit, .. } => *estimated_profit,
            MevOpportunity::JitLiquidity { estimated_fees, .. } => *estimated_fees,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            MevOpportunity::Arbitrage { .. } => "arbitrage",
            MevOpportunity::Sandwich { .. } => "sandwich",
            MevOpportunity::Liquidation { .. } => "liquidation",
            MevOpportunity::JitLiquidity { .. } => "jit_liquidity",
        }
    }
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum MevError {
    ParseError(String),
    RpcError(String),
    InsufficientProfit { expected: U256, minimum: U256 },
    SimulationFailed(String),
    GasTooHigh(U256),
    NonceError(String),
    Timeout,
    PoolNotFound(String),
    SlippageExceeded { expected: U256, actual: U256 },
}

impl std::fmt::Display for MevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MevError::ParseError(s) => write!(f, "Parse error: {}", s),
            MevError::RpcError(s) => write!(f, "RPC error: {}", s),
            MevError::InsufficientProfit { expected, minimum } =>
                write!(f, "Insufficient profit: {} < minimum {}", expected, minimum),
            MevError::SimulationFailed(s) => write!(f, "Simulation failed: {}", s),
            MevError::GasTooHigh(g) => write!(f, "Gas too high: {}", g),
            MevError::NonceError(s) => write!(f, "Nonce error: {}", s),
            MevError::Timeout => write!(f, "Operation timed out"),
            MevError::PoolNotFound(s) => write!(f, "Pool not found: {}", s),
            MevError::SlippageExceeded { expected, actual } =>
                write!(f, "Slippage exceeded: expected {} got {}", expected, actual),
        }
    }
}

impl std::error::Error for MevError {}

pub type Result<T> = std::result::Result<T, MevError>;

// ============================================================================
// CALLDATA DECODER
// ============================================================================

/// Decode swap parameters from transaction calldata
pub struct CallDataDecoder;

impl CallDataDecoder {
    /// Decode a UniswapV2-style swap from calldata
    pub fn decode_v2_swap(input: &[u8], tx_hash: &str, to_addr: &str, gas_price: U256, value: U256) -> Option<DecodedSwap> {
        if input.len() < 4 { return None; }

        let selector = [input[0], input[1], input[2], input[3]];
        if !selectors::is_swap(&selector) { return None; }

        let dex = DexProtocol::from_address(to_addr);

        // swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)
        // swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline) — value = amountIn
        match selector {
            selectors::SWAP_EXACT_TOKENS_FOR_TOKENS => {
                if input.len() < 4 + 5 * 32 { return None; }
                let amount_in = Self::decode_u256(&input[4..36])?;
                let amount_out_min = Self::decode_u256(&input[36..68])?;
                let path = Self::decode_address_array(&input[4..], 2)?;
                let recipient = Self::decode_address(&input[4 + 3 * 32..4 + 4 * 32])?;
                let deadline = Self::decode_u64(&input[4 + 4 * 32..4 + 5 * 32]);

                Some(DecodedSwap {
                    tx_hash: tx_hash.to_string(),
                    dex,
                    token_in: path.first()?.clone(),
                    token_out: path.last()?.clone(),
                    amount_in,
                    amount_out_min,
                    path,
                    recipient,
                    deadline,
                    gas_price,
                    is_exact_input: true,
                })
            }
            selectors::SWAP_EXACT_ETH_FOR_TOKENS => {
                if input.len() < 4 + 4 * 32 { return None; }
                let amount_out_min = Self::decode_u256(&input[4..36])?;
                let path = Self::decode_address_array(&input[4..], 1)?;
                let recipient = Self::decode_address(&input[4 + 2 * 32..4 + 3 * 32])?;
                let deadline = Self::decode_u64(&input[4 + 3 * 32..4 + 4 * 32]);

                Some(DecodedSwap {
                    tx_hash: tx_hash.to_string(),
                    dex,
                    token_in: tokens::WAVAX.to_string(),
                    token_out: path.last()?.clone(),
                    amount_in: value,
                    amount_out_min,
                    path,
                    recipient,
                    deadline,
                    gas_price,
                    is_exact_input: true,
                })
            }
            _ => {
                // Generic swap detection — we know it's a swap but can't fully decode
                Some(DecodedSwap {
                    tx_hash: tx_hash.to_string(),
                    dex,
                    token_in: "unknown".to_string(),
                    token_out: "unknown".to_string(),
                    amount_in: value,
                    amount_out_min: U256::ZERO,
                    path: vec![],
                    recipient: String::new(),
                    deadline: 0,
                    gas_price,
                    is_exact_input: true,
                })
            }
        }
    }

    fn decode_u256(data: &[u8]) -> Option<U256> {
        if data.len() < 32 { return None; }
        let mut high_bytes = [0u8; 16];
        let mut low_bytes = [0u8; 16];
        high_bytes.copy_from_slice(&data[0..16]);
        low_bytes.copy_from_slice(&data[16..32]);
        Some(U256 {
            high: u128::from_be_bytes(high_bytes),
            low: u128::from_be_bytes(low_bytes),
        })
    }

    fn decode_u64(data: &[u8]) -> u64 {
        if data.len() < 32 { return 0; }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[24..32]);
        u64::from_be_bytes(bytes)
    }

    fn decode_address(data: &[u8]) -> Option<String> {
        if data.len() < 32 { return None; }
        Some(format!("0x{}", faster_hex::hex_string(&data[12..32])))
    }

    fn decode_address_array(data: &[u8], offset_slot: usize) -> Option<Vec<String>> {
        if data.len() < (offset_slot + 1) * 32 { return None; }
        let offset = Self::decode_u64(&data[offset_slot * 32..(offset_slot + 1) * 32]) as usize;
        if data.len() < offset + 32 { return None; }
        let length = Self::decode_u64(&data[offset..offset + 32]) as usize;
        if length == 0 || length > 10 { return None; }

        let mut addrs = Vec::with_capacity(length);
        for i in 0..length {
            let start = offset + 32 + i * 32;
            if start + 32 > data.len() { break; }
            if let Some(addr) = Self::decode_address(&data[start..start + 32]) {
                addrs.push(addr);
            }
        }
        if addrs.is_empty() { None } else { Some(addrs) }
    }
}

// ============================================================================
// MEMPOOL MONITOR
// ============================================================================

/// Configuration for mempool monitoring
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Minimum swap value in AVAX to consider (filter noise)
    pub min_swap_avax: f64,
    /// Minimum profit in AVAX to execute
    pub min_profit_avax: f64,
    /// Maximum gas price multiplier for frontrun tx
    pub max_gas_multiplier: f64,
    /// Polling interval for pending txs
    pub poll_interval: Duration,
    /// Maximum pending txs to track
    pub max_pending: usize,
    /// Sandwich: minimum slippage tolerance to target (bps)
    pub min_slippage_bps: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            min_swap_avax: 10.0,
            min_profit_avax: 0.1,
            max_gas_multiplier: 2.0,
            poll_interval: Duration::from_millis(100),
            max_pending: 10_000,
            min_slippage_bps: 50, // 0.5% minimum slippage
        }
    }
}

/// Mempool monitor — watches pending transactions for MEV opportunities
pub struct MempoolMonitor {
    config: MempoolConfig,
    /// RPC endpoint for live mempool queries (used by future WebSocket subscription)
    #[allow(dead_code)]
    rpc_endpoint: String,
    /// Pending decoded swaps awaiting evaluation
    #[allow(dead_code)]
    pending_swaps: Arc<RwLock<Vec<DecodedSwap>>>,
    opportunities: Arc<Mutex<Vec<MevOpportunity>>>,
    stats: Arc<RwLock<MonitorStats>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MonitorStats {
    pub txs_scanned: u64,
    pub swaps_detected: u64,
    pub opportunities_found: u64,
    pub opportunities_executed: u64,
    pub total_profit: f64,
    pub uptime_seconds: u64,
    pub last_block: u64,
    pub scan_latency_ns: u64,
}

impl MempoolMonitor {
    pub fn new(rpc_endpoint: &str, config: MempoolConfig) -> Self {
        Self {
            config,
            rpc_endpoint: rpc_endpoint.to_string(),
            pending_swaps: Arc::new(RwLock::new(Vec::new())),
            opportunities: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(RwLock::new(MonitorStats::default())),
        }
    }

    /// Scan a pending transaction for swap activity
    pub async fn scan_tx(&self, tx: &PendingTx) -> Option<DecodedSwap> {
        let start = Instant::now();

        // Quick filter: must have calldata and a target
        if tx.input.len() < 4 || tx.to.is_none() {
            return None;
        }

        let to = tx.to.as_ref().unwrap();

        // Check if target is a known DEX router
        let dex = DexProtocol::from_address(to);
        if dex == DexProtocol::Unknown {
            return None;
        }

        // Check if calldata is a swap
        if !selectors::is_swap(&tx.input) {
            return None;
        }

        // Decode the swap
        let swap = CallDataDecoder::decode_v2_swap(
            &tx.input,
            &tx.hash,
            to,
            tx.gas_price,
            tx.value,
        );

        // Update stats
        let scan_ns = start.elapsed().as_nanos() as u64;
        let mut stats = self.stats.write().await;
        stats.txs_scanned += 1;
        stats.scan_latency_ns = scan_ns;
        if swap.is_some() {
            stats.swaps_detected += 1;
        }

        swap
    }

    /// Evaluate a swap for sandwich opportunity
    pub fn evaluate_sandwich(&self, swap: &DecodedSwap) -> Option<MevOpportunity> {
        // Skip tiny swaps
        let amount_in_avax = swap.amount_in.to_avax();
        if amount_in_avax < self.config.min_swap_avax {
            return None;
        }

        // Calculate slippage tolerance from amount_out_min
        if swap.amount_out_min.is_zero() || swap.amount_in.is_zero() {
            return None;
        }

        // Estimate profit: ~0.3% of swap value for typical sandwich
        // Actual profit depends on pool liquidity depth
        let estimated_profit_avax = amount_in_avax * 0.003;
        let gas_cost_avax = 0.01; // ~2 txs at ~350k gas each

        let net_profit_avax = estimated_profit_avax - gas_cost_avax;
        if net_profit_avax < self.config.min_profit_avax {
            return None;
        }

        // Frontrun amount: typically 2-5x the victim's swap
        let frontrun_multiplier = 3.0;
        let frontrun_amount = U256::from_u128((amount_in_avax * frontrun_multiplier * 1e18) as u128);

        Some(MevOpportunity::Sandwich {
            victim_tx: swap.tx_hash.clone(),
            victim_swap: swap.clone(),
            frontrun_amount,
            backrun_amount: frontrun_amount, // simplified: same as frontrun
            estimated_profit: U256::from_u128((estimated_profit_avax * 1e18) as u128),
            gas_cost: U256::from_u128((gas_cost_avax * 1e18) as u128),
            net_profit: U256::from_u128((net_profit_avax * 1e18) as u128),
            slippage_tolerance_bps: 50,
        })
    }

    /// Evaluate cross-DEX arbitrage
    pub fn evaluate_arbitrage(
        &self,
        token_a: &str,
        token_b: &str,
        price_a: f64, // price on DEX A (token_b per token_a)
        price_b: f64, // price on DEX B
        dex_a: DexProtocol,
        dex_b: DexProtocol,
    ) -> Option<MevOpportunity> {
        if price_a <= 0.0 || price_b <= 0.0 { return None; }

        let (buy_dex, sell_dex, buy_price, sell_price) = if price_a < price_b {
            (dex_a, dex_b, price_a, price_b)
        } else {
            (dex_b, dex_a, price_b, price_a)
        };

        let spread_bps = ((sell_price - buy_price) / buy_price) * 10_000.0;

        // Need at least 30bps to cover gas + slippage
        if spread_bps < 30.0 { return None; }

        // Estimate: trade 10 AVAX worth
        let trade_size_avax = 10.0;
        let estimated_profit_avax = trade_size_avax * (spread_bps / 10_000.0);
        let gas_cost_avax = 0.005; // single arb tx

        let net_profit_avax = estimated_profit_avax - gas_cost_avax;
        if net_profit_avax < self.config.min_profit_avax { return None; }

        Some(MevOpportunity::Arbitrage {
            token_a: token_a.to_string(),
            token_b: token_b.to_string(),
            buy_dex,
            sell_dex,
            buy_price,
            sell_price,
            spread_bps,
            estimated_profit: U256::from_u128((estimated_profit_avax * 1e18) as u128),
            gas_cost: U256::from_u128((gas_cost_avax * 1e18) as u128),
            net_profit: U256::from_u128((net_profit_avax * 1e18) as u128),
        })
    }

    /// Get current stats
    pub async fn stats(&self) -> MonitorStats {
        self.stats.read().await.clone()
    }

    /// Get pending opportunities sorted by profit
    pub async fn opportunities(&self) -> Vec<MevOpportunity> {
        let mut opps = self.opportunities.lock().await.clone();
        opps.sort_by(|a, b| b.net_profit().cmp(&a.net_profit()));
        opps
    }
}

// ============================================================================
// BUNDLE BUILDER
// ============================================================================

/// A bundle of transactions to be submitted atomically
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevBundle {
    pub transactions: Vec<BundleTx>,
    pub block_number: u64,
    pub min_timestamp: Option<u64>,
    pub max_timestamp: Option<u64>,
    pub reverting_tx_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleTx {
    pub signed_tx: String,    // raw signed transaction hex
    pub can_revert: bool,
    pub gas_price: U256,
    pub description: String,
}

impl MevBundle {
    pub fn new(block_number: u64) -> Self {
        Self {
            transactions: vec![],
            block_number,
            min_timestamp: None,
            max_timestamp: None,
            reverting_tx_hashes: vec![],
        }
    }

    /// Add frontrun transaction
    pub fn add_frontrun(&mut self, signed_tx: String, gas_price: U256) {
        self.transactions.push(BundleTx {
            signed_tx,
            can_revert: false, // frontrun must succeed
            gas_price,
            description: "frontrun".to_string(),
        });
    }

    /// Add victim transaction (the target swap)
    pub fn add_victim(&mut self, tx_hash: String) {
        self.reverting_tx_hashes.push(tx_hash);
    }

    /// Add backrun transaction
    pub fn add_backrun(&mut self, signed_tx: String, gas_price: U256) {
        self.transactions.push(BundleTx {
            signed_tx,
            can_revert: false, // backrun must succeed
            gas_price,
            description: "backrun".to_string(),
        });
    }

    pub fn total_gas_cost(&self) -> U256 {
        self.transactions.iter()
            .fold(U256::ZERO, |acc, tx| acc.saturating_add(tx.gas_price))
    }

    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
}

// ============================================================================
// POOL STATE TRACKER (AMM math)
// ============================================================================

/// Track UniswapV2-style pool reserves for price calculation
#[derive(Debug, Clone)]
pub struct PoolState {
    pub address: String,
    pub token0: String,
    pub token1: String,
    pub reserve0: U256,
    pub reserve1: U256,
    pub fee_bps: u64, // typically 30 for 0.3%
    pub last_updated: Instant,
}

impl PoolState {
    /// Calculate output amount for a given input (constant product AMM)
    /// x * y = k formula with fee
    pub fn get_amount_out(&self, amount_in: U256, token_in: &str) -> U256 {
        let (reserve_in, reserve_out) = if token_in.to_lowercase() == self.token0.to_lowercase() {
            (self.reserve0, self.reserve1)
        } else {
            (self.reserve1, self.reserve0)
        };

        if reserve_in.is_zero() || reserve_out.is_zero() || amount_in.is_zero() {
            return U256::ZERO;
        }

        // amount_out = (amount_in * fee_factor * reserve_out) / (reserve_in * 10000 + amount_in * fee_factor)
        // For simplicity, use f64 (good enough for estimation, production would use fixed-point)
        let amt_in = amount_in.to_f64();
        let r_in = reserve_in.to_f64();
        let r_out = reserve_out.to_f64();
        let fee_factor = (10_000 - self.fee_bps) as f64;

        let numerator = amt_in * fee_factor * r_out;
        let denominator = r_in * 10_000.0 + amt_in * fee_factor;

        if denominator == 0.0 { return U256::ZERO; }

        U256::from_u128((numerator / denominator) as u128)
    }

    /// Calculate price impact of a swap (in basis points)
    pub fn price_impact_bps(&self, amount_in: U256, token_in: &str) -> f64 {
        let (reserve_in, reserve_out) = if token_in.to_lowercase() == self.token0.to_lowercase() {
            (self.reserve0, self.reserve1)
        } else {
            (self.reserve1, self.reserve0)
        };

        if reserve_in.is_zero() || reserve_out.is_zero() {
            return 10_000.0; // 100% impact
        }

        let spot_price = reserve_out.to_f64() / reserve_in.to_f64();
        let amount_out = self.get_amount_out(amount_in, token_in);
        let execution_price = amount_out.to_f64() / amount_in.to_f64();

        ((spot_price - execution_price) / spot_price) * 10_000.0
    }

    /// Simulate sandwich: calculate profit from frontrun + backrun around victim
    pub fn simulate_sandwich(
        &self,
        victim_amount: U256,
        frontrun_amount: U256,
        token_in: &str,
    ) -> SandwichResult {
        // Step 1: Frontrun — we buy before victim
        let frontrun_out = self.get_amount_out(frontrun_amount, token_in);

        // Step 2: Update reserves after frontrun
        let mut pool_after_frontrun = self.clone();
        let token_out = if token_in.to_lowercase() == self.token0.to_lowercase() {
            pool_after_frontrun.reserve0 = pool_after_frontrun.reserve0.saturating_add(frontrun_amount);
            pool_after_frontrun.reserve1 = pool_after_frontrun.reserve1.saturating_sub(frontrun_out);
            &self.token1
        } else {
            pool_after_frontrun.reserve1 = pool_after_frontrun.reserve1.saturating_add(frontrun_amount);
            pool_after_frontrun.reserve0 = pool_after_frontrun.reserve0.saturating_sub(frontrun_out);
            &self.token0
        };

        // Step 3: Victim swap executes at worse price
        let victim_out = pool_after_frontrun.get_amount_out(victim_amount, token_in);

        // Step 4: Update reserves after victim
        let mut pool_after_victim = pool_after_frontrun.clone();
        if token_in.to_lowercase() == self.token0.to_lowercase() {
            pool_after_victim.reserve0 = pool_after_victim.reserve0.saturating_add(victim_amount);
            pool_after_victim.reserve1 = pool_after_victim.reserve1.saturating_sub(victim_out);
        } else {
            pool_after_victim.reserve1 = pool_after_victim.reserve1.saturating_add(victim_amount);
            pool_after_victim.reserve0 = pool_after_victim.reserve0.saturating_sub(victim_out);
        }

        // Step 5: Backrun — we sell what we bought
        let backrun_out = pool_after_victim.get_amount_out(frontrun_out, token_out);

        // Profit = backrun_out - frontrun_amount (we started with token_in, end with token_in)
        let profit = backrun_out.saturating_sub(frontrun_amount);
        let victim_loss = {
            let normal_out = self.get_amount_out(victim_amount, token_in);
            normal_out.saturating_sub(victim_out)
        };

        SandwichResult {
            frontrun_in: frontrun_amount,
            frontrun_out,
            victim_in: victim_amount,
            victim_out,
            backrun_in: frontrun_out,
            backrun_out,
            profit,
            victim_loss,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandwichResult {
    pub frontrun_in: U256,
    pub frontrun_out: U256,
    pub victim_in: U256,
    pub victim_out: U256,
    pub backrun_in: U256,
    pub backrun_out: U256,
    pub profit: U256,
    pub victim_loss: U256,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u256_basics() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(50);
        assert_eq!(a.saturating_sub(b), U256::from_u64(50));
        assert_eq!(a.saturating_add(b), U256::from_u64(150));
    }

    #[test]
    fn test_u256_from_hex() {
        let v = U256::from_hex("0x64").unwrap();
        assert_eq!(v.low, 100);
        assert_eq!(v.high, 0);

        let v = U256::from_hex("0xde0b6b3a7640000").unwrap(); // 1e18
        assert_eq!(v.to_avax(), 1.0);
    }

    #[test]
    fn test_u256_overflow_safe() {
        let max = U256 { high: u128::MAX, low: u128::MAX };
        let one = U256::from_u64(1);
        let result = max.saturating_add(one);
        assert_eq!(result.high, u128::MAX); // saturated

        let result = U256::ZERO.saturating_sub(one);
        assert_eq!(result, U256::ZERO); // floor at zero
    }

    #[test]
    fn test_dex_protocol_lookup() {
        assert_eq!(
            DexProtocol::from_address("0x60aE616a2155Ee3d9A68541Ba4544862310933d4"),
            DexProtocol::TraderJoe
        );
        assert_eq!(
            DexProtocol::from_address("0xE54Ca86531e17Ef3616d22Ca28b0D458b6C89106"),
            DexProtocol::Pangolin
        );
        assert_eq!(
            DexProtocol::from_address("0x1234567890abcdef1234567890abcdef12345678"),
            DexProtocol::Unknown
        );
    }

    #[test]
    fn test_selector_detection() {
        assert!(selectors::is_swap(&selectors::SWAP_EXACT_TOKENS_FOR_TOKENS));
        assert!(selectors::is_swap(&selectors::SWAP_EXACT_ETH_FOR_TOKENS));
        assert!(selectors::is_swap(&selectors::EXACT_INPUT_SINGLE));
        assert!(!selectors::is_swap(&selectors::TRANSFER));
        assert!(!selectors::is_swap(&selectors::APPROVE));
        assert!(!selectors::is_swap(&[0x00, 0x00]));
    }

    #[test]
    fn test_token_lookup() {
        assert_eq!(tokens::name(tokens::WAVAX), "WAVAX");
        assert_eq!(tokens::name(tokens::USDC), "USDC");
        assert_eq!(tokens::decimals(tokens::USDC), 6);
        assert_eq!(tokens::decimals(tokens::WAVAX), 18);
    }

    #[test]
    fn test_pool_amm_math() {
        let pool = PoolState {
            address: "0xpool".to_string(),
            token0: tokens::WAVAX.to_string(),
            token1: tokens::USDC.to_string(),
            reserve0: U256::from_u128(1_000_000 * 10u128.pow(18)),   // 1M AVAX
            reserve1: U256::from_u128(20_000_000 * 10u128.pow(6)),   // 20M USDC
            fee_bps: 30,
            last_updated: Instant::now(),
        };

        // Swap 100 AVAX → USDC
        let amount_in = U256::from_u128(100 * 10u128.pow(18));
        let amount_out = pool.get_amount_out(amount_in, tokens::WAVAX);

        // Should get ~1994 USDC (100 AVAX * $20 - fees - price impact)
        let usdc_out = amount_out.to_token(6);
        assert!(usdc_out > 1990.0 && usdc_out < 2000.0,
            "Expected ~1994 USDC, got {}", usdc_out);
    }

    #[test]
    fn test_pool_price_impact() {
        let pool = PoolState {
            address: "0xpool".to_string(),
            token0: tokens::WAVAX.to_string(),
            token1: tokens::USDC.to_string(),
            reserve0: U256::from_u128(100_000 * 10u128.pow(18)),   // 100K AVAX
            reserve1: U256::from_u128(2_000_000 * 10u128.pow(6)),  // 2M USDC
            fee_bps: 30,
            last_updated: Instant::now(),
        };

        // Small swap: low impact
        let small = U256::from_u128(10 * 10u128.pow(18)); // 10 AVAX
        let impact = pool.price_impact_bps(small, tokens::WAVAX);
        assert!(impact < 50.0, "Small swap impact too high: {} bps", impact);

        // Large swap: high impact
        let large = U256::from_u128(10_000 * 10u128.pow(18)); // 10K AVAX (10% of pool)
        let impact = pool.price_impact_bps(large, tokens::WAVAX);
        assert!(impact > 500.0, "Large swap impact too low: {} bps", impact);
    }

    #[test]
    fn test_sandwich_simulation() {
        let pool = PoolState {
            address: "0xpool".to_string(),
            token0: tokens::WAVAX.to_string(),
            token1: tokens::USDC.to_string(),
            reserve0: U256::from_u128(100_000 * 10u128.pow(18)),
            reserve1: U256::from_u128(2_000_000 * 10u128.pow(6)),
            fee_bps: 30,
            last_updated: Instant::now(),
        };

        let victim_amount = U256::from_u128(1_000 * 10u128.pow(18)); // 1000 AVAX victim
        let frontrun_amount = U256::from_u128(3_000 * 10u128.pow(18)); // 3000 AVAX frontrun

        let result = pool.simulate_sandwich(victim_amount, frontrun_amount, tokens::WAVAX);

        // Sandwich should be profitable
        assert!(!result.profit.is_zero(), "Sandwich should be profitable");
        let profit_avax = result.profit.to_avax();
        assert!(profit_avax > 0.0, "Profit should be positive: {} AVAX", profit_avax);

        // Victim should lose some value
        assert!(!result.victim_loss.is_zero(), "Victim should have loss");
    }

    #[test]
    fn test_arbitrage_evaluation() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig::default());

        // 200bps spread between TraderJoe and Pangolin
        let opp = monitor.evaluate_arbitrage(
            tokens::WAVAX,
            tokens::USDC,
            20.00,  // TJ price
            20.40,  // Pangolin price (2% higher)
            DexProtocol::TraderJoe,
            DexProtocol::Pangolin,
        );

        assert!(opp.is_some(), "Should find arbitrage opportunity");
        let opp = opp.unwrap();
        match opp {
            MevOpportunity::Arbitrage { spread_bps, buy_dex, sell_dex, .. } => {
                assert!(spread_bps > 190.0 && spread_bps < 210.0);
                assert_eq!(buy_dex, DexProtocol::TraderJoe);
                assert_eq!(sell_dex, DexProtocol::Pangolin);
            }
            _ => panic!("Expected Arbitrage"),
        }
    }

    #[test]
    fn test_no_arbitrage_small_spread() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig::default());

        // Only 10bps spread — below gas cost threshold
        let opp = monitor.evaluate_arbitrage(
            tokens::WAVAX, tokens::USDC,
            20.00, 20.02,
            DexProtocol::TraderJoe, DexProtocol::Pangolin,
        );

        assert!(opp.is_none(), "Should not find opportunity with 10bps spread");
    }

    #[test]
    fn test_bundle_builder() {
        let mut bundle = MevBundle::new(79_000_000);
        bundle.add_frontrun("0xsigned_frontrun".into(), U256::from_u64(50_000_000_000));
        bundle.add_victim("0xvictim_hash".into());
        bundle.add_backrun("0xsigned_backrun".into(), U256::from_u64(45_000_000_000));

        assert_eq!(bundle.tx_count(), 2); // frontrun + backrun
        assert_eq!(bundle.reverting_tx_hashes.len(), 1); // victim
    }

    // ====================================================================
    // TDD AUDIT: Additional coverage tests
    // ====================================================================

    // --- U256 edge cases ---

    #[test]
    fn test_u256_zero() {
        assert!(U256::ZERO.is_zero());
        assert!(!U256::from_u64(1).is_zero());
    }

    #[test]
    fn test_u256_display() {
        assert_eq!(format!("{}", U256::from_u64(255)), "0xff");
        assert_eq!(format!("{}", U256::ZERO), "0x0");
        // Large value with high bits
        let big = U256 { high: 1, low: 0 };
        let s = format!("{}", big);
        assert!(s.starts_with("0x1"));
    }

    #[test]
    fn test_u256_from_hex_edge_cases() {
        assert_eq!(U256::from_hex("0x").unwrap(), U256::ZERO);
        assert_eq!(U256::from_hex("").unwrap(), U256::ZERO);
        assert_eq!(U256::from_hex("0x0").unwrap(), U256::ZERO);
        assert_eq!(U256::from_hex("0xff").unwrap(), U256::from_u64(255));

        // Max u128
        let max = U256::from_hex("0xffffffffffffffffffffffffffffffff").unwrap();
        assert_eq!(max.low, u128::MAX);
        assert_eq!(max.high, 0);

        // Full 256-bit
        let full = U256::from_hex("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert!(full.is_err()); // too long (65 hex chars > 64)
    }

    #[test]
    fn test_u256_to_avax() {
        let one_avax = U256::from_u128(1_000_000_000_000_000_000); // 1e18
        assert!((one_avax.to_avax() - 1.0).abs() < 0.001);

        let half_avax = U256::from_u128(500_000_000_000_000_000);
        assert!((half_avax.to_avax() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_u256_to_token_decimals() {
        // USDC: 6 decimals
        let one_usdc = U256::from_u128(1_000_000);
        assert!((one_usdc.to_token(6) - 1.0).abs() < 0.001);

        // WAVAX: 18 decimals
        let one_avax = U256::from_u128(1_000_000_000_000_000_000);
        assert!((one_avax.to_token(18) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_u256_saturating_sub_underflow() {
        let small = U256::from_u64(5);
        let big = U256::from_u64(100);
        assert_eq!(small.saturating_sub(big), U256::ZERO);
    }

    #[test]
    fn test_u256_ordering() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, U256::from_u64(100));

        // High bits comparison
        let c = U256 { high: 1, low: 0 };
        let d = U256 { high: 0, low: u128::MAX };
        assert!(c > d);
    }

    // --- DEX protocol coverage ---

    #[test]
    fn test_dex_router_addresses() {
        // Every DEX should have a non-zero router
        let dexes = [
            DexProtocol::TraderJoe, DexProtocol::TraderJoeV2,
            DexProtocol::Pangolin, DexProtocol::SushiSwap,
            DexProtocol::Platypus, DexProtocol::GMX,
            DexProtocol::WooFi, DexProtocol::Curve,
            DexProtocol::Pharaoh,
        ];
        for dex in &dexes {
            let addr = dex.router_address();
            assert!(addr.starts_with("0x"), "Router should start with 0x: {:?}", dex);
            assert_ne!(addr, "0x0000000000000000000000000000000000000000",
                "Router should not be zero: {:?}", dex);
        }
    }

    #[test]
    fn test_dex_roundtrip() {
        // from_address(router_address()) should return the same DEX
        let dexes = [
            DexProtocol::TraderJoe, DexProtocol::Pangolin,
            DexProtocol::Platypus, DexProtocol::GMX,
            DexProtocol::WooFi, DexProtocol::Curve,
            DexProtocol::Pharaoh,
        ];
        for dex in &dexes {
            assert_eq!(DexProtocol::from_address(dex.router_address()), *dex,
                "Roundtrip failed for {:?}", dex);
        }
    }

    #[test]
    fn test_dex_case_insensitive() {
        let upper = DexProtocol::from_address("0x60AE616A2155EE3D9A68541BA4544862310933D4");
        let lower = DexProtocol::from_address("0x60ae616a2155ee3d9a68541ba4544862310933d4");
        assert_eq!(upper, lower);
        assert_eq!(upper, DexProtocol::TraderJoe);
    }

    // --- Calldata decoder ---

    #[test]
    fn test_decode_v2_swap_too_short() {
        // Empty calldata
        assert!(CallDataDecoder::decode_v2_swap(&[], "0x", "0x", U256::ZERO, U256::ZERO).is_none());

        // Only selector, no params
        assert!(CallDataDecoder::decode_v2_swap(
            &selectors::SWAP_EXACT_TOKENS_FOR_TOKENS, "0x", "0x", U256::ZERO, U256::ZERO
        ).is_none());
    }

    #[test]
    fn test_decode_non_swap_calldata() {
        // ERC-20 transfer (not a swap)
        let mut calldata = vec![0u8; 68];
        calldata[..4].copy_from_slice(&selectors::TRANSFER);
        assert!(CallDataDecoder::decode_v2_swap(
            &calldata, "0xtx", tokens::WAVAX, U256::ZERO, U256::ZERO
        ).is_none());
    }

    #[test]
    fn test_decode_unknown_dex() {
        let mut calldata = vec![0u8; 200];
        calldata[..4].copy_from_slice(&selectors::SWAP_EXACT_TOKENS_FOR_TOKENS);
        // Unknown router address — decode attempts but address array is zeroed
        let _result = CallDataDecoder::decode_v2_swap(
            &calldata, "0xtx", "0x1111111111111111111111111111111111111111", U256::from_u64(1000), U256::ZERO
        );
        // Returns None (zeroed address array) or Some with Unknown dex — either is valid
    }

    // --- Selector coverage ---

    #[test]
    fn test_all_swap_selectors() {
        assert!(selectors::is_swap(&selectors::SWAP_EXACT_TOKENS_FOR_TOKENS));
        assert!(selectors::is_swap(&selectors::SWAP_TOKENS_FOR_EXACT_TOKENS));
        assert!(selectors::is_swap(&selectors::SWAP_EXACT_ETH_FOR_TOKENS));
        assert!(selectors::is_swap(&selectors::SWAP_TOKENS_FOR_EXACT_ETH));
        assert!(selectors::is_swap(&selectors::SWAP_EXACT_TOKENS_FOR_ETH));
        assert!(selectors::is_swap(&selectors::SWAP_ETH_FOR_EXACT_TOKENS));
        assert!(selectors::is_swap(&selectors::MULTICALL));
        assert!(selectors::is_swap(&selectors::EXACT_INPUT_SINGLE));
        assert!(selectors::is_swap(&selectors::EXACT_INPUT));
        assert!(selectors::is_swap(&selectors::EXACT_OUTPUT_SINGLE));
        assert!(selectors::is_swap(&selectors::EXACT_OUTPUT));
    }

    #[test]
    fn test_non_swap_selectors() {
        assert!(!selectors::is_swap(&selectors::TRANSFER));
        assert!(!selectors::is_swap(&selectors::APPROVE));
        assert!(!selectors::is_swap(&[0x00, 0x00, 0x00, 0x00]));
        assert!(!selectors::is_swap(&[0xFF, 0xFF, 0xFF, 0xFF]));
    }

    // --- Token registry ---

    #[test]
    fn test_all_token_names() {
        assert_eq!(tokens::name(tokens::WAVAX), "WAVAX");
        assert_eq!(tokens::name(tokens::USDC), "USDC");
        assert_eq!(tokens::name(tokens::USDT), "USDT");
        assert_eq!(tokens::name(tokens::WETH), "WETH.e");
        assert_eq!(tokens::name(tokens::WBTC), "WBTC.e");
        assert_eq!(tokens::name(tokens::DAI), "DAI.e");
        assert_eq!(tokens::name(tokens::JOE), "JOE");
        assert_eq!(tokens::name(tokens::PNG), "PNG");
        assert_eq!(tokens::name(tokens::SAVAX), "sAVAX");
        assert_eq!(tokens::name("0xunknown"), "???");
    }

    #[test]
    fn test_token_decimals_coverage() {
        assert_eq!(tokens::decimals(tokens::USDC), 6);
        assert_eq!(tokens::decimals(tokens::USDT), 6);
        assert_eq!(tokens::decimals(tokens::WAVAX), 18);
        assert_eq!(tokens::decimals(tokens::WETH), 18);
        assert_eq!(tokens::decimals("0xunknown"), 18); // default
    }

    // --- MevOpportunity ---

    #[test]
    fn test_opportunity_kind() {
        let arb = MevOpportunity::Arbitrage {
            token_a: "a".into(), token_b: "b".into(),
            buy_dex: DexProtocol::TraderJoe, sell_dex: DexProtocol::Pangolin,
            buy_price: 1.0, sell_price: 1.1, spread_bps: 100.0,
            estimated_profit: U256::from_u64(100),
            gas_cost: U256::from_u64(10),
            net_profit: U256::from_u64(90),
        };
        assert_eq!(arb.kind(), "arbitrage");
        assert_eq!(arb.net_profit(), U256::from_u64(90));
    }

    #[test]
    fn test_opportunity_sandwich_kind() {
        let sw = MevOpportunity::Sandwich {
            victim_tx: "0x".into(),
            victim_swap: DecodedSwap {
                tx_hash: "0x".into(), dex: DexProtocol::TraderJoe,
                token_in: "a".into(), token_out: "b".into(),
                amount_in: U256::ZERO, amount_out_min: U256::ZERO,
                path: vec![], recipient: "".into(), deadline: 0,
                gas_price: U256::ZERO, is_exact_input: true,
            },
            frontrun_amount: U256::ZERO, backrun_amount: U256::ZERO,
            estimated_profit: U256::from_u64(50),
            gas_cost: U256::from_u64(5),
            net_profit: U256::from_u64(45),
            slippage_tolerance_bps: 50,
        };
        assert_eq!(sw.kind(), "sandwich");
    }

    #[test]
    fn test_opportunity_liquidation_kind() {
        let liq = MevOpportunity::Liquidation {
            protocol: "aave".into(), borrower: "0x".into(),
            debt_token: "a".into(), collateral_token: "b".into(),
            debt_amount: U256::ZERO, collateral_amount: U256::ZERO,
            bonus_bps: 500, estimated_profit: U256::from_u64(200),
        };
        assert_eq!(liq.kind(), "liquidation");
        assert_eq!(liq.net_profit(), U256::from_u64(200));
    }

    // --- Pool math edge cases ---

    #[test]
    fn test_pool_zero_reserves() {
        let pool = PoolState {
            address: "0x".into(),
            token0: "A".into(), token1: "B".into(),
            reserve0: U256::ZERO,
            reserve1: U256::from_u128(1_000_000),
            fee_bps: 30,
            last_updated: Instant::now(),
        };
        assert_eq!(pool.get_amount_out(U256::from_u64(100), "A"), U256::ZERO);
    }

    #[test]
    fn test_pool_zero_input() {
        let pool = PoolState {
            address: "0x".into(),
            token0: "A".into(), token1: "B".into(),
            reserve0: U256::from_u128(1_000_000),
            reserve1: U256::from_u128(1_000_000),
            fee_bps: 30,
            last_updated: Instant::now(),
        };
        assert_eq!(pool.get_amount_out(U256::ZERO, "A"), U256::ZERO);
    }

    #[test]
    fn test_pool_symmetric_reserves() {
        let pool = PoolState {
            address: "0x".into(),
            token0: "A".into(), token1: "B".into(),
            reserve0: U256::from_u128(1_000_000),
            reserve1: U256::from_u128(1_000_000),
            fee_bps: 30,
            last_updated: Instant::now(),
        };
        // With equal reserves, output should be less than input (due to fee + impact)
        let out = pool.get_amount_out(U256::from_u128(1000), "A");
        assert!(out.low < 1000, "Output should be less than input due to fees");
        assert!(out.low > 900, "Output shouldn't be too much less: {}", out.low);
    }

    #[test]
    fn test_pool_fee_impact() {
        // 0% fee pool
        let pool_no_fee = PoolState {
            address: "0x".into(),
            token0: "A".into(), token1: "B".into(),
            reserve0: U256::from_u128(1_000_000_000),
            reserve1: U256::from_u128(1_000_000_000),
            fee_bps: 0,
            last_updated: Instant::now(),
        };
        // 1% fee pool
        let pool_1pct = PoolState {
            fee_bps: 100,
            ..pool_no_fee.clone()
        };

        let amount = U256::from_u128(1000);
        let out_no_fee = pool_no_fee.get_amount_out(amount, "A");
        let out_1pct = pool_1pct.get_amount_out(amount, "A");

        assert!(out_no_fee.low > out_1pct.low,
            "No-fee output ({}) should exceed 1% fee output ({})",
            out_no_fee.low, out_1pct.low);
    }

    #[test]
    fn test_pool_direction_matters() {
        let pool = PoolState {
            address: "0x".into(),
            token0: "A".into(), token1: "B".into(),
            reserve0: U256::from_u128(1_000_000),   // less of A
            reserve1: U256::from_u128(10_000_000),   // more of B
            fee_bps: 30,
            last_updated: Instant::now(),
        };

        let amount = U256::from_u128(1000);
        let out_a_to_b = pool.get_amount_out(amount, "A");
        let out_b_to_a = pool.get_amount_out(amount, "B");

        // A→B should give more output (B is cheaper)
        assert!(out_a_to_b.low > out_b_to_a.low,
            "A→B ({}) should give more than B→A ({})", out_a_to_b.low, out_b_to_a.low);
    }

    #[test]
    fn test_price_impact_scales_with_size() {
        let pool = PoolState {
            address: "0x".into(),
            token0: tokens::WAVAX.into(), token1: tokens::USDC.into(),
            reserve0: U256::from_u128(100_000 * 10u128.pow(18)),
            reserve1: U256::from_u128(2_000_000 * 10u128.pow(6)),
            fee_bps: 30,
            last_updated: Instant::now(),
        };

        let impact_1 = pool.price_impact_bps(U256::from_u128(1 * 10u128.pow(18)), tokens::WAVAX);
        let impact_100 = pool.price_impact_bps(U256::from_u128(100 * 10u128.pow(18)), tokens::WAVAX);
        let impact_10k = pool.price_impact_bps(U256::from_u128(10_000 * 10u128.pow(18)), tokens::WAVAX);

        assert!(impact_1 < impact_100, "1 AVAX ({:.1}bps) should have less impact than 100 ({:.1}bps)", impact_1, impact_100);
        assert!(impact_100 < impact_10k, "100 AVAX ({:.1}bps) should have less impact than 10K ({:.1}bps)", impact_100, impact_10k);
    }

    // --- Sandwich edge cases ---

    #[test]
    fn test_sandwich_small_victim_unprofitable() {
        let pool = PoolState {
            address: "0x".into(),
            token0: tokens::WAVAX.into(), token1: tokens::USDC.into(),
            reserve0: U256::from_u128(100_000 * 10u128.pow(18)),
            reserve1: U256::from_u128(2_000_000 * 10u128.pow(6)),
            fee_bps: 30,
            last_updated: Instant::now(),
        };

        // Tiny victim (1 AVAX) — sandwich overhead exceeds profit
        let victim = U256::from_u128(1 * 10u128.pow(18));
        let frontrun = U256::from_u128(3 * 10u128.pow(18));
        let result = pool.simulate_sandwich(victim, frontrun, tokens::WAVAX);

        // Profit should be very small or zero for tiny swaps
        let profit_avax = result.profit.to_avax();
        assert!(profit_avax < 0.01, "Tiny sandwich should yield minimal profit: {} AVAX", profit_avax);
    }

    #[test]
    fn test_sandwich_profit_increases_with_victim_size() {
        let pool = PoolState {
            address: "0x".into(),
            token0: tokens::WAVAX.into(), token1: tokens::USDC.into(),
            reserve0: U256::from_u128(100_000 * 10u128.pow(18)),
            reserve1: U256::from_u128(2_000_000 * 10u128.pow(6)),
            fee_bps: 30,
            last_updated: Instant::now(),
        };

        let frontrun = U256::from_u128(3_000 * 10u128.pow(18));

        let r100 = pool.simulate_sandwich(
            U256::from_u128(100 * 10u128.pow(18)), frontrun, tokens::WAVAX);
        let r1000 = pool.simulate_sandwich(
            U256::from_u128(1_000 * 10u128.pow(18)), frontrun, tokens::WAVAX);

        assert!(r1000.profit.low > r100.profit.low,
            "1000 AVAX victim profit ({}) should exceed 100 AVAX ({})",
            r1000.profit.to_avax(), r100.profit.to_avax());
    }

    // --- Mempool monitor ---

    #[tokio::test]
    async fn test_scan_tx_non_swap() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig::default());
        let tx = PendingTx {
            hash: "0x123".into(),
            from: "0xsender".into(),
            to: Some(tokens::WAVAX.to_string()), // not a DEX router
            value: U256::from_u64(1000),
            gas_price: U256::from_u64(25_000_000_000),
            gas_limit: 21000,
            input: vec![0xa9, 0x05, 0x9c, 0xbb, 0x00], // transfer selector
            nonce: 0,
            timestamp: 0,
        };
        assert!(monitor.scan_tx(&tx).await.is_none());
    }

    #[tokio::test]
    async fn test_scan_tx_no_calldata() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig::default());
        let tx = PendingTx {
            hash: "0x123".into(), from: "0x".into(), to: Some("0x".into()),
            value: U256::from_u64(1000), gas_price: U256::from_u64(25_000_000_000),
            gas_limit: 21000, input: vec![], nonce: 0, timestamp: 0,
        };
        assert!(monitor.scan_tx(&tx).await.is_none());
    }

    #[tokio::test]
    async fn test_scan_tx_no_to() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig::default());
        let tx = PendingTx {
            hash: "0x123".into(), from: "0x".into(), to: None,
            value: U256::from_u64(1000), gas_price: U256::from_u64(25_000_000_000),
            gas_limit: 21000, input: vec![0x38, 0xed, 0x17, 0x39], nonce: 0, timestamp: 0,
        };
        assert!(monitor.scan_tx(&tx).await.is_none());
    }

    #[tokio::test]
    async fn test_monitor_stats_increment() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig::default());
        // Use a known DEX router with a swap selector to reach the stats update code
        let mut input = vec![0u8; 200];
        input[..4].copy_from_slice(&selectors::SWAP_EXACT_TOKENS_FOR_TOKENS);
        let tx = PendingTx {
            hash: "0x123".into(), from: "0x".into(),
            to: Some(DexProtocol::TraderJoe.router_address().to_string()),
            value: U256::ZERO, gas_price: U256::from_u64(25_000_000_000),
            gas_limit: 21000, input, nonce: 0, timestamp: 0,
        };
        let _ = monitor.scan_tx(&tx).await;
        let stats = monitor.stats().await;
        assert_eq!(stats.txs_scanned, 1);
    }

    // --- Sandwich evaluation ---

    #[test]
    fn test_evaluate_sandwich_too_small() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig {
            min_swap_avax: 10.0,
            ..MempoolConfig::default()
        });
        let swap = DecodedSwap {
            tx_hash: "0x".into(), dex: DexProtocol::TraderJoe,
            token_in: tokens::WAVAX.into(), token_out: tokens::USDC.into(),
            amount_in: U256::from_u128(1 * 10u128.pow(18)), // 1 AVAX (below 10 min)
            amount_out_min: U256::from_u128(20 * 10u128.pow(6)),
            path: vec![], recipient: "0x".into(), deadline: 0,
            gas_price: U256::from_u64(25_000_000_000), is_exact_input: true,
        };
        assert!(monitor.evaluate_sandwich(&swap).is_none());
    }

    #[test]
    fn test_evaluate_sandwich_zero_amounts() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig::default());
        let swap = DecodedSwap {
            tx_hash: "0x".into(), dex: DexProtocol::TraderJoe,
            token_in: tokens::WAVAX.into(), token_out: tokens::USDC.into(),
            amount_in: U256::from_u128(100 * 10u128.pow(18)),
            amount_out_min: U256::ZERO, // zero min = skip
            path: vec![], recipient: "0x".into(), deadline: 0,
            gas_price: U256::from_u64(25_000_000_000), is_exact_input: true,
        };
        assert!(monitor.evaluate_sandwich(&swap).is_none());
    }

    // --- Arbitrage edge cases ---

    #[test]
    fn test_arbitrage_zero_price() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig::default());
        assert!(monitor.evaluate_arbitrage("A", "B", 0.0, 20.0,
            DexProtocol::TraderJoe, DexProtocol::Pangolin).is_none());
        assert!(monitor.evaluate_arbitrage("A", "B", 20.0, 0.0,
            DexProtocol::TraderJoe, DexProtocol::Pangolin).is_none());
    }

    #[test]
    fn test_arbitrage_negative_price() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig::default());
        assert!(monitor.evaluate_arbitrage("A", "B", -1.0, 20.0,
            DexProtocol::TraderJoe, DexProtocol::Pangolin).is_none());
    }

    #[test]
    fn test_arbitrage_picks_correct_direction() {
        let monitor = MempoolMonitor::new("http://localhost:9650", MempoolConfig {
            min_profit_avax: 0.001, // low threshold for test
            ..MempoolConfig::default()
        });

        // B is cheaper on Pangolin — should buy on Pangolin, sell on TraderJoe
        let opp = monitor.evaluate_arbitrage("A", "B",
            25.0,  // TraderJoe: higher price
            20.0,  // Pangolin: lower price
            DexProtocol::TraderJoe, DexProtocol::Pangolin,
        );
        assert!(opp.is_some());
        match opp.unwrap() {
            MevOpportunity::Arbitrage { buy_dex, sell_dex, .. } => {
                assert_eq!(buy_dex, DexProtocol::Pangolin);  // buy where cheap
                assert_eq!(sell_dex, DexProtocol::TraderJoe); // sell where expensive
            }
            _ => panic!("Expected Arbitrage"),
        }
    }

    // --- Bundle builder edge cases ---

    #[test]
    fn test_bundle_empty() {
        let bundle = MevBundle::new(100);
        assert_eq!(bundle.tx_count(), 0);
        assert_eq!(bundle.total_gas_cost(), U256::ZERO);
    }

    #[test]
    fn test_bundle_gas_accumulation() {
        let mut bundle = MevBundle::new(100);
        bundle.add_frontrun("0x1".into(), U256::from_u64(100));
        bundle.add_backrun("0x2".into(), U256::from_u64(200));
        assert_eq!(bundle.total_gas_cost(), U256::from_u64(300));
    }

    // --- Error display ---

    #[test]
    fn test_mev_error_display() {
        assert!(format!("{}", MevError::Timeout).contains("timed out"));
        assert!(format!("{}", MevError::PoolNotFound("0xabc".into())).contains("0xabc"));
        assert!(format!("{}", MevError::GasTooHigh(U256::from_u64(999))).contains("0x3e7"));
        assert!(format!("{}", MevError::SlippageExceeded {
            expected: U256::from_u64(100), actual: U256::from_u64(80)
        }).contains("expected"));
    }

    // --- Stress tests ---

    #[test]
    fn test_sandwich_simulation_stress() {
        let pool = PoolState {
            address: "0x".into(),
            token0: tokens::WAVAX.into(), token1: tokens::USDC.into(),
            reserve0: U256::from_u128(100_000 * 10u128.pow(18)),
            reserve1: U256::from_u128(2_000_000 * 10u128.pow(6)),
            fee_bps: 30,
            last_updated: Instant::now(),
        };

        // Run 1000 sandwich simulations with varying sizes
        let start = Instant::now();
        for i in 1..=1000u64 {
            let victim = U256::from_u128(i as u128 * 10u128.pow(18));
            let frontrun = U256::from_u128(i as u128 * 3 * 10u128.pow(18));
            let _ = pool.simulate_sandwich(victim, frontrun, tokens::WAVAX);
        }
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 100,
            "1000 sandwich sims should take <100ms, took {:?}", elapsed);
    }

    #[test]
    fn test_selector_detection_stress() {
        let start = Instant::now();
        for _ in 0..1_000_000 {
            let _ = selectors::is_swap(&selectors::SWAP_EXACT_TOKENS_FOR_TOKENS);
            let _ = selectors::is_swap(&selectors::TRANSFER);
        }
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 50,
            "1M selector checks should take <50ms, took {:?}", elapsed);
    }
}
