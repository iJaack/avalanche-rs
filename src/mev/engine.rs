//! MEV Engine — integrates mempool monitoring, pool scanning, and opportunity detection
//! into the live node pipeline.

use super::v4::{PoolKey, V4ArbOpportunity, V4PoolScanner};
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

// ============================================================================
// MEV ENGINE — unified interface for all MEV strategies
// ============================================================================

/// Configuration for the MEV engine
#[derive(Debug, Clone)]
pub struct MevEngineConfig {
    /// Mempool monitoring config
    pub mempool: MempoolConfig,
    /// Enable V4 pool scanning
    pub enable_v4: bool,
    /// Maximum opportunities to track
    pub max_opportunities: usize,
    /// How often to prune stale opportunities (seconds)
    pub prune_interval_secs: u64,
    /// RPC endpoint for live pool queries
    pub rpc_endpoint: String,
    /// Dry run mode — detect but don't execute
    pub dry_run: bool,
}

impl Default for MevEngineConfig {
    fn default() -> Self {
        Self {
            mempool: MempoolConfig::default(),
            enable_v4: true,
            max_opportunities: 1000,
            prune_interval_secs: 30,
            rpc_endpoint: "http://127.0.0.1:9650/ext/bc/C/rpc".to_string(),
            dry_run: true,
        }
    }
}

/// Live MEV engine state
pub struct MevEngine {
    config: MevEngineConfig,
    monitor: MempoolMonitor,
    v4_scanner: Arc<RwLock<V4PoolScanner>>,
    /// Known V2-style pools (address → PoolState)
    v2_pools: Arc<RwLock<HashMap<String, PoolState>>>,
    /// Detected opportunities (most recent)
    opportunities: Arc<RwLock<Vec<TimedOpportunity>>>,
    /// Engine stats
    stats: Arc<RwLock<EngineStats>>,
    start_time: Instant,
}

/// An opportunity with detection timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedOpportunity {
    pub opportunity: MevOpportunity,
    pub detected_at_ms: u64,
    pub block_number: u64,
    pub status: OpportunityStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpportunityStatus {
    Detected,
    Simulated,
    Submitted,
    Executed,
    Expired,
    Failed,
}

/// Engine-level statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngineStats {
    pub blocks_scanned: u64,
    pub txs_scanned: u64,
    pub swaps_detected: u64,
    pub arbitrages_found: u64,
    pub sandwiches_found: u64,
    pub v4_pools_tracked: u64,
    pub v2_pools_tracked: u64,
    pub total_profit_avax: f64,
    pub opportunities_expired: u64,
    pub uptime_secs: u64,
    pub last_block_scanned: u64,
    pub scan_latency_us: u64,
}

impl MevEngine {
    /// Create a new MEV engine
    pub fn new(config: MevEngineConfig) -> Self {
        let monitor = MempoolMonitor::new(&config.rpc_endpoint, config.mempool.clone());
        Self {
            v4_scanner: Arc::new(RwLock::new(V4PoolScanner::new())),
            v2_pools: Arc::new(RwLock::new(HashMap::new())),
            opportunities: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(EngineStats::default())),
            start_time: Instant::now(),
            monitor,
            config,
        }
    }

    /// Process a pending transaction — scan for swaps and evaluate MEV opportunities
    pub async fn process_pending_tx(&self, tx: &PendingTx, block_number: u64) {
        let start = Instant::now();

        // Step 1: Scan for swap
        let swap = match self.monitor.scan_tx(tx).await {
            Some(s) => s,
            None => return,
        };

        let mut stats = self.stats.write().await;
        stats.swaps_detected += 1;
        stats.txs_scanned += 1;

        // Step 2: Evaluate sandwich opportunity
        if let Some(opp) = self.monitor.evaluate_sandwich(&swap) {
            stats.sandwiches_found += 1;
            drop(stats);

            let timed = TimedOpportunity {
                opportunity: opp,
                detected_at_ms: self.start_time.elapsed().as_millis() as u64,
                block_number,
                status: OpportunityStatus::Detected,
            };
            self.add_opportunity(timed).await;
        } else {
            stats.scan_latency_us = start.elapsed().as_micros() as u64;
        }
    }

    /// Register a V2-style liquidity pool
    pub async fn register_v2_pool(&self, pool: PoolState) {
        let addr = pool.address.clone();
        self.v2_pools.write().await.insert(addr, pool);
        self.stats.write().await.v2_pools_tracked += 1;
    }

    /// Register a V4 pool
    pub async fn register_v4_pool(
        &self,
        key: PoolKey,
        sqrt_price: U256,
        liquidity: u128,
        tick: i32,
    ) {
        self.v4_scanner
            .write()
            .await
            .add_pool(key, sqrt_price, liquidity, tick);
        self.stats.write().await.v4_pools_tracked += 1;
    }

    /// Check for cross-DEX arbitrage opportunities on V2 pools
    pub async fn scan_v2_arbitrage(&self) {
        let pools = self.v2_pools.read().await;

        // Group pools by token pair
        let mut pair_pools: HashMap<(String, String), Vec<&PoolState>> = HashMap::new();
        for pool in pools.values() {
            let t0 = pool.token0.to_lowercase();
            let t1 = pool.token1.to_lowercase();
            let key = if t0 < t1 { (t0, t1) } else { (t1, t0) };
            pair_pools.entry(key).or_default().push(pool);
        }

        // Find arbitrage between pools with same pair
        for ((t0, t1), pair) in &pair_pools {
            if pair.len() < 2 {
                continue;
            }

            for i in 0..pair.len() {
                for j in (i + 1)..pair.len() {
                    let pool_a = pair[i];
                    let pool_b = pair[j];

                    // Calculate spot prices
                    let price_a = if !pool_a.reserve0.is_zero() {
                        pool_a.reserve1.to_f64() / pool_a.reserve0.to_f64()
                    } else {
                        continue;
                    };
                    let price_b = if !pool_b.reserve0.is_zero() {
                        pool_b.reserve1.to_f64() / pool_b.reserve0.to_f64()
                    } else {
                        continue;
                    };

                    // Use DEX protocol from pool addresses
                    let dex_a = DexProtocol::from_address(&pool_a.address);
                    let dex_b = DexProtocol::from_address(&pool_b.address);

                    if let Some(opp) = self
                        .monitor
                        .evaluate_arbitrage(t0, t1, price_a, price_b, dex_a, dex_b)
                    {
                        let timed = TimedOpportunity {
                            opportunity: opp,
                            detected_at_ms: self.start_time.elapsed().as_millis() as u64,
                            block_number: 0,
                            status: OpportunityStatus::Detected,
                        };
                        self.add_opportunity(timed).await;
                        self.stats.write().await.arbitrages_found += 1;
                    }
                }
            }
        }
    }

    /// Check for V4 cross-pool arbitrage
    pub async fn scan_v4_arbitrage(
        &self,
        token0: &str,
        token1: &str,
        amount: U256,
    ) -> Option<V4ArbOpportunity> {
        if !self.config.enable_v4 {
            return None;
        }
        self.v4_scanner
            .read()
            .await
            .find_v4_arb(token0, token1, amount)
    }

    /// Process a confirmed block — extract pool state updates from swap events
    pub async fn process_block(&self, block_number: u64, transactions: &[PendingTx]) {
        let start = Instant::now();

        for tx in transactions {
            self.process_pending_tx(tx, block_number).await;
        }

        let mut stats = self.stats.write().await;
        stats.blocks_scanned += 1;
        stats.last_block_scanned = block_number;
        stats.uptime_secs = self.start_time.elapsed().as_secs();
        stats.scan_latency_us = start.elapsed().as_micros() as u64;
    }

    /// Prune expired opportunities
    pub async fn prune_stale(&self) {
        let now_ms = self.start_time.elapsed().as_millis() as u64;
        let max_age_ms = self.config.prune_interval_secs * 1000;

        let mut opps = self.opportunities.write().await;
        let before = opps.len();
        opps.retain(|o| {
            now_ms.saturating_sub(o.detected_at_ms) < max_age_ms
                && o.status != OpportunityStatus::Expired
                && o.status != OpportunityStatus::Failed
        });
        let pruned = before - opps.len();
        if pruned > 0 {
            self.stats.write().await.opportunities_expired += pruned as u64;
        }
    }

    /// Add an opportunity (with size cap)
    async fn add_opportunity(&self, opp: TimedOpportunity) {
        let mut opps = self.opportunities.write().await;
        if opps.len() >= self.config.max_opportunities {
            // Remove least profitable
            opps.sort_by(|a, b| b.opportunity.net_profit().cmp(&a.opportunity.net_profit()));
            opps.truncate(self.config.max_opportunities - 1);
        }
        opps.push(opp);
    }

    /// Get current engine stats
    pub async fn stats(&self) -> EngineStats {
        let mut stats = self.stats.read().await.clone();
        stats.uptime_secs = self.start_time.elapsed().as_secs();
        stats
    }

    /// Get top N opportunities by profit
    pub async fn top_opportunities(&self, n: usize) -> Vec<TimedOpportunity> {
        let mut opps = self.opportunities.read().await.clone();
        opps.sort_by(|a, b| b.opportunity.net_profit().cmp(&a.opportunity.net_profit()));
        opps.truncate(n);
        opps
    }

    /// Get V2 pool count
    pub async fn v2_pool_count(&self) -> usize {
        self.v2_pools.read().await.len()
    }

    /// Get V4 pool count
    pub async fn v4_pool_count(&self) -> usize {
        self.v4_scanner.read().await.pools.len()
    }

    /// Summary string for logging
    pub async fn summary(&self) -> String {
        let stats = self.stats().await;
        format!(
            "MEV Engine: {}s uptime | {} blocks | {} txs | {} swaps | {} arbs | {} sandwiches | {} V2 pools | {} V4 pools",
            stats.uptime_secs, stats.blocks_scanned, stats.txs_scanned,
            stats.swaps_detected, stats.arbitrages_found, stats.sandwiches_found,
            stats.v2_pools_tracked, stats.v4_pools_tracked,
        )
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::tokens;
    use super::*;

    #[tokio::test]
    async fn test_engine_creation() {
        let engine = MevEngine::new(MevEngineConfig::default());
        let stats = engine.stats().await;
        assert_eq!(stats.blocks_scanned, 0);
        assert_eq!(stats.swaps_detected, 0);
    }

    #[tokio::test]
    async fn test_engine_process_non_swap_tx() {
        let engine = MevEngine::new(MevEngineConfig::default());
        let tx = PendingTx {
            hash: "0x123".into(),
            from: "0xsender".into(),
            to: Some("0xrecipient".into()),
            value: U256::from_u64(1000),
            gas_price: U256::from_u64(25_000_000_000),
            gas_limit: 21000,
            input: vec![],
            nonce: 0,
            timestamp: 0,
        };
        engine.process_pending_tx(&tx, 100).await;
        let stats = engine.stats().await;
        assert_eq!(stats.swaps_detected, 0);
    }

    #[tokio::test]
    async fn test_engine_process_swap_tx() {
        let engine = MevEngine::new(MevEngineConfig {
            mempool: MempoolConfig {
                min_swap_avax: 0.001,
                min_profit_avax: 0.0001,
                ..MempoolConfig::default()
            },
            ..MevEngineConfig::default()
        });

        // Use MULTICALL selector (hits the generic fallback in decode_v2_swap)
        // which returns a DecodedSwap with "unknown" tokens but still counts as detected
        let mut input = vec![0u8; 200];
        input[..4].copy_from_slice(&selectors::MULTICALL);

        let tx = PendingTx {
            hash: "0xswap".into(),
            from: "0xtrader".into(),
            to: Some(DexProtocol::TraderJoe.router_address().to_string()),
            value: U256::from_u128(100 * 10u128.pow(18)), // 100 AVAX
            gas_price: U256::from_u64(25_000_000_000),
            gas_limit: 300_000,
            input,
            nonce: 0,
            timestamp: 0,
        };

        engine.process_pending_tx(&tx, 100).await;
        let stats = engine.stats().await;
        assert_eq!(
            stats.swaps_detected, 1,
            "Should detect 1 swap via MULTICALL fallback"
        );
    }

    #[tokio::test]
    async fn test_engine_register_v2_pool() {
        let engine = MevEngine::new(MevEngineConfig::default());
        let pool = PoolState {
            address: "0xpool1".into(),
            token0: tokens::WAVAX.into(),
            token1: tokens::USDC.into(),
            reserve0: U256::from_u128(100_000 * 10u128.pow(18)),
            reserve1: U256::from_u128(2_000_000 * 10u128.pow(6)),
            fee_bps: 30,
            last_updated: Instant::now(),
        };
        engine.register_v2_pool(pool).await;
        assert_eq!(engine.v2_pool_count().await, 1);
    }

    #[tokio::test]
    async fn test_engine_register_v4_pool() {
        let engine = MevEngine::new(MevEngineConfig::default());
        let key = PoolKey::new(tokens::WAVAX, tokens::USDC, 3000, 60, "0x0");
        engine
            .register_v4_pool(key, U256::from_u128(1_000_000), 1_000_000, 0)
            .await;
        assert_eq!(engine.v4_pool_count().await, 1);
    }

    #[tokio::test]
    async fn test_engine_v2_arbitrage_scan() {
        let engine = MevEngine::new(MevEngineConfig {
            mempool: MempoolConfig {
                min_profit_avax: 0.001,
                ..MempoolConfig::default()
            },
            ..MevEngineConfig::default()
        });

        // Add two pools with different prices
        let pool1 = PoolState {
            address: DexProtocol::TraderJoe.router_address().into(),
            token0: tokens::WAVAX.to_lowercase(),
            token1: tokens::USDC.to_lowercase(),
            reserve0: U256::from_u128(100_000 * 10u128.pow(18)),
            reserve1: U256::from_u128(2_000_000 * 10u128.pow(6)),
            fee_bps: 30,
            last_updated: Instant::now(),
        };
        let pool2 = PoolState {
            address: DexProtocol::Pangolin.router_address().into(),
            token0: tokens::WAVAX.to_lowercase(),
            token1: tokens::USDC.to_lowercase(),
            reserve0: U256::from_u128(100_000 * 10u128.pow(18)),
            reserve1: U256::from_u128(2_500_000 * 10u128.pow(6)), // different price
            fee_bps: 30,
            last_updated: Instant::now(),
        };
        engine.register_v2_pool(pool1).await;
        engine.register_v2_pool(pool2).await;

        engine.scan_v2_arbitrage().await;
        let stats = engine.stats().await;
        assert!(
            stats.arbitrages_found > 0,
            "Should find arbitrage between different-priced pools"
        );
    }

    #[tokio::test]
    async fn test_engine_prune_stale() {
        let engine = MevEngine::new(MevEngineConfig {
            prune_interval_secs: 0, // everything is immediately stale
            ..MevEngineConfig::default()
        });

        // Add an opportunity
        let opp = TimedOpportunity {
            opportunity: MevOpportunity::Arbitrage {
                token_a: "A".into(),
                token_b: "B".into(),
                buy_dex: DexProtocol::TraderJoe,
                sell_dex: DexProtocol::Pangolin,
                buy_price: 1.0,
                sell_price: 1.1,
                spread_bps: 100.0,
                estimated_profit: U256::from_u64(100),
                gas_cost: U256::from_u64(10),
                net_profit: U256::from_u64(90),
            },
            detected_at_ms: 0, // old timestamp
            block_number: 1,
            status: OpportunityStatus::Detected,
        };
        engine.add_opportunity(opp).await;
        assert_eq!(engine.top_opportunities(10).await.len(), 1);

        // Wait a tiny bit then prune
        tokio::time::sleep(Duration::from_millis(10)).await;
        engine.prune_stale().await;
        assert_eq!(
            engine.top_opportunities(10).await.len(),
            0,
            "Stale opportunities should be pruned"
        );
    }

    #[tokio::test]
    async fn test_engine_max_opportunities() {
        let engine = MevEngine::new(MevEngineConfig {
            max_opportunities: 3,
            ..MevEngineConfig::default()
        });

        for i in 0..5 {
            let opp = TimedOpportunity {
                opportunity: MevOpportunity::Arbitrage {
                    token_a: "A".into(),
                    token_b: "B".into(),
                    buy_dex: DexProtocol::TraderJoe,
                    sell_dex: DexProtocol::Pangolin,
                    buy_price: 1.0,
                    sell_price: 1.1,
                    spread_bps: 100.0,
                    estimated_profit: U256::from_u64(100 + i),
                    gas_cost: U256::from_u64(10),
                    net_profit: U256::from_u64(90 + i),
                },
                detected_at_ms: i as u64 * 100,
                block_number: i as u64,
                status: OpportunityStatus::Detected,
            };
            engine.add_opportunity(opp).await;
        }

        let opps = engine.top_opportunities(10).await;
        assert!(opps.len() <= 3, "Should cap at max_opportunities");
    }

    #[tokio::test]
    async fn test_engine_summary() {
        let engine = MevEngine::new(MevEngineConfig::default());
        let summary = engine.summary().await;
        assert!(summary.contains("MEV Engine"));
        assert!(summary.contains("0 blocks"));
    }

    #[tokio::test]
    async fn test_engine_process_block() {
        let engine = MevEngine::new(MevEngineConfig::default());
        let txs = vec![PendingTx {
            hash: "0x1".into(),
            from: "0x".into(),
            to: Some("0x".into()),
            value: U256::ZERO,
            gas_price: U256::from_u64(25_000_000_000),
            gas_limit: 21000,
            input: vec![],
            nonce: 0,
            timestamp: 0,
        }];
        engine.process_block(100, &txs).await;
        let stats = engine.stats().await;
        assert_eq!(stats.blocks_scanned, 1);
        assert_eq!(stats.last_block_scanned, 100);
    }
}
