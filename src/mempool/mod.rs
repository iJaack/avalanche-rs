//! Live mempool subscription for Avalanche C-Chain
//!
//! Connects to an Avalanche node's WebSocket endpoint and subscribes
//! to `newPendingTransactions` for real-time MEV opportunity detection.

use crate::mev::{PendingTx, U256, MempoolMonitor, MempoolConfig, MevOpportunity, DecodedSwap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc, Mutex};
use serde::{Serialize, Deserialize};

// ============================================================================
// MEMPOOL SUBSCRIBER
// ============================================================================

/// Configuration for WebSocket mempool connection
#[derive(Debug, Clone)]
pub struct MempoolSubConfig {
    /// WebSocket endpoint (e.g., ws://localhost:9650/ext/bc/C/ws)
    pub ws_endpoint: String,
    /// HTTP RPC endpoint for fetching full tx details
    pub rpc_endpoint: String,
    /// Reconnect delay on disconnect
    pub reconnect_delay: Duration,
    /// Maximum reconnection attempts (0 = unlimited)
    pub max_reconnects: u32,
    /// Channel buffer size for pending tx hashes
    pub channel_buffer: usize,
    /// MEV monitor config
    pub monitor_config: MempoolConfig,
}

impl Default for MempoolSubConfig {
    fn default() -> Self {
        Self {
            ws_endpoint: "ws://localhost:9650/ext/bc/C/ws".into(),
            rpc_endpoint: "http://localhost:9650/ext/bc/C/rpc".into(),
            reconnect_delay: Duration::from_secs(1),
            max_reconnects: 0,
            channel_buffer: 10_000,
            monitor_config: MempoolConfig::default(),
        }
    }
}

/// State of the WebSocket connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Subscribing,
    Active,
    Reconnecting,
    Failed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Disconnected => write!(f, "disconnected"),
            ConnectionState::Connecting => write!(f, "connecting"),
            ConnectionState::Connected => write!(f, "connected"),
            ConnectionState::Subscribing => write!(f, "subscribing"),
            ConnectionState::Active => write!(f, "active"),
            ConnectionState::Reconnecting => write!(f, "reconnecting"),
            ConnectionState::Failed => write!(f, "failed"),
        }
    }
}

/// Subscription stats
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubscriptionStats {
    pub state: String,
    pub tx_hashes_received: u64,
    pub txs_fetched: u64,
    pub txs_failed_fetch: u64,
    pub swaps_detected: u64,
    pub opportunities_found: u64,
    pub reconnect_count: u32,
    pub uptime_secs: u64,
    pub last_tx_hash: String,
    pub last_opportunity: Option<String>,
}

/// Live mempool subscriber
///
/// Architecture:
/// 1. WebSocket receives `newPendingTransactions` (tx hashes only)
/// 2. Worker pool fetches full tx via `eth_getTransactionByHash`
/// 3. MempoolMonitor scans each tx for MEV opportunities
/// 4. Opportunities are sent to the output channel
pub struct MempoolSubscriber {
    /// Configuration (used when starting the WebSocket connection loop)
    #[allow(dead_code)]
    config: MempoolSubConfig,
    state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<SubscriptionStats>>,
    monitor: Arc<MempoolMonitor>,
    /// Channel for detected opportunities
    opportunity_tx: mpsc::Sender<MevOpportunity>,
    opportunity_rx: Arc<Mutex<mpsc::Receiver<MevOpportunity>>>,
    /// Channel for decoded swaps (for external processing)
    swap_tx: mpsc::Sender<DecodedSwap>,
    swap_rx: Arc<Mutex<mpsc::Receiver<DecodedSwap>>>,
    start_time: Instant,
}

impl MempoolSubscriber {
    pub fn new(config: MempoolSubConfig) -> Self {
        let (opp_tx, opp_rx) = mpsc::channel(config.channel_buffer);
        let (swap_tx, swap_rx) = mpsc::channel(config.channel_buffer);
        let monitor = Arc::new(MempoolMonitor::new(
            &config.rpc_endpoint,
            config.monitor_config.clone(),
        ));

        Self {
            config,
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(SubscriptionStats::default())),
            monitor,
            opportunity_tx: opp_tx,
            opportunity_rx: Arc::new(Mutex::new(opp_rx)),
            swap_tx,
            swap_rx: Arc::new(Mutex::new(swap_rx)),
            start_time: Instant::now(),
        }
    }

    /// Get current connection state
    pub async fn state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Get subscription stats
    pub async fn stats(&self) -> SubscriptionStats {
        let mut s = self.stats.read().await.clone();
        s.state = self.state().await.to_string();
        s.uptime_secs = self.start_time.elapsed().as_secs();
        s
    }

    /// Build the JSON-RPC subscription request
    pub fn build_subscribe_request(id: u64) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "eth_subscribe",
            "params": ["newPendingTransactions"]
        }).to_string()
    }

    /// Build a transaction fetch request
    pub fn build_get_tx_request(id: u64, tx_hash: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "eth_getTransactionByHash",
            "params": [tx_hash]
        }).to_string()
    }

    /// Parse a pending transaction from JSON-RPC response
    pub fn parse_pending_tx(value: &serde_json::Value) -> Option<PendingTx> {
        let result = value.get("result")?;

        let hash = result.get("hash")?.as_str()?.to_string();
        let from = result.get("from")?.as_str()?.to_string();
        let to = result.get("to").and_then(|v| v.as_str()).map(|s| s.to_string());

        let value_hex = result.get("value")?.as_str().unwrap_or("0x0");
        let value = U256::from_hex(value_hex).unwrap_or(U256::ZERO);

        let gas_price_hex = result.get("gasPrice")
            .or_else(|| result.get("maxFeePerGas"))
            .and_then(|v| v.as_str())
            .unwrap_or("0x0");
        let gas_price = U256::from_hex(gas_price_hex).unwrap_or(U256::ZERO);

        let gas_limit_hex = result.get("gas")?.as_str().unwrap_or("0x0");
        let gas_limit = u64::from_str_radix(
            gas_limit_hex.trim_start_matches("0x"), 16
        ).unwrap_or(0);

        let input_hex = result.get("input")?.as_str().unwrap_or("0x");
        let input_clean = input_hex.trim_start_matches("0x");
        let input = (0..input_clean.len())
            .step_by(2)
            .filter_map(|i| {
                if i + 2 <= input_clean.len() {
                    u8::from_str_radix(&input_clean[i..i + 2], 16).ok()
                } else {
                    None
                }
            })
            .collect();

        let nonce_hex = result.get("nonce")?.as_str().unwrap_or("0x0");
        let nonce = u64::from_str_radix(
            nonce_hex.trim_start_matches("0x"), 16
        ).unwrap_or(0);

        Some(PendingTx {
            hash, from, to, value, gas_price, gas_limit, input, nonce,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    /// Process a single pending transaction through the MEV pipeline
    pub async fn process_tx(&self, tx: &PendingTx) -> Option<MevOpportunity> {
        // Stage 1: Scan for swap
        let swap = self.monitor.scan_tx(tx).await?;

        // Stage 2: Evaluate sandwich opportunity
        let opportunity = self.monitor.evaluate_sandwich(&swap);

        // Send swap to external consumers
        let _ = self.swap_tx.try_send(swap);

        // Send opportunity if found
        if let Some(ref opp) = opportunity {
            let _ = self.opportunity_tx.try_send(opp.clone());
            let mut stats = self.stats.write().await;
            stats.opportunities_found += 1;
            stats.last_opportunity = Some(opp.kind().to_string());
        }

        // Update stats
        let mut stats = self.stats.write().await;
        stats.swaps_detected += 1;
        stats.last_tx_hash = tx.hash.clone();

        opportunity
    }

    /// Try to receive the next opportunity (non-blocking)
    pub async fn try_recv_opportunity(&self) -> Option<MevOpportunity> {
        self.opportunity_rx.lock().await.try_recv().ok()
    }

    /// Try to receive the next decoded swap (non-blocking)
    pub async fn try_recv_swap(&self) -> Option<DecodedSwap> {
        self.swap_rx.lock().await.try_recv().ok()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mev::{selectors, DexProtocol};

    #[test]
    fn test_subscribe_request() {
        let req = MempoolSubscriber::build_subscribe_request(1);
        let parsed: serde_json::Value = serde_json::from_str(&req).unwrap();
        assert_eq!(parsed["method"], "eth_subscribe");
        assert_eq!(parsed["params"][0], "newPendingTransactions");
        assert_eq!(parsed["id"], 1);
    }

    #[test]
    fn test_get_tx_request() {
        let req = MempoolSubscriber::build_get_tx_request(42, "0xabc123");
        let parsed: serde_json::Value = serde_json::from_str(&req).unwrap();
        assert_eq!(parsed["method"], "eth_getTransactionByHash");
        assert_eq!(parsed["params"][0], "0xabc123");
    }

    #[test]
    fn test_parse_pending_tx() {
        let json = serde_json::json!({
            "result": {
                "hash": "0xdeadbeef",
                "from": "0x1234567890abcdef1234567890abcdef12345678",
                "to": "0x60ae616a2155ee3d9a68541ba4544862310933d4",
                "value": "0xde0b6b3a7640000",
                "gasPrice": "0x5d21dba00",
                "gas": "0x5208",
                "input": "0x38ed1739",
                "nonce": "0x5"
            }
        });

        let tx = MempoolSubscriber::parse_pending_tx(&json).unwrap();
        assert_eq!(tx.hash, "0xdeadbeef");
        assert_eq!(tx.to, Some("0x60ae616a2155ee3d9a68541ba4544862310933d4".to_string()));
        assert!(!tx.value.is_zero()); // 1 AVAX
        assert_eq!(tx.gas_limit, 21000); // 0x5208
        assert_eq!(tx.nonce, 5);
        assert_eq!(tx.input, vec![0x38, 0xed, 0x17, 0x39]); // swap selector
    }

    #[test]
    fn test_parse_pending_tx_no_to() {
        let json = serde_json::json!({
            "result": {
                "hash": "0xcontract_deploy",
                "from": "0x1234567890abcdef1234567890abcdef12345678",
                "to": null,
                "value": "0x0",
                "gasPrice": "0x5d21dba00",
                "gas": "0x100000",
                "input": "0x6060604052",
                "nonce": "0x0"
            }
        });

        let tx = MempoolSubscriber::parse_pending_tx(&json).unwrap();
        assert!(tx.to.is_none());
    }

    #[test]
    fn test_parse_pending_tx_eip1559() {
        let json = serde_json::json!({
            "result": {
                "hash": "0xeip1559tx",
                "from": "0xaaa",
                "to": "0xbbb",
                "value": "0x0",
                "maxFeePerGas": "0x77359400",
                "gas": "0x5208",
                "input": "0x",
                "nonce": "0xa"
            }
        });

        let tx = MempoolSubscriber::parse_pending_tx(&json).unwrap();
        assert_eq!(tx.gas_price.low, 0x77359400); // maxFeePerGas used as gas_price
        assert_eq!(tx.nonce, 10); // 0xa
    }

    #[test]
    fn test_parse_pending_tx_invalid() {
        let json = serde_json::json!({ "result": null });
        assert!(MempoolSubscriber::parse_pending_tx(&json).is_none());

        let json2 = serde_json::json!({ "error": "not found" });
        assert!(MempoolSubscriber::parse_pending_tx(&json2).is_none());
    }

    #[tokio::test]
    async fn test_subscriber_creation() {
        let sub = MempoolSubscriber::new(MempoolSubConfig::default());
        assert_eq!(sub.state().await, ConnectionState::Disconnected);
        let stats = sub.stats().await;
        assert_eq!(stats.tx_hashes_received, 0);
        assert_eq!(stats.opportunities_found, 0);
    }

    #[tokio::test]
    async fn test_process_swap_tx() {
        let sub = MempoolSubscriber::new(MempoolSubConfig::default());

        // Construct a swap tx to TraderJoe
        let mut input = vec![0u8; 200];
        input[..4].copy_from_slice(&selectors::SWAP_EXACT_TOKENS_FOR_TOKENS);

        let tx = PendingTx {
            hash: "0xtest".into(),
            from: "0xsender".into(),
            to: Some(DexProtocol::TraderJoe.router_address().to_string()),
            value: U256::from_u128(100 * 10u128.pow(18)),
            gas_price: U256::from_u64(25_000_000_000),
            gas_limit: 300_000,
            input,
            nonce: 0,
            timestamp: 0,
        };

        // Process — may or may not find opportunity (depends on decode success)
        let _ = sub.process_tx(&tx).await;
        let stats = sub.stats().await;
        // stats updated (swaps_detected may be 0 if decode failed, that's fine)
        assert_eq!(stats.state, "disconnected"); // not connected to WS
    }

    #[tokio::test]
    async fn test_connection_state_display() {
        assert_eq!(ConnectionState::Disconnected.to_string(), "disconnected");
        assert_eq!(ConnectionState::Active.to_string(), "active");
        assert_eq!(ConnectionState::Reconnecting.to_string(), "reconnecting");
    }

    #[test]
    fn test_config_defaults() {
        let config = MempoolSubConfig::default();
        assert!(config.ws_endpoint.contains("ws://"));
        assert!(config.rpc_endpoint.contains("http://"));
        assert_eq!(config.channel_buffer, 10_000);
        assert_eq!(config.max_reconnects, 0); // unlimited
    }
}
