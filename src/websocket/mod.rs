//! JSON-RPC WebSocket support for real-time subscriptions.
//!
//! Phase 10: WebSocket upgrade on /ws, eth_subscribe for newHeads,
//! logs, and newPendingTransactions. Connection management.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Subscription Types
// ---------------------------------------------------------------------------

/// Subscription types supported by eth_subscribe.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubscriptionType {
    /// New block headers
    NewHeads,
    /// Log events matching a filter
    Logs(LogFilter),
    /// New pending transaction hashes
    NewPendingTransactions,
}

impl SubscriptionType {
    /// Parse from JSON-RPC params.
    pub fn from_params(params: &[serde_json::Value]) -> Option<Self> {
        let type_str = params.first()?.as_str()?;
        match type_str {
            "newHeads" => Some(Self::NewHeads),
            "logs" => {
                let filter = if let Some(filter_obj) = params.get(1) {
                    LogFilter::from_json(filter_obj)
                } else {
                    LogFilter::default()
                };
                Some(Self::Logs(filter))
            }
            "newPendingTransactions" => Some(Self::NewPendingTransactions),
            _ => None,
        }
    }
}

/// Log filter for eth_subscribe("logs").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct LogFilter {
    pub addresses: Vec<[u8; 20]>,
    pub topics: Vec<Option<[u8; 32]>>,
}

impl LogFilter {
    pub fn from_json(value: &serde_json::Value) -> Self {
        let mut filter = Self::default();

        if let Some(addr) = value.get("address") {
            if let Some(s) = addr.as_str() {
                if let Some(bytes) = parse_hex_address(s) {
                    filter.addresses.push(bytes);
                }
            } else if let Some(arr) = addr.as_array() {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        if let Some(bytes) = parse_hex_address(s) {
                            filter.addresses.push(bytes);
                        }
                    }
                }
            }
        }

        if let Some(topics) = value.get("topics").and_then(|t| t.as_array()) {
            for t in topics {
                if t.is_null() {
                    filter.topics.push(None);
                } else if let Some(s) = t.as_str() {
                    filter.topics.push(parse_hex_hash(s));
                } else {
                    filter.topics.push(None);
                }
            }
        }

        filter
    }

    /// Check if a log entry matches this filter.
    pub fn matches(&self, address: &[u8; 20], topics: &[[u8; 32]]) -> bool {
        // Check address filter
        if !self.addresses.is_empty() && !self.addresses.contains(address) {
            return false;
        }

        // Check topics filter
        for (i, filter_topic) in self.topics.iter().enumerate() {
            if let Some(expected) = filter_topic {
                if i >= topics.len() || topics[i] != *expected {
                    return false;
                }
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Subscription Manager
// ---------------------------------------------------------------------------

/// A single WebSocket subscription.
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub sub_type: SubscriptionType,
    pub connection_id: u64,
}

/// Manages WebSocket subscriptions.
pub struct SubscriptionManager {
    /// All active subscriptions
    subscriptions: HashMap<String, Subscription>,
    /// Subscriptions indexed by connection
    by_connection: HashMap<u64, Vec<String>>,
    /// Next subscription ID
    next_id: AtomicU64,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Current connection count
    pub connection_count: u64,
}

impl SubscriptionManager {
    pub fn new(max_connections: usize) -> Self {
        Self {
            subscriptions: HashMap::new(),
            by_connection: HashMap::new(),
            next_id: AtomicU64::new(1),
            max_connections,
            connection_count: 0,
        }
    }

    /// Register a new connection. Returns connection ID or error if at limit.
    pub fn connect(&mut self) -> Result<u64, WsError> {
        if self.connection_count as usize >= self.max_connections {
            return Err(WsError::TooManyConnections(self.max_connections));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.connection_count += 1;
        Ok(id)
    }

    /// Remove a connection and all its subscriptions.
    pub fn disconnect(&mut self, connection_id: u64) {
        if let Some(sub_ids) = self.by_connection.remove(&connection_id) {
            for sub_id in sub_ids {
                self.subscriptions.remove(&sub_id);
            }
        }
        self.connection_count = self.connection_count.saturating_sub(1);
    }

    /// Add a subscription. Returns the subscription ID.
    pub fn subscribe(&mut self, connection_id: u64, sub_type: SubscriptionType) -> String {
        let id = format!("0x{:x}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let sub = Subscription {
            id: id.clone(),
            sub_type,
            connection_id,
        };
        self.subscriptions.insert(id.clone(), sub);
        self.by_connection
            .entry(connection_id)
            .or_insert_with(Vec::new)
            .push(id.clone());
        id
    }

    /// Remove a subscription by ID. Returns true if found and removed.
    pub fn unsubscribe(&mut self, sub_id: &str) -> bool {
        if let Some(sub) = self.subscriptions.remove(sub_id) {
            if let Some(conn_subs) = self.by_connection.get_mut(&sub.connection_id) {
                conn_subs.retain(|s| s != sub_id);
            }
            true
        } else {
            false
        }
    }

    /// Get all subscriptions of a given type (for broadcasting events).
    pub fn get_subscriptions_by_type(&self, sub_type_name: &str) -> Vec<&Subscription> {
        self.subscriptions
            .values()
            .filter(|s| match (&s.sub_type, sub_type_name) {
                (SubscriptionType::NewHeads, "newHeads") => true,
                (SubscriptionType::Logs(_), "logs") => true,
                (SubscriptionType::NewPendingTransactions, "newPendingTransactions") => true,
                _ => false,
            })
            .collect()
    }

    /// Count active subscriptions.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }
}

// ---------------------------------------------------------------------------
// WebSocket Messages
// ---------------------------------------------------------------------------

/// A notification to push to subscribers.
#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionNotification {
    pub jsonrpc: String,
    pub method: String,
    pub params: SubscriptionParams,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionParams {
    pub subscription: String,
    pub result: serde_json::Value,
}

/// Build a newHeads notification.
pub fn new_heads_notification(sub_id: &str, block: &BlockHeader) -> String {
    let result = serde_json::json!({
        "number": format!("0x{:x}", block.number),
        "hash": format!("0x{}", hex::encode(block.hash)),
        "parentHash": format!("0x{}", hex::encode(block.parent_hash)),
        "timestamp": format!("0x{:x}", block.timestamp),
        "stateRoot": format!("0x{}", hex::encode(block.state_root)),
        "gasLimit": format!("0x{:x}", block.gas_limit),
        "gasUsed": format!("0x{:x}", block.gas_used),
    });

    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_subscription",
        "params": {
            "subscription": sub_id,
            "result": result,
        }
    })
    .to_string()
}

/// Build a newPendingTransactions notification.
pub fn new_pending_tx_notification(sub_id: &str, tx_hash: &[u8; 32]) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_subscription",
        "params": {
            "subscription": sub_id,
            "result": format!("0x{}", hex::encode(tx_hash)),
        }
    })
    .to_string()
}

/// Build a logs notification.
pub fn logs_notification(sub_id: &str, log: &LogEntry) -> String {
    let topics: Vec<String> = log
        .topics
        .iter()
        .map(|t| format!("0x{}", hex::encode(t)))
        .collect();

    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_subscription",
        "params": {
            "subscription": sub_id,
            "result": {
                "address": format!("0x{}", hex::encode(log.address)),
                "topics": topics,
                "data": format!("0x{}", hex::encode(&log.data)),
                "blockNumber": format!("0x{:x}", log.block_number),
                "transactionHash": format!("0x{}", hex::encode(log.tx_hash)),
                "logIndex": format!("0x{:x}", log.log_index),
            }
        }
    })
    .to_string()
}

/// Simplified block header for WebSocket notifications.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub number: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub timestamp: u64,
    pub state_root: [u8; 32],
    pub gas_limit: u64,
    pub gas_used: u64,
}

/// Log entry for WebSocket notifications.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub tx_hash: [u8; 32],
    pub log_index: u32,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum WsError {
    TooManyConnections(usize),
    InvalidSubscription(String),
    ConnectionNotFound(u64),
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyConnections(max) => write!(f, "max connections ({}) reached", max),
            Self::InvalidSubscription(s) => write!(f, "invalid subscription: {}", s),
            Self::ConnectionNotFound(id) => write!(f, "connection {} not found", id),
        }
    }
}

impl std::error::Error for WsError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_hex_address(s: &str) -> Option<[u8; 20]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn parse_hex_hash(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_manager_creation() {
        let mgr = SubscriptionManager::new(100);
        assert_eq!(mgr.max_connections, 100);
        assert_eq!(mgr.connection_count, 0);
        assert_eq!(mgr.subscription_count(), 0);
    }

    #[test]
    fn test_connect_disconnect() {
        let mut mgr = SubscriptionManager::new(100);
        let conn_id = mgr.connect().unwrap();
        assert_eq!(mgr.connection_count, 1);
        mgr.disconnect(conn_id);
        assert_eq!(mgr.connection_count, 0);
    }

    #[test]
    fn test_connection_limit() {
        let mut mgr = SubscriptionManager::new(2);
        mgr.connect().unwrap();
        mgr.connect().unwrap();
        let result = mgr.connect();
        assert!(result.is_err());
    }

    #[test]
    fn test_subscribe_unsubscribe() {
        let mut mgr = SubscriptionManager::new(100);
        let conn = mgr.connect().unwrap();

        let sub_id = mgr.subscribe(conn, SubscriptionType::NewHeads);
        assert_eq!(mgr.subscription_count(), 1);

        assert!(mgr.unsubscribe(&sub_id));
        assert_eq!(mgr.subscription_count(), 0);
    }

    #[test]
    fn test_disconnect_cleans_subscriptions() {
        let mut mgr = SubscriptionManager::new(100);
        let conn = mgr.connect().unwrap();
        mgr.subscribe(conn, SubscriptionType::NewHeads);
        mgr.subscribe(conn, SubscriptionType::NewPendingTransactions);
        assert_eq!(mgr.subscription_count(), 2);

        mgr.disconnect(conn);
        assert_eq!(mgr.subscription_count(), 0);
    }

    #[test]
    fn test_get_subscriptions_by_type() {
        let mut mgr = SubscriptionManager::new(100);
        let conn1 = mgr.connect().unwrap();
        let conn2 = mgr.connect().unwrap();

        mgr.subscribe(conn1, SubscriptionType::NewHeads);
        mgr.subscribe(conn2, SubscriptionType::NewHeads);
        mgr.subscribe(conn1, SubscriptionType::NewPendingTransactions);

        let heads = mgr.get_subscriptions_by_type("newHeads");
        assert_eq!(heads.len(), 2);

        let pending = mgr.get_subscriptions_by_type("newPendingTransactions");
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_subscription_type_parsing() {
        let params = vec![serde_json::Value::String("newHeads".to_string())];
        assert_eq!(
            SubscriptionType::from_params(&params),
            Some(SubscriptionType::NewHeads)
        );

        let params = vec![serde_json::Value::String(
            "newPendingTransactions".to_string(),
        )];
        assert_eq!(
            SubscriptionType::from_params(&params),
            Some(SubscriptionType::NewPendingTransactions)
        );

        let params = vec![serde_json::Value::String("unknown".to_string())];
        assert!(SubscriptionType::from_params(&params).is_none());
    }

    #[test]
    fn test_log_filter_matches() {
        let filter = LogFilter {
            addresses: vec![[0x01; 20]],
            topics: vec![Some([0xAA; 32])],
        };

        // Match
        assert!(filter.matches(&[0x01; 20], &[[0xAA; 32]]));
        // Wrong address
        assert!(!filter.matches(&[0x02; 20], &[[0xAA; 32]]));
        // Wrong topic
        assert!(!filter.matches(&[0x01; 20], &[[0xBB; 32]]));
        // Empty filter matches all
        let empty = LogFilter::default();
        assert!(empty.matches(&[0xFF; 20], &[]));
    }

    #[test]
    fn test_new_heads_notification() {
        let header = BlockHeader {
            number: 100,
            hash: [0x01; 32],
            parent_hash: [0x02; 32],
            timestamp: 1700000000,
            state_root: [0x03; 32],
            gas_limit: 30_000_000,
            gas_used: 21_000,
        };

        let msg = new_heads_notification("0x1", &header);
        assert!(msg.contains("eth_subscription"));
        assert!(msg.contains("0x1"));
        assert!(msg.contains("0x64")); // 100 in hex
    }

    #[test]
    fn test_pending_tx_notification() {
        let hash = [0xAA; 32];
        let msg = new_pending_tx_notification("0x2", &hash);
        assert!(msg.contains("eth_subscription"));
        assert!(msg.contains("0x2"));
    }

    #[test]
    fn test_logs_notification() {
        let log = LogEntry {
            address: [0x01; 20],
            topics: vec![[0xAA; 32]],
            data: vec![0xBB; 32],
            block_number: 50,
            tx_hash: [0xCC; 32],
            log_index: 0,
        };

        let msg = logs_notification("0x3", &log);
        assert!(msg.contains("eth_subscription"));
        assert!(msg.contains("0x3"));
    }

    #[test]
    fn test_unsubscribe_nonexistent() {
        let mut mgr = SubscriptionManager::new(100);
        assert!(!mgr.unsubscribe("0xdeadbeef"));
    }

    #[test]
    fn test_log_filter_from_json() {
        let json = serde_json::json!({
            "address": "0x0101010101010101010101010101010101010101",
            "topics": ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        });

        let filter = LogFilter::from_json(&json);
        assert_eq!(filter.addresses.len(), 1);
        assert_eq!(filter.topics.len(), 1);
        assert!(filter.topics[0].is_some());
    }
}
