//! Metrics & Observability for avalanche-rs.
//!
//! Phase 7: Prometheus metrics endpoint, health check endpoint,
//! structured JSON logging, and startup banner.

use std::time::SystemTime;

use prometheus::{
    Encoder, IntCounter, IntGauge,
    Registry, TextEncoder,
};

// ---------------------------------------------------------------------------
// Node Metrics
// ---------------------------------------------------------------------------

/// Centralized metrics registry for the node.
pub struct NodeMetrics {
    pub registry: Registry,

    // -- P2P --
    pub peers_connected: IntGauge,
    pub peers_discovered: IntCounter,
    pub messages_sent: IntCounter,
    pub messages_received: IntCounter,
    pub bytes_sent: IntCounter,
    pub bytes_received: IntCounter,

    // -- Sync --
    pub blocks_downloaded: IntCounter,
    pub blocks_executed: IntCounter,
    pub sync_height: IntGauge,
    pub sync_target_height: IntGauge,
    pub trie_nodes_downloaded: IntCounter,

    // -- Consensus --
    pub blocks_accepted: IntCounter,
    pub blocks_rejected: IntCounter,
    pub consensus_rounds: IntCounter,

    // -- Database --
    pub db_reads: IntCounter,
    pub db_writes: IntCounter,
    pub db_bytes_written: IntCounter,

    // -- EVM --
    pub evm_txs_executed: IntCounter,
    pub evm_gas_used: IntCounter,

    // -- Uptime --
    pub start_time_seconds: IntGauge,
}

impl NodeMetrics {
    /// Create a new metrics registry with all counters and gauges.
    pub fn new() -> Self {
        let registry = Registry::new();

        let peers_connected = IntGauge::new("avalanche_peers_connected", "Number of connected peers").unwrap();
        let peers_discovered = IntCounter::new("avalanche_peers_discovered_total", "Total peers discovered").unwrap();
        let messages_sent = IntCounter::new("avalanche_messages_sent_total", "Total messages sent").unwrap();
        let messages_received = IntCounter::new("avalanche_messages_received_total", "Total messages received").unwrap();
        let bytes_sent = IntCounter::new("avalanche_bytes_sent_total", "Total bytes sent").unwrap();
        let bytes_received = IntCounter::new("avalanche_bytes_received_total", "Total bytes received").unwrap();

        let blocks_downloaded = IntCounter::new("avalanche_blocks_downloaded_total", "Total blocks downloaded").unwrap();
        let blocks_executed = IntCounter::new("avalanche_blocks_executed_total", "Total blocks executed").unwrap();
        let sync_height = IntGauge::new("avalanche_sync_height", "Current sync height").unwrap();
        let sync_target_height = IntGauge::new("avalanche_sync_target_height", "Target sync height").unwrap();
        let trie_nodes_downloaded = IntCounter::new("avalanche_trie_nodes_downloaded_total", "Total trie nodes downloaded").unwrap();

        let blocks_accepted = IntCounter::new("avalanche_blocks_accepted_total", "Total blocks accepted by consensus").unwrap();
        let blocks_rejected = IntCounter::new("avalanche_blocks_rejected_total", "Total blocks rejected").unwrap();
        let consensus_rounds = IntCounter::new("avalanche_consensus_rounds_total", "Total consensus rounds").unwrap();

        let db_reads = IntCounter::new("avalanche_db_reads_total", "Total DB read operations").unwrap();
        let db_writes = IntCounter::new("avalanche_db_writes_total", "Total DB write operations").unwrap();
        let db_bytes_written = IntCounter::new("avalanche_db_bytes_written_total", "Total DB bytes written").unwrap();

        let evm_txs_executed = IntCounter::new("avalanche_evm_txs_executed_total", "Total EVM transactions executed").unwrap();
        let evm_gas_used = IntCounter::new("avalanche_evm_gas_used_total", "Total EVM gas used").unwrap();

        let start_time_seconds = IntGauge::new("avalanche_start_time_seconds", "Node start time (unix seconds)").unwrap();

        // Register all metrics
        let _ = registry.register(Box::new(peers_connected.clone()));
        let _ = registry.register(Box::new(peers_discovered.clone()));
        let _ = registry.register(Box::new(messages_sent.clone()));
        let _ = registry.register(Box::new(messages_received.clone()));
        let _ = registry.register(Box::new(bytes_sent.clone()));
        let _ = registry.register(Box::new(bytes_received.clone()));
        let _ = registry.register(Box::new(blocks_downloaded.clone()));
        let _ = registry.register(Box::new(blocks_executed.clone()));
        let _ = registry.register(Box::new(sync_height.clone()));
        let _ = registry.register(Box::new(sync_target_height.clone()));
        let _ = registry.register(Box::new(trie_nodes_downloaded.clone()));
        let _ = registry.register(Box::new(blocks_accepted.clone()));
        let _ = registry.register(Box::new(blocks_rejected.clone()));
        let _ = registry.register(Box::new(consensus_rounds.clone()));
        let _ = registry.register(Box::new(db_reads.clone()));
        let _ = registry.register(Box::new(db_writes.clone()));
        let _ = registry.register(Box::new(db_bytes_written.clone()));
        let _ = registry.register(Box::new(evm_txs_executed.clone()));
        let _ = registry.register(Box::new(evm_gas_used.clone()));
        let _ = registry.register(Box::new(start_time_seconds.clone()));

        // Set start time
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        start_time_seconds.set(now);

        Self {
            registry,
            peers_connected,
            peers_discovered,
            messages_sent,
            messages_received,
            bytes_sent,
            bytes_received,
            blocks_downloaded,
            blocks_executed,
            sync_height,
            sync_target_height,
            trie_nodes_downloaded,
            blocks_accepted,
            blocks_rejected,
            consensus_rounds,
            db_reads,
            db_writes,
            db_bytes_written,
            evm_txs_executed,
            evm_gas_used,
            start_time_seconds,
        }
    }

    /// Render all metrics in Prometheus text format for /metrics endpoint.
    pub fn render_prometheus(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap_or_default();
        String::from_utf8(buffer).unwrap_or_default()
    }
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Health Check
// ---------------------------------------------------------------------------

/// Node health status compatible with AvalancheGo /ext/health.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub checks: HealthChecks,
}

/// Individual health checks.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthChecks {
    /// Whether the node is bootstrapped
    pub bootstrapped: CheckResult,
    /// Whether the node has connected peers
    pub network: CheckResult,
    /// Whether the database is accessible
    pub database: CheckResult,
    /// Whether the node is syncing
    pub sync: CheckResult,
}

/// Single health check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CheckResult {
    pub healthy: bool,
    pub message: String,
}

impl HealthStatus {
    /// Build health status from current node state.
    pub fn check(
        is_bootstrapped: bool,
        peer_count: usize,
        db_accessible: bool,
        sync_phase: &str,
    ) -> Self {
        let bootstrapped = CheckResult {
            healthy: is_bootstrapped,
            message: if is_bootstrapped {
                "node is bootstrapped".to_string()
            } else {
                "node is bootstrapping".to_string()
            },
        };

        let network = CheckResult {
            healthy: peer_count > 0,
            message: format!("{} peers connected", peer_count),
        };

        let database = CheckResult {
            healthy: db_accessible,
            message: if db_accessible {
                "database is accessible".to_string()
            } else {
                "database is inaccessible".to_string()
            },
        };

        let sync = CheckResult {
            healthy: sync_phase != "idle",
            message: format!("sync phase: {}", sync_phase),
        };

        let all_healthy = bootstrapped.healthy && network.healthy && database.healthy;

        HealthStatus {
            healthy: all_healthy,
            checks: HealthChecks {
                bootstrapped,
                network,
                database,
                sync,
            },
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| r#"{"healthy":false}"#.to_string())
    }
}

// ---------------------------------------------------------------------------
// Startup Banner
// ---------------------------------------------------------------------------

/// Print the startup banner for the node.
pub fn print_startup_banner(
    version: &str,
    network_id: u32,
    node_id: &str,
    staking_port: u16,
    http_port: u16,
    data_dir: &str,
) -> String {
    let network_name = match network_id {
        1 => "mainnet",
        5 => "fuji",
        _ => "custom",
    };

    format!(
        r#"
================================================================================
  avalanche-rs v{}
  Network:      {} (id={})
  NodeID:       {}
  Staking Port: {}
  HTTP Port:    {}
  Data Dir:     {}
================================================================================
"#,
        version, network_name, network_id, node_id, staking_port, http_port, data_dir
    )
}

/// Build a structured JSON log entry.
pub fn structured_log(level: &str, module: &str, message: &str, fields: &[(&str, &str)]) -> String {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut obj = serde_json::Map::new();
    obj.insert("timestamp".to_string(), serde_json::Value::Number(timestamp.into()));
    obj.insert("level".to_string(), serde_json::Value::String(level.to_string()));
    obj.insert("module".to_string(), serde_json::Value::String(module.to_string()));
    obj.insert("message".to_string(), serde_json::Value::String(message.to_string()));

    for (key, value) in fields {
        obj.insert(key.to_string(), serde_json::Value::String(value.to_string()));
    }

    serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_metrics_creation() {
        let metrics = NodeMetrics::new();
        assert!(metrics.start_time_seconds.get() > 0);
    }

    #[test]
    fn test_node_metrics_counters() {
        let metrics = NodeMetrics::new();
        metrics.blocks_downloaded.inc();
        metrics.blocks_downloaded.inc();
        assert_eq!(metrics.blocks_downloaded.get(), 2);

        metrics.peers_connected.set(5);
        assert_eq!(metrics.peers_connected.get(), 5);

        metrics.sync_height.set(12345);
        assert_eq!(metrics.sync_height.get(), 12345);
    }

    #[test]
    fn test_node_metrics_render_prometheus() {
        let metrics = NodeMetrics::new();
        metrics.blocks_downloaded.inc_by(100);
        metrics.peers_connected.set(3);

        let output = metrics.render_prometheus();
        assert!(output.contains("avalanche_blocks_downloaded_total"));
        assert!(output.contains("avalanche_peers_connected"));
        assert!(output.contains("100"));
    }

    #[test]
    fn test_health_status_healthy() {
        let health = HealthStatus::check(true, 5, true, "following");
        assert!(health.healthy);
        assert!(health.checks.bootstrapped.healthy);
        assert!(health.checks.network.healthy);
        assert!(health.checks.database.healthy);
    }

    #[test]
    fn test_health_status_unhealthy_no_peers() {
        let health = HealthStatus::check(true, 0, true, "synced");
        assert!(!health.healthy);
        assert!(!health.checks.network.healthy);
    }

    #[test]
    fn test_health_status_unhealthy_not_bootstrapped() {
        let health = HealthStatus::check(false, 3, true, "fetching");
        assert!(!health.healthy);
        assert!(!health.checks.bootstrapped.healthy);
    }

    #[test]
    fn test_health_status_unhealthy_db() {
        let health = HealthStatus::check(true, 5, false, "synced");
        assert!(!health.healthy);
        assert!(!health.checks.database.healthy);
    }

    #[test]
    fn test_health_status_json() {
        let health = HealthStatus::check(true, 5, true, "synced");
        let json = health.to_json();
        assert!(json.contains("\"healthy\": true"));
        assert!(json.contains("bootstrapped"));
        assert!(json.contains("network"));
    }

    #[test]
    fn test_startup_banner() {
        let banner = print_startup_banner(
            "0.1.0",
            1,
            "NodeID-abc123",
            9651,
            9650,
            "./data",
        );
        assert!(banner.contains("avalanche-rs v0.1.0"));
        assert!(banner.contains("mainnet"));
        assert!(banner.contains("NodeID-abc123"));
        assert!(banner.contains("9651"));
        assert!(banner.contains("9650"));
    }

    #[test]
    fn test_startup_banner_fuji() {
        let banner = print_startup_banner("0.1.0", 5, "NodeID-xyz", 9651, 9650, "./data");
        assert!(banner.contains("fuji"));
    }

    #[test]
    fn test_structured_log() {
        let log = structured_log("info", "sync", "block downloaded", &[("height", "12345"), ("size", "1024")]);
        assert!(log.contains("\"level\":\"info\""));
        assert!(log.contains("\"module\":\"sync\""));
        assert!(log.contains("\"height\":\"12345\""));
    }

    #[test]
    fn test_structured_log_empty_fields() {
        let log = structured_log("warn", "network", "peer disconnected", &[]);
        assert!(log.contains("\"level\":\"warn\""));
        assert!(log.contains("peer disconnected"));
    }

    #[test]
    fn test_metrics_increment_patterns() {
        let metrics = NodeMetrics::new();

        // Simulate sync activity
        metrics.blocks_downloaded.inc_by(500);
        metrics.bytes_received.inc_by(1_000_000);
        metrics.evm_txs_executed.inc_by(100);
        metrics.evm_gas_used.inc_by(2_100_000);
        metrics.db_writes.inc_by(600);

        let output = metrics.render_prometheus();
        assert!(output.contains("500"));
        assert!(output.contains("avalanche_evm_txs_executed_total"));
    }
}
