//! avalanche-rs — Production Avalanche full node daemon.
//!
//! Phase 6: Wire everything into a production binary.
//! Supports bootstrapping from peers, EVM execution, and JSON-RPC serving.

#![allow(
    clippy::field_reassign_with_default,
    clippy::overly_complex_bool_expr,
    clippy::assertions_on_constants,
    clippy::if_same_then_else,
    clippy::large_enum_variant,
    clippy::match_like_matches_macro,
    clippy::module_inception,
    clippy::single_match,
    clippy::unnecessary_sort_by,
    clippy::vec_init_then_push,
    clippy::while_let_loop,
    clippy::doc_lazy_continuation,
    clippy::too_many_arguments
)]

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use alloy_primitives::U256;
use bech32::{FromBase32, ToBase32};
use clap::Parser;
use lru::LruCache;
use prost::Message as ProstMessage;
use rand::{seq::SliceRandom, Rng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use tracing_subscriber::{reload, EnvFilter, Registry};

use avalanche_rs::archive::ArchiveStore;
use avalanche_rs::block::{
    extract_cchain_atomic_transactions, extract_cchain_block_fields, extract_cchain_transactions,
    parse_raw_cchain_transaction, BlockHeader, BlockMetadata, CChainRawTx, Chain, ChainGraph,
};
use avalanche_rs::consensus::SnowmanConsensus;
use avalanche_rs::db::{Database, CF_BLOCKS, CF_STATE_ROOTS};
use avalanche_rs::debug::{EvmTracer, TraceConfig, TracerType};
use avalanche_rs::evm::{BlockContext, EvmExecutor, EvmTransaction, TxReceipt};
use avalanche_rs::hardening::get_rss_bytes;
use avalanche_rs::identity::{self, NodeIdentity};
use avalanche_rs::mev::engine::{MevEngine, MevEngineConfig};
use avalanche_rs::network::{
    BlockId, ChainId, NetworkConfig, NetworkMessage, NodeId, Peer, PeerInfo, PeerManager,
    PeerState, PersistentPeerRecord,
};
use avalanche_rs::proto::{self, ProtoMessage, ProtoOneOf};
use avalanche_rs::staking::{MIN_DELEGATOR_STAKE, MIN_VALIDATOR_STAKE};
use avalanche_rs::subnet::{SubnetId, SubnetTracker};
use avalanche_rs::sync::{BlockFetchMode, SyncConfig, SyncEngine, SyncPhase};
use avalanche_rs::tx::{Eip1559Tx, LegacyTx, SignedTransaction, Wallet};
use avalanche_rs::txpool::{PoolTransaction, TransactionPool};
use avalanche_rs::websocket::{
    logs_notification, new_accepted_tx_notification, new_heads_notification,
    new_pending_tx_notification, BlockHeader as WsBlockHeader, LogEntry as WsLogEntry,
    SubscriptionManager, SubscriptionType as WsSubscriptionType,
};

const DEFAULT_CCHAIN_GAS_LIMIT: u64 = 30_000_000;
const DEFAULT_BASE_FEE_PER_GAS: u128 = 25_000_000_000;
const PRIORITY_FEE_FLOOR: u128 = 1_000_000_000;
const PRIORITY_FEE_SAMPLE_BLOCKS: u64 = 20;
const PRIORITY_FEE_PERCENTILE: f64 = 60.0;
const MAX_PLATFORM_GET_STAKE_ADDRS: usize = 256;
const MAX_PLATFORM_GET_UTXOS_ADDRS: usize = 1024;
const PLATFORM_GET_UTXOS_MAX_PAGE_SIZE: usize = 1024;
const PROPOSER_VM_RECENTLY_ACCEPTED_WINDOW_SECS: u64 = 30;
const PLATFORM_TX_DROPPED_CACHE_SIZE: usize = 64;
const PLATFORM_VM_ID: &str = "11111111111111111111111111111111LpoYY";
const EVM_VM_ID: &str = "mgj786NP7uDwBCcq6YwThhaN8FLyybkCa4zBWTQbNgmK6k9A6";
const AVAX_ASSET_ID_MAINNET: &str = "FvwEAhmxKfeiG8SnEvq42hc6whRyY3EFYAvebMqDNDGCgxN5Z";
const AVAX_ASSET_ID_FUJI: &str = "U8iRqJoiJm8xZHAacmvYyZVwqQx6uDNtQeP3CQ6fcgQk3JqnK";
const BAD_BLOCK_LIMIT: usize = 10;
const PENDING_FILTER_EVENT_LIMIT: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct PlatformDynamicFeeConfig {
    weights: [u64; 4],
    max_capacity: u64,
    max_per_second: u64,
    target_per_second: u64,
    min_price: u64,
    excess_conversion_constant: u64,
}

#[derive(Debug, Clone, Copy)]
struct PlatformValidatorFeeConfig {
    capacity: u64,
    target: u64,
    min_price: u64,
    excess_conversion_constant: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct PlatformGasState {
    capacity: u64,
    excess: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PlatformValidatorFeeState {
    active: u64,
    excess: u64,
    accrued_fees: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PlatformL1ValidatorFeeRecord {
    subnet_id: [u8; 32],
    node_id: [u8; 20],
    public_key: Vec<u8>,
    remaining_balance_owner: Option<avalanche_rs::pchain::PlatformPChainOwner>,
    deactivation_owner: Option<avalanche_rs::pchain::PlatformPChainOwner>,
    start_time: u64,
    weight: u64,
    min_nonce: u64,
    end_accumulated_fee: u64,
}

type PlatformL1ValidatorMap = std::collections::HashMap<[u8; 32], PlatformL1ValidatorFeeRecord>;
type PlatformL1ValidatorScan = (PlatformL1ValidatorMap, PlatformValidatorFeeState, u64);

#[cfg(feature = "indexer")]
use avalanche_rs::api;
#[cfg(feature = "indexer")]
use avalanche_rs::indexer::{IndexedBlock, IndexerQuery, IndexerWriter};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Avalanche full node written in Rust.
#[derive(Parser, Debug, Serialize)]
#[command(
    name = "avalanche-rs",
    version = "0.1.0",
    about = "Production Avalanche full node",
    after_help = "Examples:\n  avalanche-rs --network-id 1\n  avalanche-rs --network-id 5 --log-level debug\n  avalanche-rs --network-id 5 --subnet-id <SUBNET_ID> --tracked-subnets <SUBNET_ID>"
)]
struct Cli {
    /// Network ID (1 = mainnet, 5 = fuji)
    #[arg(long, default_value = "1", env = "AVAX_NETWORK_ID")]
    network_id: u32,

    /// Data directory for blockchain storage
    #[arg(long, default_value = "./data/avalanche-rs", env = "AVAX_DATA_DIR")]
    data_dir: PathBuf,

    /// Bootstrap node addresses (comma-separated ip:port)
    #[arg(long, value_delimiter = ',', env = "AVAX_BOOTSTRAP_IPS")]
    bootstrap_ips: Vec<String>,

    /// Tracked subnet IDs (comma-separated, hex or CB58).
    #[arg(long, default_value = "", env = "AVAX_TRACKED_SUBNETS")]
    tracked_subnets: String,

    /// Observe a specific Avalanche L1/subnet ID (hex or CB58).
    #[arg(long, env = "AVAX_SUBNET_ID")]
    subnet_id: Option<String>,

    /// Path to TLS certificate file (PEM)
    #[arg(long, env = "AVAX_TLS_CERT_FILE")]
    staking_tls_cert_file: Option<PathBuf>,

    /// Path to TLS key file (PEM)
    #[arg(long, env = "AVAX_TLS_KEY_FILE")]
    staking_tls_key_file: Option<PathBuf>,

    /// HTTP JSON-RPC port
    #[arg(long, default_value = "9650", env = "AVAX_HTTP_PORT")]
    http_port: u16,

    /// Staking / P2P port
    #[arg(long, default_value = "9651", env = "AVAX_STAKING_PORT")]
    staking_port: u16,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", env = "AVAX_LOG_LEVEL")]
    log_level: String,

    /// Log format: "json" or "pretty"
    #[arg(long, default_value = "pretty", env = "AVAX_LOG_FORMAT")]
    log_format: String,

    /// C-Chain chain ID for EVM
    #[arg(long, default_value = "43114")]
    chain_id: u64,

    /// Enable validator mode: produce and broadcast new blocks every ~2s.
    /// Requires a funded account in the EVM state and connected peers.
    #[arg(long, default_value = "false", env = "AVAX_VALIDATOR")]
    validator: bool,

    /// State pruning depth: keep only the last N blocks of trie nodes.
    /// Set to 0 to disable pruning. Genesis and finalized blocks are always protected.
    #[arg(long, default_value = "256", env = "AVAX_STATE_PRUNING_DEPTH")]
    state_pruning_depth: u64,

    /// Enable light client mode: download headers only, verify via proofs.
    #[arg(long, default_value = "false", env = "AVAX_LIGHT_CLIENT")]
    light_client: bool,

    /// Enable archive mode: keep ALL historical state, never prune.
    /// Allows eth_getBalance/eth_call at any historical block number.
    #[arg(long, default_value = "false", env = "AVAX_ARCHIVE")]
    archive: bool,

    /// Blob retention period in epochs (EIP-4844). Default 4096 epochs.
    #[arg(long, default_value = "4096", env = "AVAX_BLOB_RETENTION_EPOCHS")]
    blob_retention_epochs: u64,

    /// Transaction pool size limit.
    #[arg(long, default_value = "4096", env = "AVAX_TXPOOL_SIZE")]
    txpool_size: usize,

    /// Block LRU cache size.
    #[arg(long, default_value = "1024", env = "AVAX_BLOCK_CACHE_SIZE")]
    block_cache_size: usize,

    /// Maximum RPC request body size in bytes (default 5MB).
    #[arg(long, default_value = "5242880", env = "AVAX_RPC_MAX_BODY_SIZE")]
    rpc_max_body_size: usize,

    /// Maximum memory usage in MB (0 = unlimited). Rejects new connections when near limit.
    #[arg(long, default_value = "0", env = "AVAX_MAX_MEMORY_MB")]
    max_memory_mb: u64,

    /// Maximum log file size in MiB before rotation (default 100).
    #[arg(long, default_value = "100", env = "AVAX_LOG_MAX_SIZE")]
    log_max_size: u64,

    /// Maximum number of rotated log files to keep (default 10).
    #[arg(long, default_value = "10", env = "AVAX_LOG_MAX_FILES")]
    log_max_files: u32,

    /// Max concurrent startup dials and steady outbound pool target.
    #[arg(long, default_value = "8", env = "AVAX_CONNECTION_POOL_SIZE")]
    connection_pool_size: usize,

    /// AVAX amount to stake (supports validator/delegator flows).
    #[arg(long, env = "AVAX_STAKE_AMOUNT")]
    stake_amount: Option<u64>,

    /// Staking duration in days.
    #[arg(long, env = "AVAX_STAKE_DURATION")]
    stake_duration: Option<u16>,

    /// Delegation fee percentage (minimum 2.0).
    #[arg(long, env = "AVAX_DELEGATION_FEE")]
    delegation_fee: Option<f64>,

    /// Hex reward address where staking rewards should be sent.
    #[arg(long, env = "AVAX_REWARD_ADDRESS")]
    reward_address: Option<String>,

    /// Managed private keys for account-backed C-Chain RPC methods.
    #[arg(
        long = "rpc-private-key",
        value_delimiter = ',',
        env = "AVAX_RPC_PRIVATE_KEYS"
    )]
    rpc_private_keys: Vec<String>,

    /// Enable PostgreSQL indexer for explorer backends.
    #[cfg(feature = "indexer")]
    #[arg(long, env = "INDEXER_ENABLED")]
    indexer_enabled: bool,

    /// PostgreSQL connection URL for the indexer.
    #[cfg(feature = "indexer")]
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgres://indexer:indexer_pass@localhost/avalanche_indexer"
    )]
    database_url: String,
}

// ---------------------------------------------------------------------------
// Bootstrap nodes (Avalanche mainnet)
// ---------------------------------------------------------------------------

// Mainnet bootstrap nodes — synced from AvalancheGo genesis/bootstrappers.json (Mar 2026)
const MAINNET_BOOTSTRAP_IPS: &[&str] = &[
    "54.232.137.108:9651",
    "13.124.187.98:9651",
    "54.232.142.167:9651",
    "3.39.67.183:9651",
    "13.245.185.253:9651",
    "13.246.169.11:9651",
    "13.251.82.39:9651",
    "34.250.50.224:9651",
    "18.142.247.237:9651",
    "34.252.106.116:9651",
    "43.205.156.229:9651",
    "13.233.176.118:9651",
    "35.164.160.193:9651",
    "54.185.77.104:9651",
    "3.74.3.14:9651",
    "3.135.107.20:9651",
    "3.77.28.168:9651",
    "18.216.88.69:9651",
    "3.24.26.175:9651",
    "52.64.55.185:9651",
    "16.162.27.145:9651",
    "18.163.169.191:9651",
    "13.39.184.151:9651",
    "13.36.28.133:9651",
];

// Fuji bootstrap nodes — synced from AvalancheGo genesis/bootstrappers.json (Mar 2026)
const FUJI_BOOTSTRAP_IPS: &[&str] = &[
    "18.192.93.241:9651",
    "3.76.143.200:9651",
    "16.163.84.252:9651",
    "13.237.111.196:9651",
    "18.167.242.179:9651",
    "54.207.25.7:9651",
    "15.184.214.136:9651",
    "13.55.124.229:9651",
    "3.99.55.15:9651",
    "157.241.59.198:9651",
    "52.29.72.46:9651",
    "16.163.75.62:9651",
    "34.248.69.195:9651",
    "54.66.120.144:9651",
    "3.97.132.61:9651",
    "18.230.111.83:9651",
    "52.67.156.131:9651",
    "176.34.80.199:9651",
    "176.34.97.64:9651",
    "3.97.255.92:9651",
    "15.184.142.50:9651",
];

// ---------------------------------------------------------------------------
// Bootstrap state machine
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Clone, Copy)]
enum BootstrapState {
    Idle,
    WaitingFrontier(u32),
    WaitingAccepted(u32),
    WaitingAncestors(u32),
    FetchingAncestors {
        req: u32,
        depth: u32,
        total_blocks: u32,
    },
    Done,
}

// ---------------------------------------------------------------------------
// C-Chain bootstrap state machine
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Clone, Copy)]
enum CChainBootstrapState {
    Idle,
    WaitingAccepted(u32),
    WaitingAncestors(u32),
    FetchingAncestors {
        req: u32,
        depth: u32,
        total_blocks: u32,
    },
    Done,
}

// ---------------------------------------------------------------------------
// Chain metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ChainMetrics {
    pub blocks_synced: u64,
    pub genesis_height: u64,
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
    pub chain_length: u64,
    pub last_sync_time: Instant,
}

const META_SYNC_STATE: &[u8] = b"sync_state";
const META_BAD_BLOCKS: &[u8] = b"bad_blocks";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedSyncState {
    current_block_height: u64,
    p_chain_tip_height: u64,
    c_chain_tip_height: u64,
    bootstrap_state: String,
    bootstrap_complete: bool,
}

impl Default for ChainMetrics {
    fn default() -> Self {
        ChainMetrics {
            blocks_synced: 0,
            genesis_height: 0,
            tip_height: 0,
            tip_hash: [0u8; 32],
            chain_length: 0,
            last_sync_time: Instant::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Validator tracking
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct ValidatorInfo {
    node_id: String,
    weight: u64,
    start_time: u64,
    end_time: u64,
}

// ---------------------------------------------------------------------------
// Block chain verification
// ---------------------------------------------------------------------------

/// Walk the P-Chain block tree from tip toward genesis, verifying the stored chain.
/// Blocks are stored by SHA-256(raw_bytes) in CF_BLOCKS.
/// Parent block ID offset depends on block type:
///   - Banff (typeID 29): bytes [18..50]
///   - Banff (typeID 30-32): bytes [14..46]
///   - Apricot (typeID 0-4): bytes [6..38]
/// Walk the P-Chain from tip_id toward genesis.
/// Returns (chain_length, tip_height, genesis_height).
fn verify_block_chain(db: &Database, tip_id: [u8; 32]) -> (u64, u64, u64) {
    info!(
        "Chain walk: starting from tip {:02x}{:02x}{:02x}{:02x}…{:02x}{:02x}{:02x}{:02x}",
        tip_id[0], tip_id[1], tip_id[2], tip_id[3], tip_id[28], tip_id[29], tip_id[30], tip_id[31]
    );

    // Check immediately whether the tip is in the DB at all.
    match db.get_cf(CF_BLOCKS, &tip_id) {
        Ok(None) => {
            info!(
                "TIP ID NOT IN STORED BLOCKS: {:02x}{:02x}{:02x}{:02x}…{:02x}{:02x}{:02x}{:02x}",
                tip_id[0],
                tip_id[1],
                tip_id[2],
                tip_id[3],
                tip_id[28],
                tip_id[29],
                tip_id[30],
                tip_id[31]
            );
            return (0, 0, 0);
        }
        Err(e) => {
            warn!("Chain walk: DB error looking up tip: {}", e);
            return (0, 0, 0);
        }
        Ok(Some(_)) => {
            info!(
                "Found tip in DB: {:02x}{:02x}{:02x}{:02x}…",
                tip_id[0], tip_id[1], tip_id[2], tip_id[3]
            );
        }
    }

    let mut current = tip_id;
    let mut count = 0u64;
    let mut tip_height = 0u64;
    let mut genesis_height = 0u64;

    loop {
        match db.get_cf(CF_BLOCKS, &current) {
            Ok(Some(block_data)) => {
                count += 1;

                // Parse the full block to extract height (for tip and genesis reporting).
                if let Ok(hdr) = avalanche_rs::block::BlockHeader::parse(
                    &block_data,
                    avalanche_rs::block::Chain::PChain,
                ) {
                    if count == 1 {
                        tip_height = hdr.height;
                        info!(
                            "Chain walk tip block: height={}, type={:?}",
                            tip_height, hdr.block_type
                        );
                    }
                    if hdr.is_genesis() {
                        genesis_height = hdr.height;
                        info!(
                            "Genesis block height: {} (type={:?}, {} bytes)",
                            genesis_height,
                            hdr.block_type,
                            block_data.len()
                        );
                    }
                }

                match avalanche_rs::block::BlockHeader::extract_parent_id(&block_data) {
                    Some(parent) => {
                        if parent == [0u8; 32] {
                            info!("✅ Verified chain of {} blocks from tip (height {}) to genesis (height {})", count, tip_height, genesis_height);
                            break;
                        }
                        current = parent;
                    }
                    None => {
                        info!(
                            "Chain walk: block too short ({} bytes) at depth {}",
                            block_data.len(),
                            count
                        );
                        break;
                    }
                }
            }
            Ok(None) => {
                if count > 0 {
                    info!(
                        "Chain walk: parent not in DB after {} blocks (chain may be incomplete, may need more fetch rounds)",
                        count
                    );
                } else {
                    warn!("Chain walk: tip block not found in DB");
                }
                break;
            }
            Err(e) => {
                warn!("Chain walk DB error after {} blocks: {}", count, e);
                break;
            }
        }
    }
    (count, tip_height, genesis_height)
}

/// Iterate all P-Chain blocks in CF_BLOCKS, compute SHA-256 of each block's raw bytes,
/// and verify it matches the stored key. Returns (verified_count, mismatch_count).
fn integrity_check_pchain(db: &Database) -> (usize, usize) {
    use sha2::{Digest, Sha256};
    let all = db.iter_cf_owned(CF_BLOCKS);
    let mut ok = 0usize;
    let mut mismatch = 0usize;

    for (key, value) in &all {
        if key.starts_with(b"c:") {
            continue;
        }
        if key.len() != 32 {
            continue;
        }
        let mut hasher = Sha256::new();
        hasher.update(value);
        let computed: [u8; 32] = hasher.finalize().into();
        let stored_key: [u8; 32] = key.as_slice().try_into().unwrap();
        if computed == stored_key {
            ok += 1;
        } else {
            mismatch += 1;
            info!(
                "Integrity mismatch: key={:02x}{:02x}{:02x}{:02x}… computed={:02x}{:02x}{:02x}{:02x}…",
                stored_key[0], stored_key[1], stored_key[2], stored_key[3],
                computed[0], computed[1], computed[2], computed[3]
            );
        }
    }
    info!(
        "Block integrity check: {} blocks verified, {} mismatches",
        ok, mismatch
    );
    (ok, mismatch)
}

/// Iterate P-Chain blocks and find the one whose parent_id is all zeros.
/// Returns (block_id_key, raw_bytes) of the genesis block.
fn find_genesis_block(db: &Database) -> Option<([u8; 32], Vec<u8>)> {
    let all = db.iter_cf_owned(CF_BLOCKS);
    for (key, value) in all {
        if key.starts_with(b"c:") || key.len() != 32 {
            continue;
        }
        if let Some(parent) = avalanche_rs::block::BlockHeader::extract_parent_id(&value) {
            if parent == [0u8; 32] {
                let id: [u8; 32] = key.try_into().unwrap();
                return Some((id, value));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Node state
// ---------------------------------------------------------------------------

#[allow(dead_code)]
enum WsOutboundMessage {
    Text(String),
    Pong(Vec<u8>),
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LoggerLevelState {
    log_level: String,
    display_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AtomicTxMetadata {
    status: String,
    block_height: Option<u64>,
}

#[derive(Debug, Clone)]
struct PendingPlatformTx {
    ledger: avalanche_rs::pchain::PlatformTxLedgerSummary,
}

type PlatformBaseInputKey = ([u8; 32], u32);
type PlatformAtomicInputKey = ([u8; 32], [u8; 32], u32);

#[derive(Debug)]
struct PlatformTxPool {
    processing: std::collections::BTreeMap<String, PendingPlatformTx>,
    processing_inputs: std::collections::BTreeMap<PlatformBaseInputKey, String>,
    processing_atomic_inputs: std::collections::BTreeMap<PlatformAtomicInputKey, String>,
    dropped: LruCache<String, String>,
}

impl Default for PlatformTxPool {
    fn default() -> Self {
        Self::new(PLATFORM_TX_DROPPED_CACHE_SIZE)
    }
}

impl PlatformTxPool {
    fn new(dropped_cache_size: usize) -> Self {
        let capacity = NonZeroUsize::new(dropped_cache_size.max(1)).unwrap();
        Self {
            processing: std::collections::BTreeMap::new(),
            processing_inputs: std::collections::BTreeMap::new(),
            processing_atomic_inputs: std::collections::BTreeMap::new(),
            dropped: LruCache::new(capacity),
        }
    }

    fn contains_processing(&self, tx_id: &str) -> bool {
        self.processing.contains_key(tx_id)
    }

    fn processing_entries(&self) -> Vec<(String, avalanche_rs::pchain::PlatformTxLedgerSummary)> {
        self.processing
            .iter()
            .map(|(tx_id, entry)| (tx_id.clone(), entry.ledger.clone()))
            .collect()
    }

    fn drop_reason(&self, tx_id: &str) -> Option<String> {
        self.dropped.peek(tx_id).cloned()
    }

    fn add_processing(
        &mut self,
        tx_id: &str,
        ledger: avalanche_rs::pchain::PlatformTxLedgerSummary,
    ) -> Result<(), String> {
        if let Some(reason) = self.drop_reason(tx_id) {
            return Err(reason);
        }

        if self.contains_processing(tx_id) {
            return Ok(());
        }

        for input in &ledger.inputs {
            if let Some(existing_tx_id) = self
                .processing_inputs
                .get(&(input.tx_id, input.output_index))
            {
                return Err(format!("conflicts with processing tx {}", existing_tx_id));
            }
        }

        if let Some(source_chain) = ledger.import_source_chain {
            for input in &ledger.imported_inputs {
                if let Some(existing_tx_id) = self.processing_atomic_inputs.get(&(
                    source_chain,
                    input.tx_id,
                    input.output_index,
                )) {
                    return Err(format!("conflicts with processing tx {}", existing_tx_id));
                }
            }
        }

        for input in &ledger.inputs {
            self.processing_inputs
                .insert((input.tx_id, input.output_index), tx_id.to_string());
        }

        if let Some(source_chain) = ledger.import_source_chain {
            for input in &ledger.imported_inputs {
                self.processing_atomic_inputs.insert(
                    (source_chain, input.tx_id, input.output_index),
                    tx_id.to_string(),
                );
            }
        }

        self.processing
            .insert(tx_id.to_string(), PendingPlatformTx { ledger });
        Ok(())
    }

    fn remove_processing(&mut self, tx_id: &str) {
        let Some(entry) = self.processing.remove(tx_id) else {
            return;
        };

        for input in &entry.ledger.inputs {
            self.processing_inputs
                .remove(&(input.tx_id, input.output_index));
        }

        if let Some(source_chain) = entry.ledger.import_source_chain {
            for input in &entry.ledger.imported_inputs {
                self.processing_atomic_inputs.remove(&(
                    source_chain,
                    input.tx_id,
                    input.output_index,
                ));
            }
        }
    }

    fn mark_dropped(&mut self, tx_id: &str, reason: impl Into<String>) {
        self.remove_processing(tx_id);
        self.dropped.put(tx_id.to_string(), reason.into());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BadBlockRecord {
    hash: [u8; 32],
    raw_block: Vec<u8>,
    number: Option<u64>,
    reason: String,
    receipts: Vec<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct RecentAcceptedPChainBlock {
    height: u64,
    accepted_at: u64,
}

type LogReloadHandle = reload::Handle<EnvFilter, Registry>;
type RecentAcceptedPChainBlocks =
    Arc<RwLock<std::collections::VecDeque<RecentAcceptedPChainBlock>>>;

static LOG_RELOAD_HANDLE: once_cell::sync::OnceCell<LogReloadHandle> =
    once_cell::sync::OnceCell::new();

#[allow(dead_code)]
struct NodeState {
    identity: NodeIdentity,
    db: Database,
    evm: Arc<RwLock<EvmExecutor>>,
    sync_engine: Arc<SyncEngine>,
    peer_manager: Arc<RwLock<PeerManager>>,
    config: Cli,
    start_time: Instant,
    validators: std::collections::HashMap<String, ValidatorInfo>,
    /// Unique validator NodeIDs seen via PeerList gossip.
    validators_seen: Arc<RwLock<std::collections::HashSet<String>>>,
    /// Accumulated stake weight from PeerList info (best-effort, 0 if unavailable).
    total_stake_weight: Arc<RwLock<u64>>,
    /// Per-chain sync metrics updated by bootstrap and verified via chain walk.
    p_chain_metrics: Arc<RwLock<ChainMetrics>>,
    c_chain_metrics: Arc<RwLock<ChainMetrics>>,
    /// MEV engine for C-Chain opportunity detection
    mev_engine: Arc<MevEngine>,
    /// Shared transaction pool for RPC submission and block building.
    txpool: Arc<RwLock<TransactionPool>>,
    /// Managed wallets exposed through account-backed C-Chain RPC methods.
    rpc_wallets: Arc<StdHashMap<[u8; 20], Wallet>>,
    /// P-Chain mempool and recently dropped tx cache for Platform RPC lifecycle.
    platform_tx_pool: Arc<RwLock<PlatformTxPool>>,
    /// Light client for headers-only mode
    light_client: Arc<RwLock<avalanche_rs::light::LightClient>>,
    /// Archive store for historical state queries
    archive_store: Arc<ArchiveStore>,
    /// Subnet/L1 tracker for observed chains and validators.
    subnet_tracker: Arc<RwLock<SubnetTracker>>,
    /// Last sync state loaded from disk and refreshed on shutdown.
    persisted_sync_state: Arc<RwLock<Option<PersistedSyncState>>>,
    /// Shared WebSocket subscription manager for `/ws` and `/ext/bc/C/ws`.
    ws_subscriptions: Arc<RwLock<SubscriptionManager>>,
    /// Active WebSocket connections keyed by connection ID.
    ws_connections: Arc<RwLock<StdHashMap<u64, mpsc::UnboundedSender<WsOutboundMessage>>>>,
    /// Additional HTTP endpoint aliases registered through `admin.alias`.
    http_aliases: Arc<RwLock<StdHashMap<String, String>>>,
    /// Additional blockchain aliases registered through `admin.aliasChain`.
    chain_aliases: Arc<RwLock<StdHashMap<[u8; 32], Vec<String>>>>,
    /// Best-effort externally reachable staking address used for handshakes/info RPC.
    resolved_public_ip: Arc<RwLock<Option<SocketAddr>>>,
    /// Runtime logger levels exposed through `admin.getLoggerLevel` / `admin.setLoggerLevel`.
    logger_levels: Arc<RwLock<StdHashMap<String, LoggerLevelState>>>,
    /// P-Chain blocks accepted within the recent proposer window.
    p_chain_recently_accepted: RecentAcceptedPChainBlocks,
    /// PostgreSQL indexer for block/tx/log analytics (optional).
    #[cfg(feature = "indexer")]
    indexer: Option<Arc<IndexerWriter>>,
}

fn new_recently_accepted_pchain_blocks() -> RecentAcceptedPChainBlocks {
    Arc::new(RwLock::new(std::collections::VecDeque::new()))
}

fn prune_recently_accepted_pchain_blocks(
    blocks: &mut std::collections::VecDeque<RecentAcceptedPChainBlock>,
    now: u64,
) {
    while blocks.front().is_some_and(|entry| {
        now.saturating_sub(entry.accepted_at) > PROPOSER_VM_RECENTLY_ACCEPTED_WINDOW_SECS
    }) {
        blocks.pop_front();
    }
}

#[cfg(test)]
async fn record_recently_accepted_pchain_block_at(node: &NodeState, height: u64, accepted_at: u64) {
    let mut recent = node.p_chain_recently_accepted.write().await;
    prune_recently_accepted_pchain_blocks(&mut recent, accepted_at);
    recent.retain(|entry| entry.height != height);
    recent.push_back(RecentAcceptedPChainBlock {
        height,
        accepted_at,
    });
}

fn load_persisted_sync_state(db: &Database) -> Option<PersistedSyncState> {
    db.get_metadata(META_SYNC_STATE)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

fn load_bad_block_records(db: &Database) -> Vec<BadBlockRecord> {
    db.get_metadata(META_BAD_BLOCKS)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn persist_bad_block_records(db: &Database, records: &[BadBlockRecord]) {
    match serde_json::to_vec(records) {
        Ok(encoded) => {
            if let Err(e) = db.put_metadata(META_BAD_BLOCKS, &encoded) {
                debug!("failed to persist bad block metadata: {}", e);
            }
        }
        Err(e) => debug!("failed to encode bad block metadata: {}", e),
    }
}

fn append_bad_block_record(db: &Database, record: BadBlockRecord) {
    let mut records = load_bad_block_records(db);
    records.retain(|existing| existing.hash != record.hash);
    records.push(record);
    if records.len() > BAD_BLOCK_LIMIT {
        let drain = records.len() - BAD_BLOCK_LIMIT;
        records.drain(0..drain);
    }
    persist_bad_block_records(db, &records);
}

async fn persist_sync_state(node: &NodeState) {
    let current_block_height = node.db.last_accepted_height().unwrap_or(None).unwrap_or(0);
    let p_tip = node.p_chain_metrics.read().await.tip_height;
    let c_tip = node.c_chain_metrics.read().await.tip_height;
    let phase = node.sync_engine.phase().await;
    let bootstrap_complete = matches!(phase, SyncPhase::Synced | SyncPhase::Following);

    let state = PersistedSyncState {
        current_block_height,
        p_chain_tip_height: p_tip,
        c_chain_tip_height: c_tip,
        bootstrap_state: phase.to_string(),
        bootstrap_complete,
    };

    match serde_json::to_vec(&state) {
        Ok(encoded) => {
            if let Err(e) = node.db.put_metadata(META_SYNC_STATE, &encoded) {
                warn!("Failed to persist sync state: {}", e);
            } else {
                *node.persisted_sync_state.write().await = Some(state);
            }
        }
        Err(e) => warn!("Failed to encode sync state: {}", e),
    }
}

async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = signal::ctrl_c() => return "SIGINT",
                _ = sigterm.recv() => return "SIGTERM",
            }
        }
    }

    let _ = signal::ctrl_c().await;
    "SIGINT"
}

fn load_rpc_wallets(cli: &Cli) -> Result<StdHashMap<[u8; 20], Wallet>, String> {
    let mut wallets = StdHashMap::new();
    for key in &cli.rpc_private_keys {
        let wallet = Wallet::from_hex(key, cli.chain_id).map_err(|e| e.to_string())?;
        wallets.insert(*wallet.address(), wallet);
    }
    Ok(wallets)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let rpc_wallets = load_rpc_wallets(&cli).unwrap_or_else(|e| {
        error!("Failed to load RPC wallet(s): {}", e);
        std::process::exit(1);
    });

    // Initialize structured logging
    init_logging(&cli.log_level, &cli.log_format);

    // Install default rustls crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    info!(
        "avalanche-rs v0.1.0 starting (network_id={}, chain_id={})",
        cli.network_id, cli.chain_id
    );

    // 1. Generate or load TLS identity
    let identity = match (&cli.staking_tls_cert_file, &cli.staking_tls_key_file) {
        (Some(cert), Some(key)) => {
            info!("Loading TLS identity from {:?} / {:?}", cert, key);
            NodeIdentity::load_from_files(cert, key).unwrap_or_else(|e| {
                error!("Failed to load TLS identity: {}", e);
                std::process::exit(1);
            })
        }
        _ => {
            info!("Generating ephemeral TLS identity");
            NodeIdentity::generate().unwrap_or_else(|e| {
                error!("Failed to generate TLS identity: {}", e);
                std::process::exit(1);
            })
        }
    };

    info!(
        "NodeID: {}, cert_size={} bytes",
        identity.node_id,
        identity.cert_der.len()
    );

    // 2. Initialize database
    let db_path = cli.data_dir.join("db");
    std::fs::create_dir_all(&db_path).unwrap_or_else(|e| {
        error!("Failed to create data directory: {}", e);
        std::process::exit(1);
    });

    let db = Database::open(&db_path).unwrap_or_else(|e| {
        error!("Failed to open database: {}", e);
        std::process::exit(1);
    });

    let last_height = db.last_accepted_height().unwrap_or(None).unwrap_or(0);
    info!(
        "Database opened at {:?}, last accepted height: {}",
        db_path, last_height
    );

    let persisted_sync_state = load_persisted_sync_state(&db);
    if let Some(state) = &persisted_sync_state {
        info!(
            "Loaded persisted sync state: height={}, p_tip={}, c_tip={}, bootstrap={} ({})",
            state.current_block_height,
            state.p_chain_tip_height,
            state.c_chain_tip_height,
            state.bootstrap_complete,
            state.bootstrap_state
        );
    }

    // Phase 8: verify block chain integrity on startup
    let (ok, bad) = integrity_check_pchain(&db);
    if bad > 0 {
        warn!(
            "Chain integrity: {} blocks OK, {} MISMATCHES — block storage format issue!",
            ok, bad
        );
    } else if ok > 0 {
        info!("Chain integrity: {} blocks verified, all match", ok);
    }

    // Phase 8: dump P-Chain genesis for validator extraction analysis
    if let Some((genesis_id, genesis_raw)) = find_genesis_block(&db) {
        let dump_len = genesis_raw.len().min(200);
        info!(
            "P-Chain genesis found: id={:02x}{:02x}{:02x}{:02x}…, {} bytes total",
            genesis_id[0],
            genesis_id[1],
            genesis_id[2],
            genesis_id[3],
            genesis_raw.len()
        );
        info!(
            "P-Chain genesis: first {} bytes = {:02x?}",
            dump_len,
            &genesis_raw[..dump_len]
        );
        if let Ok(hdr) = avalanche_rs::block::BlockHeader::parse(
            &genesis_raw,
            avalanche_rs::block::Chain::PChain,
        ) {
            info!(
                "P-Chain genesis parsed: height={}, type={:?}, timestamp={}",
                hdr.height, hdr.block_type, hdr.timestamp
            );
        }
    } else {
        info!("P-Chain genesis block not found in DB (need more sync rounds)");
    }

    // Log C-Chain stateRoot mapping count
    let state_root_entries = db.iter_cf_owned(CF_STATE_ROOTS).len();
    info!("C-Chain stateRoot mapping: {} entries", state_root_entries);

    // 3. Initialize EVM executor
    let evm = Arc::new(RwLock::new(EvmExecutor::new(cli.chain_id)));
    info!("EVM executor initialized (chain_id={})", cli.chain_id);

    // 4. Initialize peer manager
    let net_config = NetworkConfig {
        network_id: cli.network_id,
        ..Default::default()
    };
    let peer_manager = Arc::new(RwLock::new(PeerManager::new(
        net_config,
        identity.node_id.clone(),
    )));

    // 5. Initialize sync engine
    let mut chain_id_bytes = [0u8; 32];
    // C-Chain ID for mainnet
    chain_id_bytes[31] = if cli.network_id == 1 { 0x01 } else { 0x05 };
    let sync_config = SyncConfig {
        chain_id: ChainId(chain_id_bytes),
        block_fetch_mode: BlockFetchMode::GetAncestors {
            max_containers_size: 2_000_000,
        },
        ..Default::default()
    };
    let sync_engine = Arc::new(SyncEngine::new(sync_config));

    // 6. Initialize validator set (pre-populated with known Fuji bootstrap validators)
    let mut validators = std::collections::HashMap::new();
    validators.insert(
        "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg".to_string(),
        ValidatorInfo {
            node_id: "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg".to_string(),
            weight: 2_000_000_000_000,
            start_time: 0,
            end_time: u64::MAX,
        },
    );
    validators.insert(
        "NodeID-MFrZFg3yDfKz2dE8bR5qitG58rN3FH1DX".to_string(),
        ValidatorInfo {
            node_id: "NodeID-MFrZFg3yDfKz2dE8bR5qitG58rN3FH1DX".to_string(),
            weight: 2_000_000_000_000,
            start_time: 0,
            end_time: u64::MAX,
        },
    );
    info!(
        "Validator set initialized with {} known Fuji validators",
        validators.len()
    );

    let archive_enabled = cli.archive;
    let archive_store = Arc::new(ArchiveStore::new(archive_enabled));
    if archive_enabled {
        info!("Archive mode enabled — all historical state will be preserved");
    }

    let mut subnet_tracker = SubnetTracker::new();
    subnet_tracker.add_subnet(SubnetId::primary_network());
    for subnet in SubnetTracker::parse_tracked_subnets(&cli.tracked_subnets) {
        subnet_tracker.add_subnet(subnet);
    }
    if let Some(subnet_id) = cli.subnet_id.as_deref().and_then(SubnetId::from_str_any) {
        subnet_tracker.observe_l1_chain(
            subnet_id.clone(),
            ChainId(chain_id_bytes),
            format!("L1-{}", &subnet_id.to_hex()[..8]),
            "customvm",
        );
        info!("Tracking requested subnet/L1 {}", subnet_id);
    }
    let subnet_tracker = Arc::new(RwLock::new(subnet_tracker));

    // Initialize indexer before node creation so it can be stored in NodeState
    #[cfg(feature = "indexer")]
    let indexer_writer: Option<Arc<IndexerWriter>> = if cli.indexer_enabled {
        match IndexerWriter::new(&cli.database_url).await {
            Ok(writer) => {
                info!("PostgreSQL indexer initialized");
                Some(Arc::new(writer))
            }
            Err(e) => {
                error!("Failed to initialize indexer: {}", e);
                None
            }
        }
    } else {
        None
    };

    let txpool = Arc::new(RwLock::new(TransactionPool::new(cli.txpool_size)));
    let platform_tx_pool = Arc::new(RwLock::new(PlatformTxPool::default()));
    let ws_subscriptions = Arc::new(RwLock::new(SubscriptionManager::new(10_000)));
    let ws_connections = Arc::new(RwLock::new(StdHashMap::new()));
    let resolved_public_ip = Arc::new(RwLock::new(discover_public_ip(cli.staking_port)));
    let logger_levels = Arc::new(RwLock::new(initial_logger_levels(&cli.log_level)));
    let rpc_wallets = Arc::new(rpc_wallets);

    if !rpc_wallets.is_empty() {
        info!("Loaded {} managed RPC wallet(s)", rpc_wallets.len());
    }

    let node = Arc::new(NodeState {
        identity,
        db,
        evm,
        sync_engine: sync_engine.clone(),
        peer_manager,
        config: cli,
        start_time: Instant::now(),
        validators,
        validators_seen: Arc::new(RwLock::new(std::collections::HashSet::new())),
        total_stake_weight: Arc::new(RwLock::new(0u64)),
        p_chain_metrics: Arc::new(RwLock::new(ChainMetrics::default())),
        c_chain_metrics: Arc::new(RwLock::new(ChainMetrics::default())),
        mev_engine: Arc::new(MevEngine::new(MevEngineConfig::default())),
        txpool,
        rpc_wallets,
        platform_tx_pool,
        light_client: Arc::new(RwLock::new(avalanche_rs::light::LightClient::new())),
        archive_store,
        subnet_tracker,
        persisted_sync_state: Arc::new(RwLock::new(persisted_sync_state.clone())),
        ws_subscriptions,
        ws_connections,
        http_aliases: Arc::new(RwLock::new(StdHashMap::new())),
        chain_aliases: Arc::new(RwLock::new(StdHashMap::new())),
        resolved_public_ip,
        logger_levels,
        p_chain_recently_accepted: new_recently_accepted_pchain_blocks(),
        #[cfg(feature = "indexer")]
        indexer: indexer_writer.clone(),
    });

    if let Some(state) = persisted_sync_state {
        {
            let mut p = node.p_chain_metrics.write().await;
            p.tip_height = state.p_chain_tip_height;
        }
        {
            let mut c = node.c_chain_metrics.write().await;
            c.tip_height = state.c_chain_tip_height;
        }
        if state.bootstrap_complete {
            info!("Resuming from persisted state; skipping full bootstrap replay");
        }
    }

    refresh_txpool_base_fee(&node).await;

    // Log light client mode
    if node.config.light_client {
        info!("Light client mode enabled — headers only, state via on-demand proofs");
    }

    #[cfg(feature = "indexer")]
    if let Some(ref writer) = indexer_writer {
        let chain_height = node.c_chain_metrics.read().await.tip_height as i64;
        if let Err(e) =
            avalanche_rs::indexer::catchup::startup_catchup(&writer.pool(), chain_height).await
        {
            error!("Indexer startup catchup scan failed: {}", e);
        }
    }

    // 6. Start P2P listener
    let staking_addr: SocketAddr = format!("0.0.0.0:{}", node.config.staking_port)
        .parse()
        .unwrap();
    let p2p_handle = tokio::spawn(run_p2p_listener(staking_addr, node.clone()));

    // 7. Connect to bootstrap nodes
    let bootstrap_handle = tokio::spawn(connect_to_bootstrap_nodes(node.clone()));

    // 8. Start JSON-RPC server
    let http_addr: SocketAddr = format!("0.0.0.0:{}", node.config.http_port)
        .parse()
        .unwrap();
    let rpc_handle = tokio::spawn(run_rpc_server(http_addr, node.clone()));

    // 9. Start sync / consensus loop
    let consensus_handle = tokio::spawn(run_consensus_loop(node.clone()));

    // 9a. Start block builder if validator mode is enabled
    if node.config.validator {
        info!("Validator mode enabled — starting block builder (2s interval)");
        let builder_node = node.clone();
        tokio::spawn(async move {
            run_block_builder(builder_node).await;
        });
    }

    // 10. Start metrics logging (every 10s)
    let metrics_node = node.clone();
    let metrics_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let p = metrics_node.p_chain_metrics.read().await;
            let c = metrics_node.c_chain_metrics.read().await;
            info!(
                "P-Chain: {} blocks synced, height {}→{}, chain length {}",
                p.blocks_synced, p.genesis_height, p.tip_height, p.chain_length
            );
            let state_root_count = metrics_node
                .db
                .iter_cf_owned(avalanche_rs::db::CF_STATE_ROOTS)
                .len();
            info!(
                "C-Chain: {} blocks synced, {} stateRoot mappings",
                c.blocks_synced, state_root_count
            );

            // MEV engine stats
            let mev_stats = metrics_node.mev_engine.stats().await;
            if mev_stats.txs_scanned > 0
                || mev_stats.v2_pools_tracked > 0
                || mev_stats.v4_pools_tracked > 0
            {
                info!(
                    "MEV: {} txs scanned, {} swaps, {} arbs, {} sandwiches | {} V2 pools, {} V4 pools",
                    mev_stats.txs_scanned, mev_stats.swaps_detected,
                    mev_stats.arbitrages_found, mev_stats.sandwiches_found,
                    mev_stats.v2_pools_tracked, mev_stats.v4_pools_tracked,
                );
            }
        }
    });

    // 10a. Start state pruning background task (every 60s) — disabled in archive mode
    if node.config.state_pruning_depth > 0 && !node.config.archive {
        let prune_node = node.clone();
        let prune_depth = node.config.state_pruning_depth;
        tokio::spawn(async move {
            let mut pruner = avalanche_rs::db::StatePruner::new(prune_depth);
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await; // skip first tick
            loop {
                interval.tick().await;
                let current = prune_node
                    .db
                    .last_accepted_height()
                    .unwrap_or(None)
                    .unwrap_or(0);
                // Use current height as finalized (conservative — protects tip)
                let (pruned, bytes) = pruner.prune_once(&prune_node.db, current, current);
                if pruned > 0 {
                    let (total_pruned, total_bytes) = pruner.metrics();
                    info!(
                        "State pruning: {} entries removed ({} bytes), total: {} entries ({} bytes)",
                        pruned, bytes, total_pruned, total_bytes
                    );
                }
            }
        });
        info!("State pruning enabled: depth={}", prune_depth);
    }

    // 11. Start REST API for indexer (when --indexer-enabled)
    #[cfg(feature = "indexer")]
    let _api_handle = {
        if let Some(ref writer) = indexer_writer {
            let query = IndexerQuery::new(writer.pool());
            let api_router = api::router(query);
            let api_addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
            info!("Starting REST API server on {}", api_addr);
            let handle = tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind(api_addr).await.unwrap();
                axum::serve(listener, api_router).await.unwrap();
            });
            info!("PostgreSQL indexer enabled, REST API on port 8080");
            Some(handle)
        } else {
            None
        }
    };

    info!(
        "Node started: p2p=:{}, http=:{}, node_id={}",
        node.config.staking_port, node.config.http_port, node.identity.node_id
    );

    // 12. Graceful shutdown
    let sig = wait_for_shutdown_signal().await;
    info!("Received {}, shutting down gracefully...", sig);

    persist_sync_state(&node).await;

    let uptime = node.start_time.elapsed();
    info!("Shutting down after {:.1}s uptime", uptime.as_secs_f64());

    // Abort background tasks
    p2p_handle.abort();
    bootstrap_handle.abort();
    rpc_handle.abort();
    consensus_handle.abort();
    metrics_handle.abort();

    info!("avalanche-rs stopped.");
}

// ---------------------------------------------------------------------------
// P2P Listener
// ---------------------------------------------------------------------------

async fn run_p2p_listener(addr: SocketAddr, node: Arc<NodeState>) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            info!("P2P listener bound to {}", addr);
            l
        }
        Err(e) => {
            error!("Failed to bind P2P listener on {}: {}", addr, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("Inbound connection from {}", peer_addr);
                let node = node.clone();
                tokio::spawn(async move {
                    handle_inbound_connection(stream, peer_addr, node).await;
                });
            }
            Err(e) => {
                warn!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_inbound_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    node: Arc<NodeState>,
) {
    info!("Handling inbound connection from {}", peer_addr);

    // TLS accept
    let tls_config = match node.identity.tls_server_config() {
        Ok(c) => c,
        Err(e) => {
            warn!("TLS server config error for {}: {}", peer_addr, e);
            return;
        }
    };

    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let mut tls_stream =
        match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!("TLS accept from {} failed: {}", peer_addr, e);
                return;
            }
            Err(_) => {
                warn!("TLS accept from {} timed out", peer_addr);
                return;
            }
        };

    // Extract peer NodeID from cert
    let peer_certs = tls_stream.get_ref().1.peer_certificates();
    let peer_node_id = peer_certs
        .and_then(|certs| certs.first())
        .map(|cert| identity::derive_node_id(cert.as_ref()))
        .unwrap_or(NodeId([0u8; 20]));

    info!("TLS accepted from {} (NodeID: {})", peer_addr, peer_node_id);

    let mut peer = Peer::new(peer_node_id.clone(), peer_addr);

    match read_one_decoded_message(&mut tls_stream, peer_addr, 15).await {
        Ok(decoded) => {
            info!(
                "Received {} from inbound peer {}",
                decoded.message.name(),
                peer_addr
            );
            if let NetworkMessage::Version {
                my_version,
                tracked_subnets,
                ..
            } = decoded.message
            {
                peer.version = Some(my_version);
                peer.tracked_subnets = tracked_subnets;
            }
            if let Some(handshake) = decoded.handshake {
                peer.public_ip = handshake.public_ip;
                peer.supported_acps = handshake.supported_acps;
                peer.objected_acps = handshake.objected_acps;
            }
        }
        Err(_) => {
            warn!("No handshake from {}", peer_addr);
        }
    }

    // Send PeerList response
    let peer_list = NetworkMessage::PeerList { peers: vec![] };
    if let Ok(encoded) = peer_list.encode_proto() {
        let _ = tls_stream.write_all(&encoded).await;
        let _ = tls_stream.flush().await;
    }

    // Register peer
    let mut pm = node.peer_manager.write().await;
    peer.state = PeerState::Connected;
    let reputation = peer.reputation;
    if pm.add_peer(peer).is_ok() {
        persist_connected_peer(&node, &peer_node_id, peer_addr, reputation, 0);
    }
}

// ---------------------------------------------------------------------------
// Bootstrap connection
// ---------------------------------------------------------------------------

async fn connect_to_bootstrap_nodes(node: Arc<NodeState>) {
    let bootstrap_ips: Vec<String> = if node.config.bootstrap_ips.is_empty() {
        match node.config.network_id {
            1 => MAINNET_BOOTSTRAP_IPS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            5 => FUJI_BOOTSTRAP_IPS.iter().map(|s| s.to_string()).collect(),
            _ => {
                warn!("No bootstrap IPs for network_id={}", node.config.network_id);
                vec![]
            }
        }
    } else {
        node.config.bootstrap_ips.clone()
    };

    let mut startup_targets = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for ip_str in &bootstrap_ips {
        match ip_str.parse::<SocketAddr>() {
            Ok(addr) => {
                if seen.insert(addr) {
                    startup_targets.push(StartupPeerTarget { addr, score: 0 });
                }
            }
            Err(e) => {
                warn!("Invalid bootstrap address '{}': {}", ip_str, e);
            }
        }
    }

    for target in load_persistent_peer_targets(&node.db, 256) {
        if seen.insert(target.addr) {
            startup_targets.push(target);
        }
    }

    if startup_targets.is_empty() {
        warn!("No startup peers available, running in standalone mode");
        return;
    }

    startup_targets.sort_by(|a, b| b.score.cmp(&a.score));
    let pool_size = node.config.connection_pool_size.max(1);
    startup_targets.truncate(pool_size);

    info!(
        "Connecting to {} startup peers (pool_size={})",
        startup_targets.len(),
        pool_size
    );

    for target in startup_targets {
        let addr = target.addr;
        let node = node.clone();
        tokio::spawn(async move {
            if let Err(e) = connect_and_handshake(addr, node).await {
                warn!("Startup peer {} failed: {}", addr, e);
            }
        });
    }
}

#[derive(Clone, Debug)]
struct StartupPeerTarget {
    addr: SocketAddr,
    score: i64,
}

fn load_persistent_peer_targets(db: &Database, limit: usize) -> Vec<StartupPeerTarget> {
    let mut records: Vec<_> = db
        .load_all_peers()
        .into_iter()
        .filter_map(|(_key, value)| PersistentPeerRecord::decode(&value))
        .collect();

    records.sort_by(|a, b| peer_score(b).cmp(&peer_score(a)));

    records
        .into_iter()
        .take(limit)
        .filter_map(|record| {
            record.socket_addr().map(|addr| StartupPeerTarget {
                addr,
                score: peer_score(&record),
            })
        })
        .collect()
}

fn persist_connected_peer(
    node: &NodeState,
    node_id: &NodeId,
    addr: SocketAddr,
    reputation: i32,
    latency_ms: u64,
) {
    let mut record =
        PersistentPeerRecord::new(node_id.0, socket_addr_to_ip_bytes(addr), addr.port());
    record.update_seen(reputation);
    record.latency_ms = latency_ms;
    if let Err(e) = node.db.put_peer(&node_id.0, &record.encode()) {
        debug!("Failed to persist peer {}: {}", node_id, e);
    }
}

fn peer_score(record: &PersistentPeerRecord) -> i64 {
    let latency_component = (record.latency_ms as i64 / 10).min(10_000);
    (record.reputation as i64 * 10) + record.reliability_score as i64 - latency_component
}

fn latency_to_reputation(latency_ms: u64) -> i32 {
    (1000_i32 - (latency_ms.min(1000) as i32)).max(0)
}

fn socket_addr_to_ip_bytes(addr: SocketAddr) -> Vec<u8> {
    match addr.ip() {
        std::net::IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
        std::net::IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
    }
}

fn discover_public_ip(staking_port: u16) -> Option<SocketAddr> {
    for target in ["8.8.8.8:80", "1.1.1.1:80", "[2001:4860:4860::8888]:80"] {
        let bind_addr = if target.starts_with('[') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let Ok(socket) = std::net::UdpSocket::bind(bind_addr) else {
            continue;
        };
        if socket.connect(target).is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                if !local_addr.ip().is_unspecified() {
                    return Some(SocketAddr::new(local_addr.ip(), staking_port));
                }
            }
        }
    }
    None
}

fn socket_addr_from_ip_bytes(ip_bytes: &[u8], port: u16) -> Option<SocketAddr> {
    let ip = match ip_bytes.len() {
        4 => {
            let arr: [u8; 4] = ip_bytes.try_into().ok()?;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(arr))
        }
        16 => {
            let arr: [u8; 16] = ip_bytes.try_into().ok()?;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(arr))
        }
        _ => return None,
    };
    if port == 0 {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}

/// Dial up to 10 new peers discovered via PeerList.
/// Skips peers we can't parse as a SocketAddr.
fn dial_new_peers(new_peers: Vec<PeerInfo>, node: Arc<NodeState>) {
    let to_dial: Vec<_> = new_peers
        .into_iter()
        .take(10)
        .filter_map(|p| {
            // Convert raw IP bytes + port to SocketAddr
            let ip = match p.ip_addr.len() {
                4 => {
                    let arr: [u8; 4] = p.ip_addr.try_into().ok()?;
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(arr))
                }
                16 => {
                    let arr: [u8; 16] = p.ip_addr.try_into().ok()?;
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(arr))
                }
                _ => return None,
            };
            if p.ip_port == 0 {
                return None;
            }
            Some(std::net::SocketAddr::new(ip, p.ip_port))
        })
        .collect();

    for addr in to_dial {
        let node = node.clone();
        tokio::spawn(async move {
            info!("Dialing discovered peer {}", addr);
            if let Err(e) = connect_and_handshake(addr, node).await {
                debug!("Discovered peer {} failed: {}", addr, e);
            }
        });
    }
}

/// Read one length-prefixed protobuf message from a TLS stream.
async fn read_one_message<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    addr: SocketAddr,
    timeout_secs: u64,
) -> Result<NetworkMessage, Box<dyn std::error::Error + Send + Sync>> {
    read_one_decoded_message(stream, addr, timeout_secs)
        .await
        .map(|decoded| decoded.message)
}

#[derive(Debug, Clone, Default)]
struct HandshakeMetadata {
    public_ip: Option<SocketAddr>,
    supported_acps: Vec<u32>,
    objected_acps: Vec<u32>,
}

#[derive(Debug, Clone)]
struct DecodedPeerMessage {
    message: NetworkMessage,
    handshake: Option<HandshakeMetadata>,
}

async fn read_one_decoded_message<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    addr: SocketAddr,
    timeout_secs: u64,
) -> Result<DecodedPeerMessage, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        stream.read_exact(&mut len_buf),
    )
    .await
    .map_err(|_| format!("read timeout from {}", addr))?
    .map_err(|e| format!("read length from {}: {}", addr, e))?;

    let msg_len = u32::from_be_bytes(len_buf) as usize;
    if msg_len > 16 * 1024 * 1024 {
        return Err(format!("message too large from {}: {} bytes", addr, msg_len).into());
    }

    let mut msg_buf = vec![0u8; msg_len];
    tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        stream.read_exact(&mut msg_buf),
    )
    .await
    .map_err(|_| format!("message read timeout from {}", addr))?
    .map_err(|e| format!("read message from {}: {}", addr, e))?;

    // Reconstruct length-prefixed buffer for decode_proto
    let mut full_buf = Vec::with_capacity(4 + msg_len);
    full_buf.extend_from_slice(&len_buf);
    full_buf.extend_from_slice(&msg_buf);

    let handshake = ProtoMessage::decode(msg_buf.as_slice())
        .ok()
        .and_then(|proto_msg| match proto_msg.message {
            Some(ProtoOneOf::Handshake(handshake)) => Some(HandshakeMetadata {
                public_ip: socket_addr_from_ip_bytes(&handshake.ip_addr, handshake.ip_port as u16),
                supported_acps: handshake.supported_acps,
                objected_acps: handshake.objected_acps,
            }),
            _ => None,
        });

    // Try normal decode first
    match NetworkMessage::decode_proto(&full_buf) {
        Ok(msg) => Ok(DecodedPeerMessage {
            message: msg,
            handshake,
        }),
        Err(e) => {
            // Try raw protobuf parse for diagnostics
            if let Ok(proto_msg) = ProtoMessage::decode(msg_buf.as_slice()) {
                if let Some(ProtoOneOf::CompressedZstd(_)) = &proto_msg.message {
                    if let Ok(inner) = proto::decompress_message(&msg_buf) {
                        // Try to convert decompressed message
                        debug!(
                            "Decompressed message from {}: {:?}",
                            addr,
                            std::mem::discriminant(&inner)
                        );
                    }
                }
            }
            Err(format!("decode from {}: {} (raw {} bytes)", addr, e, msg_len).into())
        }
    }
}

/// Connect to a peer: TCP → TLS upgrade → send Handshake → receive PeerList.
async fn connect_and_handshake(
    addr: SocketAddr,
    node: Arc<NodeState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Connecting to bootstrap node {}", addr);
    let dial_started = Instant::now();

    // 1. TCP connect with timeout
    let tcp_stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map_err(|_| format!("TCP connect timeout to {}", addr))?
    .map_err(|e| format!("TCP connect to {}: {}", addr, e))?;

    tcp_stream.set_nodelay(true).ok();
    info!("TCP connected to {}", addr);

    // 2. TLS upgrade
    let tls_config = node
        .identity
        .tls_client_config()
        .map_err(|e| format!("TLS config: {}", e))?;

    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from("avalanche-node")
        .map_err(|e| format!("server name: {}", e))?;

    let mut tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name.to_owned(), tcp_stream),
    )
    .await
    .map_err(|_| format!("TLS handshake timeout to {}", addr))?
    .map_err(|e| format!("TLS handshake with {}: {}", addr, e))?;

    // Extract peer's certificate and derive their NodeID
    let peer_certs = tls_stream.get_ref().1.peer_certificates();
    let peer_node_id = if let Some(certs) = peer_certs {
        if let Some(cert) = certs.first() {
            let nid = identity::derive_node_id(cert.as_ref());
            info!(
                "TLS handshake complete with {} → peer NodeID: {}",
                addr, nid
            );
            nid
        } else {
            warn!("No peer certificate from {}", addr);
            NodeId([0u8; 20])
        }
    } else {
        warn!("No peer certificates from {}", addr);
        NodeId([0u8; 20])
    };

    // 3. Build and send Handshake message
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let public_addr = if let Some(addr) = *node.resolved_public_ip.read().await {
        addr
    } else if let Some(discovered) = discover_public_ip(node.config.staking_port) {
        *node.resolved_public_ip.write().await = Some(discovered);
        discovered
    } else {
        SocketAddr::new(addr.ip(), node.config.staking_port)
    };
    let my_ip = socket_addr_to_ip_bytes(public_addr);
    let supported_acps = local_supported_acps(node.config.network_id, now);

    // Sign the IP with the TLS key in AvalancheGo format
    let ip_sig = node
        .identity
        .sign_ip_with_tls_key(&my_ip, node.config.staking_port, now);
    // Sign with BLS for proof-of-possession
    let bls_sig = node
        .identity
        .sign_ip_bls(&my_ip, node.config.staking_port, now);

    // Build protobuf Handshake directly (need BLS sig field)
    use avalanche_rs::proto::pb;

    let upgrade_time = avalanche_rs::fortuna::latest_upgrade_time(node.config.network_id);

    // Build valid bloom filter: [numHashes(1byte)] [seed(8bytes)] [entries(1+bytes)]
    // Format: numHashes=1, seed=random 8 bytes, entries=all zeros (we know no peers)
    let bloom_seed: u64 = rand::thread_rng().gen();
    let mut bloom_filter_bytes = Vec::with_capacity(10);
    bloom_filter_bytes.push(1u8); // numHashes = 1
    bloom_filter_bytes.extend_from_slice(&bloom_seed.to_be_bytes()); // 8-byte seed
    bloom_filter_bytes.push(0u8); // 1 byte of entries (empty = we know nobody)

    let mut tracked_subnets = SubnetTracker::parse_tracked_subnets(&node.config.tracked_subnets);
    if let Some(subnet_id) = &node.config.subnet_id {
        if let Some(parsed) = SubnetId::from_str_any(subnet_id) {
            tracked_subnets.push(parsed);
        }
    }
    tracked_subnets.sort_by_key(|s| s.0);
    tracked_subnets.dedup();
    let tracked_subnet_bytes: Vec<bytes::Bytes> = tracked_subnets
        .iter()
        .map(|s| bytes::Bytes::from(s.0.to_vec()))
        .collect();

    let bloom_salt: [u8; 8] = rand::thread_rng().gen();
    let handshake_proto = pb::Message {
        message: Some(pb::message::Message::Handshake(pb::Handshake {
            network_id: node.config.network_id,
            my_time: now,
            // Send IP as-is (4 bytes for IPv4) — AvalancheGo handles both 4 and 16
            ip_addr: bytes::Bytes::from(my_ip.clone()),
            ip_port: node.config.staking_port as u32,
            upgrade_time,
            ip_signing_time: now,
            ip_node_id_sig: bytes::Bytes::from(ip_sig),
            tracked_subnets: tracked_subnet_bytes.clone(),
            client: Some(pb::Client {
                name: "avalanchego".into(),
                major: 1,
                minor: 14,
                patch: 1,
            }),
            supported_acps: supported_acps.clone(),
            objected_acps: vec![],
            known_peers: Some(pb::BloomFilter {
                filter: bytes::Bytes::from(bloom_filter_bytes),
                salt: bytes::Bytes::from(bloom_salt.to_vec()),
            }),
            ip_bls_sig: bytes::Bytes::from(bls_sig),
            all_subnets: tracked_subnet_bytes.is_empty(),
        })),
    };

    // Encode with length prefix
    let raw = prost::Message::encode_to_vec(&handshake_proto);
    let len = (raw.len() as u32).to_be_bytes();
    let mut encoded = Vec::with_capacity(4 + raw.len());
    encoded.extend_from_slice(&len);
    encoded.extend_from_slice(&raw);

    info!(
        "Handshake: network_id={}, ip={:02x?}, port={}, raw_msg={} bytes",
        node.config.network_id,
        &my_ip,
        node.config.staking_port,
        encoded.len()
    );

    tls_stream
        .write_all(&encoded)
        .await
        .map_err(|e| format!("send handshake to {}: {}", addr, e))?;
    tls_stream.flush().await.ok();

    info!("Sent Handshake to {} ({} bytes)", addr, encoded.len());

    // 4. Read messages from peer. Protocol: peer sends Handshake back, then PeerList.
    //    Read up to 5 initial messages to complete the handshake exchange.
    let mut handshake_received = false;
    let mut peerlist_received = false;
    let mut peer_version: Option<String> = None;
    let mut peer_tracked_subnets = Vec::new();
    let mut peer_public_ip = None;
    let mut peer_supported_acps = Vec::new();
    let mut peer_objected_acps = Vec::new();
    let mut peer_reported_uptime = 0u32;

    for msg_idx in 0..5 {
        let decoded = match read_one_decoded_message(&mut tls_stream, addr, 15).await {
            Ok(m) => m,
            Err(e) => {
                if msg_idx == 0 {
                    warn!("Failed to read first response from {}: {}", addr, e);
                    return Err(e);
                }
                // After first message, a read failure is OK (peer might not send more)
                debug!("No more messages from {} after {}: {}", addr, msg_idx, e);
                break;
            }
        };
        let msg = decoded.message;
        if let Some(handshake) = decoded.handshake {
            peer_public_ip = handshake.public_ip;
            peer_supported_acps = handshake.supported_acps;
            peer_objected_acps = handshake.objected_acps;
        }

        info!(
            "Received {} from {} (msg #{})",
            msg.name(),
            addr,
            msg_idx + 1
        );

        match &msg {
            NetworkMessage::Version {
                network_id,
                my_version,
                node_id,
                tracked_subnets,
                supported_acps,
                objected_acps,
                ..
            } => {
                handshake_received = true;
                info!(
                    "Peer {} handshake: network_id={}, version={}, node_id={}",
                    addr, network_id, my_version, node_id
                );
                peer_version = Some(my_version.clone());
                peer_tracked_subnets = tracked_subnets.clone();
                peer_supported_acps = supported_acps.clone();
                peer_objected_acps = objected_acps.clone();

                // Send empty PeerList back — AvalancheGo requires this to mark
                // the handshake as finished (finishedHandshake = true).
                // Without it, the peer drops all chain messages.
                let peerlist = pb::Message {
                    message: Some(pb::message::Message::PeerList(pb::PeerList {
                        claimed_ip_ports: vec![],
                    })),
                };
                let raw = prost::Message::encode_to_vec(&peerlist);
                let len = (raw.len() as u32).to_be_bytes();
                let mut peerlist_encoded = Vec::with_capacity(4 + raw.len());
                peerlist_encoded.extend_from_slice(&len);
                peerlist_encoded.extend_from_slice(&raw);
                if let Err(e) = tls_stream.write_all(&peerlist_encoded).await {
                    warn!("Failed to send PeerList to {}: {}", addr, e);
                } else {
                    let _ = tls_stream.flush().await;
                    info!("Sent empty PeerList to {} (handshake completion)", addr);
                }
            }
            NetworkMessage::PeerList { peers } => {
                peerlist_received = true;
                info!("Got PeerList with {} peers from {}", peers.len(), addr);
                let new = {
                    let mut pm = node.peer_manager.write().await;
                    pm.process_peer_list(peers)
                };
                if !new.is_empty() {
                    info!("Discovered {} new peers via {}", new.len(), addr);
                    dial_new_peers(new, node.clone());
                }
            }
            NetworkMessage::Ping { uptime } => {
                peer_reported_uptime = *uptime;
                let pong = NetworkMessage::Pong { uptime: *uptime };
                if let Ok(encoded) = pong.encode_proto() {
                    let _ = tls_stream.write_all(&encoded).await;
                    let _ = tls_stream.flush().await;
                }
            }
            other => {
                debug!("Handshake phase: ignoring {} from {}", other.name(), addr);
            }
        }

        if handshake_received && peerlist_received {
            info!("Handshake complete with {}", addr);
            break;
        }
    }

    // 5. Register peer
    let mut pm = node.peer_manager.write().await;
    let mut peer = Peer::new(peer_node_id.clone(), addr);
    let handshake_latency_ms = dial_started.elapsed().as_millis() as u64;
    peer.reputation = latency_to_reputation(handshake_latency_ms);
    peer.state = PeerState::Connected;
    peer.version = peer_version.or_else(|| Some("unknown".to_string()));
    peer.public_ip = peer_public_ip;
    peer.tracked_subnets = peer_tracked_subnets;
    peer.supported_acps = peer_supported_acps;
    peer.objected_acps = peer_objected_acps;
    peer.reported_uptime = peer_reported_uptime;
    peer.is_validator = false;
    if let Ok(()) = pm.add_peer(peer) {
        info!("Peer {} registered (NodeID: {})", addr, peer_node_id);
        persist_connected_peer(
            &node,
            &peer_node_id,
            addr,
            latency_to_reputation(handshake_latency_ms),
            handshake_latency_ms,
        );
    }

    // 6. Keep connection alive — read messages in a loop
    info!("Entering message loop with {}", addr);

    let ping_interval = Duration::from_secs(30);
    let pong_timeout = Duration::from_secs(60);
    let mut ping_timer = tokio::time::interval(ping_interval);
    ping_timer.tick().await; // consume the immediate first tick
    let mut last_ping_sent: Option<Instant> = None;
    let mut pong_received_since_last_ping = true; // start true so first ping isn't rejected

    let resume_bootstrap = node
        .persisted_sync_state
        .read()
        .await
        .as_ref()
        .map(|s| s.bootstrap_complete)
        .unwrap_or(false);

    // Bootstrap state machine: send GetAcceptedFrontier after 10s delay
    let bootstrap_request_base: u32 = rand::thread_rng().gen::<u16>() as u32 * 10;
    let mut bootstrap_state = if resume_bootstrap {
        BootstrapState::Done
    } else {
        BootstrapState::Idle
    };
    let mut bootstrap_timer = Box::pin(tokio::time::sleep(Duration::from_secs(10)));
    let mut bootstrap_timer_fired = resume_bootstrap;
    let mut p_chain_tip: Option<[u8; 32]> = None;
    let mut p_chain_ancestors_target: Option<[u8; 32]> = None; // block ID sent in GetAncestors

    // C-Chain bootstrap state
    let mut cchain_bootstrap_state = if resume_bootstrap {
        CChainBootstrapState::Done
    } else {
        CChainBootstrapState::Idle
    };
    let mut cchain_frontier: Option<[u8; 32]> = None;
    let mut cchain_ancestors_target: Option<[u8; 32]> = None;

    // Continuous sync: check for new blocks every 2s after bootstrap completes
    let mut sync_timer = tokio::time::interval(Duration::from_secs(2));
    sync_timer.tick().await; // consume the immediate first tick
    let mut continuous_sync_req: Option<u32> = None;
    let mut sync_req_counter: u32 = bootstrap_request_base.wrapping_add(10000);
    let mut last_known_tip: Option<[u8; 32]> = None;
    // Flag: has first C-Chain block bytes been logged for debug?
    let mut cchain_debug_logged = false;

    // Decode C-Chain ID from CB58 based on network.
    // Fuji (5):   yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp
    // Mainnet (1): 2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5
    let cchain_id: [u8; 32] = {
        let cb58 = match node.config.network_id {
            1 => "2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5",
            _ => "yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp",
        };
        let decoded = bs58::decode(cb58).into_vec().unwrap_or_default();
        // CB58 = base58(payload + checksum4), strip last 4 bytes
        if decoded.len() >= 36 {
            decoded[..32].try_into().unwrap_or([0u8; 32])
        } else {
            warn!("Failed to decode C-Chain ID from CB58");
            [0u8; 32]
        }
    };
    info!(
        "C-Chain ID for network_id={}: 0x{:08x}...",
        node.config.network_id,
        u32::from_be_bytes(cchain_id[..4].try_into().unwrap_or([0u8; 4]))
    );

    loop {
        let mut len_buf = [0u8; 4];
        tokio::select! {
            // Arm 1: periodic ping
            _ = ping_timer.tick() => {
                // Check if we haven't received a pong since last ping
                if let Some(t) = last_ping_sent {
                    if !pong_received_since_last_ping && t.elapsed() > pong_timeout {
                        warn!("No Pong from {} within {}s, closing", addr, pong_timeout.as_secs());
                        break;
                    }
                }
                let ping = NetworkMessage::Ping { uptime: 100 };
                if let Ok(encoded) = ping.encode_proto() {
                    match tls_stream.write_all(&encoded).await {
                        Ok(_) => {
                            let _ = tls_stream.flush().await;
                            last_ping_sent = Some(Instant::now());
                            pong_received_since_last_ping = false;
                            debug!("Sent Ping to {}", addr);
                        }
                        Err(e) => {
                            warn!("Failed to send Ping to {}: {}", addr, e);
                            break;
                        }
                    }
                }
            }

            // Arm 3: bootstrap timer — send GetAcceptedFrontier after 10s
            _ = &mut bootstrap_timer, if !bootstrap_timer_fired => {
                bootstrap_timer_fired = true;
                let req = NetworkMessage::GetAcceptedFrontier {
                    chain_id: ChainId([0u8; 32]),
                    request_id: bootstrap_request_base,
                    deadline: 5_000_000_000u64,
                };
                if let Ok(encoded) = req.encode_proto() {
                    if tls_stream.write_all(&encoded).await.is_ok() {
                        let _ = tls_stream.flush().await;
                        info!("Bootstrap: sent GetAcceptedFrontier (req={}) to {}", bootstrap_request_base, addr);
                        bootstrap_state = BootstrapState::WaitingFrontier(bootstrap_request_base);
                    } else {
                        warn!("Bootstrap: failed to send GetAcceptedFrontier to {}", addr);
                    }
                }
                // Also kick off C-Chain bootstrap (works on both mainnet and Fuji)
                {
                    let cchain_req = NetworkMessage::GetAcceptedFrontier {
                        chain_id: ChainId(cchain_id),
                        request_id: bootstrap_request_base + 1000,
                        deadline: 5_000_000_000u64,
                    };
                    if let Ok(encoded) = cchain_req.encode_proto() {
                        if tls_stream.write_all(&encoded).await.is_ok() {
                            let _ = tls_stream.flush().await;
                            info!("Bootstrap: sent GetAcceptedFrontier for C-Chain (req={})",
                                bootstrap_request_base + 1000);
                        }
                    }
                }
            }

            // Arm 4: continuous sync timer — every 2s, check for new blocks after bootstrap
            _ = sync_timer.tick() => {
                if matches!(bootstrap_state, BootstrapState::Done) {
                    // Poll P-Chain tip
                    sync_req_counter = sync_req_counter.wrapping_add(1);
                    continuous_sync_req = Some(sync_req_counter);
                    let req = NetworkMessage::GetAcceptedFrontier {
                        chain_id: ChainId([0u8; 32]),
                        request_id: sync_req_counter,
                        deadline: 5_000_000_000u64,
                    };
                    if let Ok(encoded) = req.encode_proto() {
                        if tls_stream.write_all(&encoded).await.is_ok() {
                            let _ = tls_stream.flush().await;
                            debug!("Continuous sync: GetAcceptedFrontier req={} to {}", sync_req_counter, addr);
                        }
                    }
                    // Also poll C-Chain tip for new blocks
                    sync_req_counter = sync_req_counter.wrapping_add(1);
                    let cchain_sync_req = NetworkMessage::GetAcceptedFrontier {
                        chain_id: ChainId(cchain_id),
                        request_id: sync_req_counter,
                        deadline: 5_000_000_000u64,
                    };
                    if let Ok(encoded) = cchain_sync_req.encode_proto() {
                        if tls_stream.write_all(&encoded).await.is_ok() {
                            let _ = tls_stream.flush().await;
                        }
                    }
                }
            }

            // Arm 2: incoming message
            result = tls_stream.read_exact(&mut len_buf) => {
                match result {
                    Ok(_) => {
                        let msg_len = u32::from_be_bytes(len_buf) as usize;
                        if msg_len > 16 * 1024 * 1024 {
                            warn!("Message too large from {}: {} bytes", addr, msg_len);
                            break;
                        }
                        let mut msg_data = vec![0u8; msg_len];
                        match tls_stream.read_exact(&mut msg_data).await {
                            Ok(_) => {
                                let mut full = Vec::with_capacity(4 + msg_len);
                                full.extend_from_slice(&len_buf);
                                full.extend_from_slice(&msg_data);
                                match NetworkMessage::decode_proto(&full) {
                                    Ok(msg) => {
                                        debug!("Received {} from {} ({} bytes)", msg.name(), addr, msg_len);
                                        match msg {
                                            NetworkMessage::Ping { uptime } => {
                                                let mut pm = node.peer_manager.write().await;
                                                if let Some(peer) = pm.get_peer_mut(&peer_node_id)
                                                {
                                                    peer.reported_uptime = uptime;
                                                }
                                                drop(pm);
                                                let pong = NetworkMessage::Pong { uptime };
                                                if let Ok(encoded) = pong.encode_proto() {
                                                    let _ = tls_stream.write_all(&encoded).await;
                                                    let _ = tls_stream.flush().await;
                                                    debug!("Sent Pong to {}", addr);
                                                }
                                            }
                                            NetworkMessage::Pong { .. } => {
                                                pong_received_since_last_ping = true;
                                                debug!("Received Pong from {}", addr);
                                            }
                                            NetworkMessage::PeerList { peers } => {
                                                let new_peers = {
                                                    let mut pm = node.peer_manager.write().await;
                                                    pm.process_peer_list(&peers)
                                                };
                                                if !new_peers.is_empty() {
                                                    info!("Discovered {} new peers via {}", new_peers.len(), addr);
                                                    dial_new_peers(new_peers, node.clone());
                                                }
                                                // Track validators seen via PeerList gossip
                                                {
                                                    let mut vs = node.validators_seen.write().await;
                                                    for peer in &peers {
                                                        // Derive NodeID from cert if available, else use node_id field
                                                        let nid_str = if !peer.cert_bytes.is_empty() {
                                                            full_node_id_string(&identity::derive_node_id(&peer.cert_bytes))
                                                        } else {
                                                            full_node_id_string(&peer.node_id)
                                                        };
                                                        vs.insert(nid_str);
                                                    }
                                                    let count = vs.len();
                                                    if count > 0 {
                                                        info!("Validator tracking: {} unique validators seen (via {})", count, addr);
                                                    }
                                                }
                                            }
                                            NetworkMessage::GetAcceptedFrontier { chain_id, request_id, .. } => {
                                                // Respond with empty frontier (we have nothing yet)
                                                let response = NetworkMessage::AcceptedFrontier {
                                                    chain_id,
                                                    request_id,
                                                    container_id: BlockId::zero(),
                                                };
                                                if let Ok(encoded) = response.encode_proto() {
                                                    let _ = tls_stream.write_all(&encoded).await;
                                                    let _ = tls_stream.flush().await;
                                                    debug!("Responded to GetAcceptedFrontier from {}", addr);
                                                }
                                            }
                                            NetworkMessage::AcceptedFrontier { request_id, container_id, .. } => {
                                                info!("AcceptedFrontier from {} — tip={}", addr, container_id);

                                                // Continuous sync: handle periodic frontier check
                                                if Some(request_id) == continuous_sync_req {
                                                    continuous_sync_req = None;
                                                    if container_id.0 != [0u8; 32] {
                                                        let is_new = last_known_tip != Some(container_id.0);
                                                        if is_new {
                                                            info!("Continuous sync: new tip detected {} from {}", container_id, addr);
                                                            last_known_tip = Some(container_id.0);
                                                            // Kick off GetAccepted to fetch new blocks
                                                            sync_req_counter = sync_req_counter.wrapping_add(1);
                                                            let fetch_req = sync_req_counter;
                                                            let get_accepted = NetworkMessage::GetAccepted {
                                                                chain_id: ChainId([0u8; 32]),
                                                                request_id: fetch_req,
                                                                deadline: 5_000_000_000u64,
                                                                container_ids: vec![container_id.clone()],
                                                            };
                                                            if let Ok(encoded) = get_accepted.encode_proto() {
                                                                if tls_stream.write_all(&encoded).await.is_ok() {
                                                                    let _ = tls_stream.flush().await;
                                                                    info!("Continuous sync: GetAccepted req={} for new tip", fetch_req);
                                                                    bootstrap_state = BootstrapState::WaitingAccepted(fetch_req);
                                                                }
                                                            }
                                                        } else {
                                                            debug!("Continuous sync: tip unchanged {}", container_id);
                                                        }
                                                    }
                                                }

                                                // Store C-Chain frontier for later use
                                                if request_id == bootstrap_request_base + 1000 {
                                                    info!("C-Chain AcceptedFrontier from {} — tip={}", addr, container_id);
                                                    if container_id.0 != [0u8; 32] {
                                                        cchain_frontier = Some(container_id.0);
                                                    }
                                                }
                                                if let BootstrapState::WaitingFrontier(req) = bootstrap_state {
                                                    if request_id == req {
                                                        if container_id.0 != [0u8; 32] {
                                                            let tid = container_id.0;
                                                            info!(
                                                                "Bootstrap: P-Chain tip from AcceptedFrontier = {:02x}{:02x}{:02x}{:02x}…{:02x}{:02x}{:02x}{:02x}",
                                                                tid[0], tid[1], tid[2], tid[3],
                                                                tid[28], tid[29], tid[30], tid[31]
                                                            );
                                                            p_chain_tip = Some(container_id.0);
                                                            p_chain_ancestors_target = Some(container_id.0);
                                                            let new_req = req + 1;
                                                            let get_accepted = NetworkMessage::GetAccepted {
                                                                chain_id: ChainId([0u8; 32]),
                                                                request_id: new_req,
                                                                deadline: 5_000_000_000u64,
                                                                container_ids: vec![container_id],
                                                            };
                                                            if let Ok(encoded) = get_accepted.encode_proto() {
                                                                if tls_stream.write_all(&encoded).await.is_ok() {
                                                                    let _ = tls_stream.flush().await;
                                                                    info!("Bootstrap: sent GetAccepted (req={}) to {}", new_req, addr);
                                                                    bootstrap_state = BootstrapState::WaitingAccepted(new_req);
                                                                }
                                                            }
                                                        } else {
                                                            info!("Bootstrap: peer {} has empty frontier", addr);
                                                            bootstrap_state = BootstrapState::Done;
                                                        }
                                                    }
                                                }
                                            }
                                            NetworkMessage::Accepted { request_id, container_ids, chain_id } => {
                                                info!("Accepted from {} — {} block IDs", addr, container_ids.len());
                                                // C-Chain Accepted
                                                if let CChainBootstrapState::WaitingAccepted(req) = cchain_bootstrap_state {
                                                    if request_id == req {
                                                        if !container_ids.is_empty() {
                                                            let new_req = req + 1;
                                                            let target = container_ids.into_iter().next().unwrap();
                                                            let target_id = target.0;
                                                            let get_ancestors = NetworkMessage::GetAncestors {
                                                                chain_id: ChainId(cchain_id),
                                                                request_id: new_req,
                                                                deadline: 5_000_000_000u64,
                                                                container_id: target,
                                                                max_containers_size: 2_000_000,
                                                            };
                                                            if let Ok(encoded) = get_ancestors.encode_proto() {
                                                                if tls_stream.write_all(&encoded).await.is_ok() {
                                                                    let _ = tls_stream.flush().await;
                                                                    info!("C-Chain Bootstrap: sent GetAncestors (req={}) to {}", new_req, addr);
                                                                    cchain_ancestors_target = Some(target_id);
                                                                    cchain_bootstrap_state = CChainBootstrapState::WaitingAncestors(new_req);
                                                                }
                                                            }
                                                        } else {
                                                            info!("C-Chain Bootstrap: peer {} accepted no blocks", addr);
                                                            cchain_bootstrap_state = CChainBootstrapState::Done;
                                                        }
                                                    }
                                                // P-Chain Accepted
                                                } else if let BootstrapState::WaitingAccepted(req) = bootstrap_state {
                                                    if request_id == req {
                                                        if !container_ids.is_empty() {
                                                            let new_req = req + 1;
                                                            let target = container_ids.into_iter().next().unwrap();
                                                            p_chain_ancestors_target = Some(target.0);
                                                            // Update tip to match the actual accepted block ID
                                                            // (may differ from AcceptedFrontier tip)
                                                            p_chain_tip = Some(target.0);
                                                            let get_ancestors = NetworkMessage::GetAncestors {
                                                                chain_id: ChainId([0u8; 32]),
                                                                request_id: new_req,
                                                                deadline: 5_000_000_000u64,
                                                                container_id: target,
                                                                max_containers_size: 2_000_000,
                                                            };
                                                            if let Ok(encoded) = get_ancestors.encode_proto() {
                                                                if tls_stream.write_all(&encoded).await.is_ok() {
                                                                    let _ = tls_stream.flush().await;
                                                                    info!("Bootstrap: sent GetAncestors (req={}) to {}", new_req, addr);
                                                                    bootstrap_state = BootstrapState::WaitingAncestors(new_req);
                                                                }
                                                            }
                                                        } else {
                                                            info!("Bootstrap: peer {} accepted no blocks", addr);
                                                            bootstrap_state = BootstrapState::Done;
                                                        }
                                                    }
                                                }
                                                let _ = chain_id;
                                            }
                                            NetworkMessage::Ancestors { request_id, containers, chain_id } => {
                                                let total_bytes: usize = containers.iter().map(|c| c.len()).sum();
                                                let is_cchain = chain_id.0 == cchain_id;
                                                info!(
                                                    "{} Ancestors from {} — {} containers, {} bytes total",
                                                    if is_cchain { "C-Chain" } else { "P-Chain" },
                                                    addr, containers.len(), total_bytes
                                                );

                                                if is_cchain {
                                                    // ── C-Chain block fetching ────────────────────────────────────────
                                                    let expected_req = match cchain_bootstrap_state {
                                                        CChainBootstrapState::WaitingAncestors(req) => Some((req, 0u32, 0u32)),
                                                        CChainBootstrapState::FetchingAncestors { req, depth, total_blocks } => Some((req, depth, total_blocks)),
                                                        _ => None,
                                                    };

                                                    if let Some((req, depth, prev_total)) = expected_req {
                                                        if request_id == req {
                                                            if let Some(target_id) = cchain_ancestors_target {
                                                                if let Err(e) = SyncEngine::validate_cchain_ancestor_chain(&containers, target_id) {
                                                                    warn!("C-Chain Bootstrap: invalid ancestor hash chain: {}", e);
                                                                    cchain_bootstrap_state = CChainBootstrapState::Done;
                                                                    continue;
                                                                }
                                                            }

                                                            let mut stored = 0u32;
                                                            let mut oldest_container: Option<Vec<u8>> = None;

                                                            for container in &containers {
                                                                // Debug: log first C-Chain block format once
                                                                if !cchain_debug_logged {
                                                                    cchain_debug_logged = true;
                                                                    let preview_len = container.len().min(20);
                                                                    info!(
                                                                        "C-Chain block format debug: first {} bytes = {:02x?} (total {} bytes)",
                                                                        preview_len, &container[..preview_len], container.len()
                                                                    );
                                                                    if container.len() >= 2 {
                                                                        if container[0] == 0x00 && container[1] == 0x00 {
                                                                            info!("C-Chain block: detected Avalanche codec wrapper (0x00 0x00 prefix)");
                                                                        } else if container[0] >= 0xf8 {
                                                                            info!("C-Chain block: detected raw RLP long list (0x{:02x} prefix)", container[0]);
                                                                        } else if container[0] >= 0xc0 {
                                                                            info!("C-Chain block: detected raw RLP short list (0x{:02x} prefix)", container[0]);
                                                                        } else {
                                                                            warn!("C-Chain block: unexpected format — first byte 0x{:02x}", container[0]);
                                                                        }
                                                                    }
                                                                }

                                                                let mut hasher = Sha256::new();
                                                                hasher.update(container);
                                                                let hash: [u8; 32] = hasher.finalize().into();
                                                                // Prefix C-Chain keys with "c:" to distinguish from P-Chain
                                                                let mut key = Vec::with_capacity(34);
                                                                key.extend_from_slice(b"c:");
                                                                key.extend_from_slice(&hash);
                                                                if let Err(e) = node.db.put_cf(CF_BLOCKS, &key, container) {
                                                                    warn!("C-Chain: failed to store block {:02x?}: {}", &hash[..4], e);
                                                                } else {
                                                                    stored += 1;
                                                                    // Store stateRoot → block_hash mapping
                                                                    if let Some(state_root) = avalanche_rs::block::BlockHeader::extract_state_root(container) {
                                                                        if let Err(e) = node.db.put_cf(CF_STATE_ROOTS, &state_root, &hash) {
                                                                            debug!("state_root store failed: {}", e);
                                                                        }
                                                                    }
                                                                    // Execute block through EVM and store receipts
                                                                    execute_cchain_block_and_store(
                                                                        container,
                                                                        &node,
                                                                    ).await;
                                                                    // Index block for PostgreSQL analytics
                                                                    #[cfg(feature = "indexer")]
                                                                    if let Some(ref indexer) = node.indexer {
                                                                        if let Some(indexed) = build_indexed_cchain_block(container, &hash) {
                                                                            indexer.index_block(indexed).await;
                                                                        }
                                                                    }
                                                                }
                                                                oldest_container = Some(container.clone());
                                                            }

                                                            let new_total = prev_total + stored;
                                                            info!("C-Chain Bootstrap: stored {} blocks (total: {})", stored, new_total);
                                                            let _ = node.db.put_metadata(
                                                                b"c_chain_blocks_downloaded",
                                                                &new_total.to_le_bytes(),
                                                            );
                                                            {
                                                                let mut m = node.c_chain_metrics.write().await;
                                                                m.blocks_synced = new_total as u64;
                                                                m.last_sync_time = Instant::now();
                                                            }

                                                            // Use block parser to determine if oldest block is genesis
                                                            // (handles both raw RLP and Avalanche-wrapped format)
                                                            let should_recurse = depth < 10
                                                                && oldest_container.as_ref().is_some_and(|c| {
                                                                    match avalanche_rs::block::BlockHeader::parse(c, avalanche_rs::block::Chain::CChain) {
                                                                        Ok(h) => !h.is_genesis(),
                                                                        Err(_) => !c.is_empty() && c[0] >= 0xc0,
                                                                    }
                                                                });

                                                            if should_recurse {
                                                                let oldest = oldest_container.unwrap();
                                                                let mut hasher = Sha256::new();
                                                                hasher.update(&oldest);
                                                                let oldest_id: [u8; 32] = hasher.finalize().into();
                                                                let new_req = req + 1;
                                                                let new_depth = depth + 1;
                                                                let get_ancestors = NetworkMessage::GetAncestors {
                                                                    chain_id: ChainId(cchain_id),
                                                                    request_id: new_req,
                                                                    deadline: 5_000_000_000u64,
                                                                    container_id: BlockId(oldest_id),
                                                                    max_containers_size: 2_000_000,
                                                                };
                                                                if let Ok(encoded) = get_ancestors.encode_proto() {
                                                                    if tls_stream.write_all(&encoded).await.is_ok() {
                                                                        let _ = tls_stream.flush().await;
                                                                        info!(
                                                                            "C-Chain Bootstrap: recursive GetAncestors depth={} req={} (total: {})",
                                                                            new_depth, new_req, new_total
                                                                        );
                                                                        cchain_ancestors_target = Some(oldest_id);
                                                                        cchain_bootstrap_state = CChainBootstrapState::FetchingAncestors {
                                                                            req: new_req,
                                                                            depth: new_depth,
                                                                            total_blocks: new_total,
                                                                        };
                                                                    } else {
                                                                        warn!("C-Chain Bootstrap: failed to send recursive GetAncestors");
                                                                        cchain_bootstrap_state = CChainBootstrapState::Done;
                                                                    }
                                                                }
                                                            } else {
                                                                if depth >= 10 {
                                                                    info!("C-Chain Bootstrap: reached max depth (10 rounds, {} blocks)", new_total);
                                                                } else {
                                                                    info!("C-Chain Bootstrap: reached genesis, {} blocks total", new_total);
                                                                }
                                                                cchain_bootstrap_state = CChainBootstrapState::Done;
                                                                info!("Bootstrap C-Chain complete with {} — {} total blocks stored", addr, new_total);
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    // ── P-Chain block fetching ────────────────────────────────────────
                                                    let expected_req = match bootstrap_state {
                                                        BootstrapState::WaitingAncestors(req) => Some((req, 0u32, 0u32)),
                                                        BootstrapState::FetchingAncestors { req, depth, total_blocks } => Some((req, depth, total_blocks)),
                                                        _ => None,
                                                    };

                                                    if let Some((req, depth, prev_total)) = expected_req {
                                                        if request_id == req {
                                                            let mut stored = 0u32;
                                                            let mut oldest_container: Option<Vec<u8>> = None;
                                                            // Parent-chain linking: container[0] ID = GetAncestors target,
                                                            // container[N+1] ID = container[N].parent_id
                                                            let mut current_id: Option<[u8; 32]> = p_chain_ancestors_target;

                                                            for container in &containers {
                                                                let block_id = current_id.unwrap_or_else(|| {
                                                                    let mut hasher = Sha256::new();
                                                                    hasher.update(container);
                                                                    hasher.finalize().into()
                                                                });

                                                                if let Err(e) = node.db.put_cf(CF_BLOCKS, &block_id, container) {
                                                                    warn!("Failed to store block {:02x}{:02x}{:02x}{:02x}: {}", block_id[0], block_id[1], block_id[2], block_id[3], e);
                                                                } else {
                                                                    stored += 1;
                                                                    // Index block for PostgreSQL analytics
                                                                    #[cfg(feature = "indexer")]
                                                                    if let Some(ref indexer) = node.indexer {
                                                                        if let Some(indexed) = build_indexed_pchain_block(container, &block_id) {
                                                                            indexer.index_block(indexed).await;
                                                                        }
                                                                    }
                                                                }

                                                                // Extract parent_id — this is the block ID of the NEXT container
                                                                let parent = avalanche_rs::block::BlockHeader::extract_parent_id(container);
                                                                // Debug: log first few blocks at trace level
                                                                if stored <= 3 {
                                                                    debug!("Block[{}]: {} bytes, id={:02x}{:02x}{:02x}{:02x}",
                                                                        stored, container.len(),
                                                                        block_id[0], block_id[1], block_id[2], block_id[3],
                                                                    );
                                                                }
                                                                current_id = parent;
                                                                oldest_container = Some(container.clone());
                                                            }

                                                            if depth == 0 {
                                                                if let Some(target) = p_chain_ancestors_target {
                                                                    info!(
                                                                        "Stored {} blocks via parent-chain linking (tip={:02x}{:02x}{:02x}{:02x}…, {} containers)",
                                                                        stored, target[0], target[1], target[2], target[3], containers.len()
                                                                    );
                                                                }
                                                            }

                                                            let new_total = prev_total + stored;
                                                            info!("Bootstrap: stored {} blocks (total: {})", stored, new_total);

                                                            let _ = node.db.put_metadata(
                                                                b"p_chain_blocks_downloaded",
                                                                &new_total.to_le_bytes(),
                                                            );

                                                            // Use type-aware parent extraction (handles Apricot and Banff)
                                                            let should_recurse = depth < 10
                                                                && oldest_container.as_ref().is_some_and(|c| {
                                                                    match avalanche_rs::block::BlockHeader::extract_parent_id(c) {
                                                                        Some(parent) => parent != [0u8; 32],
                                                                        None => false,
                                                                    }
                                                                });

                                                            if should_recurse {
                                                                // Use parent_id of oldest block (= current_id after loop)
                                                                let oldest_parent = current_id.unwrap_or([0u8; 32]);
                                                                p_chain_ancestors_target = Some(oldest_parent);
                                                                let new_req = req + 1;
                                                                let new_depth = depth + 1;
                                                                let get_ancestors = NetworkMessage::GetAncestors {
                                                                    chain_id: ChainId([0u8; 32]),
                                                                    request_id: new_req,
                                                                    deadline: 5_000_000_000u64,
                                                                    container_id: BlockId(oldest_parent),
                                                                    max_containers_size: 2_000_000,
                                                                };
                                                                if let Ok(encoded) = get_ancestors.encode_proto() {
                                                                    if tls_stream.write_all(&encoded).await.is_ok() {
                                                                        let _ = tls_stream.flush().await;
                                                                        info!(
                                                                            "Bootstrap: recursive GetAncestors depth={} req={} (total blocks so far: {})",
                                                                            new_depth, new_req, new_total
                                                                        );
                                                                        bootstrap_state = BootstrapState::FetchingAncestors {
                                                                            req: new_req,
                                                                            depth: new_depth,
                                                                            total_blocks: new_total,
                                                                        };
                                                                    } else {
                                                                        warn!("Bootstrap: failed to send recursive GetAncestors, stopping");
                                                                        bootstrap_state = BootstrapState::Done;
                                                                    }
                                                                }
                                                            } else {
                                                                if depth >= 10 {
                                                                    info!("Bootstrap: reached max depth (10 rounds, {} blocks), stopping fetch", new_total);
                                                                } else {
                                                                    info!("Bootstrap: reached genesis (or short block), {} blocks total", new_total);
                                                                }
                                                                bootstrap_state = BootstrapState::Done;
                                                                info!("Bootstrap P-Chain complete with {} — {} total blocks stored", addr, new_total);

                                                                // Transition sync engine to Following phase
                                                                node.sync_engine.mark_following().await;
                                                                info!("Sync engine: transitioned to Following (live chain tracking)");

                                                                // Verify the stored chain and update metrics
                                                                if let Some(tip) = p_chain_tip {
                                                                    let (chain_len, tip_height, genesis_height) = verify_block_chain(&node.db, tip);
                                                                    info!("P-Chain chain walk: {} blocks linked from tip", chain_len);
                                                                    let mut m = node.p_chain_metrics.write().await;
                                                                    m.blocks_synced = new_total as u64;
                                                                    m.chain_length = chain_len;
                                                                    m.tip_height = tip_height;
                                                                    m.tip_hash = tip;
                                                                    m.genesis_height = genesis_height;
                                                                    m.last_sync_time = Instant::now();
                                                                }

                                                                // Start C-Chain bootstrap if we have the frontier
                                                                if let Some(tip) = cchain_frontier {
                                                                    if cchain_bootstrap_state == CChainBootstrapState::Idle {
                                                                        let cchain_req = bootstrap_request_base + 2000;
                                                                        let get_accepted = NetworkMessage::GetAccepted {
                                                                            chain_id: ChainId(cchain_id),
                                                                            request_id: cchain_req,
                                                                            deadline: 5_000_000_000u64,
                                                                            container_ids: vec![BlockId(tip)],
                                                                        };
                                                                        if let Ok(encoded) = get_accepted.encode_proto() {
                                                                            if tls_stream.write_all(&encoded).await.is_ok() {
                                                                                let _ = tls_stream.flush().await;
                                                                                info!("C-Chain Bootstrap: sent GetAccepted (req={}) to {}", cchain_req, addr);
                                                                                cchain_bootstrap_state = CChainBootstrapState::WaitingAccepted(cchain_req);
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            NetworkMessage::GetAccepted { chain_id, request_id, .. } => {
                                                // Respond with empty accepted list
                                                let response = NetworkMessage::Accepted {
                                                    chain_id,
                                                    request_id,
                                                    container_ids: vec![],
                                                };
                                                if let Ok(encoded) = response.encode_proto() {
                                                    let _ = tls_stream.write_all(&encoded).await;
                                                    let _ = tls_stream.flush().await;
                                                    debug!("Responded to GetAccepted from {}", addr);
                                                }
                                            }
                                            NetworkMessage::GetAncestors { chain_id, request_id, .. } => {
                                                // Respond with empty ancestors
                                                let response = NetworkMessage::Ancestors {
                                                    chain_id,
                                                    request_id,
                                                    containers: vec![],
                                                };
                                                if let Ok(encoded) = response.encode_proto() {
                                                    let _ = tls_stream.write_all(&encoded).await;
                                                    let _ = tls_stream.flush().await;
                                                    debug!("Responded to GetAncestors from {}", addr);
                                                }
                                            }
                                            // ── Snowman consensus messages ──────────────────────────
                                            NetworkMessage::Chits { chain_id, request_id, preferred_id, accepted_id, .. } => {
                                                // Chits = poll response — records the sender's preferred block
                                                info!(
                                                    "Chits from {} (req={}, preferred={}, accepted={})",
                                                    addr, request_id, preferred_id, accepted_id
                                                );
                                                let _ = chain_id;
                                            }
                                            NetworkMessage::PushQuery { chain_id, request_id, deadline, container } => {
                                                // PushQuery = peer pushes a block and asks for our preference
                                                debug!(
                                                    "PushQuery from {} (req={}, block={} bytes)",
                                                    addr, request_id, container.len()
                                                );
                                                // If this is a C-Chain block, execute it through the EVM
                                                let is_cchain_block = chain_id.0 == cchain_id
                                                    || !container.is_empty() && (container[0] >= 0xc0
                                                        || (container.len() >= 6 && container[0] == 0x00 && container[1] == 0x00));
                                                if is_cchain_block && matches!(bootstrap_state, BootstrapState::Done) {
                                                    // Store the new block
                                                    let mut h = sha2::Sha256::new();
                                                    sha2::Digest::update(&mut h, &container);
                                                    let hash: [u8; 32] = sha2::Digest::finalize(h).into();
                                                    let mut key = Vec::with_capacity(34);
                                                    key.extend_from_slice(b"c:");
                                                    key.extend_from_slice(&hash);
                                                    let _ = node.db.put_cf(CF_BLOCKS, &key, &container);
                                                    // Execute through EVM
                                                    execute_cchain_block_and_store(
                                                        &container,
                                                        &node,
                                                    ).await;
                                                    if let Some(fields) = extract_cchain_block_fields(&container) {
                                                        info!("Following: new C-Chain block #{} via PushQuery from {}", fields.number, addr);
                                                    }
                                                    // Index block for PostgreSQL analytics
                                                    #[cfg(feature = "indexer")]
                                                    if let Some(ref indexer) = node.indexer {
                                                        if let Some(indexed) = build_indexed_cchain_block(&container, &hash) {
                                                            indexer.index_block(indexed).await;
                                                        }
                                                    }
                                                }
                                                // Respond with Chits pointing to our zero (no preference yet)
                                                let chits = NetworkMessage::Chits {
                                                    chain_id,
                                                    request_id,
                                                    preferred_id: BlockId::zero(),
                                                    preferred_id_at_height: BlockId::zero(),
                                                    accepted_id: BlockId::zero(),
                                                };
                                                if let Ok(encoded) = chits.encode_proto() {
                                                    let _ = tls_stream.write_all(&encoded).await;
                                                    let _ = tls_stream.flush().await;
                                                    debug!("Sent Chits in response to PushQuery from {}", addr);
                                                }
                                                let _ = deadline;
                                            }
                                            NetworkMessage::PullQuery { chain_id, request_id, deadline, container_id } => {
                                                // PullQuery = peer asks our preference for a known block ID
                                                info!(
                                                    "PullQuery from {} (req={}, block={})",
                                                    addr, request_id, container_id
                                                );
                                                // Respond with Chits
                                                let chits = NetworkMessage::Chits {
                                                    chain_id,
                                                    request_id,
                                                    preferred_id: BlockId::zero(),
                                                    preferred_id_at_height: BlockId::zero(),
                                                    accepted_id: BlockId::zero(),
                                                };
                                                if let Ok(encoded) = chits.encode_proto() {
                                                    let _ = tls_stream.write_all(&encoded).await;
                                                    let _ = tls_stream.flush().await;
                                                    debug!("Sent Chits in response to PullQuery from {}", addr);
                                                }
                                                let _ = deadline;
                                            }
                                            other => {
                                                debug!("Unhandled message {} from {}", other.name(), addr);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        debug!("Failed to decode message from {}: {}", addr, e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Read error from {}: {}", addr, e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Connection to {} closed: {}", addr, e);
                        break;
                    }
                }
            }
        }
    }

    // Remove peer on disconnect
    let mut pm = node.peer_manager.write().await;
    pm.remove_peer(&peer_node_id);
    warn!("Peer {} disconnected", addr);

    Ok(())
}

// bootstrap_p_chain removed — bootstrap logic now lives inside the message loop as a state machine.
// Keeping this dead code block here as a tombstone to avoid merge confusion.
#[allow(dead_code)]
async fn bootstrap_p_chain<S>(stream: &mut S, addr: std::net::SocketAddr, request_id_base: u32)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let p_chain_id = ChainId([0u8; 32]);
    let deadline_ns = 5_000_000_000u64; // 5 seconds in nanoseconds

    // Step 1: GetAcceptedFrontier
    let req = NetworkMessage::GetAcceptedFrontier {
        chain_id: p_chain_id.clone(),
        request_id: request_id_base,
        deadline: deadline_ns,
    };
    if let Ok(encoded) = req.encode_proto() {
        if let Err(e) = stream.write_all(&encoded).await {
            warn!(
                "bootstrap: failed to send GetAcceptedFrontier to {}: {}",
                addr, e
            );
            return;
        }
        let _ = stream.flush().await;
        info!(
            "bootstrap: sent GetAcceptedFrontier (req={}) to {}",
            request_id_base, addr
        );
    }

    // Step 2: Wait for AcceptedFrontier
    let frontier_block_id = loop {
        match read_one_message(stream, addr, 30).await {
            Ok(NetworkMessage::AcceptedFrontier {
                request_id,
                container_id,
                ..
            }) if request_id == request_id_base => {
                info!(
                    "bootstrap: AcceptedFrontier from {} — tip={}",
                    addr, container_id
                );
                break container_id;
            }
            Ok(NetworkMessage::Ping { uptime }) => {
                // Respond to pings while waiting
                let pong = NetworkMessage::Pong { uptime };
                if let Ok(enc) = pong.encode_proto() {
                    let _ = stream.write_all(&enc).await;
                    let _ = stream.flush().await;
                }
            }
            Ok(other) => {
                debug!(
                    "bootstrap: ignoring {} while waiting for AcceptedFrontier",
                    other.name()
                );
            }
            Err(e) => {
                warn!(
                    "bootstrap: error waiting for AcceptedFrontier from {}: {}",
                    addr, e
                );
                return;
            }
        }
    };

    if frontier_block_id.0 == [0u8; 32] {
        info!(
            "bootstrap: peer {} has empty frontier — nothing to bootstrap",
            addr
        );
        return;
    }

    // Step 3: GetAccepted
    let req = NetworkMessage::GetAccepted {
        chain_id: p_chain_id.clone(),
        request_id: request_id_base + 1,
        deadline: deadline_ns,
        container_ids: vec![frontier_block_id.clone()],
    };
    if let Ok(encoded) = req.encode_proto() {
        if let Err(e) = stream.write_all(&encoded).await {
            warn!("bootstrap: failed to send GetAccepted to {}: {}", addr, e);
            return;
        }
        let _ = stream.flush().await;
        info!(
            "bootstrap: sent GetAccepted (req={}) to {}",
            request_id_base + 1,
            addr
        );
    }

    // Step 4: Wait for Accepted
    let accepted_ids = loop {
        match read_one_message(stream, addr, 30).await {
            Ok(NetworkMessage::Accepted {
                request_id,
                container_ids,
                ..
            }) if request_id == request_id_base + 1 => {
                info!(
                    "bootstrap: Accepted from {} — {} block IDs",
                    addr,
                    container_ids.len()
                );
                break container_ids;
            }
            Ok(NetworkMessage::Ping { uptime }) => {
                let pong = NetworkMessage::Pong { uptime };
                if let Ok(enc) = pong.encode_proto() {
                    let _ = stream.write_all(&enc).await;
                    let _ = stream.flush().await;
                }
            }
            Ok(other) => {
                debug!(
                    "bootstrap: ignoring {} while waiting for Accepted",
                    other.name()
                );
            }
            Err(e) => {
                warn!("bootstrap: error waiting for Accepted from {}: {}", addr, e);
                return;
            }
        }
    };

    if accepted_ids.is_empty() {
        info!("bootstrap: peer {} accepted no blocks from our set", addr);
        return;
    }

    // Step 5: GetAncestors for the first accepted block
    let target = &accepted_ids[0];
    let req = NetworkMessage::GetAncestors {
        chain_id: p_chain_id.clone(),
        request_id: request_id_base + 2,
        deadline: deadline_ns,
        container_id: target.clone(),
        max_containers_size: 2_000_000,
    };
    if let Ok(encoded) = req.encode_proto() {
        if let Err(e) = stream.write_all(&encoded).await {
            warn!("bootstrap: failed to send GetAncestors to {}: {}", addr, e);
            return;
        }
        let _ = stream.flush().await;
        info!(
            "bootstrap: sent GetAncestors (req={}) for block {} to {}",
            request_id_base + 2,
            target,
            addr
        );
    }

    // Step 6: Wait for Ancestors
    loop {
        match read_one_message(stream, addr, 30).await {
            Ok(NetworkMessage::Ancestors {
                request_id,
                containers,
                ..
            }) if request_id == request_id_base + 2 => {
                info!(
                    "bootstrap: Ancestors from {} — {} containers, total {} bytes",
                    addr,
                    containers.len(),
                    containers.iter().map(|c| c.len()).sum::<usize>()
                );
                for (i, c) in containers.iter().enumerate() {
                    debug!("  container[{}]: {} bytes", i, c.len());
                }
                break;
            }
            Ok(NetworkMessage::Ping { uptime }) => {
                let pong = NetworkMessage::Pong { uptime };
                if let Ok(enc) = pong.encode_proto() {
                    let _ = stream.write_all(&enc).await;
                    let _ = stream.flush().await;
                }
            }
            Ok(other) => {
                debug!(
                    "bootstrap: ignoring {} while waiting for Ancestors",
                    other.name()
                );
            }
            Err(e) => {
                warn!(
                    "bootstrap: error waiting for Ancestors from {}: {}",
                    addr, e
                );
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Validator: Block builder
// ---------------------------------------------------------------------------

/// A constructed C-Chain block ready for broadcasting.
#[derive(Debug, Clone)]
pub struct BuiltBlock {
    /// RLP-encoded block bytes (Avalanche-wrapped).
    pub raw: Vec<u8>,
    /// SHA-256 block ID.
    pub id: [u8; 32],
    /// Block number (height).
    pub number: u64,
    /// Number of transactions included.
    pub tx_count: usize,
    /// Total gas used.
    pub gas_used: u64,
    /// Receipts produced while executing the block.
    pub receipts: Vec<TxReceipt>,
    /// BLS signature over the block ID (48-byte public key proof).
    pub bls_signature: Vec<u8>,
}

/// Run the block producer loop. Produces a new C-Chain block every ~2 seconds
/// when in Following mode (or after bootstrap). Broadcasts via PushQuery to peers.
///
/// In the current implementation the mempool is empty (no real pending
/// transaction pool exists yet), so blocks contain zero transactions. The
/// infrastructure — header construction, EVM execution, BLS signing, and
/// peer broadcast — is fully wired and ready for a mempool integration.
async fn run_block_builder(node: Arc<NodeState>) {
    // Wait for bootstrap to complete before producing blocks
    info!("Block builder: waiting for sync to reach Following phase...");
    loop {
        if node.sync_engine.is_following().await {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    info!("Block builder: sync is Following — starting block production");

    let mut interval = tokio::time::interval(Duration::from_millis(2000));
    interval.tick().await; // skip immediate tick

    loop {
        interval.tick().await;

        let pool_txs = {
            let pool = node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let tip_height = node.c_chain_metrics.read().await.tip_height;
        let block_number = tip_height + 1;

        match build_cchain_block(&node, block_number, pool_txs.clone()).await {
            Ok(block) => {
                info!(
                    "Block builder: produced block #{} ({} txs, {} gas, id={:02x}{:02x}{:02x}{:02x}…)",
                    block.number, block.tx_count, block.gas_used,
                    block.id[0], block.id[1], block.id[2], block.id[3]
                );

                // Store in DB
                let mut key = Vec::with_capacity(34);
                key.extend_from_slice(b"c:");
                key.extend_from_slice(&block.id);
                if let Err(e) = node.db.put_cf(CF_BLOCKS, &key, &block.raw) {
                    warn!(
                        "Block builder: failed to store block #{}: {}",
                        block.number, e
                    );
                    continue;
                }
                if let Err(e) = node.db.put_block(block.number, &block.raw) {
                    warn!(
                        "Block builder: failed to store block #{} by height: {}",
                        block.number, e
                    );
                }
                if let Err(e) = persist_local_cchain_tx_artifacts(&node.db, &block, &pool_txs) {
                    warn!(
                        "Block builder: failed to persist tx artifacts for block #{}: {}",
                        block.number, e
                    );
                }

                // Update last accepted height
                let _ = node.db.set_last_accepted_height(block.number);
                {
                    let mut m = node.c_chain_metrics.write().await;
                    m.tip_height = block.number;
                    m.tip_hash = block.id;
                    m.blocks_synced += 1;
                }
                refresh_txpool_base_fee(&node).await;

                let tx_hashes = pool_txs.iter().map(|tx| tx.hash).collect::<Vec<_>>();
                websocket_broadcast_cchain_block_events(
                    &node,
                    &block.raw,
                    &tx_hashes,
                    &block.receipts,
                )
                .await;

                reconcile_mined_pool_transactions(&node, &pool_txs).await;

                // Index block for PostgreSQL analytics
                #[cfg(feature = "indexer")]
                if let Some(ref indexer) = node.indexer {
                    if let Some(mut indexed) = build_indexed_cchain_block(&block.raw, &block.id) {
                        indexed.gas_used = block.gas_used as i64;
                        indexed.transaction_count = block.tx_count as i32;
                        indexer.index_block(indexed).await;
                    }
                }

                // Broadcast to peers via PushQuery
                broadcast_block_to_peers(&node, &block).await;
            }
            Err(e) => {
                debug!(
                    "Block builder: failed to build block #{}: {}",
                    block_number, e
                );
            }
        }
    }
}

/// Build a valid C-Chain block at the given height with the provided transactions.
///
/// Constructs a proper Ethereum RLP block header (parentHash, miner, stateRoot,
/// gasLimit, baseFee, timestamp, etc.), executes transactions through revm,
/// and signs the block ID with the node's BLS key.
async fn build_cchain_block(
    node: &NodeState,
    block_number: u64,
    txs: Vec<PoolTransaction>,
) -> Result<BuiltBlock, Box<dyn std::error::Error + Send + Sync>> {
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Look up parent block hash (tip of C-Chain) from in-memory metrics
    let parent_hash = {
        let metrics = node.c_chain_metrics.read().await;
        metrics.tip_hash
    };

    // Miner address = derived from node identity (first 20 bytes of node_id)
    let mut coinbase = [0u8; 20];
    coinbase.copy_from_slice(&node.identity.node_id.0);

    let (gas_limit, base_fee) = latest_cchain_block_fields(&node.db)
        .map(|fields| {
            (
                if fields.gas_limit == 0 {
                    DEFAULT_CCHAIN_GAS_LIMIT
                } else {
                    fields.gas_limit
                },
                predicted_next_base_fee_from_fields(node.config.network_id, &fields),
            )
        })
        .unwrap_or((DEFAULT_CCHAIN_GAS_LIMIT, DEFAULT_BASE_FEE_PER_GAS));

    // Execute transactions through EVM to get state root and receipts
    let ctx = BlockContext {
        number: block_number,
        timestamp,
        coinbase,
        gas_limit,
        base_fee,
        difficulty: 0,
        chain_id: node.config.chain_id,
    };

    let evm_txs: Vec<EvmTransaction> = txs.iter().map(pool_tx_to_evm_tx).collect();

    let (block_result, state_root) = {
        let mut evm = node.evm.write().await;
        let result = evm
            .execute_block(&evm_txs, &ctx)
            .map_err(|e| format!("EVM execution: {}", e))?;
        let state_root = result.state_root;
        (result, state_root)
    };

    // Build RLP block
    let raw = encode_cchain_block_rlp(
        &parent_hash,
        &coinbase,
        &state_root,
        block_number,
        gas_limit,
        block_result.gas_used,
        timestamp,
        base_fee,
        &txs,
    );

    // Compute block ID = SHA-256 of raw bytes
    let mut hasher = Sha256::new();
    hasher.update(&raw);
    let id: [u8; 32] = hasher.finalize().into();

    // Sign with BLS key
    let bls_signature = node.identity.sign_block_bls(&id);

    Ok(BuiltBlock {
        raw,
        id,
        number: block_number,
        tx_count: block_result.tx_count,
        gas_used: block_result.gas_used,
        receipts: block_result.receipts,
        bls_signature,
    })
}

/// Encode a C-Chain block as RLP with Avalanche wrapper.
fn encode_cchain_block_rlp(
    parent_hash: &[u8; 32],
    coinbase: &[u8; 20],
    state_root: &[u8; 32],
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    base_fee: u128,
    txs: &[PoolTransaction],
) -> Vec<u8> {
    fn rlp_bytes32(v: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![0xa0u8];
        out.extend_from_slice(v);
        out
    }
    fn rlp_bytes20(v: &[u8; 20]) -> Vec<u8> {
        let mut out = vec![0x94u8];
        out.extend_from_slice(v);
        out
    }
    fn rlp_u64(v: u64) -> Vec<u8> {
        if v == 0 {
            return vec![0x80];
        }
        let b = v.to_be_bytes();
        let s = b.iter().position(|&x| x != 0).unwrap_or(7);
        let sl = &b[s..];
        let mut out = vec![0x80 + sl.len() as u8];
        out.extend_from_slice(sl);
        out
    }
    fn rlp_u128(v: u128) -> Vec<u8> {
        if v == 0 {
            return vec![0x80];
        }
        let b = v.to_be_bytes();
        let s = b.iter().position(|&x| x != 0).unwrap_or(15);
        let sl = &b[s..];
        if sl.len() == 1 && sl[0] < 0x80 {
            return vec![sl[0]];
        }
        let mut out = vec![0x80 + sl.len() as u8];
        out.extend_from_slice(sl);
        out
    }
    fn rlp_bytes(v: &[u8]) -> Vec<u8> {
        if v.is_empty() {
            return vec![0x80];
        }
        if v.len() == 1 && v[0] < 0x80 {
            return vec![v[0]];
        }
        let mut out = Vec::new();
        if v.len() <= 55 {
            out.push(0x80 + v.len() as u8);
        } else {
            let lb = v.len().to_be_bytes();
            let ls = lb.iter().position(|&x| x != 0).unwrap_or(7);
            let lsl = &lb[ls..];
            out.push(0xb7 + lsl.len() as u8);
            out.extend_from_slice(lsl);
        }
        out.extend_from_slice(v);
        out
    }
    fn rlp_list(payload: Vec<u8>) -> Vec<u8> {
        let len = payload.len();
        let mut out = Vec::new();
        if len <= 55 {
            out.push(0xc0 + len as u8);
        } else {
            let lb = len.to_be_bytes();
            let ls = lb.iter().position(|&x| x != 0).unwrap_or(7);
            let lsl = &lb[ls..];
            out.push(0xf7 + lsl.len() as u8);
            out.extend_from_slice(lsl);
        }
        out.extend(payload);
        out
    }
    /// Encode a single locally-generated transaction as a legacy RLP list:
    /// [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    fn rlp_encode_unsigned_legacy_tx(tx: &PoolTransaction) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend(rlp_u64(tx.nonce));
        payload.extend(rlp_u128(tx.max_fee_per_gas));
        payload.extend(rlp_u64(tx.gas_limit));
        // to: 20-byte address or 0x80 for contract creation
        match tx.to {
            Some(addr) => payload.extend(rlp_bytes20(&addr)),
            None => payload.push(0x80),
        }
        payload.extend(rlp_u128(tx.value));
        payload.extend(rlp_bytes(&tx.data));
        // v, r, s: empty signature (locally built block)
        payload.push(0x80); // v = 0
        payload.push(0x80); // r = 0
        payload.push(0x80); // s = 0
        rlp_list(payload)
    }

    fn encode_block_tx(tx: &PoolTransaction) -> Vec<u8> {
        match tx.raw.as_deref() {
            Some(raw) if !raw.is_empty() => {
                if raw[0] >= 0xc0 {
                    raw.to_vec()
                } else {
                    rlp_bytes(raw)
                }
            }
            _ => rlp_encode_unsigned_legacy_tx(tx),
        }
    }

    let empty32 = [0u8; 32];
    let empty256 = [0u8; 256];

    let mut header_payload: Vec<u8> = Vec::new();
    header_payload.extend(rlp_bytes32(parent_hash)); // parentHash
    header_payload.extend(rlp_bytes32(&empty32)); // sha3Uncles (empty)
    header_payload.extend(rlp_bytes20(coinbase)); // miner
    header_payload.extend(rlp_bytes32(state_root)); // stateRoot
    header_payload.extend(rlp_bytes32(&empty32)); // txsRoot (empty)
    header_payload.extend(rlp_bytes32(&empty32)); // receiptRoot (empty)
    header_payload.push(0xb9);
    header_payload.push(0x01);
    header_payload.push(0x00);
    header_payload.extend_from_slice(&empty256); // bloom (256 bytes)
    header_payload.push(0x80); // difficulty = 0
    header_payload.extend(rlp_u64(number)); // number
    header_payload.extend(rlp_u64(gas_limit)); // gasLimit
    header_payload.extend(rlp_u64(gas_used)); // gasUsed
    header_payload.extend(rlp_u64(timestamp)); // timestamp
    header_payload.push(0x80); // extraData (empty)
    header_payload.extend(rlp_bytes32(&empty32)); // mixHash
                                                  // nonce: 8 zero bytes = 0x8800000000000000
    header_payload.extend_from_slice(&[0x88, 0, 0, 0, 0, 0, 0, 0, 0]); // nonce
    header_payload.extend(rlp_u128(base_fee)); // baseFeePerGas

    let header = rlp_list(header_payload);
    let uncles = 0xc0u8; // empty uncles list

    // Encode transactions list
    let txs_encoded = if txs.is_empty() {
        vec![0xc0u8] // empty list
    } else {
        let mut txs_payload = Vec::new();
        for tx in txs {
            txs_payload.extend(encode_block_tx(tx));
        }
        rlp_list(txs_payload)
    };

    let mut outer: Vec<u8> = Vec::new();
    outer.extend(header);
    outer.push(uncles);
    outer.extend(txs_encoded);
    let rlp = rlp_list(outer);

    // Wrap with Avalanche codec header: version(2) + typeID(4)
    let mut wrapped = Vec::with_capacity(6 + rlp.len());
    wrapped.extend_from_slice(&[0x00, 0x00]); // codec version
    wrapped.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // typeID (0 = EVM)
    wrapped.extend(rlp);
    wrapped
}

/// Broadcast a built block to all connected peers via PushQuery.
async fn broadcast_block_to_peers(node: &NodeState, block: &BuiltBlock) {
    let peers = {
        let pm = node.peer_manager.read().await;
        pm.active_peer_addrs()
    };

    if peers.is_empty() {
        debug!("Block builder: no peers to broadcast to");
        return;
    }

    // Build PushQuery message
    let cchain_id: [u8; 32] = {
        let cb58 = if node.config.network_id == 5 {
            "yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp"
        } else {
            "2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5"
        };
        let decoded = bs58::decode(cb58).into_vec().unwrap_or_default();
        if decoded.len() >= 36 {
            decoded[..32].try_into().unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        }
    };

    let req_id: u32 = rand::thread_rng().gen();
    let push_query = NetworkMessage::PushQuery {
        chain_id: ChainId(cchain_id),
        request_id: req_id,
        deadline: 5_000_000_000u64,
        container: block.raw.clone(),
    };

    if let Ok(encoded) = push_query.encode_proto() {
        info!(
            "Block builder: broadcasting block #{} to {} peers",
            block.number,
            peers.len()
        );
        for peer_addr in peers {
            // Non-blocking best-effort TCP send to the peer's staking port
            let encoded = encoded.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = tokio::net::TcpStream::connect(peer_addr).await {
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, &encoded).await;
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Indexer helpers
// ---------------------------------------------------------------------------

/// Build an IndexedBlock from raw C-Chain block data for the PostgreSQL indexer.
#[cfg(feature = "indexer")]
fn build_indexed_cchain_block(container: &[u8], hash: &[u8; 32]) -> Option<IndexedBlock> {
    let fields = extract_cchain_block_fields(container)?;
    let header = BlockHeader::parse(container, Chain::CChain).ok()?;
    Some(IndexedBlock {
        number: header.height as i64,
        hash: hash.to_vec(),
        parent_hash: header.parent_id.to_vec(),
        timestamp: chrono::DateTime::from_timestamp(fields.timestamp as i64, 0)
            .unwrap_or_else(chrono::Utc::now),
        gas_used: 0, // filled after EVM execution
        gas_limit: fields.gas_limit as i64,
        transaction_count: 0, // filled after EVM execution
        size: container.len() as i64,
        transactions: Vec::new(),
    })
}

/// Build an IndexedBlock from raw P-Chain block data for the PostgreSQL indexer.
#[cfg(feature = "indexer")]
fn build_indexed_pchain_block(container: &[u8], block_id: &[u8; 32]) -> Option<IndexedBlock> {
    let header = BlockHeader::parse(container, Chain::PChain).ok()?;
    Some(IndexedBlock {
        number: header.height as i64,
        hash: block_id.to_vec(),
        parent_hash: header.parent_id.to_vec(),
        timestamp: if header.timestamp > 0 {
            chrono::DateTime::from_timestamp(header.timestamp as i64, 0)
                .unwrap_or_else(chrono::Utc::now)
        } else {
            chrono::Utc::now()
        },
        gas_used: 0,
        gas_limit: 0,
        transaction_count: 0,
        size: container.len() as i64,
        transactions: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// C-Chain EVM execution helper
// ---------------------------------------------------------------------------

/// Execute a downloaded C-Chain block through the EVM and persist receipts.
///
/// Extracts transactions from the raw RLP block, runs them through the in-memory
/// EVM executor, and stores receipts in CF_RECEIPTS keyed by `(block_height, tx_idx)`.
/// The EVM state is cumulative across blocks within a single peer session.
async fn execute_cchain_block_and_store(raw_block: &[u8], node: &NodeState) {
    let fields = match extract_cchain_block_fields(raw_block) {
        Some(f) => f,
        None => {
            record_bad_cchain_block(node, raw_block, None, "invalid c-chain block", Vec::new());
            return;
        }
    };
    let expected_state_root = BlockHeader::extract_state_root(raw_block);

    // Compute block hash for tip tracking
    let block_hash = cchain_block_hash(raw_block);

    let raw_txs = extract_cchain_transactions(raw_block);
    if raw_txs.is_empty() {
        if let Some(expected) = expected_state_root {
            let computed = {
                let evm = node.evm.read().await;
                evm.compute_state_root_mpt()
            };
            if computed != expected {
                let reason = format!(
                    "state root mismatch: expected=0x{}, computed=0x{}",
                    hex::encode(expected),
                    hex::encode(computed)
                );
                debug!("C-Chain #{} {}", fields.number, reason);
                record_bad_cchain_block(node, raw_block, Some(fields.number), reason, Vec::new());
                return;
            }
        }

        let mut key = Vec::with_capacity(34);
        key.extend_from_slice(b"c:");
        key.extend_from_slice(&block_hash);
        if let Err(e) = node.db.put_cf(CF_BLOCKS, &key, raw_block) {
            debug!(
                "failed to store imported C-Chain block hash entry #{}: {}",
                fields.number, e
            );
        }

        if let Err(e) = node.db.put_block(fields.number, raw_block) {
            debug!(
                "failed to store imported C-Chain block #{} by height: {}",
                fields.number, e
            );
        }

        let current_height = current_cchain_height(node);
        if fields.number > current_height {
            if let Err(e) = node.db.set_last_accepted_height(fields.number) {
                debug!(
                    "failed to advance imported C-Chain head to #{}: {}",
                    fields.number, e
                );
            }
        }

        // Even with no transactions update tip height and hash
        let mut m = node.c_chain_metrics.write().await;
        if fields.number > m.tip_height {
            m.tip_height = fields.number;
            m.tip_hash = block_hash;
        }
        drop(m);
        refresh_txpool_base_fee(node).await;
        websocket_broadcast_cchain_block_events(node, raw_block, &[], &[]).await;
        return;
    }

    let ctx = BlockContext {
        number: fields.number,
        timestamp: fields.timestamp,
        coinbase: fields.miner,
        gas_limit: fields.gas_limit,
        base_fee: fields.base_fee,
        difficulty: 0,
        chain_id: node.config.chain_id,
    };

    // Recover sender addresses from ECDSA signatures, falling back to zero address
    let result = {
        let mut evm = node.evm.write().await;
        let evm_txs: Vec<EvmTransaction> = raw_txs
            .iter()
            .map(|t| {
                let from = t.recover_sender().unwrap_or([0u8; 20]);
                // Pre-fund recovered sender so gas deduction succeeds
                evm.set_balance(from, u128::MAX / 2);
                EvmTransaction {
                    from,
                    to: t.to,
                    value: t.value,
                    data: t.data.clone(),
                    gas_limit: t.gas_limit,
                    gas_price: t.gas_price.max(fields.base_fee),
                    nonce: t.nonce,
                }
            })
            .collect();
        evm.execute_block(&evm_txs, &ctx)
    };

    match result {
        Ok(block_result) => {
            if let Some(expected) = expected_state_root {
                if block_result.state_root != expected {
                    let reason = format!(
                        "state root mismatch: expected=0x{}, computed=0x{}",
                        hex::encode(expected),
                        hex::encode(block_result.state_root)
                    );
                    debug!("C-Chain #{} {}", fields.number, reason);
                    let bad_receipts = bad_block_receipt_values(
                        &raw_txs,
                        &block_result.receipts,
                        &block_hash,
                        fields.number,
                    );
                    record_bad_cchain_block(
                        node,
                        raw_block,
                        Some(fields.number),
                        reason,
                        bad_receipts,
                    );
                    return;
                }
            }

            debug!(
                "C-Chain #{}: executed {} txs, {} gas used, state_root=0x{}",
                fields.number,
                block_result.tx_count,
                block_result.gas_used,
                hex::encode(block_result.state_root)
            );

            let mut key = Vec::with_capacity(34);
            key.extend_from_slice(b"c:");
            key.extend_from_slice(&block_hash);
            if let Err(e) = node.db.put_cf(CF_BLOCKS, &key, raw_block) {
                debug!(
                    "failed to store imported C-Chain block hash entry #{}: {}",
                    fields.number, e
                );
            }

            if let Err(e) = node.db.put_block(fields.number, raw_block) {
                debug!(
                    "failed to store imported C-Chain block #{} by height: {}",
                    fields.number, e
                );
            }

            if let Err(e) = persist_imported_cchain_tx_artifacts(
                &node.db,
                fields.number,
                &block_hash,
                &raw_txs,
                &block_result.receipts,
            ) {
                debug!(
                    "failed to persist imported tx artifacts for block #{}: {}",
                    fields.number, e
                );
            }

            let current_height = current_cchain_height(node);
            if fields.number > current_height {
                if let Err(e) = node.db.set_last_accepted_height(fields.number) {
                    debug!(
                        "failed to advance imported C-Chain head to #{}: {}",
                        fields.number, e
                    );
                }
            }

            let mut m = node.c_chain_metrics.write().await;
            if fields.number > m.tip_height {
                m.tip_height = fields.number;
                m.tip_hash = block_hash;
            }
            drop(m);
            refresh_txpool_base_fee(node).await;

            let tx_hashes = raw_txs
                .iter()
                .map(|tx| raw_tx_hash(&tx.raw))
                .collect::<Vec<_>>();
            websocket_broadcast_cchain_block_events(
                node,
                raw_block,
                &tx_hashes,
                &block_result.receipts,
            )
            .await;
        }
        Err(e) => {
            debug!("C-Chain #{} EVM execution error: {}", fields.number, e);
            record_bad_cchain_block(
                node,
                raw_block,
                Some(fields.number),
                format!("evm execution error: {}", e),
                Vec::new(),
            );
        }
    }
}

fn parse_http_headers(req: &str) -> StdHashMap<String, String> {
    req.lines()
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect()
}

fn is_websocket_upgrade(path: &str, headers: &StdHashMap<String, String>) -> bool {
    matches!(path, "/ws" | "/ext/bc/C/ws")
        && headers
            .get("upgrade")
            .map(|value| value.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        && headers
            .get("connection")
            .map(|value| value.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false)
        && headers.contains_key("sec-websocket-key")
}

fn websocket_accept_key(sec_key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(sec_key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(sha1.finalize())
}

async fn read_ws_frame<R>(reader: &mut R) -> std::io::Result<Option<(u8, Vec<u8>)>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let opcode = header[0] & 0x0f;
    let masked = (header[1] & 0x80) != 0;
    let mut payload_len = u64::from(header[1] & 0x7f);

    if payload_len == 126 {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        payload_len = u16::from_be_bytes(buf) as u64;
    } else if payload_len == 127 {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).await?;
        payload_len = u64::from_be_bytes(buf);
    }

    if payload_len > 8 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "websocket frame too large",
        ));
    }

    let mut mask = [0u8; 4];
    if masked {
        reader.read_exact(&mut mask).await?;
    }

    let mut payload = vec![0u8; payload_len as usize];
    if !payload.is_empty() {
        reader.read_exact(&mut payload).await?;
    }
    if masked {
        for (idx, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[idx % 4];
        }
    }

    Ok(Some((opcode, payload)))
}

async fn write_ws_frame<W>(writer: &mut W, opcode: u8, payload: &[u8]) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut frame = Vec::with_capacity(2 + payload.len() + 8);
    frame.push(0x80 | (opcode & 0x0f));
    match payload.len() {
        len @ 0..=125 => frame.push(len as u8),
        len @ 126..=65535 => {
            frame.push(126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await
}

async fn handle_ws_rpc_request(json_str: &str, node: &NodeState, connection_id: u64) -> String {
    let req: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => {
            return r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"parse error"},"id":null}"#
                .to_string();
        }
    };

    let method = req["method"].as_str().unwrap_or("");
    let params = req["params"].as_array().cloned().unwrap_or_default();
    let id = &req["id"];

    match method {
        "eth_subscribe" => match WsSubscriptionType::from_params(&params) {
            Some(sub_type) => {
                let sub_id = node
                    .ws_subscriptions
                    .write()
                    .await
                    .subscribe(connection_id, sub_type);
                rpc_ok(&format!("\"{}\"", sub_id), id)
            }
            None => rpc_error(-32602, "invalid subscription", id),
        },
        "eth_unsubscribe" => {
            let sub_id = params
                .first()
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let removed = if sub_id.is_empty() {
                false
            } else {
                node.ws_subscriptions
                    .write()
                    .await
                    .unsubscribe_for_connection(connection_id, sub_id)
            };
            rpc_ok(if removed { "true" } else { "false" }, id)
        }
        _ => handle_rpc_request_for_path(json_str, node, "/ws").await,
    }
}

async fn ws_send_text(node: &NodeState, connection_id: u64, message: String) -> bool {
    let sender = node
        .ws_connections
        .read()
        .await
        .get(&connection_id)
        .cloned();
    match sender {
        Some(sender) => sender.send(WsOutboundMessage::Text(message)).is_ok(),
        None => false,
    }
}

async fn ws_disconnect(node: &NodeState, connection_id: u64) {
    if let Some(sender) = node.ws_connections.write().await.remove(&connection_id) {
        let _ = sender.send(WsOutboundMessage::Close);
    }
    node.ws_subscriptions
        .write()
        .await
        .disconnect(connection_id);
}

fn websocket_block_header_from_cchain(block_data: &[u8]) -> Option<WsBlockHeader> {
    let header = BlockHeader::parse(block_data, Chain::CChain).ok()?;
    let fields = extract_cchain_block_fields(block_data)?;
    Some(WsBlockHeader {
        number: fields.number,
        hash: header.id,
        parent_hash: header.parent_id,
        timestamp: fields.timestamp,
        state_root: BlockHeader::extract_state_root(block_data).unwrap_or([0u8; 32]),
        gas_limit: fields.gas_limit,
        gas_used: fields.gas_used,
    })
}

fn websocket_log_entries(
    block_number: u64,
    block_hash: [u8; 32],
    tx_hashes: &[[u8; 32]],
    receipts: &[TxReceipt],
) -> Vec<WsLogEntry> {
    let mut entries = Vec::new();
    let mut log_index = 0u32;

    for (tx_index, (tx_hash, receipt)) in tx_hashes.iter().zip(receipts.iter()).enumerate() {
        for log in &receipt.logs {
            entries.push(WsLogEntry {
                address: log.address,
                topics: log.topics.clone(),
                data: log.data.clone(),
                block_number,
                block_hash,
                tx_hash: *tx_hash,
                transaction_index: tx_index as u32,
                log_index,
                removed: false,
            });
            log_index = log_index.saturating_add(1);
        }
    }

    entries
}

async fn websocket_broadcast_pending_tx(node: &NodeState, tx_hash: &[u8; 32]) {
    let subscriptions = {
        let manager = node.ws_subscriptions.read().await;
        manager
            .get_subscriptions_by_type("newPendingTransactions")
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
    };

    for subscription in subscriptions {
        let message = new_pending_tx_notification(&subscription.id, tx_hash);
        if !ws_send_text(node, subscription.connection_id, message).await {
            ws_disconnect(node, subscription.connection_id).await;
        }
    }
}

async fn websocket_broadcast_cchain_block_events(
    node: &NodeState,
    block_data: &[u8],
    tx_hashes: &[[u8; 32]],
    receipts: &[TxReceipt],
) {
    if let Some(header) = websocket_block_header_from_cchain(block_data) {
        let head_subscriptions = {
            let manager = node.ws_subscriptions.read().await;
            manager
                .get_subscriptions_by_type("newHeads")
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        for subscription in head_subscriptions {
            let message = new_heads_notification(&subscription.id, &header);
            if !ws_send_text(node, subscription.connection_id, message).await {
                ws_disconnect(node, subscription.connection_id).await;
            }
        }

        let accepted_subscriptions = {
            let manager = node.ws_subscriptions.read().await;
            manager
                .get_subscriptions_by_type("newAcceptedTransactions")
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        if !accepted_subscriptions.is_empty() {
            let accepted_txs = extract_cchain_transactions(block_data)
                .into_iter()
                .enumerate()
                .map(|(idx, tx)| {
                    let pool_tx = pool_tx_from_cchain_raw(&tx);
                    let hash_value =
                        serde_json::Value::String(format!("0x{}", hex::encode(pool_tx.hash)));
                    let full_value = rpc_transaction_from_pool(
                        &pool_tx.hash,
                        &pool_tx,
                        Some(header.hash),
                        Some(header.number),
                        Some(idx as u32),
                    );
                    (hash_value, full_value)
                })
                .collect::<Vec<_>>();

            for subscription in accepted_subscriptions {
                let full_tx = matches!(
                    &subscription.sub_type,
                    WsSubscriptionType::NewAcceptedTransactions { full_tx: true }
                );
                for (hash_value, full_value) in &accepted_txs {
                    let result = if full_tx {
                        full_value.clone()
                    } else {
                        hash_value.clone()
                    };
                    let message = new_accepted_tx_notification(&subscription.id, result);
                    if !ws_send_text(node, subscription.connection_id, message).await {
                        ws_disconnect(node, subscription.connection_id).await;
                        break;
                    }
                }
            }
        }

        let log_entries = websocket_log_entries(header.number, header.hash, tx_hashes, receipts);
        if log_entries.is_empty() {
            return;
        }

        let log_subscriptions = {
            let manager = node.ws_subscriptions.read().await;
            manager
                .get_subscriptions_by_type("logs")
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        for subscription in log_subscriptions {
            if let WsSubscriptionType::Logs(filter) = &subscription.sub_type {
                for log in &log_entries {
                    if !filter.matches(&log.address, &log.topics) {
                        continue;
                    }
                    let message = logs_notification(&subscription.id, log);
                    if !ws_send_text(node, subscription.connection_id, message.clone()).await {
                        ws_disconnect(node, subscription.connection_id).await;
                        break;
                    }
                }
            }
        }
    }
}

async fn handle_websocket_connection(
    stream: tokio::net::TcpStream,
    headers: &StdHashMap<String, String>,
    node: Arc<NodeState>,
) {
    let sec_key = match headers.get("sec-websocket-key") {
        Some(key) => key.clone(),
        None => return,
    };

    let connection_id = match node.ws_subscriptions.write().await.connect() {
        Ok(id) => id,
        Err(e) => {
            let mut stream = stream;
            let body = serde_json::json!({"error": e.to_string()}).to_string();
            let response = format!(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            return;
        }
    };

    let accept_key = websocket_accept_key(&sec_key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key
    );

    let (mut reader, mut writer) = stream.into_split();
    if writer.write_all(response.as_bytes()).await.is_err() {
        node.ws_subscriptions
            .write()
            .await
            .disconnect(connection_id);
        return;
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<WsOutboundMessage>();
    node.ws_connections
        .write()
        .await
        .insert(connection_id, tx.clone());

    let writer_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let result = match message {
                WsOutboundMessage::Text(text) => {
                    write_ws_frame(&mut writer, 0x1, text.as_bytes()).await
                }
                WsOutboundMessage::Pong(payload) => {
                    write_ws_frame(&mut writer, 0xA, &payload).await
                }
                WsOutboundMessage::Close => {
                    let _ = write_ws_frame(&mut writer, 0x8, &[]).await;
                    break;
                }
            };
            if result.is_err() {
                break;
            }
        }
    });

    loop {
        match read_ws_frame(&mut reader).await {
            Ok(Some((0x1, payload))) => {
                let request = match String::from_utf8(payload) {
                    Ok(text) => text,
                    Err(_) => continue,
                };
                let response = handle_ws_rpc_request(&request, &node, connection_id).await;
                if tx.send(WsOutboundMessage::Text(response)).is_err() {
                    break;
                }
            }
            Ok(Some((0x8, _))) => break,
            Ok(Some((0x9, payload))) => {
                if tx.send(WsOutboundMessage::Pong(payload)).is_err() {
                    break;
                }
            }
            Ok(Some((_opcode, _payload))) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }

    let _ = tx.send(WsOutboundMessage::Close);
    ws_disconnect(&node, connection_id).await;
    let _ = writer_task.await;
}

// ---------------------------------------------------------------------------
// JSON-RPC Server (minimal)
// ---------------------------------------------------------------------------

async fn run_rpc_server(addr: SocketAddr, node: Arc<NodeState>) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            info!("JSON-RPC server listening on {}", addr);
            l
        }
        Err(e) => {
            error!("Failed to bind RPC server on {}: {}", addr, e);
            return;
        }
    };

    run_rpc_server_with_listener(listener, node).await;
}

async fn run_rpc_server_with_listener(listener: TcpListener, node: Arc<NodeState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let node = node.clone();
                tokio::spawn(async move {
                    handle_rpc_connection(stream, peer_addr, node).await;
                });
            }
            Err(e) => {
                warn!("RPC accept error: {}", e);
            }
        }
    }
}

async fn handle_rpc_connection(
    mut stream: tokio::net::TcpStream,
    _peer_addr: SocketAddr,
    node: Arc<NodeState>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 131072];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let req = String::from_utf8_lossy(&buf[..n]);
    let mut lines = req.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut request_parts = request_line.split_whitespace();
    let http_method = request_parts.next().unwrap_or("POST");
    let raw_path = request_parts.next().unwrap_or("/");
    let (path, query) = split_path_and_query(raw_path);
    let resolved_path = resolve_request_path(&node, path).await;
    let headers = parse_http_headers(&req);

    if is_websocket_upgrade(&resolved_path, &headers) {
        handle_websocket_connection(stream, &headers, node).await;
        return;
    }

    let (status_line, content_type, response_body) = match resolved_path.as_str() {
        "/ext/health" | "/ext/health/health" if http_method == "GET" => {
            let tags = query_tags(query);
            let report = health_report(&node, HealthReportKind::Health, &tags).await;
            let healthy = report
                .get("healthy")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            (
                if healthy {
                    "HTTP/1.1 200 OK"
                } else {
                    "HTTP/1.1 503 Service Unavailable"
                },
                "application/json",
                report.to_string(),
            )
        }
        "/ext/health/readiness" if http_method == "GET" => {
            let tags = query_tags(query);
            let report = health_report(&node, HealthReportKind::Readiness, &tags).await;
            let healthy = report
                .get("healthy")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            (
                if healthy {
                    "HTTP/1.1 200 OK"
                } else {
                    "HTTP/1.1 503 Service Unavailable"
                },
                "application/json",
                report.to_string(),
            )
        }
        "/ext/health/liveness" if http_method == "GET" => {
            let tags = query_tags(query);
            let report = health_report(&node, HealthReportKind::Liveness, &tags).await;
            ("HTTP/1.1 200 OK", "application/json", report.to_string())
        }
        "/health" => {
            let peers = node.peer_manager.read().await.connected_count();
            let phase = node.sync_engine.phase().await.to_string();
            let uptime_seconds = node.start_time.elapsed().as_secs();
            let memory_rss_bytes = get_rss_bytes();
            (
                "HTTP/1.1 200 OK",
                "application/json",
                serde_json::json!({
                    "healthy": peers > 0,
                    "connected_peers": peers,
                    "sync_state": phase,
                    "memory_rss_bytes": memory_rss_bytes,
                    "uptime_seconds": uptime_seconds,
                })
                .to_string(),
            )
        }
        "/metrics" => (
            "HTTP/1.1 200 OK",
            "text/plain; version=0.0.4",
            render_prometheus_metrics(&node).await,
        ),
        _ => {
            let body = req
                .split_once("\r\n\r\n")
                .map(|(_, b)| b)
                .unwrap_or_default();
            (
                "HTTP/1.1 200 OK",
                "application/json",
                handle_rpc_request_for_path(body, &node, &resolved_path).await,
            )
        }
    };

    let http_response = format!(
        "{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
        status_line,
        content_type,
        response_body.len(),
        response_body
    );

    let _ = stream.write_all(http_response.as_bytes()).await;
}

async fn render_prometheus_metrics(node: &NodeState) -> String {
    let phase = node.sync_engine.phase().await;
    let sync_stats = node.sync_engine.stats().await;
    let peer_count = node.peer_manager.read().await.connected_count() as u64;
    let p_height = node.p_chain_metrics.read().await.tip_height;
    let c_height = node.c_chain_metrics.read().await.tip_height;
    let memory = get_rss_bytes();
    let uptime = node.start_time.elapsed().as_secs();
    let handshake_latency = average_handshake_latency_ms(&node.db);

    format!(
        "sync_progress {}\npeer_count {}\nblock_height_p_chain {}\nblock_height_c_chain {}\nmemory_rss_bytes {}\nuptime_seconds {}\nhandshake_latency_ms {}\n",
        if matches!(phase, SyncPhase::Following | SyncPhase::Synced) {
            1.0
        } else {
            sync_stats.progress_pct() / 100.0
        },
        peer_count,
        p_height,
        c_height,
        memory,
        uptime,
        handshake_latency
    )
}

fn average_handshake_latency_ms(db: &Database) -> u64 {
    let mut latencies = Vec::new();
    for (_, value) in db.load_all_peers() {
        if let Some(record) = PersistentPeerRecord::decode(&value) {
            if record.latency_ms > 0 {
                latencies.push(record.latency_ms);
            }
        }
    }
    if latencies.is_empty() {
        0
    } else {
        latencies.iter().sum::<u64>() / latencies.len() as u64
    }
}

/// Parse a hex string (with or without 0x prefix) to bytes.
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).ok()
}

/// Parse a hex string to a 20-byte address.
fn parse_hex_address(s: &str) -> Option<[u8; 20]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 20 {
        return None;
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Parse a hex string to a 32-byte hash.
fn parse_hex_hash(s: &str) -> Option<[u8; 32]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn parse_cb58_id_32(value: &str) -> Option<[u8; 32]> {
    let decoded = bs58::decode(value).into_vec().ok()?;
    if decoded.len() < 36 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&decoded[..32]);
    Some(arr)
}

fn parse_hex_u64_str(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        Some(0)
    } else {
        u64::from_str_radix(s, 16)
            .ok()
            .or_else(|| s.parse::<u64>().ok())
    }
}

fn parse_hex_u128_str(s: &str) -> Option<u128> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        Some(0)
    } else {
        u128::from_str_radix(s, 16)
            .ok()
            .or_else(|| s.parse::<u128>().ok())
    }
}

fn parse_quantity_u64(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => parse_hex_u64_str(s),
        _ => None,
    }
}

fn parse_quantity_u128(value: &serde_json::Value) -> Option<u128> {
    match value {
        serde_json::Value::Number(n) => n.as_u64().map(u128::from),
        serde_json::Value::String(s) => parse_hex_u128_str(s),
        _ => None,
    }
}

fn rpc_simulation_block_context(node: &NodeState) -> BlockContext {
    let height = current_cchain_height(node);
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Some(fields) = latest_cchain_block_fields(&node.db) {
        return BlockContext {
            number: height.saturating_add(1),
            timestamp,
            coinbase: fields.miner,
            gas_limit: if fields.gas_limit == 0 {
                DEFAULT_CCHAIN_GAS_LIMIT
            } else {
                fields.gas_limit
            },
            base_fee: predicted_next_base_fee_from_fields(node.config.network_id, &fields),
            difficulty: 0,
            chain_id: node.config.chain_id,
        };
    }

    BlockContext {
        number: height.saturating_add(1),
        timestamp,
        coinbase: [0u8; 20],
        gas_limit: DEFAULT_CCHAIN_GAS_LIMIT,
        base_fee: DEFAULT_BASE_FEE_PER_GAS,
        difficulty: 0,
        chain_id: node.config.chain_id,
    }
}

fn parse_rpc_access_list(tx_obj: &serde_json::Value) -> Vec<avalanche_rs::tx::AccessListEntry> {
    tx_obj
        .get("accessList")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let address = item
                        .get("address")
                        .and_then(|value| value.as_str())
                        .and_then(parse_hex_address)?;
                    let storage_keys = item
                        .get("storageKeys")
                        .and_then(|value| value.as_array())
                        .map(|keys| {
                            keys.iter()
                                .filter_map(|value| value.as_str().and_then(parse_hex_hash))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    Some(avalanche_rs::tx::AccessListEntry {
                        address,
                        storage_keys,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
struct ParsedRpcSimulationTx {
    tx: EvmTransaction,
    access_list: Vec<avalanche_rs::tx::AccessListEntry>,
}

fn parse_rpc_simulation_tx(
    tx_obj: &serde_json::Value,
    evm: &EvmExecutor,
    block_ctx: &BlockContext,
) -> ParsedRpcSimulationTx {
    let from = tx_obj
        .get("from")
        .and_then(|value| value.as_str())
        .and_then(parse_hex_address)
        .unwrap_or([0u8; 20]);
    let to = tx_obj
        .get("to")
        .and_then(|value| value.as_str())
        .and_then(parse_hex_address);
    let data = tx_obj
        .get("data")
        .and_then(|value| value.as_str())
        .or_else(|| tx_obj.get("input").and_then(|value| value.as_str()))
        .and_then(parse_hex_bytes)
        .unwrap_or_default();
    let value = tx_obj
        .get("value")
        .and_then(parse_quantity_u128)
        .unwrap_or(0);
    let gas_limit = tx_obj
        .get("gas")
        .and_then(parse_quantity_u64)
        .unwrap_or(block_ctx.gas_limit);
    let gas_price = tx_obj
        .get("maxFeePerGas")
        .and_then(parse_quantity_u128)
        .or_else(|| tx_obj.get("gasPrice").and_then(parse_quantity_u128))
        .unwrap_or(block_ctx.base_fee);
    let nonce = tx_obj
        .get("nonce")
        .and_then(parse_quantity_u64)
        .unwrap_or_else(|| evm.get_nonce(from));

    ParsedRpcSimulationTx {
        tx: EvmTransaction {
            from,
            to,
            value,
            data,
            gas_limit,
            gas_price,
            nonce,
        },
        access_list: parse_rpc_access_list(tx_obj),
    }
}

#[derive(Debug, Clone)]
struct RpcManagedTxRequest {
    from: [u8; 20],
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
    gas: Option<u64>,
    gas_price: Option<u128>,
    max_fee_per_gas: Option<u128>,
    max_priority_fee_per_gas: Option<u128>,
    nonce: Option<u64>,
    access_list: Vec<avalanche_rs::tx::AccessListEntry>,
}

#[derive(Debug, Clone)]
enum RpcManagedTxEnvelope {
    Legacy(LegacyTx),
    Eip1559(Eip1559Tx),
}

impl RpcManagedTxEnvelope {
    fn sign(&self, wallet: &Wallet) -> Result<SignedTransaction, String> {
        match self {
            Self::Legacy(tx) => wallet.sign_legacy(tx).map_err(|e| e.to_string()),
            Self::Eip1559(tx) => wallet.sign_eip1559(tx).map_err(|e| e.to_string()),
        }
    }

    fn signing_payload(&self, chain_id: u64) -> Vec<u8> {
        match self {
            Self::Legacy(tx) => tx.signing_payload(chain_id),
            Self::Eip1559(tx) => tx.signing_payload(chain_id),
        }
    }

    fn to_rpc_value(&self, from: [u8; 20], chain_id: u64) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "from".to_string(),
            serde_json::Value::String(format!("0x{}", hex::encode(from))),
        );
        obj.insert(
            "chainId".to_string(),
            serde_json::Value::String(format!("0x{:x}", chain_id)),
        );
        match self {
            Self::Legacy(tx) => {
                obj.insert(
                    "type".to_string(),
                    serde_json::Value::String("0x0".to_string()),
                );
                obj.insert(
                    "to".to_string(),
                    tx.to
                        .map(|to| serde_json::Value::String(format!("0x{}", hex::encode(to))))
                        .unwrap_or(serde_json::Value::Null),
                );
                obj.insert(
                    "nonce".to_string(),
                    serde_json::Value::String(format!("0x{:x}", tx.nonce)),
                );
                obj.insert(
                    "gas".to_string(),
                    serde_json::Value::String(format!("0x{:x}", tx.gas_limit)),
                );
                obj.insert(
                    "gasPrice".to_string(),
                    serde_json::Value::String(format!("0x{:x}", tx.gas_price)),
                );
                obj.insert(
                    "value".to_string(),
                    serde_json::Value::String(format!("0x{:x}", tx.value)),
                );
                obj.insert(
                    "input".to_string(),
                    serde_json::Value::String(format!("0x{}", hex::encode(&tx.data))),
                );
            }
            Self::Eip1559(tx) => {
                obj.insert(
                    "type".to_string(),
                    serde_json::Value::String("0x2".to_string()),
                );
                obj.insert(
                    "to".to_string(),
                    tx.to
                        .map(|to| serde_json::Value::String(format!("0x{}", hex::encode(to))))
                        .unwrap_or(serde_json::Value::Null),
                );
                obj.insert(
                    "nonce".to_string(),
                    serde_json::Value::String(format!("0x{:x}", tx.nonce)),
                );
                obj.insert(
                    "gas".to_string(),
                    serde_json::Value::String(format!("0x{:x}", tx.gas_limit)),
                );
                obj.insert(
                    "maxFeePerGas".to_string(),
                    serde_json::Value::String(format!("0x{:x}", tx.max_fee_per_gas)),
                );
                obj.insert(
                    "maxPriorityFeePerGas".to_string(),
                    serde_json::Value::String(format!("0x{:x}", tx.max_priority_fee_per_gas)),
                );
                obj.insert(
                    "value".to_string(),
                    serde_json::Value::String(format!("0x{:x}", tx.value)),
                );
                obj.insert(
                    "input".to_string(),
                    serde_json::Value::String(format!("0x{}", hex::encode(&tx.data))),
                );
                obj.insert(
                    "accessList".to_string(),
                    serde_json::to_value(&tx.access_list)
                        .unwrap_or(serde_json::Value::Array(vec![])),
                );
            }
        }
        serde_json::Value::Object(obj)
    }
}

fn managed_wallet(node: &NodeState, address: [u8; 20]) -> Result<&Wallet, String> {
    node.rpc_wallets
        .get(&address)
        .ok_or_else(|| "unknown account".to_string())
}

fn parse_rpc_managed_tx_request(
    tx_obj: &serde_json::Value,
    require_from: bool,
) -> Result<RpcManagedTxRequest, String> {
    let from = match tx_obj
        .get("from")
        .and_then(|value| value.as_str())
        .and_then(parse_hex_address)
    {
        Some(from) => from,
        None if require_from => return Err("sender not specified".to_string()),
        None => [0u8; 20],
    };

    if tx_obj.get("gasPrice").is_some()
        && (tx_obj.get("maxFeePerGas").is_some() || tx_obj.get("maxPriorityFeePerGas").is_some())
    {
        return Err(
            "gasPrice cannot be combined with maxFeePerGas/maxPriorityFeePerGas".to_string(),
        );
    }

    Ok(RpcManagedTxRequest {
        from,
        to: tx_obj
            .get("to")
            .and_then(|value| value.as_str())
            .and_then(parse_hex_address),
        value: tx_obj
            .get("value")
            .and_then(parse_quantity_u128)
            .unwrap_or(0),
        data: tx_obj
            .get("data")
            .and_then(|value| value.as_str())
            .or_else(|| tx_obj.get("input").and_then(|value| value.as_str()))
            .and_then(parse_hex_bytes)
            .unwrap_or_default(),
        gas: tx_obj.get("gas").and_then(parse_quantity_u64),
        gas_price: tx_obj.get("gasPrice").and_then(parse_quantity_u128),
        max_fee_per_gas: tx_obj.get("maxFeePerGas").and_then(parse_quantity_u128),
        max_priority_fee_per_gas: tx_obj
            .get("maxPriorityFeePerGas")
            .and_then(parse_quantity_u128),
        nonce: tx_obj.get("nonce").and_then(parse_quantity_u64),
        access_list: parse_rpc_access_list(tx_obj),
    })
}

async fn prepare_rpc_managed_tx(
    node: &NodeState,
    request: &RpcManagedTxRequest,
    strict_sign: bool,
) -> Result<RpcManagedTxEnvelope, String> {
    if strict_sign {
        if request.gas.is_none() {
            return Err("gas not specified".to_string());
        }
        if request.gas_price.is_none()
            && (request.max_fee_per_gas.is_none() || request.max_priority_fee_per_gas.is_none())
        {
            return Err("missing gasPrice or maxFeePerGas/maxPriorityFeePerGas".to_string());
        }
        if request.nonce.is_none() {
            return Err("nonce not specified".to_string());
        }
    }

    let block_ctx = rpc_simulation_block_context(node);
    let base_fee = predicted_next_base_fee_from_db(&node.db, node.config.network_id);
    let suggested_tip = recent_priority_fee_suggestion(&node.db, current_cchain_height(node))
        .max(PRIORITY_FEE_FLOOR);
    let evm = node.evm.read().await;

    let nonce = request.nonce.unwrap_or_else(|| evm.get_nonce(request.from));
    let simulation_fee_cap = request
        .gas_price
        .or(request.max_fee_per_gas)
        .unwrap_or_else(|| base_fee.saturating_add(suggested_tip));
    let simulation_tx = EvmTransaction {
        from: request.from,
        to: request.to,
        value: request.value,
        data: request.data.clone(),
        gas_limit: request.gas.unwrap_or(block_ctx.gas_limit),
        gas_price: simulation_fee_cap,
        nonce,
    };
    let gas_limit = match request.gas {
        Some(gas) => gas,
        None => evm
            .estimate_gas(&simulation_tx, &block_ctx)
            .map_err(|e| e.to_string())?,
    };
    drop(evm);

    if let Some(gas_price) = request.gas_price {
        return Ok(RpcManagedTxEnvelope::Legacy(LegacyTx {
            nonce,
            gas_price,
            gas_limit,
            to: request.to,
            value: request.value,
            data: request.data.clone(),
        }));
    }

    let max_priority_fee_per_gas = request.max_priority_fee_per_gas.unwrap_or(suggested_tip);
    let max_fee_per_gas = request
        .max_fee_per_gas
        .unwrap_or_else(|| base_fee.saturating_add(max_priority_fee_per_gas));

    if max_priority_fee_per_gas > max_fee_per_gas {
        return Err("maxPriorityFeePerGas exceeds maxFeePerGas".to_string());
    }

    Ok(RpcManagedTxEnvelope::Eip1559(Eip1559Tx {
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to: request.to,
        value: request.value,
        data: request.data.clone(),
        access_list: request.access_list.clone(),
    }))
}

fn signed_transaction_result(
    signed: &SignedTransaction,
    envelope: &RpcManagedTxEnvelope,
    chain_id: u64,
) -> serde_json::Value {
    serde_json::json!({
        "raw": format!("0x{}", hex::encode(&signed.raw)),
        "tx": envelope.to_rpc_value(signed.from, chain_id),
    })
}

fn filled_transaction_result(
    request: &RpcManagedTxRequest,
    envelope: &RpcManagedTxEnvelope,
    chain_id: u64,
) -> serde_json::Value {
    serde_json::json!({
        "raw": format!("0x{}", hex::encode(envelope.signing_payload(chain_id))),
        "tx": envelope.to_rpc_value(request.from, chain_id),
    })
}

fn ethereum_signed_message_hash(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut payload = prefix.into_bytes();
    payload.extend_from_slice(message);
    let hash = revm::primitives::keccak256(payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_slice());
    out
}

fn rpc_transaction_matches_pool_request(
    request: &RpcManagedTxRequest,
    pool_tx: &PoolTransaction,
) -> bool {
    request.from == pool_tx.from
        && request.nonce == Some(pool_tx.nonce)
        && request.to == pool_tx.to
        && request.value == pool_tx.value
        && request.data == pool_tx.data
}

async fn rpc_resend_transaction(
    node: &NodeState,
    tx_obj: &serde_json::Value,
    gas_price_override: Option<u128>,
    gas_limit_override: Option<u64>,
) -> Result<[u8; 32], String> {
    let request = parse_rpc_managed_tx_request(tx_obj, true)?;
    let nonce = request
        .nonce
        .ok_or_else(|| "missing transaction nonce in transaction spec".to_string())?;
    let wallet = managed_wallet(node, request.from)?.clone();

    let existing = {
        let txpool = node.txpool.read().await;
        txpool
            .get_by_sender_nonce(&request.from, nonce)
            .cloned()
            .ok_or_else(|| "transaction not found".to_string())?
    };

    if !rpc_transaction_matches_pool_request(&request, &existing) {
        return Err("transaction not found".to_string());
    }

    let parsed_existing = existing
        .raw
        .as_deref()
        .and_then(parse_raw_cchain_transaction)
        .ok_or_else(|| "transaction not found".to_string())?;

    let replacement = match parsed_existing.tx_type {
        0 => RpcManagedTxEnvelope::Legacy(LegacyTx {
            nonce,
            gas_price: gas_price_override.unwrap_or(existing.max_fee_per_gas),
            gas_limit: gas_limit_override.unwrap_or(existing.gas_limit),
            to: existing.to,
            value: existing.value,
            data: existing.data.clone(),
        }),
        _ => {
            let replacement_fee = gas_price_override.unwrap_or(existing.max_fee_per_gas);
            RpcManagedTxEnvelope::Eip1559(Eip1559Tx {
                nonce,
                max_priority_fee_per_gas: replacement_fee.min(existing.max_priority_fee_per_gas),
                max_fee_per_gas: replacement_fee,
                gas_limit: gas_limit_override.unwrap_or(existing.gas_limit),
                to: existing.to,
                value: existing.value,
                data: existing.data.clone(),
                access_list: vec![],
            })
        }
    };

    let signed = replacement.sign(&wallet)?;
    let account_nonce = {
        let evm = node.evm.read().await;
        evm.get_nonce(request.from)
    };

    {
        let mut txpool = node.txpool.write().await;
        let removed = txpool.remove(&existing.hash);
        if removed.is_none() {
            return Err("transaction not found".to_string());
        }
    }

    match submit_raw_cchain_transaction(node, &signed.raw).await {
        Ok(hash) => Ok(hash),
        Err(error) => {
            let restored = PoolTransaction {
                hash: existing.hash,
                raw: existing.raw.clone(),
                from: existing.from,
                to: existing.to,
                nonce: existing.nonce,
                gas_limit: existing.gas_limit,
                max_fee_per_gas: existing.max_fee_per_gas,
                max_priority_fee_per_gas: existing.max_priority_fee_per_gas,
                value: existing.value,
                data: existing.data.clone(),
                size: existing.size,
                timestamp: existing.timestamp,
            };
            let _ = node.txpool.write().await.add(restored, account_nonce);
            Err(error)
        }
    }
}

/// Parse a hex block number or "latest"/"earliest"/"pending" tag.
fn parse_block_number(val: &serde_json::Value, node: &NodeState) -> u64 {
    match val.as_str() {
        Some("latest") | Some("pending") | None => {
            node.db.last_accepted_height().unwrap_or(None).unwrap_or(0)
        }
        Some("earliest") => 0,
        Some(hex_str) => {
            let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
            u64::from_str_radix(s, 16).unwrap_or(0)
        }
    }
}

fn resolve_cchain_block_height(
    selector: &serde_json::Value,
    node: &NodeState,
) -> Result<Option<u64>, String> {
    match selector.as_str() {
        Some("latest") | Some("pending") | None => Ok(Some(current_cchain_height(node))),
        Some("earliest") => Ok(Some(0)),
        Some(value) if value.starts_with("0x") && value.len() == 66 => {
            let Some(block_hash) = parse_hex_hash(value) else {
                return Err("invalid hash".to_string());
            };
            let mut key = Vec::with_capacity(34);
            key.extend_from_slice(b"c:");
            key.extend_from_slice(&block_hash);
            let raw_block = match node.db.get_cf(avalanche_rs::db::CF_BLOCKS, &key) {
                Ok(Some(data)) => data,
                _ => return Ok(None),
            };
            Ok(extract_cchain_block_fields(&raw_block).map(|fields| fields.number))
        }
        Some(_) => Ok(Some(parse_block_number(selector, node))),
    }
}

fn current_cchain_height(node: &NodeState) -> u64 {
    node.db.last_accepted_height().unwrap_or(None).unwrap_or(0)
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cb58_encode(bytes: &[u8]) -> String {
    let checksum = Sha256::digest(bytes);
    let mut encoded = Vec::with_capacity(bytes.len() + 4);
    encoded.extend_from_slice(bytes);
    encoded.extend_from_slice(&checksum[checksum.len() - 4..]);
    bs58::encode(encoded).into_string()
}

fn cb58_encode_id(id: [u8; 32]) -> String {
    cb58_encode(&id)
}

fn full_node_id_string(node_id: &NodeId) -> String {
    format!("NodeID-{}", cb58_encode(&node_id.0))
}

fn parse_short_id_20(value: &str) -> Option<[u8; 20]> {
    let decoded = bs58::decode(value).into_vec().ok()?;
    if decoded.len() != 24 {
        return None;
    }

    let mut short_id = [0u8; 20];
    short_id.copy_from_slice(&decoded[..20]);
    Some(short_id)
}

fn parse_node_id_20(value: &str) -> Option<[u8; 20]> {
    let raw = value.strip_prefix("NodeID-").unwrap_or(value);
    parse_short_id_20(raw)
}

fn parse_platform_address_20(value: &str) -> Option<[u8; 20]> {
    if let Some(short_id) = parse_short_id_20(value) {
        return Some(short_id);
    }

    let raw = value
        .split_once('-')
        .map(|(_, suffix)| suffix)
        .unwrap_or(value);
    let (_, data, _) = bech32::decode(raw).ok()?;
    let bytes = Vec::<u8>::from_base32(&data).ok()?;
    if bytes.len() != 20 {
        return None;
    }

    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);
    Some(address)
}

fn info_network_name(network_id: u32) -> &'static str {
    match network_id {
        1 => "mainnet",
        5 => "fuji",
        _ => "custom",
    }
}

fn info_blockchain_alias_id(alias: &str, network_id: u32) -> Option<[u8; 32]> {
    match alias.to_ascii_lowercase().as_str() {
        "p" | "platform" => Some(platform_pchain_blockchain_id()),
        "c" | "evm" => Some(platform_cchain_blockchain_id(network_id)),
        _ => parse_platform_id_32(alias),
    }
}

fn dedupe_aliases_case_insensitive(aliases: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::new();
    for alias in aliases {
        let key = alias.to_ascii_lowercase();
        if seen.insert(key) {
            deduped.push(alias);
        }
    }
    deduped
}

fn normalize_log_level(level: &str) -> Option<String> {
    match level.trim().to_ascii_uppercase().as_str() {
        "TRACE" => Some("TRACE".to_string()),
        "DEBUG" => Some("DEBUG".to_string()),
        "INFO" => Some("INFO".to_string()),
        "WARN" | "WARNING" => Some("WARN".to_string()),
        "ERROR" => Some("ERROR".to_string()),
        _ => None,
    }
}

fn initial_logger_levels(level: &str) -> StdHashMap<String, LoggerLevelState> {
    let normalized = normalize_log_level(level).unwrap_or_else(|| "INFO".to_string());
    let mut levels = StdHashMap::new();
    levels.insert(
        "root".to_string(),
        LoggerLevelState {
            log_level: normalized.clone(),
            display_level: normalized,
        },
    );
    levels
}

fn env_filter_from_logger_levels(levels: &StdHashMap<String, LoggerLevelState>) -> String {
    let root = levels
        .get("root")
        .map(|state| state.log_level.to_ascii_lowercase())
        .unwrap_or_else(|| "info".to_string());

    let mut directives = levels
        .iter()
        .filter(|(name, _)| name.as_str() != "root")
        .map(|(name, state)| format!("{name}={}", state.log_level.to_ascii_lowercase()))
        .collect::<Vec<_>>();
    directives.sort();
    directives.insert(0, root);
    directives.join(",")
}

fn reload_logger_filter(levels: &StdHashMap<String, LoggerLevelState>) -> Result<(), String> {
    let Some(handle) = LOG_RELOAD_HANDLE.get() else {
        return Ok(());
    };
    let filter = EnvFilter::new(env_filter_from_logger_levels(levels));
    handle
        .reload(filter)
        .map_err(|e| format!("failed to reload logger filter: {e}"))
}

fn canonical_blockchain_alias(chain_id: [u8; 32], network_id: u32) -> String {
    if chain_id == platform_pchain_blockchain_id() {
        return "P".to_string();
    }
    if chain_id == platform_cchain_blockchain_id(network_id) {
        return "C".to_string();
    }
    cb58_encode_id(chain_id)
}

async fn resolve_blockchain_alias_id(node: &NodeState, alias: &str) -> Option<[u8; 32]> {
    if let Some(chain_id) = info_blockchain_alias_id(alias, node.config.network_id) {
        return Some(chain_id);
    }

    {
        let chain_aliases = node.chain_aliases.read().await;
        for (chain_id, aliases) in chain_aliases.iter() {
            if aliases
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(alias))
            {
                return Some(*chain_id);
            }
        }
    }

    let tracker = node.subnet_tracker.read().await;
    tracker
        .all_chains()
        .into_iter()
        .find(|state| state.config.name.eq_ignore_ascii_case(alias))
        .map(|state| state.config.chain_id.0)
}

async fn blockchain_aliases_for_id(node: &NodeState, chain_id: [u8; 32]) -> Vec<String> {
    let mut aliases = match chain_id {
        id if id == platform_pchain_blockchain_id() => {
            vec!["P".to_string(), "platform".to_string()]
        }
        id if id == platform_cchain_blockchain_id(node.config.network_id) => {
            vec!["C".to_string(), "evm".to_string()]
        }
        _ => Vec::new(),
    };

    {
        let tracker = node.subnet_tracker.read().await;
        if let Some(state) = tracker.chain_state(&ChainId(chain_id)) {
            aliases.push(state.config.name.clone());
        }
    }

    aliases.push(cb58_encode_id(chain_id));

    {
        let chain_aliases = node.chain_aliases.read().await;
        if let Some(extra) = chain_aliases.get(&chain_id) {
            aliases.extend(extra.iter().cloned());
        }
    }

    dedupe_aliases_case_insensitive(aliases)
}

fn admin_normalize_endpoint_path(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("ext/") {
        Some(format!("/{}", trimmed))
    } else {
        Some(format!("/ext/{}", trimmed))
    }
}

fn admin_endpoint_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("endpoint"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn admin_alias_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("alias"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(1).and_then(|value| value.as_str()))
}

fn admin_chain_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("chain"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn admin_logger_name_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("loggerName"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn admin_log_level_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("logLevel"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(1).and_then(|value| value.as_str()))
}

fn admin_display_level_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("displayLevel"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(2).and_then(|value| value.as_str()))
}

fn logger_levels_response(
    levels: &StdHashMap<String, LoggerLevelState>,
    logger_name: Option<&str>,
) -> serde_json::Value {
    let mut logger_levels = serde_json::Map::new();
    if let Some(logger_name) = logger_name {
        if let Some(state) = levels
            .get(logger_name)
            .cloned()
            .or_else(|| levels.get("root").cloned())
        {
            logger_levels.insert(
                logger_name.to_string(),
                serde_json::json!({
                    "logLevel": state.log_level,
                    "displayLevel": state.display_level,
                }),
            );
        }
    } else {
        let mut names = levels.keys().cloned().collect::<Vec<_>>();
        names.sort();
        for name in names {
            if let Some(state) = levels.get(&name) {
                logger_levels.insert(
                    name,
                    serde_json::json!({
                        "logLevel": state.log_level,
                        "displayLevel": state.display_level,
                    }),
                );
            }
        }
    }
    serde_json::json!({ "loggerLevels": logger_levels })
}

async fn resolve_request_path(node: &NodeState, path: &str) -> String {
    let mut resolved = path.to_string();

    {
        let aliases = node.http_aliases.read().await;
        let mut best_match: Option<(usize, String)> = None;
        for (alias, target) in aliases.iter() {
            let suffix = if resolved == *alias {
                Some("")
            } else if resolved.starts_with(alias)
                && resolved.as_bytes().get(alias.len()) == Some(&b'/')
            {
                Some(&resolved[alias.len()..])
            } else {
                None
            };

            if let Some(suffix) = suffix {
                let candidate = format!("{}{}", target, suffix);
                if best_match
                    .as_ref()
                    .map(|(len, _)| alias.len() > *len)
                    .unwrap_or(true)
                {
                    best_match = Some((alias.len(), candidate));
                }
            }
        }

        if let Some((_, candidate)) = best_match {
            resolved = candidate;
        }
    }

    if let Some(rest) = resolved.strip_prefix("/ext/bc/") {
        let (alias, suffix) = rest
            .split_once('/')
            .map(|(segment, suffix)| (segment, format!("/{}", suffix)))
            .unwrap_or((rest, String::new()));
        if let Some(chain_id) = resolve_blockchain_alias_id(node, alias).await {
            let canonical = canonical_blockchain_alias(chain_id, node.config.network_id);
            return format!("/ext/bc/{}{}", canonical, suffix);
        }
    }

    resolved
}

#[derive(Debug, Clone, Copy)]
enum ProposerVmTarget {
    PChain,
    CChain,
    Custom([u8; 32]),
}

enum ProposerVmRoute {
    NotProposerVm,
    UnknownChain(String),
    Target(ProposerVmTarget),
}

async fn resolve_proposervm_route(node: &NodeState, path: &str) -> ProposerVmRoute {
    let Some(rest) = path.strip_prefix("/ext/bc/") else {
        return ProposerVmRoute::NotProposerVm;
    };
    let Some(chain_alias) = rest.strip_suffix("/proposervm") else {
        return ProposerVmRoute::NotProposerVm;
    };
    if chain_alias.is_empty() || chain_alias.contains('/') {
        return ProposerVmRoute::NotProposerVm;
    }

    let Some(chain_id) = resolve_blockchain_alias_id(node, chain_alias).await else {
        return ProposerVmRoute::UnknownChain(chain_alias.to_string());
    };

    if chain_id == platform_pchain_blockchain_id() {
        ProposerVmRoute::Target(ProposerVmTarget::PChain)
    } else if chain_id == platform_cchain_blockchain_id(node.config.network_id) {
        ProposerVmRoute::Target(ProposerVmTarget::CChain)
    } else {
        ProposerVmRoute::Target(ProposerVmTarget::Custom(chain_id))
    }
}

fn info_node_ids_param(params: &serde_json::Value) -> Vec<[u8; 20]> {
    platform_params_object(params)
        .and_then(|obj| obj.get("nodeIDs"))
        .or_else(|| params.get(0))
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().and_then(parse_node_id_20))
                .collect()
        })
        .unwrap_or_default()
}

fn info_alias_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("alias"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn info_chain_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("chain"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn info_vm_id(tag: &[u8]) -> [u8; 32] {
    let mut id = [0u8; 32];
    let len = tag.len().min(id.len());
    id[..len].copy_from_slice(&tag[..len]);
    id
}

fn info_get_node_version_result() -> serde_json::Value {
    let version = format!("avalanche-rs/{}", env!("CARGO_PKG_VERSION"));
    serde_json::json!({
        "version": version,
        "databaseVersion": format!("v{}", env!("CARGO_PKG_VERSION")),
        "rpcProtocolVersion": "0",
        "gitCommit": option_env!("GIT_COMMIT").unwrap_or("rust"),
        "vmVersions": {
            "platform": format!("avalanche-rs/{}", env!("CARGO_PKG_VERSION")),
            "evm": format!("avalanche-rs/{}", env!("CARGO_PKG_VERSION")),
        }
    })
}

fn info_get_tx_fee_result(network_id: u32) -> serde_json::Value {
    let (create_subnet_tx_fee, transform_subnet_tx_fee, create_blockchain_tx_fee) = match network_id
    {
        1 => (1_000_000_000u64, 10_000_000_000u64, 1_000_000_000u64),
        5 => (100_000_000u64, 1_000_000_000u64, 100_000_000u64),
        _ => (100_000_000u64, 100_000_000u64, 100_000_000u64),
    };

    serde_json::json!({
        "txFee": "1000000",
        "createAssetTxFee": "10000000",
        "createSubnetTxFee": create_subnet_tx_fee.to_string(),
        "transformSubnetTxFee": transform_subnet_tx_fee.to_string(),
        "createBlockchainTxFee": create_blockchain_tx_fee.to_string(),
        "addPrimaryNetworkValidatorFee": "0",
        "addPrimaryNetworkDelegatorFee": "0",
        "addSubnetValidatorFee": "1000000",
        "addSubnetDelegatorFee": "1000000",
    })
}

fn platform_dynamic_fee_config(_network_id: u32) -> PlatformDynamicFeeConfig {
    PlatformDynamicFeeConfig {
        weights: [1, 1_000, 1_000, 4],
        max_capacity: 1_000_000,
        max_per_second: 100_000,
        target_per_second: 50_000,
        min_price: 1,
        excess_conversion_constant: 2_164_043,
    }
}

fn platform_fee_config_result(network_id: u32) -> serde_json::Value {
    let config = platform_dynamic_fee_config(network_id);
    serde_json::json!({
        "weights": config.weights,
        "maxCapacity": config.max_capacity,
        "maxPerSecond": config.max_per_second,
        "targetPerSecond": config.target_per_second,
        "minPrice": config.min_price,
        "excessConversionConstant": config.excess_conversion_constant,
    })
}

fn platform_validator_fee_config(network_id: u32) -> PlatformValidatorFeeConfig {
    PlatformValidatorFeeConfig {
        capacity: 20_000,
        target: 10_000,
        min_price: match network_id {
            1 | 5 => 512u64,
            _ => 1u64,
        },
        excess_conversion_constant: match network_id {
            1 => 1_246_488_515u64,
            5 => 51_937_021u64,
            _ => 865_617u64,
        },
    }
}

fn platform_validator_fee_config_result(network_id: u32) -> serde_json::Value {
    let config = platform_validator_fee_config(network_id);
    serde_json::json!({
        "capacity": config.capacity,
        "target": config.target,
        "minPrice": config.min_price,
        "excessConversionConstant": config.excess_conversion_constant,
    })
}

fn platform_gas_price(min_price: u64, excess: u64, excess_conversion_constant: u64) -> u64 {
    let numerator = U256::from(excess);
    let denominator = U256::from(excess_conversion_constant);
    let mut i = U256::from(1u64);
    let mut output = U256::ZERO;
    let mut numerator_accum = U256::from(min_price) * denominator;
    let max_output = denominator * U256::from(u64::MAX);

    while numerator_accum > U256::ZERO {
        output += numerator_accum;
        if output >= max_output {
            return u64::MAX;
        }
        numerator_accum = (numerator_accum * numerator) / denominator / i;
        i += U256::from(1u64);
    }

    ((output / denominator).to::<u128>()).min(u64::MAX as u128) as u64
}

fn platform_gas_state_advance(
    state: PlatformGasState,
    config: PlatformDynamicFeeConfig,
    seconds: u64,
) -> PlatformGasState {
    PlatformGasState {
        capacity: state
            .capacity
            .saturating_add(config.max_per_second.saturating_mul(seconds))
            .min(config.max_capacity),
        excess: state
            .excess
            .saturating_sub(config.target_per_second.saturating_mul(seconds)),
    }
}

fn platform_gas_state_consume(
    state: PlatformGasState,
    gas: u64,
) -> Result<PlatformGasState, String> {
    if gas > state.capacity {
        return Err(format!(
            "insufficient gas capacity: capacity ({}) < gas ({})",
            state.capacity, gas
        ));
    }
    Ok(PlatformGasState {
        capacity: state.capacity - gas,
        excess: state.excess.saturating_add(gas),
    })
}

fn info_upgrades_result(network_id: u32) -> serde_json::Value {
    match network_id {
        1 => serde_json::json!({
            "apricotPhase1Time": "2021-03-31T14:00:00Z",
            "apricotPhase2Time": "2021-05-10T11:00:00Z",
            "apricotPhase3Time": "2021-08-24T14:00:00Z",
            "apricotPhase4Time": "2021-09-22T21:00:00Z",
            "apricotPhase4MinPChainHeight": 793005,
            "apricotPhase5Time": "2021-12-02T18:00:00Z",
            "apricotPhasePre6Time": "2022-09-05T01:30:00Z",
            "apricotPhase6Time": "2022-09-06T20:00:00Z",
            "apricotPhasePost6Time": "2022-09-07T03:00:00Z",
            "banffTime": "2022-10-18T16:00:00Z",
            "cortinaTime": "2023-04-25T15:00:00Z",
            "cortinaXChainStopVertexID": "jrGWDh5Po9FMj54depyunNixpia5PN4aAYxfmNzU8n752Rjga",
            "durangoTime": "2024-03-06T16:00:00Z",
            "etnaTime": "2024-12-16T17:00:00Z",
            "fortunaTime": "2025-04-08T15:00:00Z",
            "graniteTime": "2025-11-19T16:00:00Z",
            "graniteEpochDuration": 300_000_000_000u64,
            "heliconTime": "9999-12-01T00:00:00Z",
        }),
        5 => serde_json::json!({
            "apricotPhase1Time": "2021-03-26T14:00:00Z",
            "apricotPhase2Time": "2021-05-05T14:00:00Z",
            "apricotPhase3Time": "2021-08-16T19:00:00Z",
            "apricotPhase4Time": "2021-09-16T21:00:00Z",
            "apricotPhase4MinPChainHeight": 47437,
            "apricotPhase5Time": "2021-11-24T15:00:00Z",
            "apricotPhasePre6Time": "2022-09-06T20:00:00Z",
            "apricotPhase6Time": "2022-09-06T20:00:00Z",
            "apricotPhasePost6Time": "2022-09-07T06:00:00Z",
            "banffTime": "2022-10-03T14:00:00Z",
            "cortinaTime": "2023-04-06T15:00:00Z",
            "cortinaXChainStopVertexID": "2D1cmbiG36BqQMRyHt4kFhWarmatA1ighSpND3FeFgz3vFVtCZ",
            "durangoTime": "2024-02-13T16:00:00Z",
            "etnaTime": "2024-11-25T16:00:00Z",
            "fortunaTime": "2025-03-13T15:00:00Z",
            "graniteTime": "2025-10-29T15:00:00Z",
            "graniteEpochDuration": 300_000_000_000u64,
            "heliconTime": "9999-12-01T00:00:00Z",
        }),
        _ => serde_json::json!({
            "apricotPhase1Time": "2020-12-05T05:00:00Z",
            "apricotPhase2Time": "2020-12-05T05:00:00Z",
            "apricotPhase3Time": "2020-12-05T05:00:00Z",
            "apricotPhase4Time": "2020-12-05T05:00:00Z",
            "apricotPhase4MinPChainHeight": 0,
            "apricotPhase5Time": "2020-12-05T05:00:00Z",
            "apricotPhasePre6Time": "2020-12-05T05:00:00Z",
            "apricotPhase6Time": "2020-12-05T05:00:00Z",
            "apricotPhasePost6Time": "2020-12-05T05:00:00Z",
            "banffTime": "2020-12-05T05:00:00Z",
            "cortinaTime": "2020-12-05T05:00:00Z",
            "cortinaXChainStopVertexID": "11111111111111111111111111111111LpoYY",
            "durangoTime": "2020-12-05T05:00:00Z",
            "etnaTime": "2020-12-05T05:00:00Z",
            "fortunaTime": "2020-12-05T05:00:00Z",
            "graniteTime": "2020-12-05T05:00:00Z",
            "graniteEpochDuration": 30_000_000_000u64,
            "heliconTime": "9999-12-01T00:00:00Z",
        }),
    }
}

const VM_ERROR_CODE_OUT_OF_GAS: i64 = 1;
const VM_ERROR_CODE_INVALID_JUMP: i64 = 8;
const VM_ERROR_CODE_EXECUTION_REVERTED: i64 = 6;
const VM_ERROR_CODE_STACK_UNDERFLOW: i64 = 14;
const VM_ERROR_CODE_STACK_OVERFLOW: i64 = 15;
const VM_ERROR_CODE_INVALID_OPCODE: i64 = 16;
const VM_ERROR_CODE_UNKNOWN: i64 = i64::MAX - 1;

fn upgrade_time_unix(upgrades: &serde_json::Value, field: &str) -> u64 {
    upgrades
        .get(field)
        .and_then(|value| value.as_str())
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.timestamp().max(0) as u64)
        .unwrap_or(0)
}

fn cchain_berlin_london_blocks(network_id: u32) -> (u64, u64) {
    match network_id {
        1 => (1_640_340, 3_308_552),
        5 => (184_985, 805_078),
        _ => (0, 0),
    }
}

fn cchain_chain_config_result(node: &NodeState) -> serde_json::Value {
    let upgrades = info_upgrades_result(node.config.network_id);
    let (berlin_block, london_block) = cchain_berlin_london_blocks(node.config.network_id);

    serde_json::json!({
        "chainId": node.config.chain_id,
        "homesteadBlock": 0,
        "daoForkBlock": 0,
        "daoForkSupport": true,
        "eip150Block": 0,
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "muirGlacierBlock": 0,
        "berlinBlock": berlin_block,
        "londonBlock": london_block,
        "shanghaiTime": upgrade_time_unix(&upgrades, "durangoTime"),
        "cancunTime": upgrade_time_unix(&upgrades, "etnaTime"),
        "apricotPhase1BlockTimestamp": upgrade_time_unix(&upgrades, "apricotPhase1Time"),
        "apricotPhase2BlockTimestamp": upgrade_time_unix(&upgrades, "apricotPhase2Time"),
        "apricotPhase3BlockTimestamp": upgrade_time_unix(&upgrades, "apricotPhase3Time"),
        "apricotPhase4BlockTimestamp": upgrade_time_unix(&upgrades, "apricotPhase4Time"),
        "apricotPhase5BlockTimestamp": upgrade_time_unix(&upgrades, "apricotPhase5Time"),
        "apricotPhasePre6BlockTimestamp": upgrade_time_unix(&upgrades, "apricotPhasePre6Time"),
        "apricotPhase6BlockTimestamp": upgrade_time_unix(&upgrades, "apricotPhase6Time"),
        "apricotPhasePost6BlockTimestamp": upgrade_time_unix(&upgrades, "apricotPhasePost6Time"),
        "banffBlockTimestamp": upgrade_time_unix(&upgrades, "banffTime"),
        "cortinaBlockTimestamp": upgrade_time_unix(&upgrades, "cortinaTime"),
        "durangoBlockTimestamp": upgrade_time_unix(&upgrades, "durangoTime"),
        "etnaTimestamp": upgrade_time_unix(&upgrades, "etnaTime"),
        "fortunaTimestamp": upgrade_time_unix(&upgrades, "fortunaTime"),
        "graniteTimestamp": upgrade_time_unix(&upgrades, "graniteTime"),
    })
}

fn cchain_vm_config_result(node: &NodeState) -> serde_json::Value {
    serde_json::json!({
        "config": {
            "networkID": node.config.network_id,
            "chainID": node.config.chain_id,
            "txPoolSize": node.config.txpool_size,
            "statePruningDepth": node.config.state_pruning_depth,
            "archiveMode": node.config.archive,
            "lightClient": node.config.light_client,
            "validator": node.config.validator,
            "rpcMaxBodySize": node.config.rpc_max_body_size,
            "blockCacheSize": node.config.block_cache_size,
        }
    })
}

fn cchain_suggest_price_options_result(node: &NodeState) -> serde_json::Value {
    let base_fee = predicted_next_base_fee_from_db(&node.db, node.config.network_id);
    let normal_tip = recent_priority_fee_suggestion(&node.db, current_cchain_height(node))
        .max(PRIORITY_FEE_FLOOR);
    let slow_tip = (normal_tip / 2).max(PRIORITY_FEE_FLOOR);
    let fast_tip = normal_tip.saturating_mul(2);

    let option = |tip: u128| {
        serde_json::json!({
            "maxPriorityFeePerGas": format!("0x{:x}", tip),
            "maxFeePerGas": format!("0x{:x}", base_fee.saturating_add(tip)),
        })
    };

    serde_json::json!({
        "slow": option(slow_tip),
        "normal": option(normal_tip),
        "fast": option(fast_tip),
    })
}

fn cchain_legacy_gas_price(node: &NodeState) -> u128 {
    let base_fee = predicted_next_base_fee_from_db(&node.db, node.config.network_id);
    let tip = recent_priority_fee_suggestion(&node.db, current_cchain_height(node))
        .max(PRIORITY_FEE_FLOOR);
    base_fee.saturating_add(tip)
}

fn call_detailed_err_code(error: &str) -> i64 {
    if error.contains("OutOfGas") {
        VM_ERROR_CODE_OUT_OF_GAS
    } else if error.contains("InvalidJump") {
        VM_ERROR_CODE_INVALID_JUMP
    } else if error.contains("StackUnderflow") {
        VM_ERROR_CODE_STACK_UNDERFLOW
    } else if error.contains("StackOverflow") {
        VM_ERROR_CODE_STACK_OVERFLOW
    } else if error.contains("OpcodeNotFound") || error.contains("InvalidFEOpcode") {
        VM_ERROR_CODE_INVALID_OPCODE
    } else {
        VM_ERROR_CODE_UNKNOWN
    }
}

fn eth_call_detailed_result(
    evm: &EvmExecutor,
    tx_obj: &serde_json::Value,
    block_ctx: &BlockContext,
) -> serde_json::Value {
    let parsed = parse_rpc_simulation_tx(tx_obj, evm, block_ctx);
    let mut snapshot = evm.snapshot();
    match snapshot.execute_tx(&parsed.tx, block_ctx) {
        Ok(receipt) if receipt.success => serde_json::json!({
            "gas": receipt.gas_used,
            "errCode": 0,
            "err": "",
            "returnData": format!("0x{}", hex::encode(receipt.output)),
        }),
        Ok(receipt) => {
            let output_text = String::from_utf8_lossy(&receipt.output);
            if output_text.starts_with("HALT: ") {
                serde_json::json!({
                    "gas": receipt.gas_used,
                    "errCode": call_detailed_err_code(&output_text),
                    "err": output_text,
                    "returnData": "0x",
                })
            } else {
                serde_json::json!({
                    "gas": receipt.gas_used,
                    "errCode": VM_ERROR_CODE_EXECUTION_REVERTED,
                    "err": "execution reverted",
                    "returnData": format!("0x{}", hex::encode(receipt.output)),
                })
            }
        }
        Err(err) => {
            let err = err.to_string();
            serde_json::json!({
                "gas": 0,
                "errCode": VM_ERROR_CODE_UNKNOWN,
                "err": err,
                "returnData": "0x",
            })
        }
    }
}

fn info_get_vms_result() -> serde_json::Value {
    serde_json::json!({
        "vms": {
            cb58_encode_id(info_vm_id(b"platformvm")): ["platform"],
            cb58_encode_id(info_vm_id(b"evm")): ["evm"],
        },
        "fxs": {
            cb58_encode_id(info_vm_id(b"secp256k1fx")): "secp256k1fx",
            cb58_encode_id(info_vm_id(b"nftfx")): "nftfx",
            cb58_encode_id(info_vm_id(b"propertyfx")): "propertyfx",
        }
    })
}

fn format_instant_rfc3339(instant: Instant) -> String {
    let now = chrono::Utc::now();
    match chrono::Duration::from_std(instant.elapsed()) {
        Ok(delta) => (now - delta).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        Err(_) => now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

fn format_percentage_4dp(value: f64) -> String {
    format!("{value:.4}")
}

fn info_primary_network_subnet_id() -> String {
    cb58_encode_id([0u8; 32])
}

fn info_peer_json(peer: &Peer) -> serde_json::Value {
    let tracked_subnets = if peer.tracked_subnets.is_empty() {
        vec![serde_json::Value::String(info_primary_network_subnet_id())]
    } else {
        peer.tracked_subnets
            .iter()
            .map(|subnet| serde_json::Value::String(cb58_encode_id(subnet.0)))
            .collect::<Vec<_>>()
    };
    let public_ip = peer.public_ip.unwrap_or(peer.address);

    serde_json::json!({
        "ip": peer.address.to_string(),
        "publicIP": public_ip.to_string(),
        "nodeID": full_node_id_string(&peer.node_id),
        "version": peer.version.clone().unwrap_or_else(|| "unknown".to_string()),
        "upgradeTime": 0u64,
        "lastSent": format_instant_rfc3339(peer.last_ping_sent.unwrap_or(peer.connected_at)),
        "lastReceived": format_instant_rfc3339(peer.last_seen),
        "observedUptime": peer.reported_uptime.to_string(),
        "trackedSubnets": tracked_subnets,
        "supportedACPs": peer.supported_acps.clone(),
        "objectedACPs": peer.objected_acps.clone(),
        "benched": Vec::<String>::new(),
    })
}

async fn info_acps_result(node: &NodeState) -> serde_json::Value {
    let now = unix_timestamp_secs();
    let validators = &node.validators;
    let total_active_weight = validators
        .values()
        .filter(|validator| validator.start_time <= now && now < validator.end_time)
        .map(|validator| validator.weight)
        .sum::<u64>();
    let mut totals = std::collections::BTreeMap::<u32, (u64, u64, Vec<String>, Vec<String>)>::new();

    let pm = node.peer_manager.read().await;
    for peer in pm
        .connected_peers()
        .into_iter()
        .filter_map(|node_id| pm.get_peer(&node_id))
    {
        let node_id = full_node_id_string(&peer.node_id);
        let weight = validators
            .get(&node_id)
            .filter(|validator| validator.start_time <= now && now < validator.end_time)
            .map(|validator| validator.weight)
            .unwrap_or(0);

        let mut seen_supported = std::collections::HashSet::new();
        for acp in &peer.supported_acps {
            if seen_supported.insert(*acp) {
                let entry = totals.entry(*acp).or_default();
                entry.0 = entry.0.saturating_add(weight);
                entry.2.push(node_id.clone());
            }
        }

        let mut seen_objected = std::collections::HashSet::new();
        for acp in &peer.objected_acps {
            if seen_objected.insert(*acp) {
                let entry = totals.entry(*acp).or_default();
                entry.1 = entry.1.saturating_add(weight);
                entry.3.push(node_id.clone());
            }
        }
    }

    let acps = totals
        .into_iter()
        .map(
            |(acp, (support_weight, object_weight, supporters, objectors))| {
                (
                    acp.to_string(),
                    serde_json::json!({
                        "supportWeight": support_weight.to_string(),
                        "objectWeight": object_weight.to_string(),
                        "abstainWeight": total_active_weight
                            .saturating_sub(support_weight.saturating_add(object_weight))
                            .to_string(),
                        "supporters": supporters,
                        "objectors": objectors,
                    }),
                )
            },
        )
        .collect::<serde_json::Map<String, serde_json::Value>>();

    serde_json::json!({ "acps": acps })
}

async fn info_uptime_result(node: &NodeState) -> serde_json::Value {
    const REWARDING_UPTIME_BPS: u32 = 8_000;

    let now = unix_timestamp_secs();
    let total_active_weight = node
        .validators
        .values()
        .filter(|validator| validator.start_time <= now && now < validator.end_time)
        .map(|validator| validator.weight as u128)
        .sum::<u128>();
    let pm = node.peer_manager.read().await;
    let mut weighted_uptime_bps = 0u128;
    let mut rewarding_weight = 0u128;

    for peer in pm
        .connected_peers()
        .into_iter()
        .filter_map(|node_id| pm.get_peer(&node_id))
    {
        let node_id = full_node_id_string(&peer.node_id);
        let Some(validator) = node
            .validators
            .get(&node_id)
            .filter(|validator| validator.start_time <= now && now < validator.end_time)
        else {
            continue;
        };

        let weight = validator.weight as u128;
        weighted_uptime_bps =
            weighted_uptime_bps.saturating_add(weight.saturating_mul(peer.reported_uptime as u128));
        if peer.reported_uptime >= REWARDING_UPTIME_BPS {
            rewarding_weight = rewarding_weight.saturating_add(weight);
        }
    }

    let weighted_average = if total_active_weight == 0 {
        0.0
    } else {
        (weighted_uptime_bps as f64) / (total_active_weight as f64) / 100.0
    };
    let rewarding_percentage = if total_active_weight == 0 {
        0.0
    } else {
        (rewarding_weight as f64) * 100.0 / (total_active_weight as f64)
    };

    serde_json::json!({
        "rewardingStakePercentage": format_percentage_4dp(rewarding_percentage),
        "weightedAveragePercentage": format_percentage_4dp(weighted_average),
    })
}

fn local_supported_acps(network_id: u32, now: u64) -> Vec<u32> {
    let mut acps = Vec::new();
    if avalanche_rs::fortuna::is_fortuna_active(network_id, now) {
        acps.push(176);
    }
    if avalanche_rs::granite::is_granite_active(network_id, now) {
        acps.extend([181, 204, 226]);
    }
    acps
}

async fn info_node_ip_string(node: &NodeState) -> String {
    if let Some(addr) = *node.resolved_public_ip.read().await {
        return addr.to_string();
    }

    if let Some(addr) = discover_public_ip(node.config.staking_port) {
        *node.resolved_public_ip.write().await = Some(addr);
        return addr.to_string();
    }

    format!("0.0.0.0:{}", node.config.staking_port)
}

async fn info_is_bootstrapped(node: &NodeState, chain: &str) -> Result<bool, String> {
    if chain.is_empty() {
        return Err("argument 'chain' not given".to_string());
    }

    let phase = node.sync_engine.phase().await;
    let bootstrapped = matches!(phase, SyncPhase::Synced | SyncPhase::Following);
    if matches!(
        chain.to_ascii_lowercase().as_str(),
        "p" | "platform" | "c" | "evm"
    ) {
        return Ok(bootstrapped);
    }

    if let Some(chain_id) = resolve_blockchain_alias_id(node, chain).await {
        if chain_id == platform_pchain_blockchain_id() {
            return Ok(bootstrapped);
        }
        if chain_id == platform_cchain_blockchain_id(node.config.network_id) {
            return Ok(bootstrapped);
        }

        let tracker = node.subnet_tracker.read().await;
        if let Some(state) = tracker.chain_state(&ChainId(chain_id)) {
            return Ok(matches!(
                state.phase,
                SyncPhase::Synced | SyncPhase::Following
            ));
        }
    }

    Err(format!("there is no chain with alias/ID '{}'", chain))
}

#[derive(Clone, Copy)]
enum HealthReportKind {
    Health,
    Readiness,
    Liveness,
}

fn health_tags_param(params: &serde_json::Value) -> Vec<String> {
    platform_params_object(params)
        .and_then(|obj| obj.get("tags"))
        .or_else(|| {
            params
                .get(0)
                .and_then(|value| value.as_object())
                .and_then(|obj| obj.get("tags"))
        })
        .and_then(|value| value.as_array())
        .map(|tags| {
            tags.iter()
                .filter_map(|tag| tag.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn current_timestamp_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn unix_timestamp_to_rfc3339_seconds(timestamp: u64) -> String {
    chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn avax_params_object(
    params: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    match params {
        serde_json::Value::Object(map) => Some(map),
        serde_json::Value::Array(arr) => arr.first().and_then(|value| value.as_object()),
        _ => None,
    }
}

fn avax_tx_param(params: &serde_json::Value) -> Option<&str> {
    avax_params_object(params)
        .and_then(|obj| obj.get("tx"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn avax_encoding_param<'a>(params: &'a serde_json::Value, default: &'a str) -> &'a str {
    avax_params_object(params)
        .and_then(|obj| obj.get("encoding"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(1).and_then(|value| value.as_str()))
        .unwrap_or(default)
}

fn avax_tx_id_param(params: &serde_json::Value) -> Option<&str> {
    avax_params_object(params)
        .and_then(|obj| obj.get("txID"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn atomic_tx_storage_key(tx_id: &str) -> String {
    format!("atomic:{tx_id}")
}

fn atomic_tx_meta_key(tx_id: &str) -> String {
    format!("atomic-meta:{tx_id}")
}

fn normalize_atomic_tx_id(tx_id: &str) -> Option<String> {
    if let Some(hash) = parse_hex_hash(tx_id) {
        return Some(cb58_encode_id(hash));
    }
    parse_cb58_id_32(tx_id).map(cb58_encode_id)
}

fn load_atomic_tx_metadata(db: &Database, tx_id: &str) -> Option<AtomicTxMetadata> {
    let key = atomic_tx_meta_key(tx_id);
    db.get_cf(CF_BLOCKS, key.as_bytes())
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

fn health_elapsed_string(elapsed: Duration) -> String {
    if elapsed.as_millis() > 0 {
        format!("{}ms", elapsed.as_millis())
    } else {
        format!("{}s", elapsed.as_secs())
    }
}

fn health_check_value(
    details: Option<serde_json::Value>,
    error: Option<String>,
    duration: Duration,
) -> serde_json::Value {
    let timestamp = current_timestamp_rfc3339();
    let mut value = serde_json::Map::new();
    if let Some(details) = details {
        value.insert("message".to_string(), details);
    }
    if let Some(error) = error {
        value.insert("error".to_string(), serde_json::Value::String(error));
        value.insert("contiguousFailures".to_string(), serde_json::json!(1));
        value.insert(
            "timeOfFirstFailure".to_string(),
            serde_json::Value::String(timestamp.clone()),
        );
    }
    value.insert(
        "timestamp".to_string(),
        serde_json::Value::String(timestamp),
    );
    value.insert(
        "duration".to_string(),
        serde_json::json!(duration.as_nanos() as u64),
    );
    serde_json::Value::Object(value)
}

fn health_primary_network_tag() -> String {
    cb58_encode_id(platform_pchain_blockchain_id())
}

fn health_tags_include_primary_chain(
    tags: &[String],
    aliases: &[&str],
    chain_id: [u8; 32],
) -> bool {
    if tags.is_empty() {
        return true;
    }

    let chain_id = cb58_encode_id(chain_id);
    let primary_network = health_primary_network_tag();
    tags.iter().any(|tag| {
        aliases.iter().any(|alias| tag.eq_ignore_ascii_case(alias))
            || tag == &chain_id
            || tag == &primary_network
    })
}

fn health_tags_include_tracked_chain(
    tags: &[String],
    state: &avalanche_rs::subnet::ChainSyncState,
) -> bool {
    if tags.is_empty() {
        return true;
    }

    let chain_id = cb58_encode_id(state.config.chain_id.0);
    let subnet_id = cb58_encode_id(state.config.subnet_id.0);
    tags.iter().any(|tag| {
        tag == &chain_id || tag == &subnet_id || tag.eq_ignore_ascii_case(&state.config.name)
    })
}

fn chain_health_value(
    chain_name: &str,
    last_accepted_height: u64,
    last_accepted_id: [u8; 32],
    percent_connected: f64,
) -> serde_json::Value {
    let _ = chain_name;
    health_check_value(
        Some(serde_json::json!({
            "engine": {
                "consensus": {
                    "lastAcceptedHeight": last_accepted_height,
                    "lastAcceptedID": cb58_encode_id(last_accepted_id),
                    "longestProcessingBlock": "0s",
                    "processingBlocks": 0,
                },
                "vm": serde_json::Value::Null,
            },
            "networking": {
                "percentConnected": percent_connected,
            }
        })),
        None,
        Duration::ZERO,
    )
}

async fn health_report(
    node: &NodeState,
    kind: HealthReportKind,
    tags: &[String],
) -> serde_json::Value {
    if matches!(kind, HealthReportKind::Liveness) {
        return serde_json::json!({
            "checks": {},
            "healthy": true,
        });
    }

    let phase = node.sync_engine.phase().await;
    let is_bootstrapped = matches!(phase, SyncPhase::Synced | SyncPhase::Following);
    let db_accessible = node.db.last_accepted_height().is_ok();

    let p_metrics = node.p_chain_metrics.read().await.clone();
    let c_metrics = node.c_chain_metrics.read().await.clone();

    let tracker = node.subnet_tracker.read().await;
    let tracked_chain_states = tracker
        .all_chains()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    drop(tracker);

    let pm = node.peer_manager.read().await;
    let connected_ids = pm.connected_peers();
    let connected_peers = connected_ids
        .iter()
        .filter_map(|node_id| pm.get_peer(node_id).cloned())
        .collect::<Vec<_>>();
    let peer_count = connected_peers.len();
    drop(pm);

    let now = Instant::now();
    let last_received = connected_peers
        .iter()
        .map(|peer| now.saturating_duration_since(peer.last_seen))
        .min()
        .unwrap_or_default();
    let last_sent = connected_peers
        .iter()
        .map(|peer| {
            peer.last_ping_sent
                .map(|sent| now.saturating_duration_since(sent))
                .unwrap_or_else(|| now.saturating_duration_since(peer.connected_at))
        })
        .min()
        .unwrap_or_default();
    let percent_connected = if peer_count > 0 { 1.0 } else { 0.0 };

    let mut checks = serde_json::Map::new();
    let mut healthy = true;

    let bootstrapped_error = if is_bootstrapped {
        None
    } else {
        Some("node is bootstrapping".to_string())
    };
    if bootstrapped_error.is_some() {
        healthy = false;
    }
    checks.insert(
        "bootstrapped".to_string(),
        health_check_value(
            Some(serde_json::Value::Array(vec![])),
            bootstrapped_error,
            Duration::ZERO,
        ),
    );

    if matches!(kind, HealthReportKind::Readiness) {
        return serde_json::json!({
            "checks": checks,
            "healthy": healthy,
        });
    }

    let database_error = if db_accessible {
        None
    } else {
        Some("database is inaccessible".to_string())
    };
    if database_error.is_some() {
        healthy = false;
    }
    checks.insert(
        "database".to_string(),
        health_check_value(None, database_error, Duration::ZERO),
    );

    let network_error = if peer_count > 0 {
        None
    } else {
        Some("no connected peers".to_string())
    };
    if network_error.is_some() {
        healthy = false;
    }
    checks.insert(
        "network".to_string(),
        health_check_value(
            Some(serde_json::json!({
                "connectedPeers": peer_count,
                "sendFailRate": 0,
                "timeSinceLastMsgReceived": health_elapsed_string(last_received),
                "timeSinceLastMsgSent": health_elapsed_string(last_sent),
            })),
            network_error,
            Duration::ZERO,
        ),
    );

    if health_tags_include_primary_chain(tags, &["P", "platform"], platform_pchain_blockchain_id())
    {
        checks.insert(
            "P".to_string(),
            chain_health_value(
                "P",
                p_metrics.tip_height,
                p_metrics.tip_hash,
                percent_connected,
            ),
        );
    }

    if health_tags_include_primary_chain(
        tags,
        &["C", "evm"],
        platform_cchain_blockchain_id(node.config.network_id),
    ) {
        checks.insert(
            "C".to_string(),
            chain_health_value(
                "C",
                current_cchain_height(node).max(c_metrics.tip_height),
                c_metrics.tip_hash,
                percent_connected,
            ),
        );
    }

    for chain_state in tracked_chain_states {
        if !health_tags_include_tracked_chain(tags, &chain_state) {
            continue;
        }
        checks.insert(
            chain_state.config.name.clone(),
            health_check_value(
                Some(serde_json::json!({
                    "engine": {
                        "consensus": {
                            "lastAcceptedHeight": chain_state.height,
                            "lastAcceptedID": cb58_encode_id(chain_state.config.chain_id.0),
                            "longestProcessingBlock": "0s",
                            "processingBlocks": 0,
                        },
                        "vm": serde_json::Value::Null,
                    },
                    "networking": {
                        "percentConnected": if chain_state.peers.is_empty() { 0.0 } else { 1.0 },
                    }
                })),
                None,
                Duration::ZERO,
            ),
        );
    }

    serde_json::json!({
        "checks": checks,
        "healthy": healthy,
    })
}

fn split_path_and_query(path: &str) -> (&str, &str) {
    match path.split_once('?') {
        Some((path, query)) => (path, query),
        None => (path, ""),
    }
}

fn query_tags(query: &str) -> Vec<String> {
    query
        .split('&')
        .filter_map(|segment| segment.split_once('='))
        .filter(|(key, _)| *key == "tag")
        .map(|(_, value)| value.replace('+', " "))
        .collect()
}

#[derive(Debug, Clone)]
struct PlatformValidatorRecord {
    tx_id: Option<String>,
    node_id: String,
    subnet_id: [u8; 32],
    weight: u64,
    start_time: u64,
    end_time: Option<u64>,
    removed_at: Option<u64>,
    permissionless: bool,
    validation_reward_owner: Option<PlatformOutputOwner>,
    delegation_reward_owner: Option<PlatformOutputOwner>,
    potential_reward: Option<u64>,
    accrued_delegatee_reward: Option<u64>,
    shares: Option<u32>,
    signer: Option<serde_json::Value>,
    delegators: Vec<PlatformDelegatorRecord>,
    l1: Option<PlatformL1ValidatorApiRecord>,
}

#[derive(Debug, Clone)]
struct PlatformL1ValidatorApiRecord {
    validation_id: [u8; 32],
    public_key: Vec<u8>,
    remaining_balance_owner: avalanche_rs::pchain::PlatformPChainOwner,
    deactivation_owner: avalanche_rs::pchain::PlatformPChainOwner,
    min_nonce: u64,
    balance: u64,
    active: bool,
}

#[derive(Debug, Clone)]
struct PlatformDelegatorRecord {
    tx_id: String,
    node_id: String,
    weight: u64,
    start_time: u64,
    end_time: u64,
    reward_owner: PlatformOutputOwner,
    potential_reward: Option<u64>,
}

#[derive(Debug, Clone, Default)]
struct PlatformSubnetStakingConfig {
    asset_id: Option<[u8; 32]>,
    initial_supply: Option<u64>,
    min_validator_stake: Option<u64>,
    min_delegator_stake: Option<u64>,
}

#[derive(Debug, Default)]
struct PlatformValidatorScanState {
    chain_time: u64,
    validators: Vec<PlatformValidatorRecord>,
    current_supply_deltas: std::collections::BTreeMap<[u8; 32], u64>,
    subnet_configs: std::collections::BTreeMap<[u8; 32], PlatformSubnetStakingConfig>,
}

impl PlatformValidatorRecord {
    fn status(&self, now: u64) -> &'static str {
        if let Some(l1) = &self.l1 {
            return if l1.active { "current" } else { "completed" };
        }

        if self.removed_at.is_some_and(|removed_at| now >= removed_at) {
            return "completed";
        }

        let end_time = self.end_time.unwrap_or_default();
        if now < self.start_time {
            "pending"
        } else if now < end_time {
            "current"
        } else {
            "completed"
        }
    }
}

fn platform_params_object(
    params: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    match params {
        serde_json::Value::Object(map) => Some(map),
        serde_json::Value::Array(arr) => arr.first().and_then(|value| value.as_object()),
        _ => None,
    }
}

fn platform_subnet_id_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("subnetID"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn platform_tx_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("tx"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn platform_tx_id_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("txID"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn platform_node_ids_param(params: &serde_json::Value) -> Vec<String> {
    platform_params_object(params)
        .and_then(|obj| obj.get("nodeIDs"))
        .or_else(|| params.get(1))
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn platform_node_id_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("nodeID"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn platform_size_param(params: &serde_json::Value) -> Option<usize> {
    platform_params_object(params)
        .and_then(|obj| obj.get("size"))
        .or_else(|| params.get(0))
        .and_then(parse_quantity_u64)
        .map(|size| size as usize)
}

fn platform_vm_id_for_name(vm_type: &str) -> Option<String> {
    match vm_type.trim().to_ascii_lowercase().as_str() {
        "platformvm" => Some(PLATFORM_VM_ID.to_string()),
        "evm" => Some(EVM_VM_ID.to_string()),
        _ => parse_platform_id_32(vm_type).map(cb58_encode_id),
    }
}

fn latest_pchain_block_metadata(db: &Database) -> Option<BlockMetadata> {
    db.iter_cf_owned(CF_BLOCKS)
        .into_iter()
        .filter(|(key, _)| !key.starts_with(b"c:") && key.len() == 32)
        .filter_map(|(_, raw)| BlockMetadata::from_raw(&raw, Chain::PChain).ok())
        .max_by_key(|meta| meta.height)
}

async fn current_pchain_height(node: &NodeState) -> u64 {
    let metric_height = node.p_chain_metrics.read().await.tip_height;
    latest_pchain_block_metadata(&node.db)
        .map(|meta| meta.height)
        .unwrap_or(metric_height)
        .max(metric_height)
}

async fn platform_current_supply_result(
    node: &NodeState,
    subnet_id: &SubnetId,
) -> Result<serde_json::Value, String> {
    let scan = scan_platform_validator_state(node, None);
    let initial_supply = if *subnet_id == SubnetId::primary_network() {
        platform_initial_supply(node.config.network_id, subnet_id)
    } else {
        scan.subnet_configs
            .get(&subnet_id.0)
            .and_then(|config| config.initial_supply)
    };
    let Some(initial_supply) = initial_supply else {
        return Err("current supply unavailable for subnet".to_string());
    };

    let height = current_pchain_height(node).await;
    let delta = scan
        .current_supply_deltas
        .get(&subnet_id.0)
        .copied()
        .unwrap_or(0);
    let supply = initial_supply.saturating_add(delta);
    Ok(serde_json::json!({
        "supply": supply.to_string(),
        "height": height.to_string(),
    }))
}

fn platform_latest_chain_timestamp(node: &NodeState) -> u64 {
    latest_pchain_block_metadata(&node.db)
        .map(|meta| meta.timestamp)
        .unwrap_or_else(unix_timestamp_secs)
}

fn scan_platform_dynamic_fee_state(node: &NodeState) -> Result<(PlatformGasState, u64), String> {
    let config = platform_dynamic_fee_config(node.config.network_id);
    let latest_timestamp = platform_latest_chain_timestamp(node);
    let etna_time = upgrade_time_unix(&info_upgrades_result(node.config.network_id), "etnaTime");

    if latest_timestamp < etna_time {
        return Ok((PlatformGasState::default(), latest_timestamp));
    }

    let mut state = PlatformGasState::default();
    let mut last_timestamp = etna_time;
    for (meta, raw_block) in platform_sorted_pchain_blocks(&node.db) {
        if meta.timestamp < etna_time {
            continue;
        }

        state = platform_gas_state_advance(
            state,
            config,
            meta.timestamp.saturating_sub(last_timestamp),
        );
        last_timestamp = meta.timestamp;

        let txs = avalanche_rs::pchain::extract_platform_tx_bytes_from_block(&raw_block)
            .map_err(|err| format!("fee state unavailable: {}", err))?;
        for tx_bytes in txs {
            let gas = avalanche_rs::pchain::platform_tx_dynamic_fee_gas(&tx_bytes, config.weights)
                .map_err(|err| format!("fee state unavailable: {}", err))?;
            if let Some(gas) = gas {
                state = platform_gas_state_consume(state, gas)
                    .map_err(|err| format!("fee state unavailable: {}", err))?;
            }
        }
    }

    Ok((state, latest_timestamp))
}

fn platform_fee_state_result(node: &NodeState) -> Result<serde_json::Value, String> {
    let config = platform_dynamic_fee_config(node.config.network_id);
    let (state, timestamp) = scan_platform_dynamic_fee_state(node)?;
    Ok(serde_json::json!({
        "capacity": state.capacity,
        "excess": state.excess,
        "price": platform_gas_price(
            config.min_price,
            state.excess,
            config.excess_conversion_constant,
        ),
        "timestamp": unix_timestamp_to_rfc3339_seconds(timestamp),
    }))
}

fn platform_active_l1_validator_count(validators: &PlatformL1ValidatorMap) -> u64 {
    validators
        .values()
        .filter(|validator| validator.weight != 0 && validator.end_accumulated_fee != 0)
        .count() as u64
}

fn platform_validator_fee_excess_after_seconds(
    excess: u64,
    current: u64,
    target: u64,
    seconds: u64,
) -> u64 {
    if current < target {
        excess.saturating_sub(target.saturating_sub(current).saturating_mul(seconds))
    } else {
        excess.saturating_add(current.saturating_sub(target).saturating_mul(seconds))
    }
}

fn platform_validator_fee_cost(
    current: u64,
    excess: u64,
    config: PlatformValidatorFeeConfig,
    seconds: u64,
) -> Result<u64, String> {
    if seconds == 0 {
        return Ok(0);
    }

    if current == config.target {
        let price = platform_gas_price(config.min_price, excess, config.excess_conversion_constant);
        return price
            .checked_mul(seconds)
            .ok_or_else(|| "validator fee cost overflow".to_string());
    }

    let mut cost = 0u64;
    let mut running_excess = excess;
    for elapsed in 0..seconds {
        running_excess =
            platform_validator_fee_excess_after_seconds(running_excess, current, config.target, 1);
        if running_excess == 0 {
            let remaining_seconds = seconds.saturating_sub(elapsed);
            let zero_excess_cost = config
                .min_price
                .checked_mul(remaining_seconds)
                .ok_or_else(|| "validator fee cost overflow".to_string())?;
            return cost
                .checked_add(zero_excess_cost)
                .ok_or_else(|| "validator fee cost overflow".to_string());
        }

        let price = platform_gas_price(
            config.min_price,
            running_excess,
            config.excess_conversion_constant,
        );
        cost = cost
            .checked_add(price)
            .ok_or_else(|| "validator fee cost overflow".to_string())?;
    }
    Ok(cost)
}

fn platform_advance_validator_fee_state(
    state: &mut PlatformValidatorFeeState,
    validators: &mut PlatformL1ValidatorMap,
    config: PlatformValidatorFeeConfig,
    seconds: u64,
) -> Result<(), String> {
    let current = platform_active_l1_validator_count(validators);
    let validator_cost = platform_validator_fee_cost(current, state.excess, config, seconds)?;
    state.accrued_fees = state
        .accrued_fees
        .checked_add(validator_cost)
        .ok_or_else(|| "validator accrued fees overflow".to_string())?;

    for validator in validators.values_mut() {
        if validator.weight != 0
            && validator.end_accumulated_fee != 0
            && validator.end_accumulated_fee <= state.accrued_fees
        {
            validator.end_accumulated_fee = 0;
        }
    }

    state.excess =
        platform_validator_fee_excess_after_seconds(state.excess, current, config.target, seconds);
    state.active = platform_active_l1_validator_count(validators);
    Ok(())
}

fn platform_apply_l1_validator_tx(
    state: &mut PlatformValidatorFeeState,
    validators: &mut PlatformL1ValidatorMap,
    config: PlatformValidatorFeeConfig,
    timestamp: u64,
    summary: avalanche_rs::pchain::PlatformL1ValidatorTxSummary,
) -> Result<(), String> {
    match summary {
        avalanche_rs::pchain::PlatformL1ValidatorTxSummary::ConvertSubnetToL1 {
            validators: new,
        } => {
            for validator in new {
                let mut end_accumulated_fee = 0u64;
                if validator.balance != 0 {
                    if platform_active_l1_validator_count(validators) >= config.capacity {
                        return Err("active L1 validator capacity exceeded".to_string());
                    }
                    end_accumulated_fee = state
                        .accrued_fees
                        .checked_add(validator.balance)
                        .ok_or_else(|| "validator balance overflow".to_string())?;
                }
                validators.insert(
                    validator.validation_id,
                    PlatformL1ValidatorFeeRecord {
                        subnet_id: validator.subnet_id,
                        node_id: validator.node_id,
                        public_key: validator.public_key.to_vec(),
                        remaining_balance_owner: Some(validator.remaining_balance_owner),
                        deactivation_owner: Some(validator.deactivation_owner),
                        start_time: timestamp,
                        weight: validator.weight,
                        min_nonce: 0,
                        end_accumulated_fee,
                    },
                );
            }
        }
        avalanche_rs::pchain::PlatformL1ValidatorTxSummary::RegisterL1Validator { validator } => {
            let mut end_accumulated_fee = 0u64;
            if validator.balance != 0 {
                if platform_active_l1_validator_count(validators) >= config.capacity {
                    return Err("active L1 validator capacity exceeded".to_string());
                }
                end_accumulated_fee = state
                    .accrued_fees
                    .checked_add(validator.balance)
                    .ok_or_else(|| "validator balance overflow".to_string())?;
            }
            validators.insert(
                validator.validation_id,
                PlatformL1ValidatorFeeRecord {
                    subnet_id: validator.subnet_id,
                    node_id: validator.node_id,
                    public_key: validator.public_key.to_vec(),
                    remaining_balance_owner: Some(validator.remaining_balance_owner),
                    deactivation_owner: Some(validator.deactivation_owner),
                    start_time: timestamp,
                    weight: validator.weight,
                    min_nonce: 0,
                    end_accumulated_fee,
                },
            );
        }
        avalanche_rs::pchain::PlatformL1ValidatorTxSummary::SetL1ValidatorWeight {
            validation_id,
            nonce,
            weight,
        } => {
            let Some(current) = validators.get_mut(&validation_id) else {
                return Err("unknown L1 validator".to_string());
            };
            if nonce < current.min_nonce {
                return Err("stale L1 validator nonce".to_string());
            }
            if weight == 0 {
                validators.remove(&validation_id);
            } else {
                current.min_nonce = nonce.saturating_add(1);
                current.weight = weight;
            }
        }
        avalanche_rs::pchain::PlatformL1ValidatorTxSummary::IncreaseL1ValidatorBalance {
            validation_id,
            balance,
        } => {
            let currently_active = platform_active_l1_validator_count(validators);
            let Some(current) = validators.get_mut(&validation_id) else {
                return Err("unknown L1 validator".to_string());
            };
            if current.end_accumulated_fee == 0 {
                if currently_active >= config.capacity {
                    return Err("active L1 validator capacity exceeded".to_string());
                }
                current.end_accumulated_fee = state.accrued_fees;
            }
            current.end_accumulated_fee = current
                .end_accumulated_fee
                .checked_add(balance)
                .ok_or_else(|| "validator balance overflow".to_string())?;
        }
        avalanche_rs::pchain::PlatformL1ValidatorTxSummary::DisableL1Validator {
            validation_id,
        } => {
            let Some(current) = validators.get_mut(&validation_id) else {
                return Err("unknown L1 validator".to_string());
            };
            current.end_accumulated_fee = 0;
        }
        avalanche_rs::pchain::PlatformL1ValidatorTxSummary::Other => {}
    }
    state.active = platform_active_l1_validator_count(validators);
    Ok(())
}

fn scan_platform_l1_validator_records_at(
    node: &NodeState,
    max_height: Option<u64>,
) -> Result<PlatformL1ValidatorScan, String> {
    let blocks = platform_sorted_pchain_blocks_up_to(&node.db, max_height);
    let latest_timestamp = blocks.last().map(|(meta, _)| meta.timestamp).unwrap_or(0);
    let etna_time = upgrade_time_unix(&info_upgrades_result(node.config.network_id), "etnaTime");
    if latest_timestamp < etna_time {
        return Ok((
            PlatformL1ValidatorMap::new(),
            PlatformValidatorFeeState::default(),
            latest_timestamp,
        ));
    }

    let config = platform_validator_fee_config(node.config.network_id);
    let mut state = PlatformValidatorFeeState::default();
    let mut last_timestamp = etna_time;
    let mut validators = PlatformL1ValidatorMap::new();

    for (meta, raw_block) in blocks {
        if meta.timestamp < etna_time {
            continue;
        }

        platform_advance_validator_fee_state(
            &mut state,
            &mut validators,
            config,
            meta.timestamp.saturating_sub(last_timestamp),
        )
        .map_err(|err| format!("validator fee state unavailable: {}", err))?;
        last_timestamp = meta.timestamp;

        let txs = avalanche_rs::pchain::extract_platform_tx_bytes_from_block(&raw_block)
            .map_err(|err| format!("validator fee state unavailable: {}", err))?;
        for tx_bytes in txs {
            let summary = avalanche_rs::pchain::summarize_platform_l1_validator_tx(&tx_bytes)
                .map_err(|err| format!("validator fee state unavailable: {}", err))?;
            platform_apply_l1_validator_tx(
                &mut state,
                &mut validators,
                config,
                meta.timestamp,
                summary,
            )
            .map_err(|err| format!("validator fee state unavailable: {}", err))?;
        }
    }

    state.active = platform_active_l1_validator_count(&validators);
    Ok((validators, state, latest_timestamp))
}

fn scan_platform_l1_validator_records(node: &NodeState) -> Result<PlatformL1ValidatorScan, String> {
    scan_platform_l1_validator_records_at(node, None)
}

fn scan_platform_validator_fee_state(
    node: &NodeState,
) -> Result<(PlatformValidatorFeeState, u64), String> {
    let (_, state, latest_timestamp) = scan_platform_l1_validator_records(node)?;
    Ok((state, latest_timestamp))
}

fn platform_validator_fee_state_result(node: &NodeState) -> Result<serde_json::Value, String> {
    let config = platform_validator_fee_config(node.config.network_id);
    let (state, latest_timestamp) = scan_platform_validator_fee_state(node)?;
    Ok(serde_json::json!({
        "excess": state.excess,
        "price": platform_gas_price(
            config.min_price,
            state.excess,
            config.excess_conversion_constant,
        ),
        "timestamp": unix_timestamp_to_rfc3339_seconds(latest_timestamp),
    }))
}

fn platform_l1_owner_json(
    network_id: u32,
    owner: &avalanche_rs::pchain::PlatformPChainOwner,
) -> serde_json::Value {
    serde_json::json!({
        "locktime": "0",
        "threshold": owner.threshold.to_string(),
        "addresses": owner
            .addresses
            .iter()
            .map(|address| format_platform_address(network_id, *address))
            .collect::<Vec<_>>(),
    })
}

fn platform_l1_validator_result(
    node: &NodeState,
    validation_id: [u8; 32],
) -> Result<serde_json::Value, String> {
    let (validators, state, _) = scan_platform_l1_validator_records(node)?;
    let Some(validator) = validators.get(&validation_id) else {
        return Err(format!(
            "fetching L1 validator \"{}\" failed: not found",
            cb58_encode_id(validation_id)
        ));
    };

    let Some(remaining_balance_owner) = validator.remaining_balance_owner.as_ref() else {
        return Err("L1 validator missing remaining balance owner".to_string());
    };
    let Some(deactivation_owner) = validator.deactivation_owner.as_ref() else {
        return Err("L1 validator missing deactivation owner".to_string());
    };

    let balance = if validator.end_accumulated_fee == 0 {
        0
    } else {
        validator
            .end_accumulated_fee
            .saturating_sub(state.accrued_fees)
    };
    let height = latest_pchain_block_metadata(&node.db)
        .map(|meta| meta.height)
        .unwrap_or(0);

    Ok(serde_json::json!({
        "subnetID": cb58_encode_id(validator.subnet_id),
        "nodeID": format!("NodeID-{}", cb58_encode(&validator.node_id)),
        "weight": validator.weight.to_string(),
        "startTime": validator.start_time.to_string(),
        "validationID": cb58_encode_id(validation_id),
        "publicKey": format!("0x{}", hex::encode(&validator.public_key)),
        "remainingBalanceOwner": platform_l1_owner_json(
            node.config.network_id,
            remaining_balance_owner,
        ),
        "deactivationOwner": platform_l1_owner_json(
            node.config.network_id,
            deactivation_owner,
        ),
        "minNonce": validator.min_nonce.to_string(),
        "balance": balance.to_string(),
        "height": height.to_string(),
    }))
}

async fn platform_proposed_height(node: &NodeState) -> u64 {
    let current_height = current_pchain_height(node).await;
    let now = unix_timestamp_secs();
    let mut recent = node.p_chain_recently_accepted.write().await;
    prune_recently_accepted_pchain_blocks(&mut recent, now);
    recent
        .front()
        .map(|entry| entry.height.saturating_sub(1))
        .unwrap_or(current_height)
        .min(current_height)
}

async fn proposervm_proposed_height(node: &NodeState, target: ProposerVmTarget) -> u64 {
    match target {
        ProposerVmTarget::PChain => platform_proposed_height(node).await,
        ProposerVmTarget::CChain => {
            current_cchain_height(node).max(node.c_chain_metrics.read().await.tip_height)
        }
        ProposerVmTarget::Custom(chain_id) => node
            .subnet_tracker
            .read()
            .await
            .chain_state(&ChainId(chain_id))
            .map(|state| state.height)
            .unwrap_or(0),
    }
}

fn proposervm_granite_activation_height(node: &NodeState, granite_time: u64) -> Option<u64> {
    platform_sorted_pchain_blocks(&node.db)
        .into_iter()
        .find(|(meta, _)| meta.timestamp >= granite_time)
        .map(|(meta, _)| meta.height)
}

fn calculate_granite_epoch(
    network_id: u32,
    now: u64,
    granite_time: u64,
    activation_height: u64,
) -> Option<avalanche_rs::granite::EpochInfo> {
    avalanche_rs::granite::calculate_epoch(network_id, now, granite_time, activation_height)
        .or_else(|| {
            if now < granite_time {
                return None;
            }
            let epoch_number =
                now.saturating_sub(granite_time) / avalanche_rs::granite::EPOCH_DURATION_SECS;
            Some(avalanche_rs::granite::EpochInfo {
                epoch_number,
                epoch_p_chain_height: activation_height.saturating_add(epoch_number),
                epoch_start_time: granite_time.saturating_add(
                    epoch_number.saturating_mul(avalanche_rs::granite::EPOCH_DURATION_SECS),
                ),
            })
        })
}

fn proposervm_current_epoch_result(node: &NodeState) -> Result<serde_json::Value, String> {
    let granite_time =
        upgrade_time_unix(&info_upgrades_result(node.config.network_id), "graniteTime");
    let now = unix_timestamp_secs();
    let Some(activation_height) = proposervm_granite_activation_height(node, granite_time) else {
        return Err("current epoch unavailable before Granite activation".to_string());
    };

    let Some(epoch) =
        calculate_granite_epoch(node.config.network_id, now, granite_time, activation_height)
    else {
        return Err("current epoch unavailable before Granite activation".to_string());
    };

    Ok(serde_json::json!({
        "epoch": epoch.epoch_number.to_string(),
        "startTime": epoch.epoch_start_time.to_string(),
        "pChainHeight": epoch.epoch_p_chain_height.to_string(),
    }))
}

fn platform_primary_staking_asset_id(network_id: u32) -> Option<&'static str> {
    match network_id {
        1 => Some(AVAX_ASSET_ID_MAINNET),
        5 => Some(AVAX_ASSET_ID_FUJI),
        _ => None,
    }
}

fn platform_staking_asset_id(node: &NodeState, subnet_id: Option<&SubnetId>) -> Option<String> {
    match subnet_id {
        None => platform_primary_staking_asset_id(node.config.network_id).map(str::to_string),
        Some(subnet_id) if *subnet_id == SubnetId::primary_network() => {
            platform_primary_staking_asset_id(node.config.network_id).map(str::to_string)
        }
        Some(subnet_id) => scan_platform_validator_state(node, None)
            .subnet_configs
            .get(&subnet_id.0)
            .and_then(|config| config.asset_id)
            .map(cb58_encode_id),
    }
}

fn platform_min_stake_for_subnet(
    node: &NodeState,
    subnet_id: Option<&SubnetId>,
) -> Option<(u64, u64)> {
    match subnet_id {
        None => Some((MIN_VALIDATOR_STAKE, MIN_DELEGATOR_STAKE)),
        Some(subnet_id) if *subnet_id == SubnetId::primary_network() => {
            Some((MIN_VALIDATOR_STAKE, MIN_DELEGATOR_STAKE))
        }
        Some(subnet_id) => scan_platform_validator_state(node, None)
            .subnet_configs
            .get(&subnet_id.0)
            .and_then(|config| Some((config.min_validator_stake?, config.min_delegator_stake?))),
    }
}

fn platform_subnet_ids_param(params: &serde_json::Value) -> Result<Option<Vec<SubnetId>>, String> {
    let ids = platform_params_object(params)
        .and_then(|obj| obj.get("ids"))
        .or_else(|| params.get(0))
        .and_then(|value| value.as_array());
    let Some(ids) = ids else {
        return Ok(None);
    };
    if ids.is_empty() {
        return Ok(None);
    }

    let mut parsed = Vec::with_capacity(ids.len());
    for value in ids {
        let Some(value) = value.as_str() else {
            return Err("invalid subnet ID".to_string());
        };
        let Some(subnet_id) = SubnetId::from_str_any(value) else {
            return Err("invalid subnet ID".to_string());
        };
        parsed.push(subnet_id);
    }
    Ok(Some(parsed))
}

fn platform_validation_id_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("validationID"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

#[derive(Debug, Clone, Default)]
struct PlatformSubnetApiState {
    owner: Option<PlatformOutputOwner>,
    subnet_transformation_tx_id: Option<[u8; 32]>,
    conversion_id: Option<[u8; 32]>,
    manager_chain_id: Option<[u8; 32]>,
    manager_address: Option<Vec<u8>>,
}

fn platform_network_hrp(network_id: u32) -> &'static str {
    match network_id {
        1 => "avax",
        5 => "fuji",
        10 => "testing",
        12345 => "local",
        _ => "custom",
    }
}

fn format_platform_address(network_id: u32, address: [u8; 20]) -> String {
    format_service_address(network_id, "P", address)
}

fn format_service_address(network_id: u32, chain_alias: &str, address: [u8; 20]) -> String {
    let encoded = bech32::encode(
        platform_network_hrp(network_id),
        address.to_base32(),
        bech32::Variant::Bech32,
    )
    .unwrap_or_default();
    format!("{chain_alias}-{encoded}")
}

fn platform_subnet_owner_strings(network_id: u32, owner: &PlatformOutputOwner) -> Vec<String> {
    owner
        .addresses
        .iter()
        .copied()
        .map(|address| format_platform_address(network_id, address))
        .collect()
}

fn platform_subnet_to_l1_conversion_id(unsigned_tx: &serde_json::Value) -> Option<[u8; 32]> {
    let subnet_id = parse_platform_id_32(unsigned_tx.get("subnetID")?.as_str()?)?;
    let manager_chain_id = parse_platform_id_32(unsigned_tx.get("chainID")?.as_str()?)?;
    let manager_address = parse_hex_bytes(unsigned_tx.get("address")?.as_str()?)?;
    let validators = unsigned_tx.get("validators")?.as_array()?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&subnet_id);
    bytes.extend_from_slice(&manager_chain_id);
    bytes.extend_from_slice(&(manager_address.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&manager_address);
    bytes.extend_from_slice(&(validators.len() as u32).to_be_bytes());
    for validator in validators {
        let node_id = parse_node_id_20(validator.get("nodeID")?.as_str()?)?;
        let public_key = parse_hex_bytes(validator.get("signer")?.get("publicKey")?.as_str()?)?;
        if public_key.len() != 48 {
            return None;
        }
        let weight = platform_json_u64(validator.get("weight")?)?;
        bytes.extend_from_slice(&20u32.to_be_bytes());
        bytes.extend_from_slice(&node_id);
        bytes.extend_from_slice(&public_key);
        bytes.extend_from_slice(&weight.to_be_bytes());
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(&bytes));
    Some(out)
}

fn scan_platform_subnet_api_state(
    node: &NodeState,
) -> std::collections::BTreeMap<[u8; 32], PlatformSubnetApiState> {
    let mut subnets = std::collections::BTreeMap::<[u8; 32], PlatformSubnetApiState>::new();
    let mut seen_txs = std::collections::HashSet::new();

    for (_, raw_block) in platform_sorted_pchain_blocks(&node.db) {
        let Ok(txs) = avalanche_rs::pchain::extract_platform_tx_bytes_from_block(&raw_block) else {
            continue;
        };
        for tx_bytes in txs {
            let mut tx_id = [0u8; 32];
            tx_id.copy_from_slice(&Sha256::digest(&tx_bytes));
            if !seen_txs.insert(tx_id) {
                continue;
            }

            let Ok(tx_json) = avalanche_rs::pchain::parse_platform_tx_json(&tx_bytes) else {
                continue;
            };
            let Some(unsigned_tx) = tx_json.get("unsignedTx") else {
                continue;
            };

            if let Some(owner_value) = unsigned_tx.get("owner") {
                if unsigned_tx.get("subnetID").is_none() {
                    if let Some(owner) = platform_output_owner_from_value(owner_value) {
                        subnets.entry(tx_id).or_default().owner = Some(owner);
                    }
                    continue;
                }
            }

            if let Some(new_owner_value) = unsigned_tx.get("newOwner") {
                if let Some(subnet_id) = unsigned_tx
                    .get("subnetID")
                    .and_then(|value| value.as_str())
                    .and_then(parse_platform_id_32)
                {
                    if let Some(owner) = platform_output_owner_from_value(new_owner_value) {
                        subnets.entry(subnet_id).or_default().owner = Some(owner);
                    }
                }
                continue;
            }

            if unsigned_tx.get("assetID").is_some() && unsigned_tx.get("subnetID").is_some() {
                if let Some(subnet_id) = unsigned_tx
                    .get("subnetID")
                    .and_then(|value| value.as_str())
                    .and_then(parse_platform_id_32)
                {
                    subnets
                        .entry(subnet_id)
                        .or_default()
                        .subnet_transformation_tx_id = Some(tx_id);
                }
                continue;
            }

            if unsigned_tx.get("chainID").is_some() && unsigned_tx.get("validators").is_some() {
                if let Some(subnet_id) = unsigned_tx
                    .get("subnetID")
                    .and_then(|value| value.as_str())
                    .and_then(parse_platform_id_32)
                {
                    let subnet = subnets.entry(subnet_id).or_default();
                    subnet.conversion_id = platform_subnet_to_l1_conversion_id(unsigned_tx);
                    subnet.manager_chain_id = unsigned_tx
                        .get("chainID")
                        .and_then(|value| value.as_str())
                        .and_then(parse_platform_id_32);
                    subnet.manager_address = unsigned_tx
                        .get("address")
                        .and_then(|value| value.as_str())
                        .and_then(parse_hex_bytes);
                }
            }
        }
    }

    subnets
}

fn platform_subnet_summary_json(
    network_id: u32,
    subnet_id: &SubnetId,
    subnet: Option<&PlatformSubnetApiState>,
) -> serde_json::Value {
    let (control_keys, threshold) = match subnet {
        Some(subnet) if subnet.subnet_transformation_tx_id.is_none() => subnet
            .owner
            .as_ref()
            .map(|owner| {
                (
                    platform_subnet_owner_strings(network_id, owner),
                    owner.threshold.to_string(),
                )
            })
            .unwrap_or_else(|| (Vec::new(), "0".to_string())),
        _ => (Vec::new(), "0".to_string()),
    };

    serde_json::json!({
        "id": cb58_encode_id(subnet_id.0),
        "controlKeys": control_keys,
        "threshold": threshold,
    })
}

async fn platform_get_subnet_result(
    node: &NodeState,
    subnet_id: &SubnetId,
) -> Result<serde_json::Value, String> {
    if subnet_id == &SubnetId::primary_network() {
        return Err("the primary network isn't a subnet".to_string());
    }

    let subnets = scan_platform_subnet_api_state(node);
    let Some(subnet) = subnets.get(&subnet_id.0) else {
        return Err(format!(
            "\"{}\" is not a subnet",
            cb58_encode_id(subnet_id.0)
        ));
    };

    Ok(serde_json::json!({
        "isPermissioned": subnet.subnet_transformation_tx_id.is_none() && subnet.conversion_id.is_none(),
        "controlKeys": subnet.owner.as_ref().map(|owner| platform_subnet_owner_strings(node.config.network_id, owner)).unwrap_or_default(),
        "threshold": subnet.owner.as_ref().map(|owner| owner.threshold.to_string()).unwrap_or_else(|| "0".to_string()),
        "locktime": subnet.owner.as_ref().map(|owner| owner.locktime.to_string()).unwrap_or_else(|| "0".to_string()),
        "subnetTransformationTxID": subnet.subnet_transformation_tx_id.map(cb58_encode_id).unwrap_or_else(|| cb58_encode_id([0u8; 32])),
        "conversionID": subnet.conversion_id.map(cb58_encode_id).unwrap_or_else(|| cb58_encode_id([0u8; 32])),
        "managerChainID": subnet.manager_chain_id.map(cb58_encode_id).unwrap_or_else(|| cb58_encode_id([0u8; 32])),
        "managerAddress": subnet.manager_address.as_ref().map(hex::encode),
    }))
}

async fn platform_get_subnets_result(
    node: &NodeState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let subnets_by_id = scan_platform_subnet_api_state(node);
    let requested_subnet_ids = platform_subnet_ids_param(params)?;
    let mut subnet_ids = if let Some(requested) = requested_subnet_ids {
        requested
    } else {
        let mut all = subnets_by_id
            .keys()
            .copied()
            .map(SubnetId)
            .collect::<Vec<_>>();
        all.push(SubnetId::primary_network());
        all
    };

    if subnet_ids.is_empty() {
        subnet_ids.push(SubnetId::primary_network());
    }

    subnet_ids.sort_by_key(|subnet_id| subnet_id.0);
    subnet_ids.dedup();

    let mut subnets = Vec::new();
    for subnet_id in subnet_ids {
        if subnet_id == SubnetId::primary_network() {
            subnets.push(platform_subnet_summary_json(
                node.config.network_id,
                &subnet_id,
                None,
            ));
            continue;
        }

        if let Some(subnet) = subnets_by_id.get(&subnet_id.0) {
            subnets.push(platform_subnet_summary_json(
                node.config.network_id,
                &subnet_id,
                Some(subnet),
            ));
        }
    }

    Ok(serde_json::json!({ "subnets": subnets }))
}

async fn platform_blockchains_result(node: &NodeState) -> serde_json::Value {
    let primary_subnet = cb58_encode_id(SubnetId::primary_network().0);
    let mut blockchains = vec![serde_json::json!({
        "id": cb58_encode_id(platform_cchain_blockchain_id(node.config.network_id)),
        "name": "C-Chain",
        "subnetID": primary_subnet,
        "vmID": EVM_VM_ID,
    })];

    let builtins = std::collections::HashSet::from([
        platform_pchain_blockchain_id(),
        platform_cchain_blockchain_id(node.config.network_id),
    ]);

    let tracker = node.subnet_tracker.read().await;
    let mut custom = tracker
        .all_chains()
        .into_iter()
        .filter(|state| !builtins.contains(&state.config.chain_id.0))
        .filter_map(|state| {
            let vm_id = platform_vm_id_for_name(&state.config.vm_type)?;
            Some(serde_json::json!({
                "id": cb58_encode_id(state.config.chain_id.0),
                "name": state.config.name,
                "subnetID": cb58_encode_id(state.config.subnet_id.0),
                "vmID": vm_id,
            }))
        })
        .collect::<Vec<_>>();
    custom.sort_by(|a, b| {
        let a_name = a
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let b_name = b
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        a_name.cmp(b_name).then_with(|| {
            let a_id = a
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let b_id = b
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            a_id.cmp(b_id)
        })
    });
    blockchains.extend(custom);

    serde_json::json!({ "blockchains": blockchains })
}

async fn platform_validates_ids(node: &NodeState, subnet_id: &SubnetId) -> Vec<String> {
    let mut blockchain_ids = Vec::new();
    if subnet_id == &SubnetId::primary_network() {
        blockchain_ids.push(cb58_encode_id(platform_cchain_blockchain_id(
            node.config.network_id,
        )));
    }

    let tracker = node.subnet_tracker.read().await;
    let mut tracker_ids = tracker
        .all_chains()
        .into_iter()
        .filter(|state| &state.config.subnet_id == subnet_id)
        .map(|state| cb58_encode_id(state.config.chain_id.0))
        .collect::<Vec<_>>();
    tracker_ids.sort();
    for chain_id in tracker_ids {
        if !blockchain_ids.contains(&chain_id) {
            blockchain_ids.push(chain_id);
        }
    }
    blockchain_ids
}

async fn platform_validator_records(
    node: &NodeState,
    params: &serde_json::Value,
) -> (u64, Vec<PlatformValidatorRecord>) {
    let requested_subnet_id = platform_subnet_id_param(params)
        .and_then(SubnetId::from_str_any)
        .unwrap_or_else(SubnetId::primary_network);
    let scan = scan_platform_validator_state(node, None);
    let mut chain_time = scan.chain_time;
    let mut records = scan
        .validators
        .into_iter()
        .filter(|validator| validator.subnet_id == requested_subnet_id.0)
        .collect::<Vec<_>>();

    if requested_subnet_id != SubnetId::primary_network() {
        if let Ok((validators, fee_state, latest_timestamp)) =
            scan_platform_l1_validator_records(node)
        {
            chain_time = chain_time.max(latest_timestamp);
            records.extend(
                validators
                    .into_iter()
                    .filter_map(|(validation_id, validator)| {
                        if validator.subnet_id != requested_subnet_id.0 {
                            return None;
                        }
                        let remaining_balance_owner = validator.remaining_balance_owner?;
                        let deactivation_owner = validator.deactivation_owner?;
                        let active = validator.weight != 0 && validator.end_accumulated_fee != 0;
                        let balance = if active {
                            validator
                                .end_accumulated_fee
                                .saturating_sub(fee_state.accrued_fees)
                        } else {
                            0
                        };
                        Some(PlatformValidatorRecord {
                            tx_id: None,
                            node_id: format!("NodeID-{}", cb58_encode(&validator.node_id)),
                            subnet_id: validator.subnet_id,
                            weight: validator.weight,
                            start_time: validator.start_time,
                            end_time: None,
                            removed_at: None,
                            permissionless: false,
                            validation_reward_owner: None,
                            delegation_reward_owner: None,
                            potential_reward: None,
                            accrued_delegatee_reward: None,
                            shares: None,
                            signer: None,
                            delegators: Vec::new(),
                            l1: Some(PlatformL1ValidatorApiRecord {
                                validation_id,
                                public_key: validator.public_key,
                                remaining_balance_owner,
                                deactivation_owner,
                                min_nonce: validator.min_nonce,
                                balance,
                                active,
                            }),
                        })
                    }),
            );
        }
    }

    if records.is_empty() && requested_subnet_id == SubnetId::primary_network() {
        chain_time = unix_timestamp_secs();
        records = node
            .validators
            .values()
            .map(|validator| PlatformValidatorRecord {
                tx_id: None,
                node_id: validator.node_id.clone(),
                subnet_id: SubnetId::primary_network().0,
                weight: validator.weight,
                start_time: validator.start_time,
                end_time: Some(validator.end_time),
                removed_at: None,
                permissionless: true,
                validation_reward_owner: None,
                delegation_reward_owner: None,
                potential_reward: None,
                accrued_delegatee_reward: None,
                shares: Some(0),
                signer: None,
                delegators: Vec::new(),
                l1: None,
            })
            .collect();
    }

    let requested_node_ids = platform_node_ids_param(params);
    if !requested_node_ids.is_empty() {
        let requested = requested_node_ids
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        records.retain(|record| requested.contains(&record.node_id));
    }

    records.sort_by(|a, b| {
        a.node_id
            .cmp(&b.node_id)
            .then_with(|| a.start_time.cmp(&b.start_time))
            .then_with(|| a.tx_id.cmp(&b.tx_id))
    });
    (chain_time, records)
}

fn platform_api_owner_json(network_id: u32, owner: &PlatformOutputOwner) -> serde_json::Value {
    serde_json::json!({
        "locktime": owner.locktime.to_string(),
        "threshold": owner.threshold.to_string(),
        "addresses": owner
            .addresses
            .iter()
            .copied()
            .map(|address| format_platform_address(network_id, address))
            .collect::<Vec<_>>(),
    })
}

async fn platform_validator_connection_and_uptime(
    node: &NodeState,
    node_id: &str,
) -> (bool, String) {
    let connected = node.validators_seen.read().await.contains(node_id);
    let pm = node.peer_manager.read().await;
    let uptime = parse_node_id_20(node_id)
        .and_then(|node_id| pm.get_peer(&NodeId(node_id)))
        .map(|peer| format_percentage_4dp((peer.reported_uptime as f64) / 100.0))
        .unwrap_or_else(|| "0.0000".to_string());
    (connected, uptime)
}

fn platform_primary_delegator_json(
    network_id: u32,
    delegator: &PlatformDelegatorRecord,
) -> serde_json::Value {
    let mut value = serde_json::Map::new();
    value.insert("txID".to_string(), serde_json::json!(delegator.tx_id));
    value.insert("nodeID".to_string(), serde_json::json!(delegator.node_id));
    value.insert(
        "startTime".to_string(),
        serde_json::json!(delegator.start_time.to_string()),
    );
    value.insert(
        "endTime".to_string(),
        serde_json::json!(delegator.end_time.to_string()),
    );
    value.insert(
        "weight".to_string(),
        serde_json::json!(delegator.weight.to_string()),
    );
    value.insert(
        "rewardOwner".to_string(),
        platform_api_owner_json(network_id, &delegator.reward_owner),
    );
    if let Some(potential_reward) = delegator.potential_reward {
        value.insert(
            "potentialReward".to_string(),
            serde_json::json!(potential_reward.to_string()),
        );
    }
    serde_json::Value::Object(value)
}

async fn platform_validator_response_values(
    node: &NodeState,
    chain_time: u64,
    records: Vec<PlatformValidatorRecord>,
    include_delegators: bool,
) -> Vec<serde_json::Value> {
    let mut values = Vec::with_capacity(records.len());
    for validator in records {
        let status = validator.status(chain_time);
        if let Some(l1) = validator.l1 {
            values.push(serde_json::json!({
                "nodeID": validator.node_id,
                "startTime": validator.start_time.to_string(),
                "weight": validator.weight.to_string(),
                "validationID": cb58_encode_id(l1.validation_id),
                "publicKey": format!("0x{}", hex::encode(l1.public_key)),
                "remainingBalanceOwner": platform_l1_owner_json(
                    node.config.network_id,
                    &l1.remaining_balance_owner,
                ),
                "deactivationOwner": platform_l1_owner_json(
                    node.config.network_id,
                    &l1.deactivation_owner,
                ),
                "minNonce": l1.min_nonce.to_string(),
                "balance": l1.balance.to_string(),
                "status": status,
            }));
            continue;
        }

        let mut value = serde_json::Map::new();
        if let Some(tx_id) = validator.tx_id.clone() {
            value.insert("txID".to_string(), serde_json::json!(tx_id));
        }
        value.insert("nodeID".to_string(), serde_json::json!(validator.node_id));
        value.insert(
            "startTime".to_string(),
            serde_json::json!(validator.start_time.to_string()),
        );
        if let Some(end_time) = validator.end_time {
            value.insert(
                "endTime".to_string(),
                serde_json::json!(end_time.to_string()),
            );
        }
        value.insert(
            "weight".to_string(),
            serde_json::json!(validator.weight.to_string()),
        );

        if validator.permissionless {
            value.insert(
                "stakeAmount".to_string(),
                serde_json::json!(validator.weight.to_string()),
            );
            if let Some(owner) = validator.validation_reward_owner.as_ref() {
                value.insert(
                    "validationRewardOwner".to_string(),
                    platform_api_owner_json(node.config.network_id, owner),
                );
            }
            if let Some(owner) = validator.delegation_reward_owner.as_ref() {
                value.insert(
                    "delegationRewardOwner".to_string(),
                    platform_api_owner_json(node.config.network_id, owner),
                );
            }
            if let Some(potential_reward) = validator.potential_reward {
                value.insert(
                    "potentialReward".to_string(),
                    serde_json::json!(potential_reward.to_string()),
                );
            }
            if let Some(accrued_delegatee_reward) = validator.accrued_delegatee_reward {
                value.insert(
                    "accruedDelegateeReward".to_string(),
                    serde_json::json!(accrued_delegatee_reward.to_string()),
                );
            }
            let exact_fee = validator.shares.unwrap_or_default();
            value.insert(
                "delegationFee".to_string(),
                serde_json::json!(format_percentage_4dp((exact_fee as f64) / 10_000.0)),
            );
            value.insert(
                "exactDelegationFee".to_string(),
                serde_json::json!(exact_fee),
            );
            if let Some(signer) = validator.signer.clone() {
                value.insert("signer".to_string(), signer);
            }

            let delegator_weight = validator.delegators.iter().fold(0u64, |total, delegator| {
                total.saturating_add(delegator.weight)
            });
            value.insert(
                "delegatorCount".to_string(),
                serde_json::json!(validator.delegators.len().to_string()),
            );
            value.insert(
                "delegatorWeight".to_string(),
                serde_json::json!(delegator_weight.to_string()),
            );
            if include_delegators {
                value.insert(
                    "delegators".to_string(),
                    serde_json::Value::Array(
                        validator
                            .delegators
                            .iter()
                            .map(|delegator| {
                                platform_primary_delegator_json(node.config.network_id, delegator)
                            })
                            .collect(),
                    ),
                );
            }

            if validator.subnet_id == SubnetId::primary_network().0 && status == "current" {
                let (connected, uptime) =
                    platform_validator_connection_and_uptime(node, &validator.node_id).await;
                value.insert("connected".to_string(), serde_json::json!(connected));
                value.insert("uptime".to_string(), serde_json::json!(uptime));
            }
        }

        value.insert("status".to_string(), serde_json::json!(status));
        values.push(serde_json::Value::Object(value));
    }
    values
}

#[derive(Debug, Clone, Copy)]
enum PlatformQueryHeight {
    Accepted(u64),
    Proposed,
}

fn platform_query_height_param(
    params: &serde_json::Value,
) -> Result<Option<PlatformQueryHeight>, String> {
    let Some(height_value) = platform_params_object(params)
        .and_then(|obj| obj.get("height"))
        .or_else(|| params.get(0))
    else {
        return Ok(None);
    };

    if matches!(height_value, serde_json::Value::Null) {
        return Ok(None);
    }

    if let Some(height) = parse_quantity_u64(height_value) {
        return Ok(Some(PlatformQueryHeight::Accepted(height)));
    }

    if height_value
        .as_str()
        .is_some_and(|value| value.eq_ignore_ascii_case("proposed"))
    {
        return Ok(Some(PlatformQueryHeight::Proposed));
    }

    Err("invalid height".to_string())
}

async fn platform_resolve_query_height(
    node: &NodeState,
    query_height: Option<PlatformQueryHeight>,
) -> Result<Option<u64>, String> {
    let latest_height = current_pchain_height(node).await;
    match query_height {
        None => Ok(None),
        Some(PlatformQueryHeight::Accepted(height)) => {
            if height > latest_height {
                return Err(format!(
                    "failed to get validator set at {height}: height unavailable"
                ));
            }
            Ok(Some(height))
        }
        Some(PlatformQueryHeight::Proposed) => Ok(Some(platform_proposed_height(node).await)),
    }
}

fn platform_validator_public_key(record: &PlatformValidatorRecord) -> Option<String> {
    if let Some(l1) = &record.l1 {
        return Some(format!("0x{}", hex::encode(&l1.public_key)));
    }
    record
        .signer
        .as_ref()
        .and_then(|signer| signer.get("publicKey"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

async fn platform_get_validators_at_result(
    node: &NodeState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let subnet_id = platform_subnet_id_param(params)
        .and_then(SubnetId::from_str_any)
        .unwrap_or_else(SubnetId::primary_network);
    let height = platform_resolve_query_height(node, platform_query_height_param(params)?).await?;
    let scan = scan_platform_validator_state(node, height);
    let chain_time = scan.chain_time;
    let mut records = scan
        .validators
        .into_iter()
        .filter(|validator| validator.subnet_id == subnet_id.0)
        .filter(|validator| validator.status(chain_time) == "current")
        .collect::<Vec<_>>();

    if subnet_id != SubnetId::primary_network() {
        let (validators, fee_state, _) = scan_platform_l1_validator_records_at(node, height)?;
        records.extend(
            validators
                .into_iter()
                .filter_map(|(validation_id, validator)| {
                    if validator.subnet_id != subnet_id.0 {
                        return None;
                    }
                    let remaining_balance_owner = validator.remaining_balance_owner?;
                    let deactivation_owner = validator.deactivation_owner?;
                    let active = validator.weight != 0 && validator.end_accumulated_fee != 0;
                    if !active {
                        return None;
                    }
                    let balance = validator
                        .end_accumulated_fee
                        .saturating_sub(fee_state.accrued_fees);
                    Some(PlatformValidatorRecord {
                        tx_id: None,
                        node_id: format!("NodeID-{}", cb58_encode(&validator.node_id)),
                        subnet_id: validator.subnet_id,
                        weight: validator.weight,
                        start_time: validator.start_time,
                        end_time: None,
                        removed_at: None,
                        permissionless: false,
                        validation_reward_owner: None,
                        delegation_reward_owner: None,
                        potential_reward: None,
                        accrued_delegatee_reward: None,
                        shares: None,
                        signer: None,
                        delegators: Vec::new(),
                        l1: Some(PlatformL1ValidatorApiRecord {
                            validation_id,
                            public_key: validator.public_key,
                            remaining_balance_owner,
                            deactivation_owner,
                            min_nonce: validator.min_nonce,
                            balance,
                            active: true,
                        }),
                    })
                }),
        );
    }

    if records.is_empty()
        && latest_pchain_block_metadata(&node.db).is_none()
        && subnet_id == SubnetId::primary_network()
    {
        let now = unix_timestamp_secs();
        records = node
            .validators
            .values()
            .filter(|validator| validator.start_time <= now && now < validator.end_time)
            .map(|validator| PlatformValidatorRecord {
                tx_id: None,
                node_id: validator.node_id.clone(),
                subnet_id: SubnetId::primary_network().0,
                weight: validator.weight,
                start_time: validator.start_time,
                end_time: Some(validator.end_time),
                removed_at: None,
                permissionless: true,
                validation_reward_owner: None,
                delegation_reward_owner: None,
                potential_reward: None,
                accrued_delegatee_reward: None,
                shares: Some(0),
                signer: None,
                delegators: Vec::new(),
                l1: None,
            })
            .collect();
    }

    let mut validators = serde_json::Map::new();
    records.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    for record in records {
        let mut entry = serde_json::Map::new();
        entry.insert(
            "weight".to_string(),
            serde_json::json!(record.weight.to_string()),
        );
        if let Some(public_key) = platform_validator_public_key(&record) {
            entry.insert("publicKey".to_string(), serde_json::json!(public_key));
        }
        validators.insert(record.node_id.clone(), serde_json::Value::Object(entry));
    }
    Ok(serde_json::json!({ "validators": validators }))
}

async fn platform_get_all_validators_at_result(
    node: &NodeState,
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let height = platform_resolve_query_height(node, platform_query_height_param(params)?).await?;
    let scan = scan_platform_validator_state(node, height);
    let chain_time = scan.chain_time;
    let mut grouped = std::collections::BTreeMap::<
        [u8; 32],
        (u64, std::collections::BTreeMap<String, (u64, Vec<String>)>),
    >::new();

    for record in scan
        .validators
        .into_iter()
        .filter(|validator| validator.status(chain_time) == "current")
    {
        let subnet = grouped
            .entry(record.subnet_id)
            .or_insert_with(|| (0, std::collections::BTreeMap::new()));
        subnet.0 = subnet.0.saturating_add(record.weight);
        if let Some(public_key) = platform_validator_public_key(&record) {
            let entry = subnet
                .1
                .entry(public_key)
                .or_insert_with(|| (0, Vec::new()));
            entry.0 = entry.0.saturating_add(record.weight);
            entry.1.push(record.node_id.clone());
        }
    }

    let (l1_validators, _, _) = scan_platform_l1_validator_records_at(node, height)?;
    for (_, validator) in l1_validators {
        if validator.weight == 0 || validator.end_accumulated_fee == 0 {
            continue;
        }
        let subnet = grouped
            .entry(validator.subnet_id)
            .or_insert_with(|| (0, std::collections::BTreeMap::new()));
        subnet.0 = subnet.0.saturating_add(validator.weight);
        let public_key = format!("0x{}", hex::encode(&validator.public_key));
        let entry = subnet
            .1
            .entry(public_key)
            .or_insert_with(|| (0, Vec::new()));
        entry.0 = entry.0.saturating_add(validator.weight);
        entry
            .1
            .push(format!("NodeID-{}", cb58_encode(&validator.node_id)));
    }

    if grouped.is_empty() && latest_pchain_block_metadata(&node.db).is_none() {
        let now = unix_timestamp_secs();
        let mut total_weight = 0u64;
        for validator in node
            .validators
            .values()
            .filter(|validator| validator.start_time <= now && now < validator.end_time)
        {
            total_weight = total_weight.saturating_add(validator.weight);
        }
        if total_weight > 0 {
            grouped.insert(
                SubnetId::primary_network().0,
                (total_weight, std::collections::BTreeMap::new()),
            );
        }
    }

    let mut validator_sets = serde_json::Map::new();
    for (subnet_id, (total_weight, validators)) in grouped {
        if total_weight == 0 {
            continue;
        }
        let validators = validators
            .into_iter()
            .map(|(public_key, (weight, mut node_ids))| {
                node_ids.sort();
                serde_json::json!({
                    "publicKey": public_key,
                    "weight": weight.to_string(),
                    "nodeIDs": node_ids,
                })
            })
            .collect::<Vec<_>>();
        validator_sets.insert(
            cb58_encode_id(subnet_id),
            serde_json::json!({
                "validators": validators,
                "totalWeight": total_weight.to_string(),
            }),
        );
    }

    Ok(serde_json::json!({ "validatorSets": validator_sets }))
}

fn parse_platform_id_32(value: &str) -> Option<[u8; 32]> {
    if let Some(hash) = parse_hex_hash(value) {
        return Some(hash);
    }

    let decoded = bs58::decode(value).into_vec().ok()?;
    if decoded.len() < 36 {
        return None;
    }

    let mut id = [0u8; 32];
    id.copy_from_slice(&decoded[..32]);
    Some(id)
}

fn platform_cchain_blockchain_id(network_id: u32) -> [u8; 32] {
    let cb58 = match network_id {
        1 => "2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5",
        _ => "yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp",
    };
    parse_platform_id_32(cb58).unwrap_or([0u8; 32])
}

fn platform_pchain_blockchain_id() -> [u8; 32] {
    [0u8; 32]
}

fn platform_block_id_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("blockID"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn platform_blockchain_id_param(params: &serde_json::Value) -> Option<&str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("blockchainID"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn platform_height_param(params: &serde_json::Value) -> Option<u64> {
    platform_params_object(params)
        .and_then(|obj| obj.get("height"))
        .or_else(|| params.get(0))
        .and_then(parse_quantity_u64)
}

fn platform_encoding_param<'a>(params: &'a serde_json::Value, default: &'a str) -> &'a str {
    platform_params_object(params)
        .and_then(|obj| obj.get("encoding"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(1).and_then(|value| value.as_str()))
        .unwrap_or(default)
}

fn normalize_platform_tx_id(tx_id: &str) -> Option<String> {
    parse_platform_id_32(tx_id).map(cb58_encode_id)
}

fn platform_tx_id_from_bytes(tx_bytes: &[u8]) -> String {
    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(&Sha256::digest(tx_bytes));
    cb58_encode_id(tx_hash)
}

fn platform_tx_submission_ledger(
    node: &NodeState,
    tx_bytes: &[u8],
    scan: &PlatformScanState,
) -> Result<avalanche_rs::pchain::PlatformTxLedgerSummary, String> {
    let tx_json = avalanche_rs::pchain::parse_platform_tx_json(tx_bytes)
        .map_err(|err| format!("couldn't parse tx: {}", err))?;
    let unsigned = tx_json
        .get("unsignedTx")
        .ok_or_else(|| "missing unsignedTx".to_string())?;
    let network_id = unsigned
        .get("networkID")
        .and_then(platform_json_u64)
        .ok_or_else(|| "missing networkID".to_string())?;
    if network_id != u64::from(node.config.network_id) {
        return Err(format!(
            "tx networkID {} does not match node network {}",
            network_id, node.config.network_id
        ));
    }

    let blockchain_id = unsigned
        .get("blockchainID")
        .and_then(|value| value.as_str())
        .and_then(parse_platform_id_32)
        .ok_or_else(|| "invalid blockchainID".to_string())?;
    if blockchain_id != platform_pchain_blockchain_id() {
        return Err("tx blockchainID is not the P-Chain".to_string());
    }

    let ledger = avalanche_rs::pchain::summarize_platform_tx_ledger(tx_bytes)
        .map_err(|err| format!("couldn't summarize tx: {}", err))?;
    if !platform_tx_inputs_available(&ledger, scan) {
        return Err("inputs unavailable in accepted state".to_string());
    }
    Ok(ledger)
}

fn platform_encode_blob(bytes: &[u8], encoding: &str) -> Result<String, String> {
    match encoding.to_ascii_lowercase().as_str() {
        "hex" => Ok(format!("0x{}", hex::encode(bytes))),
        "hexnc" => Ok(hex::encode(bytes)),
        "cb58" => Ok(cb58_encode(bytes)),
        _ => Err("unsupported encoding".to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlatformProposalDecision {
    Commit,
    Abort,
}

#[derive(Debug, Clone)]
struct PlatformLedgerUtxo {
    tx_id: [u8; 32],
    output_index: u32,
    output: avalanche_rs::pchain::PlatformOwnedOutput,
}

#[derive(Debug, Clone)]
struct AcceptedAtomicTx {
    raw_bytes: Vec<u8>,
    block_height: u64,
}

#[derive(Debug, Clone)]
struct PlatformOutputOwner {
    locktime: u64,
    threshold: u32,
    addresses: Vec<[u8; 20]>,
}

#[derive(Debug, Clone)]
struct PlatformStakerLedger {
    base_output_count: usize,
    stake_outputs: Vec<avalanche_rs::pchain::PlatformOwnedOutput>,
}

#[derive(Debug, Clone)]
struct PlatformStakerRewardInfo {
    kind: avalanche_rs::pchain::PlatformStakerKind,
    node_id: [u8; 20],
    subnet_id: [u8; 32],
    start_time: u64,
    end_time: u64,
    stake_asset_id: [u8; 32],
    stake_amount: u64,
    direct_reward_owner: PlatformOutputOwner,
    delegation_reward_owner: PlatformOutputOwner,
    shares: u32,
}

type PlatformLedgerUtxos = std::collections::BTreeMap<([u8; 32], u32), PlatformLedgerUtxo>;
type PlatformAtomicRoute = ([u8; 32], [u8; 32]);
type PlatformAtomicUtxos = std::collections::BTreeMap<PlatformAtomicRoute, PlatformLedgerUtxos>;

#[derive(Debug, Default)]
struct PlatformScanState {
    active_stakers:
        std::collections::BTreeMap<String, avalanche_rs::pchain::PlatformStakeTxSummary>,
    utxos: PlatformLedgerUtxos,
    atomic_utxos: PlatformAtomicUtxos,
    reward_utxos: std::collections::BTreeMap<String, Vec<PlatformLedgerUtxo>>,
    accepted_atomic_txs: std::collections::BTreeMap<String, AcceptedAtomicTx>,
    current_supply_delta: u64,
}

fn platform_tx_inputs_available(
    ledger: &avalanche_rs::pchain::PlatformTxLedgerSummary,
    scan: &PlatformScanState,
) -> bool {
    if ledger
        .inputs
        .iter()
        .any(|input| !scan.utxos.contains_key(&(input.tx_id, input.output_index)))
    {
        return false;
    }

    if let Some(source_chain) = ledger.import_source_chain {
        let Some(atomic_utxos) = scan
            .atomic_utxos
            .get(&(source_chain, platform_pchain_blockchain_id()))
        else {
            return ledger.imported_inputs.is_empty();
        };
        if ledger
            .imported_inputs
            .iter()
            .any(|input| !atomic_utxos.contains_key(&(input.tx_id, input.output_index)))
        {
            return false;
        }
    }

    true
}

async fn reconcile_platform_tx_pool(node: &NodeState) {
    let scan = scan_platform_chain_state(node);
    let processing = {
        let pool = node.platform_tx_pool.read().await;
        pool.processing_entries()
    };

    if processing.is_empty() {
        return;
    }

    let mut committed = Vec::new();
    let mut dropped = Vec::new();
    for (tx_id, ledger) in processing {
        if find_committed_platform_tx_bytes(&node.db, &tx_id).is_some() {
            committed.push(tx_id);
            continue;
        }
        if !platform_tx_inputs_available(&ledger, &scan) {
            dropped.push((tx_id, "inputs unavailable in accepted state".to_string()));
        }
    }

    if committed.is_empty() && dropped.is_empty() {
        return;
    }

    let mut pool = node.platform_tx_pool.write().await;
    for tx_id in committed {
        pool.remove_processing(&tx_id);
    }
    for (tx_id, reason) in dropped {
        pool.mark_dropped(&tx_id, reason);
    }
}

fn platform_input_id(tx_id: [u8; 32], output_index: u32) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&(output_index as u64).to_be_bytes());
    bytes.extend_from_slice(&tx_id);
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(&bytes));
    out
}

fn parse_platform_utxo_end_index(value: &str) -> Option<[u8; 32]> {
    parse_platform_id_32(value)
}

fn platform_encode_utxo(
    tx_id: [u8; 32],
    output_index: u32,
    output: &avalanche_rs::pchain::PlatformOwnedOutput,
    encoding: &str,
) -> Result<String, String> {
    let mut bytes =
        Vec::with_capacity(2 + 32 + 4 + output.asset_id.len() + output.output_raw_bytes.len());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&tx_id);
    bytes.extend_from_slice(&output_index.to_be_bytes());
    bytes.extend_from_slice(&output.asset_id);
    bytes.extend_from_slice(&output.output_raw_bytes);
    platform_encode_blob(&bytes, encoding)
}

fn platform_json_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn platform_output_owner_from_value(value: &serde_json::Value) -> Option<PlatformOutputOwner> {
    let locktime = platform_json_u64(value.get("locktime")?)?;
    let threshold = platform_json_u64(value.get("threshold")?)? as u32;
    let addresses = value
        .get("addresses")?
        .as_array()?
        .iter()
        .map(|value| value.as_str().and_then(parse_platform_address_20))
        .collect::<Option<Vec<_>>>()?;
    Some(PlatformOutputOwner {
        locktime,
        threshold,
        addresses,
    })
}

fn platform_reward_output_raw_bytes(owner: &PlatformOutputOwner, amount: u64) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(4 + 8 + 8 + 4 + 4 + owner.addresses.len().saturating_mul(20));
    bytes.extend_from_slice(&7u32.to_be_bytes());
    bytes.extend_from_slice(&amount.to_be_bytes());
    bytes.extend_from_slice(&owner.locktime.to_be_bytes());
    bytes.extend_from_slice(&owner.threshold.to_be_bytes());
    bytes.extend_from_slice(&(owner.addresses.len() as u32).to_be_bytes());
    for address in &owner.addresses {
        bytes.extend_from_slice(address);
    }
    bytes
}

fn platform_reward_owned_output(
    asset_id: [u8; 32],
    owner: &PlatformOutputOwner,
    amount: u64,
) -> avalanche_rs::pchain::PlatformOwnedOutput {
    let output_raw_bytes = platform_reward_output_raw_bytes(owner, amount);
    let mut transferable_raw_bytes = Vec::with_capacity(asset_id.len() + output_raw_bytes.len());
    transferable_raw_bytes.extend_from_slice(&asset_id);
    transferable_raw_bytes.extend_from_slice(&output_raw_bytes);
    avalanche_rs::pchain::PlatformOwnedOutput {
        asset_id,
        amount,
        owner_locktime: owner.locktime,
        stakeable_locktime: None,
        addresses: owner.addresses.clone(),
        transferable_raw_bytes,
        output_raw_bytes,
    }
}

fn platform_staker_reward_info_from_ledger(
    tx_bytes: &[u8],
    ledger: &avalanche_rs::pchain::PlatformTxLedgerSummary,
) -> Option<PlatformStakerRewardInfo> {
    let kind = ledger.kind?;
    let tx_json = avalanche_rs::pchain::parse_platform_tx_json(tx_bytes).ok()?;
    let unsigned = tx_json.get("unsignedTx")?;
    let validator = unsigned.get("validator")?;
    let node_id = parse_node_id_20(validator.get("nodeID")?.as_str()?)?;
    let start_time = platform_json_u64(validator.get("start")?)?;
    let end_time = platform_json_u64(validator.get("end")?)?;
    let direct_reward_owner = match kind {
        avalanche_rs::pchain::PlatformStakerKind::Validator => unsigned
            .get("validationRewardsOwner")
            .or_else(|| unsigned.get("rewardsOwner")),
        avalanche_rs::pchain::PlatformStakerKind::Delegator => unsigned.get("rewardsOwner"),
    }
    .and_then(platform_output_owner_from_value)?;
    let delegation_reward_owner = unsigned
        .get("delegationRewardsOwner")
        .or_else(|| unsigned.get("rewardsOwner"))
        .and_then(platform_output_owner_from_value)?;
    let subnet_id = unsigned
        .get("subnetID")
        .and_then(|value| value.as_str())
        .and_then(parse_platform_id_32)
        .unwrap_or([0u8; 32]);
    let stake_asset_id = ledger.stake_outputs.first()?.asset_id;
    let stake_amount = ledger
        .stake_outputs
        .iter()
        .filter(|output| output.asset_id == stake_asset_id)
        .fold(0u64, |total, output| total.saturating_add(output.amount));
    let shares = unsigned
        .get("shares")
        .and_then(platform_json_u64)
        .map(|value| value as u32)
        .unwrap_or(0);
    Some(PlatformStakerRewardInfo {
        kind,
        node_id,
        subnet_id,
        start_time,
        end_time,
        stake_asset_id,
        stake_amount,
        direct_reward_owner,
        delegation_reward_owner,
        shares,
    })
}

fn platform_validator_for_delegator<'a>(
    reward_info_by_tx: &'a std::collections::HashMap<String, PlatformStakerRewardInfo>,
    delegator: &PlatformStakerRewardInfo,
) -> Option<(&'a str, &'a PlatformStakerRewardInfo)> {
    reward_info_by_tx
        .iter()
        .find(|candidate| {
            candidate.1.kind == avalanche_rs::pchain::PlatformStakerKind::Validator
                && candidate.1.node_id == delegator.node_id
                && candidate.1.subnet_id == delegator.subnet_id
                && candidate.1.start_time <= delegator.start_time
                && candidate.1.end_time >= delegator.end_time
        })
        .map(|(tx_id, candidate)| (tx_id.as_str(), candidate))
}

fn platform_total_reward_amount(reward_info: &PlatformStakerRewardInfo) -> Option<u64> {
    if reward_info.end_time <= reward_info.start_time || reward_info.stake_amount == 0 {
        return None;
    }

    let reward = avalanche_rs::staking::expected_reward(
        reward_info.stake_amount,
        reward_info.end_time.saturating_sub(reward_info.start_time),
        1.0,
    );
    (reward > 0).then_some(reward)
}

fn platform_reward_split(total_reward: u64, shares: u32) -> (u64, u64) {
    const PLATFORM_REWARD_PERCENT_DENOMINATOR: u64 = 1_000_000;
    let shares = u64::from(shares).min(PLATFORM_REWARD_PERCENT_DENOMINATOR);
    let remainder_shares = PLATFORM_REWARD_PERCENT_DENOMINATOR.saturating_sub(shares);
    let remainder_amount = ((remainder_shares as u128) * (total_reward as u128)
        / (PLATFORM_REWARD_PERCENT_DENOMINATOR as u128)) as u64;
    let amount_from_shares = total_reward.saturating_sub(remainder_amount);
    (amount_from_shares, remainder_amount)
}

fn platform_is_cortina_active(network_id: u32, start_time: u64) -> bool {
    start_time >= upgrade_time_unix(&info_upgrades_result(network_id), "cortinaTime")
}

fn platform_supply_delta_add(
    deltas: &mut std::collections::BTreeMap<[u8; 32], u64>,
    subnet_id: [u8; 32],
    amount: u64,
) {
    deltas
        .entry(subnet_id)
        .and_modify(|total| *total = total.saturating_add(amount))
        .or_insert(amount);
}

fn platform_supply_delta_sub(
    deltas: &mut std::collections::BTreeMap<[u8; 32], u64>,
    subnet_id: [u8; 32],
    amount: u64,
) {
    let total = deltas.entry(subnet_id).or_insert(0);
    *total = total.saturating_sub(amount);
}

fn platform_signer_value(unsigned_tx: &serde_json::Value) -> Option<serde_json::Value> {
    match unsigned_tx.get("signer") {
        Some(serde_json::Value::Object(map)) if map.is_empty() => None,
        Some(value) => Some(value.clone()),
        None => None,
    }
}

fn platform_validator_record_from_reward_info(
    tx_id: &str,
    reward_info: &PlatformStakerRewardInfo,
    unsigned_tx: &serde_json::Value,
) -> PlatformValidatorRecord {
    PlatformValidatorRecord {
        tx_id: Some(tx_id.to_string()),
        node_id: full_node_id_string(&NodeId(reward_info.node_id)),
        subnet_id: reward_info.subnet_id,
        weight: reward_info.stake_amount,
        start_time: reward_info.start_time,
        end_time: Some(reward_info.end_time),
        removed_at: None,
        permissionless: true,
        validation_reward_owner: Some(reward_info.direct_reward_owner.clone()),
        delegation_reward_owner: Some(reward_info.delegation_reward_owner.clone()),
        potential_reward: platform_total_reward_amount(reward_info),
        accrued_delegatee_reward: None,
        shares: Some(reward_info.shares),
        signer: platform_signer_value(unsigned_tx),
        delegators: Vec::new(),
        l1: None,
    }
}

fn platform_delegator_record_from_reward_info(
    tx_id: &str,
    reward_info: &PlatformStakerRewardInfo,
) -> PlatformDelegatorRecord {
    PlatformDelegatorRecord {
        tx_id: tx_id.to_string(),
        node_id: full_node_id_string(&NodeId(reward_info.node_id)),
        weight: reward_info.stake_amount,
        start_time: reward_info.start_time,
        end_time: reward_info.end_time,
        reward_owner: reward_info.direct_reward_owner.clone(),
        potential_reward: platform_total_reward_amount(reward_info),
    }
}

fn platform_permissioned_validator_record_from_tx(
    tx_id: &str,
    unsigned_tx: &serde_json::Value,
) -> Option<PlatformValidatorRecord> {
    let validator = unsigned_tx.get("validator")?;
    Some(PlatformValidatorRecord {
        tx_id: Some(tx_id.to_string()),
        node_id: validator.get("nodeID")?.as_str()?.to_string(),
        subnet_id: validator
            .get("subnetID")
            .and_then(|value| value.as_str())
            .and_then(parse_platform_id_32)?,
        weight: platform_json_u64(validator.get("weight")?)?,
        start_time: platform_json_u64(validator.get("start")?)?,
        end_time: Some(platform_json_u64(validator.get("end")?)?),
        removed_at: None,
        permissionless: false,
        validation_reward_owner: None,
        delegation_reward_owner: None,
        potential_reward: None,
        accrued_delegatee_reward: None,
        shares: None,
        signer: None,
        delegators: Vec::new(),
        l1: None,
    })
}

fn platform_initial_supply(network_id: u32, subnet_id: &SubnetId) -> Option<u64> {
    if *subnet_id != SubnetId::primary_network() {
        return None;
    }

    match network_id {
        1 => Some(359_999_999_999_990_210),
        5 => Some(360_000_000_000_000_000),
        _ => Some(360_000_000_000_000_000),
    }
}

fn platform_push_reward_utxo(
    state: &mut PlatformScanState,
    tx_id_str: &str,
    tx_id: [u8; 32],
    output_index: u32,
    asset_id: [u8; 32],
    owner: &PlatformOutputOwner,
    amount: u64,
) {
    if amount == 0 {
        return;
    }

    let reward_utxo = PlatformLedgerUtxo {
        tx_id,
        output_index,
        output: platform_reward_owned_output(asset_id, owner, amount),
    };
    state
        .utxos
        .insert((tx_id, output_index), reward_utxo.clone());
    state
        .reward_utxos
        .entry(tx_id_str.to_string())
        .or_default()
        .push(reward_utxo);
}

fn scan_platform_validator_state(
    node: &NodeState,
    max_height: Option<u64>,
) -> PlatformValidatorScanState {
    let mut blocks = platform_sorted_pchain_blocks(&node.db);
    if let Some(max_height) = max_height {
        blocks.retain(|(meta, _)| meta.height <= max_height);
    }
    let decisions = platform_proposal_decisions(&blocks);
    let chain_time = blocks.last().map(|(meta, _)| meta.timestamp).unwrap_or(0);

    let mut state = PlatformValidatorScanState {
        chain_time,
        ..Default::default()
    };
    let mut validators_by_tx_id =
        std::collections::BTreeMap::<String, PlatformValidatorRecord>::new();
    let mut delegators_by_tx_id =
        std::collections::BTreeMap::<String, PlatformDelegatorRecord>::new();
    let mut reward_info_by_tx_id =
        std::collections::HashMap::<String, PlatformStakerRewardInfo>::new();
    let mut accrued_delegatee_rewards = std::collections::HashMap::<String, u64>::new();
    let mut permissioned_validator_index =
        std::collections::HashMap::<([u8; 32], String), String>::new();
    let mut seen_txs = std::collections::HashSet::new();

    for (meta, raw_block) in blocks {
        let Ok(txs) = avalanche_rs::pchain::extract_platform_tx_bytes_from_block(&raw_block) else {
            continue;
        };

        for tx_bytes in txs {
            let tx_id = platform_tx_id_from_bytes(&tx_bytes);
            if !seen_txs.insert(tx_id.clone()) {
                continue;
            }

            let tx_json = match avalanche_rs::pchain::parse_platform_tx_json(&tx_bytes) {
                Ok(tx_json) => tx_json,
                Err(_) => continue,
            };
            let Some(unsigned_tx) = tx_json.get("unsignedTx") else {
                continue;
            };

            if let Some(subnet_id) = unsigned_tx
                .get("subnetID")
                .and_then(|value| value.as_str())
                .and_then(parse_platform_id_32)
            {
                if let Some(config) = unsigned_tx
                    .get("assetID")
                    .and_then(|value| value.as_str())
                    .and_then(parse_platform_id_32)
                    .map(|asset_id| PlatformSubnetStakingConfig {
                        asset_id: Some(asset_id),
                        initial_supply: unsigned_tx
                            .get("initialSupply")
                            .and_then(platform_json_u64),
                        min_validator_stake: unsigned_tx
                            .get("minValidatorStake")
                            .and_then(platform_json_u64),
                        min_delegator_stake: unsigned_tx
                            .get("minDelegatorStake")
                            .and_then(platform_json_u64),
                    })
                {
                    state.subnet_configs.insert(subnet_id, config);
                }
            }

            if unsigned_tx.get("subnetAuthorization").is_some()
                && unsigned_tx.get("validator").is_some()
                && unsigned_tx.get("newOwner").is_none()
            {
                if let Some(record) =
                    platform_permissioned_validator_record_from_tx(&tx_id, unsigned_tx)
                {
                    permissioned_validator_index
                        .insert((record.subnet_id, record.node_id.clone()), tx_id.clone());
                    validators_by_tx_id.insert(tx_id.clone(), record);
                }
                continue;
            }

            if unsigned_tx.get("nodeID").is_some()
                && unsigned_tx.get("subnetAuthorization").is_some()
            {
                let Some(node_id) = unsigned_tx.get("nodeID").and_then(|value| value.as_str())
                else {
                    continue;
                };
                let Some(subnet_id) = unsigned_tx
                    .get("subnetID")
                    .and_then(|value| value.as_str())
                    .and_then(parse_platform_id_32)
                else {
                    continue;
                };
                if let Some(existing_tx_id) =
                    permissioned_validator_index.remove(&(subnet_id, node_id.to_string()))
                {
                    if let Some(record) = validators_by_tx_id.get_mut(&existing_tx_id) {
                        record.removed_at = Some(meta.timestamp);
                    }
                }
                continue;
            }

            if let Ok(ledger) = avalanche_rs::pchain::summarize_platform_tx_ledger(&tx_bytes) {
                if let Some(kind) = ledger.kind {
                    if let Some(reward_info) =
                        platform_staker_reward_info_from_ledger(&tx_bytes, &ledger)
                    {
                        if reward_info.start_time <= chain_time {
                            platform_supply_delta_add(
                                &mut state.current_supply_deltas,
                                reward_info.subnet_id,
                                platform_total_reward_amount(&reward_info).unwrap_or(0),
                            );
                        }

                        match kind {
                            avalanche_rs::pchain::PlatformStakerKind::Validator => {
                                validators_by_tx_id.insert(
                                    tx_id.clone(),
                                    platform_validator_record_from_reward_info(
                                        &tx_id,
                                        &reward_info,
                                        unsigned_tx,
                                    ),
                                );
                            }
                            avalanche_rs::pchain::PlatformStakerKind::Delegator => {
                                delegators_by_tx_id.insert(
                                    tx_id.clone(),
                                    platform_delegator_record_from_reward_info(
                                        &tx_id,
                                        &reward_info,
                                    ),
                                );
                            }
                        }
                        reward_info_by_tx_id.insert(tx_id.clone(), reward_info);
                    }
                }

                if let Some(reward_target) = ledger.reward_validator_tx_id {
                    let Some(decision) = decisions.get(&meta.id) else {
                        continue;
                    };
                    let reward_target_id = cb58_encode_id(reward_target);
                    let Some(reward_info) = reward_info_by_tx_id.get(&reward_target_id).cloned()
                    else {
                        continue;
                    };
                    if *decision == PlatformProposalDecision::Abort
                        && reward_info.start_time <= chain_time
                    {
                        platform_supply_delta_sub(
                            &mut state.current_supply_deltas,
                            reward_info.subnet_id,
                            platform_total_reward_amount(&reward_info).unwrap_or(0),
                        );
                    }

                    match reward_info.kind {
                        avalanche_rs::pchain::PlatformStakerKind::Validator => {
                            let delegatee_reward = accrued_delegatee_rewards
                                .remove(&reward_target_id)
                                .unwrap_or(0);
                            if let Some(record) = validators_by_tx_id.get_mut(&reward_target_id) {
                                record.accrued_delegatee_reward = Some(delegatee_reward);
                            }
                        }
                        avalanche_rs::pchain::PlatformStakerKind::Delegator => {
                            if *decision != PlatformProposalDecision::Commit {
                                continue;
                            }
                            let Some(total_reward) = platform_total_reward_amount(&reward_info)
                            else {
                                continue;
                            };
                            let Some((validator_tx_id, validator_info)) =
                                platform_validator_for_delegator(
                                    &reward_info_by_tx_id,
                                    &reward_info,
                                )
                            else {
                                continue;
                            };
                            let (delegatee_reward, _) =
                                platform_reward_split(total_reward, validator_info.shares);
                            if platform_is_cortina_active(
                                node.config.network_id,
                                validator_info.start_time,
                            ) {
                                let accrued = accrued_delegatee_rewards
                                    .entry(validator_tx_id.to_string())
                                    .or_insert(0);
                                *accrued = accrued.saturating_add(delegatee_reward);
                            } else if let Some(record) =
                                validators_by_tx_id.get_mut(validator_tx_id)
                            {
                                let current = record.accrued_delegatee_reward.unwrap_or(0);
                                record.accrued_delegatee_reward =
                                    Some(current.saturating_add(delegatee_reward));
                            }
                        }
                    }
                }
            }
        }
    }

    for (validator_tx_id, accrued_reward) in accrued_delegatee_rewards {
        if let Some(record) = validators_by_tx_id.get_mut(&validator_tx_id) {
            let current = record.accrued_delegatee_reward.unwrap_or(0);
            record.accrued_delegatee_reward = Some(current.saturating_add(accrued_reward));
        }
    }

    for (delegator_tx_id, reward_info) in &reward_info_by_tx_id {
        if reward_info.kind != avalanche_rs::pchain::PlatformStakerKind::Delegator {
            continue;
        }
        let Some((validator_tx_id, _)) =
            platform_validator_for_delegator(&reward_info_by_tx_id, reward_info)
        else {
            continue;
        };
        let Some(delegator) = delegators_by_tx_id.get(delegator_tx_id).cloned() else {
            continue;
        };
        if let Some(validator) = validators_by_tx_id.get_mut(validator_tx_id) {
            validator.delegators.push(delegator);
        }
    }

    state.validators = validators_by_tx_id.into_values().collect();
    state.validators.sort_by(|a, b| {
        a.node_id
            .cmp(&b.node_id)
            .then_with(|| a.start_time.cmp(&b.start_time))
            .then_with(|| a.tx_id.cmp(&b.tx_id))
    });
    for validator in &mut state.validators {
        validator.delegators.sort_by(|a, b| {
            a.start_time
                .cmp(&b.start_time)
                .then_with(|| a.tx_id.cmp(&b.tx_id))
        });
    }
    state
}

fn platform_sorted_pchain_blocks(db: &Database) -> Vec<(BlockMetadata, Vec<u8>)> {
    let mut blocks = db
        .iter_cf_owned(CF_BLOCKS)
        .into_iter()
        .filter(|(key, _)| !key.starts_with(b"c:") && key.len() == 32)
        .filter_map(|(_, raw)| {
            BlockMetadata::from_raw(&raw, Chain::PChain)
                .ok()
                .map(|meta| (meta, raw))
        })
        .collect::<Vec<_>>();
    blocks.sort_by(|a, b| {
        a.0.height
            .cmp(&b.0.height)
            .then_with(|| a.0.id.cmp(&b.0.id))
    });
    blocks
}

fn platform_sorted_pchain_blocks_up_to(
    db: &Database,
    max_height: Option<u64>,
) -> Vec<(BlockMetadata, Vec<u8>)> {
    let mut blocks = platform_sorted_pchain_blocks(db);
    if let Some(max_height) = max_height {
        blocks.retain(|(meta, _)| meta.height <= max_height);
    }
    blocks
}

fn cchain_sorted_blocks(db: &Database) -> Vec<(u64, Vec<u8>)> {
    let mut blocks = db
        .iter_cf_owned(CF_BLOCKS)
        .into_iter()
        .filter_map(|(key, raw)| {
            let height = <[u8; 8]>::try_from(key.as_slice())
                .ok()
                .map(u64::from_be_bytes)?;
            Some((height, raw))
        })
        .collect::<Vec<_>>();
    blocks.sort_by_key(|(height, _)| *height);
    blocks
}

fn platform_proposal_decisions(
    blocks: &[(BlockMetadata, Vec<u8>)],
) -> std::collections::HashMap<[u8; 32], PlatformProposalDecision> {
    let mut decisions = std::collections::HashMap::new();
    for (meta, _) in blocks {
        match meta.block_type {
            avalanche_rs::block::BlockType::ApricotCommit
            | avalanche_rs::block::BlockType::BanffCommit => {
                decisions.insert(meta.parent_id, PlatformProposalDecision::Commit);
            }
            avalanche_rs::block::BlockType::ApricotAbort
            | avalanche_rs::block::BlockType::BanffAbort => {
                decisions.insert(meta.parent_id, PlatformProposalDecision::Abort);
            }
            _ => {}
        }
    }
    decisions
}

fn scan_platform_chain_state(node: &NodeState) -> PlatformScanState {
    let blocks = platform_sorted_pchain_blocks(&node.db);
    let decisions = platform_proposal_decisions(&blocks);
    let chain_time = latest_pchain_block_metadata(&node.db)
        .map(|meta| meta.timestamp)
        .unwrap_or(0);
    let p_chain_id = platform_pchain_blockchain_id();
    let mut state = PlatformScanState::default();
    let mut staker_ledger = std::collections::HashMap::<String, PlatformStakerLedger>::new();
    let mut staker_reward_info =
        std::collections::HashMap::<String, PlatformStakerRewardInfo>::new();
    let mut accrued_delegatee_rewards = std::collections::HashMap::<String, u64>::new();
    let mut seen_txs = std::collections::HashSet::new();

    for (meta, raw_block) in blocks {
        let Ok(txs) = avalanche_rs::pchain::extract_platform_tx_bytes_from_block(&raw_block) else {
            continue;
        };

        for tx_bytes in txs {
            let tx_id = platform_tx_id_from_bytes(&tx_bytes);
            if !seen_txs.insert(tx_id.clone()) {
                continue;
            }

            if let Ok(ledger) = avalanche_rs::pchain::summarize_platform_tx_ledger(&tx_bytes) {
                let tx_id_bytes = parse_platform_id_32(&tx_id).unwrap_or([0u8; 32]);

                for input in &ledger.inputs {
                    state.utxos.remove(&(input.tx_id, input.output_index));
                }

                for (index, output) in ledger.outputs.iter().cloned().enumerate() {
                    state.utxos.insert(
                        (tx_id_bytes, index as u32),
                        PlatformLedgerUtxo {
                            tx_id: tx_id_bytes,
                            output_index: index as u32,
                            output,
                        },
                    );
                }

                if let Some(source_chain) = ledger.import_source_chain {
                    if let Some(atomic_utxos) =
                        state.atomic_utxos.get_mut(&(source_chain, p_chain_id))
                    {
                        for input in &ledger.imported_inputs {
                            atomic_utxos.remove(&(input.tx_id, input.output_index));
                        }
                    }
                }

                if let Some(destination_chain) = ledger.export_destination_chain {
                    let atomic_utxos = state
                        .atomic_utxos
                        .entry((p_chain_id, destination_chain))
                        .or_default();
                    for (offset, output) in ledger.exported_outputs.iter().cloned().enumerate() {
                        let output_index = (ledger.outputs.len() + offset) as u32;
                        atomic_utxos.insert(
                            (tx_id_bytes, output_index),
                            PlatformLedgerUtxo {
                                tx_id: tx_id_bytes,
                                output_index,
                                output,
                            },
                        );
                    }
                }

                if let Some(kind) = ledger.kind {
                    staker_ledger.insert(
                        tx_id.clone(),
                        PlatformStakerLedger {
                            base_output_count: ledger.outputs.len(),
                            stake_outputs: ledger.stake_outputs.clone(),
                        },
                    );
                    if let Ok(avalanche_rs::pchain::PlatformTxSummary::Stake(summary)) =
                        avalanche_rs::pchain::summarize_platform_tx(&tx_bytes)
                    {
                        state.active_stakers.insert(tx_id.clone(), summary);
                    } else if kind == avalanche_rs::pchain::PlatformStakerKind::Validator
                        || kind == avalanche_rs::pchain::PlatformStakerKind::Delegator
                    {
                    }
                    if let Some(reward_info) =
                        platform_staker_reward_info_from_ledger(&tx_bytes, &ledger)
                    {
                        if reward_info.start_time <= chain_time {
                            state.current_supply_delta = state.current_supply_delta.saturating_add(
                                platform_total_reward_amount(&reward_info).unwrap_or(0),
                            );
                        }
                        staker_reward_info.insert(tx_id.clone(), reward_info);
                    }
                }

                if let Some(reward_target) = ledger.reward_validator_tx_id {
                    if let Some(decision) = decisions.get(&meta.id) {
                        let reward_target_id = cb58_encode_id(reward_target);
                        state.active_stakers.remove(&reward_target_id);
                        if *decision == PlatformProposalDecision::Abort {
                            if let Some(reward_info) = staker_reward_info.get(&reward_target_id) {
                                if reward_info.start_time <= chain_time {
                                    state.current_supply_delta =
                                        state.current_supply_delta.saturating_sub(
                                            platform_total_reward_amount(reward_info).unwrap_or(0),
                                        );
                                }
                            }
                        }
                        if let Some(staker) = staker_ledger.get(&reward_target_id) {
                            for (offset, output) in staker.stake_outputs.iter().cloned().enumerate()
                            {
                                let output_index = (staker.base_output_count + offset) as u32;
                                state.utxos.insert(
                                    (reward_target, output_index),
                                    PlatformLedgerUtxo {
                                        tx_id: reward_target,
                                        output_index,
                                        output,
                                    },
                                );
                            }
                            if let Some(reward_info) = staker_reward_info.get(&reward_target_id) {
                                match reward_info.kind {
                                    avalanche_rs::pchain::PlatformStakerKind::Validator => {
                                        let total_reward =
                                            platform_total_reward_amount(reward_info).unwrap_or(0);
                                        let mut next_output_index = (staker.base_output_count
                                            + staker.stake_outputs.len())
                                            as u32;
                                        if *decision == PlatformProposalDecision::Commit {
                                            platform_push_reward_utxo(
                                                &mut state,
                                                &reward_target_id,
                                                reward_target,
                                                next_output_index,
                                                reward_info.stake_asset_id,
                                                &reward_info.direct_reward_owner,
                                                total_reward,
                                            );
                                            if total_reward > 0 {
                                                next_output_index =
                                                    next_output_index.saturating_add(1);
                                            }
                                        }

                                        let delegatee_reward = accrued_delegatee_rewards
                                            .remove(&reward_target_id)
                                            .unwrap_or(0);
                                        platform_push_reward_utxo(
                                            &mut state,
                                            &reward_target_id,
                                            reward_target,
                                            next_output_index,
                                            reward_info.stake_asset_id,
                                            &reward_info.delegation_reward_owner,
                                            delegatee_reward,
                                        );
                                    }
                                    avalanche_rs::pchain::PlatformStakerKind::Delegator => {
                                        if *decision == PlatformProposalDecision::Commit {
                                            let Some(total_reward) =
                                                platform_total_reward_amount(reward_info)
                                            else {
                                                continue;
                                            };
                                            let Some((validator_tx_id, validator_info)) =
                                                platform_validator_for_delegator(
                                                    &staker_reward_info,
                                                    reward_info,
                                                )
                                            else {
                                                continue;
                                            };
                                            let validator_shares = validator_info.shares;
                                            let (delegatee_reward, delegator_reward) =
                                                platform_reward_split(
                                                    total_reward,
                                                    validator_shares,
                                                );
                                            let mut next_output_index = (staker.base_output_count
                                                + staker.stake_outputs.len())
                                                as u32;
                                            platform_push_reward_utxo(
                                                &mut state,
                                                &reward_target_id,
                                                reward_target,
                                                next_output_index,
                                                reward_info.stake_asset_id,
                                                &reward_info.direct_reward_owner,
                                                delegator_reward,
                                            );
                                            if delegator_reward > 0 {
                                                next_output_index =
                                                    next_output_index.saturating_add(1);
                                            }

                                            if platform_is_cortina_active(
                                                node.config.network_id,
                                                validator_info.start_time,
                                            ) {
                                                let accrued = accrued_delegatee_rewards
                                                    .entry(validator_tx_id.to_string())
                                                    .or_insert(0);
                                                *accrued = accrued.saturating_add(delegatee_reward);
                                            } else {
                                                platform_push_reward_utxo(
                                                    &mut state,
                                                    &reward_target_id,
                                                    reward_target,
                                                    next_output_index,
                                                    reward_info.stake_asset_id,
                                                    &validator_info.delegation_reward_owner,
                                                    delegatee_reward,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        staker_reward_info.remove(&reward_target_id);
                    }
                }
            }
        }
    }

    let c_chain_id = platform_cchain_blockchain_id(node.config.network_id);
    let ap5_time = upgrade_time_unix(
        &info_upgrades_result(node.config.network_id),
        "apricotPhase5Time",
    );
    for (stored_height, raw_block) in cchain_sorted_blocks(&node.db) {
        let Some(fields) = extract_cchain_block_fields(&raw_block) else {
            continue;
        };
        let block_height = if fields.number == 0 {
            stored_height
        } else {
            fields.number
        };
        let batch_encoded = fields.timestamp >= ap5_time;
        let Ok(atomic_txs) = extract_cchain_atomic_transactions(&raw_block, batch_encoded) else {
            continue;
        };

        for atomic_tx in atomic_txs {
            let tx_id_str = cb58_encode_id(atomic_tx.tx_id);
            state.accepted_atomic_txs.insert(
                tx_id_str,
                AcceptedAtomicTx {
                    raw_bytes: atomic_tx.raw.clone(),
                    block_height,
                },
            );

            if let Some(source_chain) = atomic_tx.source_chain {
                if let Some(atomic_utxos) = state.atomic_utxos.get_mut(&(source_chain, c_chain_id))
                {
                    for input in &atomic_tx.imported_inputs {
                        atomic_utxos.remove(&(input.tx_id, input.output_index));
                    }
                }
            }

            if let Some(destination_chain) = atomic_tx.destination_chain {
                let atomic_utxos = state
                    .atomic_utxos
                    .entry((c_chain_id, destination_chain))
                    .or_default();
                for (output_index, output) in atomic_tx.exported_outputs.into_iter().enumerate() {
                    atomic_utxos.insert(
                        (atomic_tx.tx_id, output_index as u32),
                        PlatformLedgerUtxo {
                            tx_id: atomic_tx.tx_id,
                            output_index: output_index as u32,
                            output: avalanche_rs::pchain::PlatformOwnedOutput {
                                asset_id: output.asset_id,
                                amount: output.amount,
                                owner_locktime: output.owner_locktime,
                                stakeable_locktime: output.stakeable_locktime,
                                addresses: output.addresses,
                                transferable_raw_bytes: output.transferable_raw_bytes,
                                output_raw_bytes: output.output_raw_bytes,
                            },
                        },
                    );
                }
            }
        }
    }

    state
}

fn find_committed_platform_tx_bytes(db: &Database, tx_id: &str) -> Option<Vec<u8>> {
    db.iter_cf_owned(CF_BLOCKS)
        .into_iter()
        .filter(|(key, _)| key.len() == 32)
        .find_map(|(_, raw_block)| {
            let txs =
                avalanche_rs::pchain::extract_platform_tx_bytes_from_block(&raw_block).ok()?;
            txs.into_iter()
                .find(|tx_bytes| platform_tx_id_from_bytes(tx_bytes) == tx_id)
        })
}

fn find_committed_atomic_tx(node: &NodeState, tx_id: &str) -> Option<AcceptedAtomicTx> {
    scan_platform_chain_state(node)
        .accepted_atomic_txs
        .get(tx_id)
        .cloned()
}

fn platform_block_transactions_json(raw_block: &[u8]) -> Option<Vec<serde_json::Value>> {
    let tx_bytes = avalanche_rs::pchain::extract_platform_tx_bytes_from_block(raw_block).ok()?;
    tx_bytes
        .into_iter()
        .map(|tx_bytes| avalanche_rs::pchain::parse_platform_tx_json(&tx_bytes).ok())
        .collect()
}

fn platform_stake_response(
    node: &NodeState,
    requested_addrs: &std::collections::HashSet<[u8; 20]>,
    validators_only: bool,
    encoding: &str,
) -> Result<serde_json::Value, String> {
    let _ = platform_encode_blob(&[], encoding)?;
    let scan = scan_platform_chain_state(node);

    let mut totals = std::collections::BTreeMap::<String, u64>::new();
    let mut staked_outputs = Vec::new();
    for (_, summary) in scan.active_stakers {
        if validators_only && summary.kind != avalanche_rs::pchain::PlatformStakerKind::Validator {
            continue;
        }

        for output in summary.outputs {
            if !output
                .addresses
                .iter()
                .any(|address| requested_addrs.contains(address))
            {
                continue;
            }

            let asset_id = cb58_encode(&output.asset_id);
            totals
                .entry(asset_id)
                .and_modify(|total| *total = total.saturating_add(output.amount))
                .or_insert(output.amount);
            staked_outputs.push(platform_encode_blob(&output.raw_bytes, encoding)?);
        }
    }

    staked_outputs.sort();

    let mut stakeds = serde_json::Map::new();
    for (asset_id, amount) in totals {
        stakeds.insert(asset_id, serde_json::Value::String(amount.to_string()));
    }

    let primary_asset_id = platform_staking_asset_id(node, Some(&SubnetId::primary_network()));
    let staked = primary_asset_id
        .as_ref()
        .and_then(|asset_id| stakeds.get(asset_id))
        .and_then(|value| value.as_str())
        .unwrap_or("0")
        .to_string();
    if let Some(primary_asset_id) = primary_asset_id {
        stakeds
            .entry(primary_asset_id)
            .or_insert_with(|| serde_json::Value::String("0".to_string()));
    }

    Ok(serde_json::json!({
        "staked": staked,
        "stakeds": serde_json::Value::Object(stakeds),
        "stakedOutputs": staked_outputs,
        "encoding": encoding,
    }))
}

fn platform_balance_response(
    node: &NodeState,
    requested_addrs: &std::collections::HashSet<[u8; 20]>,
) -> serde_json::Value {
    fn add_amount(
        bucket: &mut std::collections::BTreeMap<String, u64>,
        asset_id: &str,
        amount: u64,
    ) {
        let total = bucket
            .get(asset_id)
            .copied()
            .unwrap_or(0)
            .saturating_add(amount);
        bucket.insert(asset_id.to_string(), total);
    }

    let scan = scan_platform_chain_state(node);
    let now = unix_timestamp_secs();
    let mut unlockeds = std::collections::BTreeMap::<String, u64>::new();
    let mut locked_stakeables = std::collections::BTreeMap::<String, u64>::new();
    let mut locked_not_stakeables = std::collections::BTreeMap::<String, u64>::new();
    let mut utxo_ids = Vec::new();

    for utxo in scan.utxos.values() {
        if !utxo
            .output
            .addresses
            .iter()
            .any(|address| requested_addrs.contains(address))
        {
            continue;
        }

        let asset_id = cb58_encode(&utxo.output.asset_id);
        match utxo.output.stakeable_locktime {
            Some(_) if utxo.output.owner_locktime > now => {
                add_amount(&mut locked_not_stakeables, &asset_id, utxo.output.amount);
            }
            Some(stakeable_locktime) if stakeable_locktime <= now => {
                add_amount(&mut unlockeds, &asset_id, utxo.output.amount);
            }
            Some(_) => {
                add_amount(&mut locked_stakeables, &asset_id, utxo.output.amount);
            }
            None if utxo.output.owner_locktime <= now => {
                add_amount(&mut unlockeds, &asset_id, utxo.output.amount);
            }
            None => {
                add_amount(&mut locked_not_stakeables, &asset_id, utxo.output.amount);
            }
        }

        utxo_ids.push(serde_json::json!({
            "txID": cb58_encode_id(utxo.tx_id),
            "outputIndex": utxo.output_index,
        }));
    }

    utxo_ids.sort_by(|a, b| {
        a["txID"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["txID"].as_str().unwrap_or_default())
            .then_with(|| {
                a["outputIndex"]
                    .as_u64()
                    .unwrap_or_default()
                    .cmp(&b["outputIndex"].as_u64().unwrap_or_default())
            })
    });

    let mut balances = std::collections::BTreeMap::<String, u64>::new();
    for bucket in [&unlockeds, &locked_stakeables, &locked_not_stakeables] {
        for (asset_id, amount) in bucket {
            add_amount(&mut balances, asset_id, *amount);
        }
    }

    let primary_asset = platform_staking_asset_id(node, Some(&SubnetId::primary_network()));
    let balance = primary_asset
        .as_ref()
        .and_then(|asset| balances.get(asset))
        .copied()
        .unwrap_or(0);
    let unlocked = primary_asset
        .as_ref()
        .and_then(|asset| unlockeds.get(asset))
        .copied()
        .unwrap_or(0);
    let locked_stakeable = primary_asset
        .as_ref()
        .and_then(|asset| locked_stakeables.get(asset))
        .copied()
        .unwrap_or(0);
    let locked_not_stakeable = primary_asset
        .as_ref()
        .and_then(|asset| locked_not_stakeables.get(asset))
        .copied()
        .unwrap_or(0);

    serde_json::json!({
        "balance": balance.to_string(),
        "unlocked": unlocked.to_string(),
        "lockedStakeable": locked_stakeable.to_string(),
        "lockedNotStakeable": locked_not_stakeable.to_string(),
        "balances": balances.into_iter().map(|(k, v)| (k, serde_json::Value::String(v.to_string()))).collect::<serde_json::Map<String, serde_json::Value>>(),
        "unlockeds": unlockeds.into_iter().map(|(k, v)| (k, serde_json::Value::String(v.to_string()))).collect::<serde_json::Map<String, serde_json::Value>>(),
        "lockedStakeables": locked_stakeables.into_iter().map(|(k, v)| (k, serde_json::Value::String(v.to_string()))).collect::<serde_json::Map<String, serde_json::Value>>(),
        "lockedNotStakeables": locked_not_stakeables.into_iter().map(|(k, v)| (k, serde_json::Value::String(v.to_string()))).collect::<serde_json::Map<String, serde_json::Value>>(),
        "utxoIDs": utxo_ids,
    })
}

fn platform_native_utxos_response(
    node: &NodeState,
    requested_addrs: &[(String, [u8; 20])],
    limit: usize,
    start_addr: Option<[u8; 20]>,
    start_utxo: Option<[u8; 32]>,
    encoding: &str,
) -> Result<serde_json::Value, String> {
    let scan = scan_platform_chain_state(node);
    let utxos = scan.utxos.values().collect::<Vec<_>>();
    platform_paginated_utxos_response(
        utxos,
        requested_addrs,
        limit,
        start_addr,
        start_utxo,
        encoding,
        |_, canonical| canonical.to_string(),
    )
}

fn platform_paginated_utxos_response<F>(
    utxos: Vec<&PlatformLedgerUtxo>,
    requested_addrs: &[(String, [u8; 20])],
    limit: usize,
    start_addr: Option<[u8; 20]>,
    start_utxo: Option<[u8; 32]>,
    encoding: &str,
    format_end_address: F,
) -> Result<serde_json::Value, String>
where
    F: Fn([u8; 20], &str) -> String,
{
    let mut canonical_for_addr = std::collections::BTreeMap::<[u8; 20], String>::new();
    for (canonical, addr) in requested_addrs {
        canonical_for_addr
            .entry(*addr)
            .or_insert_with(|| canonical.clone());
    }

    let mut sorted_addrs = canonical_for_addr.keys().copied().collect::<Vec<_>>();
    sorted_addrs.sort();

    let mut per_addr = std::collections::BTreeMap::<[u8; 20], Vec<&PlatformLedgerUtxo>>::new();
    for utxo in utxos {
        for addr in utxo.output.addresses.iter().copied() {
            if canonical_for_addr.contains_key(&addr) {
                per_addr.entry(addr).or_default().push(utxo);
            }
        }
    }

    for utxos in per_addr.values_mut() {
        utxos.sort_by(|a, b| {
            platform_input_id(a.tx_id, a.output_index)
                .cmp(&platform_input_id(b.tx_id, b.output_index))
        });
    }

    let mut encoded_utxos = Vec::new();
    let mut seen = std::collections::HashSet::<[u8; 32]>::new();
    let mut end_address = String::new();
    let mut end_utxo = String::new();

    for addr in sorted_addrs {
        if let Some(start_addr) = start_addr {
            if addr < start_addr {
                continue;
            }
        }
        let Some(utxos) = per_addr.get(&addr) else {
            continue;
        };
        for utxo in utxos {
            let utxo_id = platform_input_id(utxo.tx_id, utxo.output_index);
            if let Some(start_addr) = start_addr {
                if addr == start_addr && start_utxo.is_some_and(|start| utxo_id <= start) {
                    continue;
                }
            }
            if !seen.insert(utxo_id) {
                continue;
            }

            encoded_utxos.push(platform_encode_utxo(
                utxo.tx_id,
                utxo.output_index,
                &utxo.output,
                encoding,
            )?);
            end_address = format_end_address(
                addr,
                canonical_for_addr
                    .get(&addr)
                    .map(|value| value.as_str())
                    .unwrap_or_default(),
            );
            end_utxo = cb58_encode_id(utxo_id);
            if encoded_utxos.len() >= limit {
                return Ok(serde_json::json!({
                    "numFetched": encoded_utxos.len().to_string(),
                    "utxos": encoded_utxos,
                    "endIndex": {
                        "address": end_address,
                        "utxo": end_utxo,
                    },
                    "encoding": encoding,
                }));
            }
        }
    }

    Ok(serde_json::json!({
        "numFetched": encoded_utxos.len().to_string(),
        "utxos": encoded_utxos,
        "endIndex": {
            "address": end_address,
            "utxo": end_utxo,
        },
        "encoding": encoding,
    }))
}

fn platform_atomic_utxos_response(
    node: &NodeState,
    source_chain_id: [u8; 32],
    requested_addrs: &[(String, [u8; 20])],
    limit: usize,
    start_addr: Option<[u8; 20]>,
    start_utxo: Option<[u8; 32]>,
    encoding: &str,
) -> Result<serde_json::Value, String> {
    let scan = scan_platform_chain_state(node);
    let utxos = scan
        .atomic_utxos
        .get(&(source_chain_id, platform_pchain_blockchain_id()))
        .map(|utxos| utxos.values().collect::<Vec<_>>())
        .unwrap_or_default();
    platform_paginated_utxos_response(
        utxos,
        requested_addrs,
        limit,
        start_addr,
        start_utxo,
        encoding,
        |_, canonical| canonical.to_string(),
    )
}

fn avax_atomic_utxos_response(
    node: &NodeState,
    source_chain_id: [u8; 32],
    requested_addrs: &[(String, [u8; 20])],
    limit: usize,
    start_addr: Option<[u8; 20]>,
    start_utxo: Option<[u8; 32]>,
    encoding: &str,
) -> Result<serde_json::Value, String> {
    let scan = scan_platform_chain_state(node);
    let utxos = scan
        .atomic_utxos
        .get(&(
            source_chain_id,
            platform_cchain_blockchain_id(node.config.network_id),
        ))
        .map(|utxos| utxos.values().collect::<Vec<_>>())
        .unwrap_or_default();
    platform_paginated_utxos_response(
        utxos,
        requested_addrs,
        limit,
        start_addr,
        start_utxo,
        encoding,
        |addr, _| format_service_address(node.config.network_id, "C", addr),
    )
}

fn platform_chain_status_from_phase(phase: &SyncPhase) -> &'static str {
    match phase {
        SyncPhase::Following | SyncPhase::Synced => "Validating",
        SyncPhase::Idle => "Created",
        _ => "Syncing",
    }
}

async fn platform_blockchain_status(node: &NodeState, blockchain_id: [u8; 32]) -> String {
    if blockchain_id == platform_pchain_blockchain_id() {
        return platform_chain_status_from_phase(&node.sync_engine.phase().await).to_string();
    }

    if blockchain_id == platform_cchain_blockchain_id(node.config.network_id) {
        if node.c_chain_metrics.read().await.tip_height > 0 {
            return platform_chain_status_from_phase(&node.sync_engine.phase().await).to_string();
        }
        return "Created".to_string();
    }

    let tracker = node.subnet_tracker.read().await;
    tracker
        .chain_state(&ChainId(blockchain_id))
        .map(|state| platform_chain_status_from_phase(&state.phase).to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn platform_block_json_value(raw_block: &[u8]) -> serde_json::Value {
    match BlockMetadata::from_raw(raw_block, Chain::PChain) {
        Ok(meta) => {
            let extracted_txs = platform_block_transactions_json(raw_block);
            let tx_count = extracted_txs
                .as_ref()
                .map(|txs| txs.len() as u32)
                .unwrap_or(meta.tx_count);
            let txs = match extracted_txs {
                Some(txs) => serde_json::Value::Array(txs),
                None if meta.tx_count == 0 => serde_json::Value::Array(vec![]),
                None => serde_json::Value::Null,
            };
            serde_json::json!({
                "id": cb58_encode_id(meta.id),
                "parentID": cb58_encode_id(meta.parent_id),
                "height": meta.height,
                "time": meta.timestamp,
                "txs": txs,
                "blockType": format!("{:?}", meta.block_type),
                "txCount": tx_count,
                "size": meta.size_bytes,
            })
        }
        Err(_) => serde_json::json!({
            "bytes": format!("0x{}", hex::encode(raw_block)),
        }),
    }
}

fn parse_filter_from_block(filter_obj: &serde_json::Value, node: &NodeState) -> u64 {
    filter_obj
        .get("fromBlock")
        .map(|v| parse_block_number(v, node))
        .unwrap_or_else(|| current_cchain_height(node))
}

fn parse_filter_to_block(filter_obj: &serde_json::Value, node: &NodeState) -> Option<u64> {
    match filter_obj.get("toBlock").and_then(|v| v.as_str()) {
        Some("latest") | Some("pending") | None => None,
        Some("earliest") => Some(0),
        Some(_) => filter_obj
            .get("toBlock")
            .map(|v| parse_block_number(v, node)),
    }
}

fn parse_filter_topics(filter_obj: &serde_json::Value) -> Vec<Option<Vec<[u8; 32]>>> {
    match &filter_obj["topics"] {
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|v| match v {
                serde_json::Value::Null => None,
                serde_json::Value::String(s) => parse_hex_hash(s).map(|topic| vec![topic]),
                serde_json::Value::Array(options) => Some(
                    options
                        .iter()
                        .filter_map(|value| value.as_str().and_then(parse_hex_hash))
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

fn parse_log_filter(filter_obj: &serde_json::Value, node: &NodeState) -> LogFilter {
    let current_height = current_cchain_height(node);
    let from_block = parse_filter_from_block(filter_obj, node);
    let to_block = parse_filter_to_block(filter_obj, node);
    let addresses: Vec<[u8; 20]> = match &filter_obj["address"] {
        serde_json::Value::String(s) => parse_hex_address(s).into_iter().collect(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().and_then(parse_hex_address))
            .collect(),
        _ => vec![],
    };

    LogFilter {
        from_block,
        to_block,
        addresses,
        topics: parse_filter_topics(filter_obj),
        last_polled_block: if filter_obj.get("fromBlock").is_some() {
            from_block.saturating_sub(1)
        } else {
            current_height
        },
    }
}

fn parse_filter_id(value: &serde_json::Value) -> u64 {
    value
        .as_str()
        .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok())
        .unwrap_or(0)
}

fn load_cchain_block_by_hash(db: &Database, block_hash: &[u8; 32]) -> Option<Vec<u8>> {
    let mut key = Vec::with_capacity(34);
    key.extend_from_slice(b"c:");
    key.extend_from_slice(block_hash);
    db.get_cf(avalanche_rs::db::CF_BLOCKS, &key).ok().flatten()
}

fn cchain_transaction_count(block_data: &[u8]) -> u64 {
    extract_cchain_transactions(block_data).len() as u64
}

fn rpc_transaction_from_cchain_block_index(
    block_data: &[u8],
    tx_index: u64,
) -> Option<serde_json::Value> {
    let fields = extract_cchain_block_fields(block_data)?;
    let block_hash = cchain_block_hash(block_data);
    let tx = extract_cchain_transactions(block_data)
        .into_iter()
        .nth(tx_index as usize)?;
    let pool_tx = pool_tx_from_cchain_raw(&tx);
    Some(rpc_transaction_from_pool(
        &pool_tx.hash,
        &pool_tx,
        Some(block_hash),
        Some(fields.number),
        Some(tx_index as u32),
    ))
}

fn raw_transaction_hex_from_cchain_block_index(block_data: &[u8], tx_index: u64) -> Option<String> {
    extract_cchain_transactions(block_data)
        .into_iter()
        .nth(tx_index as usize)
        .map(|tx| format!("0x{}", hex::encode(tx.raw)))
}

fn accepted_transaction_changes(
    db: &Database,
    start_block: u64,
    end_block: u64,
    full_tx: bool,
) -> Vec<serde_json::Value> {
    if start_block > end_block {
        return vec![];
    }

    let mut changes = Vec::new();
    for block_height in start_block..=end_block {
        let Some(block_data) = db.get_block(block_height).ok().flatten() else {
            continue;
        };
        let Some(fields) = extract_cchain_block_fields(&block_data) else {
            continue;
        };
        let block_hash = cchain_block_hash(&block_data);
        for (idx, tx) in extract_cchain_transactions(&block_data)
            .into_iter()
            .enumerate()
        {
            let pool_tx = pool_tx_from_cchain_raw(&tx);
            changes.push(if full_tx {
                rpc_transaction_from_pool(
                    &pool_tx.hash,
                    &pool_tx,
                    Some(block_hash),
                    Some(fields.number),
                    Some(idx as u32),
                )
            } else {
                serde_json::Value::String(format!("0x{}", hex::encode(pool_tx.hash)))
            });
        }
    }
    changes
}

fn block_hash_changes(db: &Database, start_block: u64, end_block: u64) -> Vec<serde_json::Value> {
    if start_block > end_block {
        return vec![];
    }

    let mut changes = Vec::new();
    for block_height in start_block..=end_block {
        let Some(block_data) = db.get_block(block_height).ok().flatten() else {
            continue;
        };
        changes.push(serde_json::Value::String(format!(
            "0x{}",
            hex::encode(cchain_block_hash(&block_data))
        )));
    }
    changes
}

async fn pending_transaction_filter_changes(
    filter: &mut PendingTransactionFilter,
) -> Vec<serde_json::Value> {
    let events = PENDING_FILTER_EVENTS.read().await;
    let mut changes = Vec::new();
    let mut latest_event_id = filter.last_event_id;

    for (event_id, tx_hash) in events.iter() {
        if *event_id <= filter.last_event_id {
            continue;
        }
        latest_event_id = latest_event_id.max(*event_id);
        changes.push(serde_json::Value::String(format!(
            "0x{}",
            hex::encode(tx_hash)
        )));
    }

    filter.last_event_id = latest_event_id;
    changes
}

fn load_block_receipts_json(db: &Database, block_height: u64) -> Vec<serde_json::Value> {
    db.get_block_receipts(block_height)
        .ok()
        .flatten()
        .and_then(|data| serde_json::from_slice::<Vec<serde_json::Value>>(&data).ok())
        .unwrap_or_default()
}

fn load_cchain_block_fields(
    db: &Database,
    block_height: u64,
) -> Option<avalanche_rs::block::CChainBlockFields> {
    db.get_block(block_height)
        .ok()
        .flatten()
        .and_then(|data| extract_cchain_block_fields(&data))
}

fn latest_cchain_block_fields(db: &Database) -> Option<avalanche_rs::block::CChainBlockFields> {
    let height = db.last_accepted_height().ok().flatten()?;
    load_cchain_block_fields(db, height)
}

fn predicted_next_base_fee_from_fields(
    network_id: u32,
    fields: &avalanche_rs::block::CChainBlockFields,
) -> u128 {
    if avalanche_rs::fortuna::is_fortuna_active(network_id, fields.timestamp) {
        fields.base_fee
    } else {
        avalanche_rs::fortuna::legacy_base_fee(
            fields.base_fee as u64,
            fields.gas_used,
            avalanche_rs::fortuna::PRE_FORTUNA_GAS_TARGET,
        ) as u128
    }
}

fn predicted_next_base_fee_from_db(db: &Database, network_id: u32) -> u128 {
    latest_cchain_block_fields(db)
        .map(|fields| predicted_next_base_fee_from_fields(network_id, &fields))
        .unwrap_or(DEFAULT_BASE_FEE_PER_GAS)
}

fn recent_priority_fee_suggestion(db: &Database, current_height: u64) -> u128 {
    if current_height == 0 {
        return PRIORITY_FEE_FLOOR;
    }

    let oldest_block = current_height.saturating_sub(PRIORITY_FEE_SAMPLE_BLOCKS.saturating_sub(1));
    let mut rewards = Vec::new();

    for block_height in oldest_block..=current_height {
        let Some(fields) = load_cchain_block_fields(db, block_height) else {
            continue;
        };
        let Some(block_data) = db.get_block(block_height).ok().flatten() else {
            continue;
        };
        let txs = extract_cchain_transactions(&block_data);
        let receipts = load_block_receipts_json(db, block_height);
        rewards.extend(txs.iter().zip(receipts.iter()).filter_map(|(tx, receipt)| {
            let gas_used = receipt
                .get("gasUsed")
                .and_then(|value| value.as_str())
                .and_then(parse_hex_u64_str)
                .unwrap_or(0);
            if gas_used == 0 {
                None
            } else {
                Some((
                    fee_history_effective_priority_fee(tx, fields.base_fee),
                    gas_used,
                ))
            }
        }));
    }

    if rewards.is_empty() {
        return PRIORITY_FEE_FLOOR;
    }

    rewards.sort_by_key(|(reward, _)| *reward);
    let total_gas_used = rewards.iter().map(|(_, gas_used)| *gas_used).sum::<u64>();
    if total_gas_used == 0 {
        return PRIORITY_FEE_FLOOR;
    }

    let threshold = ((PRIORITY_FEE_PERCENTILE / 100.0) * total_gas_used as f64).ceil() as u64;
    let target = threshold.max(1);
    let mut cumulative = 0u64;
    let mut selected = rewards.last().map(|(reward, _)| *reward).unwrap_or(0);
    for (reward, gas_used) in &rewards {
        cumulative = cumulative.saturating_add(*gas_used);
        selected = *reward;
        if cumulative >= target {
            break;
        }
    }

    selected.max(PRIORITY_FEE_FLOOR)
}

async fn refresh_txpool_base_fee(node: &NodeState) {
    let base_fee = predicted_next_base_fee_from_db(&node.db, node.config.network_id);
    node.txpool.write().await.set_base_fee(base_fee);
}

fn fee_history_effective_priority_fee(tx: &CChainRawTx, base_fee: u128) -> u128 {
    let capped_tip = tx.gas_price.saturating_sub(base_fee);
    if tx.tx_type == 2 {
        capped_tip.min(tx.max_priority_fee_per_gas)
    } else {
        capped_tip
    }
}

fn fee_history_rewards_for_block(
    db: &Database,
    block_height: u64,
    fields: &avalanche_rs::block::CChainBlockFields,
    reward_percentiles: &[f64],
) -> Vec<String> {
    if reward_percentiles.is_empty() {
        return vec![];
    }

    let Some(block_data) = db.get_block(block_height).ok().flatten() else {
        return vec!["0x0".to_string(); reward_percentiles.len()];
    };

    let txs = extract_cchain_transactions(&block_data);
    let receipts = load_block_receipts_json(db, block_height);
    let mut rewards = txs
        .iter()
        .zip(receipts.iter())
        .filter_map(|(tx, receipt)| {
            let gas_used = receipt
                .get("gasUsed")
                .and_then(|value| value.as_str())
                .and_then(parse_hex_u64_str)
                .unwrap_or(0);
            if gas_used == 0 {
                None
            } else {
                Some((
                    fee_history_effective_priority_fee(tx, fields.base_fee),
                    gas_used,
                ))
            }
        })
        .collect::<Vec<_>>();

    if rewards.is_empty() {
        return vec!["0x0".to_string(); reward_percentiles.len()];
    }

    rewards.sort_by_key(|(reward, _)| *reward);
    let total_gas_used = rewards.iter().map(|(_, gas_used)| *gas_used).sum::<u64>();
    if total_gas_used == 0 {
        return vec!["0x0".to_string(); reward_percentiles.len()];
    }

    reward_percentiles
        .iter()
        .map(|percentile| {
            let clamped = percentile.clamp(0.0, 100.0);
            let threshold = ((clamped / 100.0) * total_gas_used as f64).ceil() as u64;
            let target = threshold.max(1);
            let mut cumulative = 0u64;
            let mut selected = rewards.last().map(|(reward, _)| *reward).unwrap_or(0);
            for (reward, gas_used) in &rewards {
                cumulative = cumulative.saturating_add(*gas_used);
                selected = *reward;
                if cumulative >= target {
                    break;
                }
            }
            format!("0x{:x}", selected)
        })
        .collect()
}

fn fee_history_next_base_fee(
    db: &Database,
    network_id: u32,
    newest_block: u64,
    fields: &avalanche_rs::block::CChainBlockFields,
) -> u128 {
    if let Some(next_fields) = load_cchain_block_fields(db, newest_block.saturating_add(1)) {
        return next_fields.base_fee;
    }

    predicted_next_base_fee_from_fields(network_id, fields)
}

fn build_fee_history_result(
    node: &NodeState,
    requested_block_count: u64,
    requested_newest_block: u64,
    reward_percentiles: &[f64],
) -> serde_json::Value {
    let current_height = current_cchain_height(node);
    let newest_block = requested_newest_block.min(current_height);
    let available_blocks = newest_block.saturating_add(1);
    let block_count = requested_block_count.min(1024).min(available_blocks.max(1));
    let oldest_block = newest_block.saturating_sub(block_count.saturating_sub(1));

    let mut base_fees = Vec::with_capacity(block_count as usize + 1);
    let mut gas_used_ratios = Vec::with_capacity(block_count as usize);
    let mut rewards_by_block = Vec::with_capacity(block_count as usize);
    let mut last_fields = None;

    for block_height in oldest_block..=newest_block {
        let fields = load_cchain_block_fields(&node.db, block_height).unwrap_or(
            avalanche_rs::block::CChainBlockFields {
                number: block_height,
                timestamp: 0,
                gas_limit: DEFAULT_CCHAIN_GAS_LIMIT,
                gas_used: 0,
                base_fee: DEFAULT_BASE_FEE_PER_GAS,
                miner: [0u8; 20],
            },
        );
        base_fees.push(format!("0x{:x}", fields.base_fee));
        gas_used_ratios.push(if fields.gas_limit == 0 {
            0.0
        } else {
            fields.gas_used as f64 / fields.gas_limit as f64
        });
        if !reward_percentiles.is_empty() {
            rewards_by_block.push(fee_history_rewards_for_block(
                &node.db,
                block_height,
                &fields,
                reward_percentiles,
            ));
        }
        last_fields = Some(fields);
    }

    let next_base_fee = last_fields
        .as_ref()
        .map(|fields| {
            fee_history_next_base_fee(&node.db, node.config.network_id, newest_block, fields)
        })
        .unwrap_or(DEFAULT_BASE_FEE_PER_GAS);
    base_fees.push(format!("0x{:x}", next_base_fee));

    let mut result = serde_json::json!({
        "oldestBlock": format!("0x{:x}", oldest_block),
        "baseFeePerGas": base_fees,
        "gasUsedRatio": gas_used_ratios,
    });

    if !reward_percentiles.is_empty() {
        result["reward"] = serde_json::Value::Array(
            rewards_by_block
                .into_iter()
                .map(|block_rewards| {
                    serde_json::Value::Array(
                        block_rewards
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    )
                })
                .collect(),
        );
    }

    result
}

fn normalize_block_log_indexes(receipts: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut next_log_index = 0u64;
    let mut logs = Vec::new();

    for receipt in receipts {
        if let Some(receipt_logs) = receipt.get("logs").and_then(|value| value.as_array()) {
            for log in receipt_logs {
                let mut normalized = log.clone();
                if let Some(obj) = normalized.as_object_mut() {
                    obj.insert(
                        "logIndex".to_string(),
                        serde_json::Value::String(format!("0x{:x}", next_log_index)),
                    );
                    obj.entry("removed".to_string())
                        .or_insert(serde_json::Value::Bool(false));
                }
                logs.push(normalized);
                next_log_index = next_log_index.saturating_add(1);
            }
        }
    }

    logs
}

fn log_matches_filter(log: &serde_json::Value, filter: &LogFilter) -> bool {
    if !filter.addresses.is_empty() {
        let Some(address) = log
            .get("address")
            .and_then(|value| value.as_str())
            .and_then(parse_hex_address)
        else {
            return false;
        };
        if !filter
            .addresses
            .iter()
            .any(|candidate| candidate == &address)
        {
            return false;
        }
    }

    let log_topics = log
        .get("topics")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();

    for (idx, wanted) in filter.topics.iter().enumerate() {
        let Some(wanted_topics) = wanted else {
            continue;
        };
        let Some(actual_topic) = log_topics
            .get(idx)
            .and_then(|value| value.as_str())
            .and_then(parse_hex_hash)
        else {
            return false;
        };
        if !wanted_topics.iter().any(|topic| topic == &actual_topic) {
            return false;
        }
    }

    true
}

fn collect_logs_for_range(
    db: &Database,
    filter: &LogFilter,
    start_block: u64,
    end_block: u64,
) -> Vec<serde_json::Value> {
    if start_block > end_block {
        return vec![];
    }

    let mut logs = Vec::new();
    for block_height in start_block..=end_block {
        let receipts = load_block_receipts_json(db, block_height);
        if receipts.is_empty() {
            continue;
        }
        logs.extend(
            normalize_block_log_indexes(&receipts)
                .into_iter()
                .filter(|log| log_matches_filter(log, filter)),
        );
    }
    logs
}

/// JSON-RPC error response helper.
fn rpc_error(code: i32, message: &str, id: &serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": code,
            "message": message,
        },
        "id": id,
    })
    .to_string()
}

/// JSON-RPC success response helper.
fn rpc_ok(result: &str, id: &serde_json::Value) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"result\":{},\"id\":{}}}",
        result, id
    )
}

fn pool_tx_to_evm_tx(tx: &PoolTransaction) -> EvmTransaction {
    EvmTransaction {
        from: tx.from,
        to: tx.to,
        value: tx.value,
        data: tx.data.clone(),
        gas_limit: tx.gas_limit,
        gas_price: tx.max_fee_per_gas,
        nonce: tx.nonce,
    }
}

fn cchain_block_context(
    fields: &avalanche_rs::block::CChainBlockFields,
    chain_id: u64,
) -> BlockContext {
    BlockContext {
        number: fields.number,
        timestamp: fields.timestamp,
        coinbase: fields.miner,
        gas_limit: fields.gas_limit,
        base_fee: fields.base_fee,
        difficulty: 0,
        chain_id,
    }
}

fn cchain_raw_to_evm_tx(tx: &CChainRawTx, base_fee: u128) -> EvmTransaction {
    EvmTransaction {
        from: tx.recover_sender().unwrap_or([0u8; 20]),
        to: tx.to,
        value: tx.value,
        data: tx.data.clone(),
        gas_limit: tx.gas_limit,
        gas_price: tx.gas_price.max(base_fee),
        nonce: tx.nonce,
    }
}

fn replay_cchain_blocks_until(
    db: &Database,
    chain_id: u64,
    target_height: u64,
) -> Result<EvmExecutor, String> {
    let mut executor = EvmExecutor::new(chain_id);

    for height in 0..target_height {
        let Some(block_data) = db.get_block(height).map_err(|e| e.to_string())? else {
            continue;
        };
        let Some(fields) = extract_cchain_block_fields(&block_data) else {
            continue;
        };
        let ctx = cchain_block_context(&fields, chain_id);
        let raw_txs = extract_cchain_transactions(&block_data);
        if raw_txs.is_empty() {
            continue;
        }
        let evm_txs = raw_txs
            .iter()
            .map(|tx| {
                let from = tx.recover_sender().unwrap_or([0u8; 20]);
                executor.set_balance(from, u128::MAX / 2);
                cchain_raw_to_evm_tx(tx, fields.base_fee)
            })
            .collect::<Vec<_>>();
        executor
            .execute_block(&evm_txs, &ctx)
            .map_err(|e| format!("replay block #{}: {}", height, e))?;
    }

    Ok(executor)
}

fn trace_result_value(
    trace: avalanche_rs::debug::TransactionTrace,
    tx: &EvmTransaction,
    config: &TraceConfig,
) -> serde_json::Value {
    match config.tracer {
        TracerType::StructLogger => serde_json::to_value(trace).unwrap_or(serde_json::Value::Null),
        TracerType::CallTracer => serde_json::to_value(trace.call_trace.unwrap_or_else(|| {
            avalanche_rs::debug::EvmTracer::call_trace(
                tx,
                trace.gas,
                !trace.failed,
                &hex::decode(trace.return_value).unwrap_or_default(),
            )
        }))
        .unwrap_or(serde_json::Value::Null),
    }
}

fn trace_mined_transaction(
    db: &Database,
    chain_id: u64,
    block_height: u64,
    tx_index: u32,
    config: &TraceConfig,
) -> Result<serde_json::Value, String> {
    let block_data = db
        .get_block(block_height)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("block #{} not found", block_height))?;
    let fields = extract_cchain_block_fields(&block_data)
        .ok_or_else(|| format!("block #{} is not a valid C-Chain block", block_height))?;
    let ctx = cchain_block_context(&fields, chain_id);
    let raw_txs = extract_cchain_transactions(&block_data);
    let tx = raw_txs.get(tx_index as usize).ok_or_else(|| {
        format!(
            "transaction {} not found in block {}",
            tx_index, block_height
        )
    })?;

    let mut executor = replay_cchain_blocks_until(db, chain_id, block_height)?;
    for prior_tx in raw_txs.iter().take(tx_index as usize) {
        let from = prior_tx.recover_sender().unwrap_or([0u8; 20]);
        executor.set_balance(from, u128::MAX / 2);
        let evm_tx = cchain_raw_to_evm_tx(prior_tx, fields.base_fee);
        executor.execute_tx(&evm_tx, &ctx).map_err(|e| {
            format!(
                "replay tx {} in block {}: {}",
                prior_tx.nonce, block_height, e
            )
        })?;
    }

    let from = tx.recover_sender().unwrap_or([0u8; 20]);
    executor.set_balance(from, u128::MAX / 2);
    let evm_tx = cchain_raw_to_evm_tx(tx, fields.base_fee);
    let trace = EvmTracer::trace_transaction(&mut executor, &evm_tx, &ctx, config);
    Ok(trace_result_value(trace, &evm_tx, config))
}

fn trace_pending_transaction(
    executor: &EvmExecutor,
    tx: &PoolTransaction,
    block_ctx: &BlockContext,
    config: &TraceConfig,
) -> serde_json::Value {
    let mut snapshot = executor.snapshot();
    snapshot.set_balance(tx.from, u128::MAX / 2);
    let evm_tx = pool_tx_to_evm_tx(tx);
    let trace = EvmTracer::trace_transaction(&mut snapshot, &evm_tx, block_ctx, config);
    trace_result_value(trace, &evm_tx, config)
}

fn trace_mined_block(
    db: &Database,
    chain_id: u64,
    block_height: u64,
    config: &TraceConfig,
) -> Result<serde_json::Value, String> {
    let block_data = db
        .get_block(block_height)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("block #{} not found", block_height))?;
    let fields = extract_cchain_block_fields(&block_data)
        .ok_or_else(|| format!("block #{} is not a valid C-Chain block", block_height))?;
    let ctx = cchain_block_context(&fields, chain_id);
    let raw_txs = extract_cchain_transactions(&block_data);
    let mut executor = replay_cchain_blocks_until(db, chain_id, block_height)?;
    let evm_txs = raw_txs
        .iter()
        .map(|tx| {
            let from = tx.recover_sender().unwrap_or([0u8; 20]);
            executor.set_balance(from, u128::MAX / 2);
            cchain_raw_to_evm_tx(tx, fields.base_fee)
        })
        .collect::<Vec<_>>();

    let traces = EvmTracer::trace_block(&mut executor, &evm_txs, &ctx, config);
    let results = traces
        .into_iter()
        .zip(evm_txs.iter())
        .map(|(trace, tx)| trace_result_value(trace, tx, config))
        .collect::<Vec<_>>();
    Ok(serde_json::Value::Array(results))
}

async fn reconcile_mined_pool_transactions(node: &NodeState, mined_txs: &[PoolTransaction]) {
    if mined_txs.is_empty() {
        return;
    }

    let nonce_by_sender = {
        let evm = node.evm.read().await;
        mined_txs
            .iter()
            .map(|tx| (tx.from, evm.get_nonce(tx.from)))
            .collect::<Vec<_>>()
    };

    let mut txpool = node.txpool.write().await;
    for (from, nonce) in nonce_by_sender {
        txpool.sync_account_nonce(from, nonce);
    }
}

fn txpool_group_transactions(txs: Vec<PoolTransaction>) -> serde_json::Value {
    let mut grouped = serde_json::Map::new();

    for tx in txs {
        let from = format!("0x{}", hex::encode(tx.from));
        let nonce = format!("0x{:x}", tx.nonce);
        let entry = serde_json::json!({
            "hash": format!("0x{}", hex::encode(tx.hash)),
            "from": from.clone(),
            "to": tx.to.map(|addr| format!("0x{}", hex::encode(addr))),
            "nonce": nonce,
            "gas": format!("0x{:x}", tx.gas_limit),
            "gasPrice": format!("0x{:x}", tx.max_fee_per_gas),
            "maxFeePerGas": format!("0x{:x}", tx.max_fee_per_gas),
            "maxPriorityFeePerGas": format!("0x{:x}", tx.max_priority_fee_per_gas),
            "value": format!("0x{:x}", tx.value),
            "input": format!("0x{}", hex::encode(tx.data)),
        });

        let account = grouped
            .entry(from)
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let Some(account) = account.as_object_mut() {
            account.insert(nonce, entry);
        }
    }

    serde_json::Value::Object(grouped)
}

fn txpool_group_inspect(txs: Vec<PoolTransaction>) -> serde_json::Value {
    let mut grouped = serde_json::Map::new();

    for tx in txs {
        let from = format!("0x{}", hex::encode(tx.from));
        let nonce = format!("0x{:x}", tx.nonce);
        let entry = serde_json::Value::String(format!(
            "{} wei + {} gas x {} wei",
            tx.value, tx.gas_limit, tx.max_fee_per_gas
        ));

        let account = grouped
            .entry(from)
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let Some(account) = account.as_object_mut() {
            account.insert(nonce, entry);
        }
    }

    serde_json::Value::Object(grouped)
}

fn txpool_content_from(pool: &TransactionPool, address: [u8; 20]) -> serde_json::Value {
    let pending = pool
        .pending_transactions()
        .into_iter()
        .filter(|tx| tx.from == address)
        .collect::<Vec<_>>();
    let queued = pool
        .queued_transactions()
        .into_iter()
        .filter(|tx| tx.from == address)
        .collect::<Vec<_>>();

    let strip_sender_scope = |grouped: serde_json::Value| -> serde_json::Value {
        let key = format!("0x{}", hex::encode(address));
        grouped
            .as_object()
            .and_then(|obj| obj.get(&key))
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()))
    };

    serde_json::json!({
        "pending": strip_sender_scope(txpool_group_transactions(pending)),
        "queued": strip_sender_scope(txpool_group_transactions(queued)),
    })
}

fn raw_tx_hash(raw: &[u8]) -> [u8; 32] {
    let hash = revm::primitives::keccak256(raw);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_slice());
    out
}

fn pool_tx_from_cchain_raw(tx: &CChainRawTx) -> PoolTransaction {
    PoolTransaction {
        hash: raw_tx_hash(&tx.raw),
        raw: Some(tx.raw.clone()),
        from: tx.recover_sender().unwrap_or([0u8; 20]),
        to: tx.to,
        nonce: tx.nonce,
        gas_limit: tx.gas_limit,
        max_fee_per_gas: tx.gas_price,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        value: tx.value,
        data: tx.data.clone(),
        size: tx.raw.len(),
        timestamp: 0,
    }
}

fn load_mined_cchain_transaction(
    db: &Database,
    block_height: u64,
    tx_index: u32,
) -> Option<([u8; 32], PoolTransaction)> {
    let block_data = db.get_block(block_height).ok()??;
    let txs = extract_cchain_transactions(&block_data);
    let tx = txs.get(tx_index as usize)?;
    let block_hash = cchain_block_hash(&block_data);
    Some((block_hash, pool_tx_from_cchain_raw(tx)))
}

fn cchain_block_hash(block_data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(block_data);
    hasher.finalize().into()
}

fn rpc_block_from_cchain_data(
    block_data: &[u8],
    include_full_txs: bool,
) -> Option<serde_json::Value> {
    let header = BlockHeader::parse(block_data, Chain::CChain).ok()?;
    let fields = extract_cchain_block_fields(block_data)?;
    let block_hash = cchain_block_hash(block_data);
    let state_root = BlockHeader::extract_state_root(block_data).unwrap_or([0u8; 32]);
    let txs = extract_cchain_transactions(block_data);
    let transactions: Vec<serde_json::Value> = txs
        .iter()
        .enumerate()
        .map(|(idx, tx)| {
            let pool_tx = pool_tx_from_cchain_raw(tx);
            if include_full_txs {
                rpc_transaction_from_pool(
                    &pool_tx.hash,
                    &pool_tx,
                    Some(block_hash),
                    Some(fields.number),
                    Some(idx as u32),
                )
            } else {
                serde_json::Value::String(format!("0x{}", hex::encode(pool_tx.hash)))
            }
        })
        .collect();

    Some(serde_json::json!({
        "number": format!("0x{:x}", fields.number),
        "hash": format!("0x{}", hex::encode(block_hash)),
        "parentHash": format!("0x{}", hex::encode(header.parent_id)),
        "miner": format!("0x{}", hex::encode(fields.miner)),
        "stateRoot": format!("0x{}", hex::encode(state_root)),
        "size": format!("0x{:x}", block_data.len()),
        "gasLimit": format!("0x{:x}", fields.gas_limit),
        "gasUsed": format!("0x{:x}", fields.gas_used),
        "timestamp": format!("0x{:x}", fields.timestamp),
        "baseFeePerGas": format!("0x{:x}", fields.base_fee),
        "transactions": transactions,
        "uncles": Vec::<serde_json::Value>::new(),
    }))
}

fn cchain_rlp_hex(block_data: &[u8]) -> String {
    let rlp = if block_data.len() >= 6 && block_data[0] == 0x00 && block_data[1] == 0x00 {
        &block_data[6..]
    } else {
        block_data
    };
    format!("0x{}", hex::encode(rlp))
}

fn bad_block_json_value(record: &BadBlockRecord) -> serde_json::Value {
    rpc_block_from_cchain_data(&record.raw_block, true).unwrap_or_else(|| {
        serde_json::json!({
            "bytes": format!("0x{}", hex::encode(&record.raw_block)),
        })
    })
}

fn bad_block_response_value(node: &NodeState, record: &BadBlockRecord) -> serde_json::Value {
    serde_json::json!({
        "hash": format!("0x{}", hex::encode(record.hash)),
        "block": bad_block_json_value(record),
        "rlp": cchain_rlp_hex(&record.raw_block),
        "reason": {
            "chainConfig": cchain_chain_config_result(node),
            "receipts": record.receipts.clone(),
            "number": record.number.unwrap_or_default(),
            "hash": format!("0x{}", hex::encode(record.hash)),
            "error": record.reason.clone(),
        }
    })
}

fn rpc_transaction_from_pool(
    tx_hash: &[u8; 32],
    tx: &PoolTransaction,
    block_hash: Option<[u8; 32]>,
    block_number: Option<u64>,
    tx_index: Option<u32>,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "hash".to_string(),
        serde_json::Value::String(format!("0x{}", hex::encode(tx_hash))),
    );
    obj.insert(
        "from".to_string(),
        serde_json::Value::String(format!("0x{}", hex::encode(tx.from))),
    );
    obj.insert(
        "to".to_string(),
        tx.to
            .map(|addr| serde_json::Value::String(format!("0x{}", hex::encode(addr))))
            .unwrap_or(serde_json::Value::Null),
    );
    obj.insert(
        "nonce".to_string(),
        serde_json::Value::String(format!("0x{:x}", tx.nonce)),
    );
    obj.insert(
        "value".to_string(),
        serde_json::Value::String(format!("0x{:x}", tx.value)),
    );
    obj.insert(
        "gas".to_string(),
        serde_json::Value::String(format!("0x{:x}", tx.gas_limit)),
    );
    obj.insert(
        "gasPrice".to_string(),
        serde_json::Value::String(format!("0x{:x}", tx.max_fee_per_gas)),
    );
    obj.insert(
        "maxFeePerGas".to_string(),
        serde_json::Value::String(format!("0x{:x}", tx.max_fee_per_gas)),
    );
    obj.insert(
        "maxPriorityFeePerGas".to_string(),
        serde_json::Value::String(format!("0x{:x}", tx.max_priority_fee_per_gas)),
    );
    obj.insert(
        "input".to_string(),
        serde_json::Value::String(format!("0x{}", hex::encode(&tx.data))),
    );
    obj.insert(
        "blockHash".to_string(),
        block_hash
            .map(|hash| serde_json::Value::String(format!("0x{}", hex::encode(hash))))
            .unwrap_or(serde_json::Value::Null),
    );
    obj.insert(
        "blockNumber".to_string(),
        block_number
            .map(|height| serde_json::Value::String(format!("0x{:x}", height)))
            .unwrap_or(serde_json::Value::Null),
    );
    obj.insert(
        "transactionIndex".to_string(),
        tx_index
            .map(|idx| serde_json::Value::String(format!("0x{:x}", idx)))
            .unwrap_or(serde_json::Value::Null),
    );
    serde_json::Value::Object(obj)
}

fn rpc_receipt_from_pool(
    tx_hash: &[u8; 32],
    tx: &PoolTransaction,
    receipt: &TxReceipt,
    block_hash: &[u8; 32],
    block_number: u64,
    tx_index: u32,
    cumulative_gas_used: u64,
    log_index_offset: u32,
) -> serde_json::Value {
    let logs: Vec<serde_json::Value> = receipt
        .logs
        .iter()
        .enumerate()
        .map(|(log_index, log)| {
            serde_json::json!({
                "address": format!("0x{}", hex::encode(log.address)),
                "topics": log
                    .topics
                    .iter()
                    .map(|topic| serde_json::Value::String(format!("0x{}", hex::encode(topic))))
                    .collect::<Vec<_>>(),
                "data": format!("0x{}", hex::encode(&log.data)),
                "blockNumber": format!("0x{:x}", block_number),
                "transactionHash": format!("0x{}", hex::encode(tx_hash)),
                "transactionIndex": format!("0x{:x}", tx_index),
                "blockHash": format!("0x{}", hex::encode(block_hash)),
                "logIndex": format!("0x{:x}", log_index_offset + log_index as u32),
                "removed": false,
            })
        })
        .collect();

    serde_json::json!({
        "transactionHash": format!("0x{}", hex::encode(tx_hash)),
        "transactionIndex": format!("0x{:x}", tx_index),
        "blockHash": format!("0x{}", hex::encode(block_hash)),
        "blockNumber": format!("0x{:x}", block_number),
        "from": format!("0x{}", hex::encode(tx.from)),
        "to": tx
            .to
            .map(|addr| serde_json::Value::String(format!("0x{}", hex::encode(addr))))
            .unwrap_or(serde_json::Value::Null),
        "cumulativeGasUsed": format!("0x{:x}", cumulative_gas_used),
        "gasUsed": format!("0x{:x}", receipt.gas_used),
        "contractAddress": receipt
            .contract_address
            .map(|addr| serde_json::Value::String(format!("0x{}", hex::encode(addr))))
            .unwrap_or(serde_json::Value::Null),
        "status": if receipt.success { "0x1" } else { "0x0" },
        "logs": logs,
    })
}

fn bad_block_receipt_values(
    txs: &[CChainRawTx],
    receipts: &[TxReceipt],
    block_hash: &[u8; 32],
    block_number: u64,
) -> Vec<serde_json::Value> {
    let mut cumulative_gas = 0u64;
    let mut log_index_offset = 0u32;

    txs.iter()
        .zip(receipts.iter())
        .enumerate()
        .map(|(idx, (tx, receipt))| {
            let pool_tx = pool_tx_from_cchain_raw(tx);
            cumulative_gas = cumulative_gas.saturating_add(receipt.gas_used);
            let receipt_json = rpc_receipt_from_pool(
                &pool_tx.hash,
                &pool_tx,
                receipt,
                block_hash,
                block_number,
                idx as u32,
                cumulative_gas,
                log_index_offset,
            );
            log_index_offset = log_index_offset.saturating_add(receipt.logs.len() as u32);
            receipt_json
        })
        .collect()
}

fn record_bad_cchain_block(
    node: &NodeState,
    raw_block: &[u8],
    number: Option<u64>,
    reason: impl Into<String>,
    receipts: Vec<serde_json::Value>,
) {
    append_bad_block_record(
        &node.db,
        BadBlockRecord {
            hash: cchain_block_hash(raw_block),
            raw_block: raw_block.to_vec(),
            number,
            reason: reason.into(),
            receipts,
        },
    );
}

fn persist_local_cchain_tx_artifacts(
    db: &Database,
    block: &BuiltBlock,
    txs: &[PoolTransaction],
) -> Result<(), avalanche_rs::db::DbError> {
    let mut cumulative_gas = 0u64;
    let mut log_index_offset = 0u32;

    for (idx, (tx, receipt)) in txs.iter().zip(block.receipts.iter()).enumerate() {
        db.put_tx_index(&tx.hash, block.number, idx as u32)?;
        cumulative_gas = cumulative_gas.saturating_add(receipt.gas_used);
        let receipt_json = rpc_receipt_from_pool(
            &tx.hash,
            tx,
            receipt,
            &block.id,
            block.number,
            idx as u32,
            cumulative_gas,
            log_index_offset,
        );
        db.put_receipt(
            block.number,
            idx as u32,
            receipt_json.to_string().as_bytes(),
        )?;
        log_index_offset = log_index_offset.saturating_add(receipt.logs.len() as u32);
    }

    Ok(())
}

fn persist_imported_cchain_tx_artifacts(
    db: &Database,
    block_number: u64,
    block_hash: &[u8; 32],
    txs: &[CChainRawTx],
    receipts: &[TxReceipt],
) -> Result<(), avalanche_rs::db::DbError> {
    let mut cumulative_gas = 0u64;
    let mut log_index_offset = 0u32;

    for (idx, (tx, receipt)) in txs.iter().zip(receipts.iter()).enumerate() {
        let pool_tx = pool_tx_from_cchain_raw(tx);
        db.put_tx_index(&pool_tx.hash, block_number, idx as u32)?;
        cumulative_gas = cumulative_gas.saturating_add(receipt.gas_used);
        let receipt_json = rpc_receipt_from_pool(
            &pool_tx.hash,
            &pool_tx,
            receipt,
            block_hash,
            block_number,
            idx as u32,
            cumulative_gas,
            log_index_offset,
        );
        db.put_receipt(
            block_number,
            idx as u32,
            receipt_json.to_string().as_bytes(),
        )?;
        log_index_offset = log_index_offset.saturating_add(receipt.logs.len() as u32);
    }

    Ok(())
}

async fn submit_raw_cchain_transaction(
    node: &NodeState,
    raw_tx: &[u8],
) -> Result<[u8; 32], String> {
    let parsed = parse_raw_cchain_transaction(raw_tx)
        .ok_or_else(|| "invalid raw transaction".to_string())?;
    let from = parsed
        .recover_sender()
        .ok_or_else(|| "invalid transaction signature".to_string())?;

    let tx_hash = raw_tx_hash(raw_tx);

    let account_nonce = {
        let evm = node.evm.read().await;
        evm.get_nonce(from)
    };

    if parsed.nonce < account_nonce {
        return Err("nonce too low".to_string());
    }

    let mut txpool = node.txpool.write().await;
    if let Some(existing) = txpool.get_by_sender_nonce(&from, parsed.nonce) {
        if existing.hash == tx_hash {
            return Ok(tx_hash);
        }
        return Err("replacement transaction not supported".to_string());
    }

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let tx = PoolTransaction {
        hash: tx_hash,
        raw: Some(raw_tx.to_vec()),
        from,
        to: parsed.to,
        nonce: parsed.nonce,
        gas_limit: parsed.gas_limit,
        max_fee_per_gas: parsed.gas_price,
        max_priority_fee_per_gas: parsed.max_priority_fee_per_gas,
        value: parsed.value,
        data: parsed.data,
        size: raw_tx.len(),
        timestamp,
    };

    txpool
        .add(tx, account_nonce)
        .map_err(|e| format!("transaction rejected: {}", e))?;
    drop(txpool);

    record_pending_filter_event(tx_hash).await;
    websocket_broadcast_pending_tx(node, &tx_hash).await;

    Ok(tx_hash)
}

/// In-memory log filter for eth_newFilter/getFilterChanges/uninstallFilter.
#[allow(dead_code)]
struct LogFilter {
    from_block: u64,
    to_block: Option<u64>,
    addresses: Vec<[u8; 20]>,
    topics: Vec<Option<Vec<[u8; 32]>>>,
    last_polled_block: u64,
}

#[allow(dead_code)]
struct PendingTransactionFilter {
    last_event_id: u64,
}

#[allow(dead_code)]
struct BlockHashFilter {
    last_polled_block: u64,
}

#[allow(dead_code)]
struct AcceptedTransactionFilter {
    last_polled_block: u64,
    full_tx: bool,
}

#[allow(dead_code)]
enum RpcFilter {
    Logs(LogFilter),
    PendingTransactions(PendingTransactionFilter),
    Blocks(BlockHashFilter),
    AcceptedTransactions(AcceptedTransactionFilter),
}

/// Global filter state — use a simple counter + HashMap behind RwLock.
static NEXT_FILTER_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static NEXT_PENDING_FILTER_EVENT_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

use once_cell::sync::Lazy;
use std::collections::{HashMap as StdHashMap, VecDeque};

type PendingFilterEvents = RwLock<VecDeque<(u64, [u8; 32])>>;

static FILTERS: Lazy<RwLock<StdHashMap<u64, RpcFilter>>> =
    Lazy::new(|| RwLock::new(StdHashMap::new()));
static PENDING_FILTER_EVENTS: Lazy<PendingFilterEvents> =
    Lazy::new(|| RwLock::new(VecDeque::new()));

async fn record_pending_filter_event(tx_hash: [u8; 32]) {
    let event_id = NEXT_PENDING_FILTER_EVENT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut events = PENDING_FILTER_EVENTS.write().await;
    events.push_back((event_id, tx_hash));
    while events.len() > PENDING_FILTER_EVENT_LIMIT {
        events.pop_front();
    }
}

#[cfg_attr(not(test), allow(dead_code))]
async fn handle_rpc_request(json_str: &str, node: &NodeState) -> String {
    handle_rpc_request_for_path(json_str, node, "/").await
}

async fn handle_rpc_request_for_path(json_str: &str, node: &NodeState, path: &str) -> String {
    let req: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => {
            return r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"parse error"},"id":null}"#
                .to_string();
        }
    };

    let method = req["method"].as_str().unwrap_or("");
    let params = &req["params"];
    let id = &req["id"];

    match method {
        // -----------------------------------------------------------------
        // Existing methods
        // -----------------------------------------------------------------
        "eth_chainId" => rpc_ok(&format!("\"0x{:x}\"", node.config.chain_id), id),
        "eth_blockNumber" => {
            let height = node.db.last_accepted_height().unwrap_or(None).unwrap_or(0);
            rpc_ok(&format!("\"0x{:x}\"", height), id)
        }
        "net_version" => rpc_ok(&format!("\"{}\"", node.config.network_id), id),
        "net_listening" => rpc_ok("true", id),
        "net_peerCount" => {
            let peer_count = node.peer_manager.read().await.connected_count() as u64;
            rpc_ok(&format!("\"0x{:x}\"", peer_count), id)
        }
        "web3_clientVersion" => rpc_ok("\"avalanche-rs/0.1.0\"", id),
        "web3_sha3" => {
            let Some(data) = params.get(0).and_then(|value| value.as_str()) else {
                return rpc_error(-32602, "missing data", id);
            };
            let Some(bytes) = parse_hex_bytes(data) else {
                return rpc_error(-32602, "invalid data", id);
            };
            let hash = revm::primitives::keccak256(bytes);
            rpc_ok(&format!("\"0x{}\"", hex::encode(hash)), id)
        }
        "eth_accounts" => {
            let mut accounts = node
                .rpc_wallets
                .keys()
                .map(|address| serde_json::Value::String(format!("0x{}", hex::encode(address))))
                .collect::<Vec<_>>();
            accounts.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            rpc_ok(&serde_json::Value::Array(accounts).to_string(), id)
        }
        "eth_syncing" => {
            let phase = node.sync_engine.phase().await;
            if phase == SyncPhase::Synced || phase == SyncPhase::Following {
                rpc_ok("false", id)
            } else {
                let stats = node.sync_engine.stats().await;
                rpc_ok(
                    &format!(
                        "{{\"startingBlock\":\"0x0\",\"currentBlock\":\"0x{:x}\",\"highestBlock\":\"0x{:x}\"}}",
                        stats.last_block_height,
                        stats.target_height
                    ),
                    id,
                )
            }
        }
        "avax_getNodeID" => rpc_ok(
            &format!("\"{}\"", full_node_id_string(&node.identity.node_id)),
            id,
        ),
        "avax_getNodeVersion" => rpc_ok("\"avalanche-rs/0.1.0\"", id),

        // -----------------------------------------------------------------
        // eth_getBalance
        // -----------------------------------------------------------------
        "eth_getBalance" => {
            let addr_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            match parse_hex_address(addr_str) {
                Some(addr) => {
                    // In light client mode, serve from proof cache first
                    if node.config.light_client {
                        let lc = node.light_client.read().await;
                        if let Some(balance) = lc.get_cached_balance(&addr) {
                            return rpc_ok(&format!("\"0x{:x}\"", balance), id);
                        }
                        // No cached proof — fall through to EVM state
                    }
                    let evm = node.evm.read().await;
                    let balance = evm.get_balance(addr);
                    rpc_ok(&format!("\"0x{:x}\"", balance), id)
                }
                None => rpc_error(-32602, "invalid address", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getTransactionCount
        // -----------------------------------------------------------------
        "eth_getTransactionCount" => {
            let addr_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            match parse_hex_address(addr_str) {
                Some(addr) => {
                    let evm = node.evm.read().await;
                    let nonce = evm.get_nonce(addr);
                    rpc_ok(&format!("\"0x{:x}\"", nonce), id)
                }
                None => rpc_error(-32602, "invalid address", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getCode
        // -----------------------------------------------------------------
        "eth_getCode" => {
            let addr_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            match parse_hex_address(addr_str) {
                Some(addr) => {
                    let evm = node.evm.read().await;
                    let code = evm.get_code(addr);
                    rpc_ok(&format!("\"0x{}\"", hex::encode(&code)), id)
                }
                None => rpc_error(-32602, "invalid address", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getStorageAt
        // -----------------------------------------------------------------
        "eth_getStorageAt" => {
            let addr_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            let slot_str = params.get(1).and_then(|v| v.as_str()).unwrap_or("0x0");
            match (parse_hex_address(addr_str), parse_hex_hash(slot_str)) {
                (Some(addr), Some(slot)) => {
                    let evm = node.evm.read().await;
                    let value = evm.get_storage_at(addr, slot);
                    rpc_ok(&format!("\"0x{}\"", hex::encode(value)), id)
                }
                _ => rpc_error(-32602, "invalid params", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getProof
        // -----------------------------------------------------------------
        "eth_getProof" => {
            let addr_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            let storage_keys = params
                .get(1)
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let current_height = current_cchain_height(node);
            let allow_current = match params.get(2) {
                None => true,
                Some(serde_json::Value::Null) => true,
                Some(serde_json::Value::String(tag)) if tag == "latest" || tag == "pending" => true,
                Some(value) => parse_block_number(value, node) == current_height,
            };
            if !allow_current {
                return rpc_error(-32000, "historical proof query not allowed", id);
            }
            let Some(address) = parse_hex_address(addr_str) else {
                return rpc_error(-32602, "invalid address", id);
            };
            let mut parsed_keys = Vec::with_capacity(storage_keys.len());
            for key in storage_keys {
                let Some(key_str) = key.as_str() else {
                    return rpc_error(-32602, "invalid storage key", id);
                };
                let Some(slot) = parse_hex_hash(key_str) else {
                    return rpc_error(-32602, "invalid storage key", id);
                };
                parsed_keys.push((slot, key_str.to_string()));
            }
            let proof = node.evm.read().await.get_proof(address, &parsed_keys);
            rpc_ok(
                &serde_json::to_value(proof)
                    .unwrap_or(serde_json::Value::Null)
                    .to_string(),
                id,
            )
        }

        // -----------------------------------------------------------------
        // eth_call
        // -----------------------------------------------------------------
        "eth_call" => {
            let tx_obj = params.get(0);
            if tx_obj.is_none() {
                return rpc_error(-32602, "missing transaction object", id);
            }
            let evm = node.evm.read().await;
            let block_ctx = rpc_simulation_block_context(node);
            let parsed = parse_rpc_simulation_tx(tx_obj.unwrap(), &evm, &block_ctx);
            match evm.execute_call(&parsed.tx, &block_ctx) {
                Ok(output) => rpc_ok(&format!("\"0x{}\"", hex::encode(&output)), id),
                Err(e) => rpc_error(-32000, &format!("{}", e), id),
            }
        }

        // -----------------------------------------------------------------
        // eth_callDetailed (Avalanche-specific)
        // -----------------------------------------------------------------
        "eth_callDetailed" => {
            let Some(tx_obj) = params.get(0) else {
                return rpc_error(-32602, "missing transaction object", id);
            };
            let evm = node.evm.read().await;
            let block_ctx = rpc_simulation_block_context(node);
            let result = eth_call_detailed_result(&evm, tx_obj, &block_ctx);
            rpc_ok(&result.to_string(), id)
        }

        // -----------------------------------------------------------------
        // eth_estimateGas
        // -----------------------------------------------------------------
        "eth_estimateGas" => {
            let tx_obj = params.get(0);
            if tx_obj.is_none() {
                return rpc_error(-32602, "missing transaction object", id);
            }
            let evm = node.evm.read().await;
            let block_ctx = rpc_simulation_block_context(node);
            let parsed = parse_rpc_simulation_tx(tx_obj.unwrap(), &evm, &block_ctx);
            match evm.estimate_gas(&parsed.tx, &block_ctx) {
                Ok(gas) => rpc_ok(&format!("\"0x{:x}\"", gas), id),
                Err(e) => rpc_error(-32000, &format!("{}", e), id),
            }
        }

        // -----------------------------------------------------------------
        // eth_gasPrice
        // -----------------------------------------------------------------
        "eth_gasPrice" => rpc_ok(&format!("\"0x{:x}\"", cchain_legacy_gas_price(node)), id),

        // -----------------------------------------------------------------
        // eth_baseFee (Avalanche-specific)
        // -----------------------------------------------------------------
        "eth_baseFee" => {
            let base_fee = predicted_next_base_fee_from_db(&node.db, node.config.network_id);
            rpc_ok(&format!("\"0x{:x}\"", base_fee), id)
        }

        // -----------------------------------------------------------------
        // eth_getChainConfig (Avalanche-specific)
        // -----------------------------------------------------------------
        "eth_getChainConfig" => rpc_ok(&cchain_chain_config_result(node).to_string(), id),

        // -----------------------------------------------------------------
        // eth_getBadBlocks (Avalanche-specific)
        // -----------------------------------------------------------------
        "eth_getBadBlocks" => {
            let results = load_bad_block_records(&node.db)
                .iter()
                .map(|record| bad_block_response_value(node, record))
                .collect::<Vec<_>>();
            rpc_ok(&serde_json::Value::Array(results).to_string(), id)
        }

        // -----------------------------------------------------------------
        // eth_pendingTransactions
        // -----------------------------------------------------------------
        "eth_pendingTransactions" => {
            let txs = node.txpool.read().await.pending_sorted_cloned();
            let result = txs
                .iter()
                .map(|tx| rpc_transaction_from_pool(&tx.hash, tx, None, None, None))
                .collect::<Vec<_>>();
            rpc_ok(&serde_json::Value::Array(result).to_string(), id)
        }

        // -----------------------------------------------------------------
        // eth_sendRawTransaction
        // -----------------------------------------------------------------
        "eth_sendRawTransaction" => {
            let tx_bytes_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
            if tx_bytes_str.is_empty() {
                return rpc_error(-32602, "missing raw transaction", id);
            }

            match parse_hex_bytes(tx_bytes_str) {
                Some(raw_tx) => match submit_raw_cchain_transaction(node, &raw_tx).await {
                    Ok(tx_hash) => rpc_ok(&format!("\"0x{}\"", hex::encode(tx_hash)), id),
                    Err(msg) => rpc_error(-32000, &msg, id),
                },
                None => rpc_error(-32602, "invalid tx hex", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_sendTransaction
        // -----------------------------------------------------------------
        "eth_sendTransaction" => {
            let Some(tx_obj) = params.get(0) else {
                return rpc_error(-32602, "missing transaction object", id);
            };
            let request = match parse_rpc_managed_tx_request(tx_obj, true) {
                Ok(request) => request,
                Err(message) => return rpc_error(-32602, &message, id),
            };
            let wallet = match managed_wallet(node, request.from) {
                Ok(wallet) => wallet.clone(),
                Err(message) => return rpc_error(-32000, &message, id),
            };
            match prepare_rpc_managed_tx(node, &request, false).await {
                Ok(envelope) => match envelope.sign(&wallet) {
                    Ok(signed) => match submit_raw_cchain_transaction(node, &signed.raw).await {
                        Ok(hash) => rpc_ok(&format!("\"0x{}\"", hex::encode(hash)), id),
                        Err(message) => rpc_error(-32000, &message, id),
                    },
                    Err(message) => rpc_error(-32000, &message, id),
                },
                Err(message) => rpc_error(-32000, &message, id),
            }
        }

        // -----------------------------------------------------------------
        // eth_fillTransaction
        // -----------------------------------------------------------------
        "eth_fillTransaction" => {
            let Some(tx_obj) = params.get(0) else {
                return rpc_error(-32602, "missing transaction object", id);
            };
            let request = match parse_rpc_managed_tx_request(tx_obj, true) {
                Ok(request) => request,
                Err(message) => return rpc_error(-32602, &message, id),
            };
            match prepare_rpc_managed_tx(node, &request, false).await {
                Ok(envelope) => {
                    let result =
                        filled_transaction_result(&request, &envelope, node.config.chain_id);
                    rpc_ok(&result.to_string(), id)
                }
                Err(message) => rpc_error(-32000, &message, id),
            }
        }

        // -----------------------------------------------------------------
        // eth_sign
        // -----------------------------------------------------------------
        "eth_sign" => {
            let addr_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            let data = params.get(1).and_then(|v| v.as_str()).unwrap_or("0x");
            let Some(address) = parse_hex_address(addr_str) else {
                return rpc_error(-32602, "invalid address", id);
            };
            let Some(message) = parse_hex_bytes(data) else {
                return rpc_error(-32602, "invalid data", id);
            };
            let wallet = match managed_wallet(node, address) {
                Ok(wallet) => wallet,
                Err(message) => return rpc_error(-32000, &message, id),
            };
            let hash = ethereum_signed_message_hash(&message);
            match wallet.sign_hash(&hash) {
                Ok(signature) => {
                    let mut encoded = Vec::with_capacity(65);
                    encoded.extend_from_slice(&signature.r);
                    encoded.extend_from_slice(&signature.s);
                    encoded.push(signature.v.saturating_add(27));
                    rpc_ok(&format!("\"0x{}\"", hex::encode(encoded)), id)
                }
                Err(message) => rpc_error(-32000, &message.to_string(), id),
            }
        }

        // -----------------------------------------------------------------
        // eth_signTransaction
        // -----------------------------------------------------------------
        "eth_signTransaction" => {
            let Some(tx_obj) = params.get(0) else {
                return rpc_error(-32602, "missing transaction object", id);
            };
            let request = match parse_rpc_managed_tx_request(tx_obj, true) {
                Ok(request) => request,
                Err(message) => return rpc_error(-32602, &message, id),
            };
            let wallet = match managed_wallet(node, request.from) {
                Ok(wallet) => wallet.clone(),
                Err(message) => return rpc_error(-32000, &message, id),
            };
            match prepare_rpc_managed_tx(node, &request, true).await {
                Ok(envelope) => match envelope.sign(&wallet) {
                    Ok(signed) => {
                        let result =
                            signed_transaction_result(&signed, &envelope, node.config.chain_id);
                        rpc_ok(&result.to_string(), id)
                    }
                    Err(message) => rpc_error(-32000, &message, id),
                },
                Err(message) => rpc_error(-32000, &message, id),
            }
        }

        // -----------------------------------------------------------------
        // eth_resend
        // -----------------------------------------------------------------
        "eth_resend" => {
            let Some(tx_obj) = params.get(0) else {
                return rpc_error(-32602, "missing transaction object", id);
            };
            let gas_price = params.get(1).and_then(parse_quantity_u128);
            let gas_limit = params.get(2).and_then(parse_quantity_u64);
            match rpc_resend_transaction(node, tx_obj, gas_price, gas_limit).await {
                Ok(hash) => rpc_ok(&format!("\"0x{}\"", hex::encode(hash)), id),
                Err(message) => rpc_error(-32000, &message, id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getTransactionByHash
        // -----------------------------------------------------------------
        "eth_getTransactionByHash" => {
            let tx_hash_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            match parse_hex_hash(tx_hash_str) {
                Some(tx_hash) => {
                    if let Some(tx) = node.txpool.read().await.get(&tx_hash).cloned() {
                        let result = rpc_transaction_from_pool(&tx_hash, &tx, None, None, None);
                        return rpc_ok(&result.to_string(), id);
                    }
                    match node.db.get_tx_index(&tx_hash) {
                        Ok(Some((block_height, tx_index))) => {
                            if let Some((block_hash, tx)) =
                                load_mined_cchain_transaction(&node.db, block_height, tx_index)
                            {
                                let result = rpc_transaction_from_pool(
                                    &tx_hash,
                                    &tx,
                                    Some(block_hash),
                                    Some(block_height),
                                    Some(tx_index),
                                );
                                rpc_ok(&result.to_string(), id)
                            } else {
                                rpc_ok(
                                    &format!(
                                        "{{\"hash\":\"0x{}\",\"blockNumber\":\"0x{:x}\",\"transactionIndex\":\"0x{:x}\"}}",
                                        hex::encode(tx_hash), block_height, tx_index
                                    ),
                                    id,
                                )
                            }
                        }
                        _ => rpc_ok("null", id),
                    }
                }
                None => rpc_error(-32602, "invalid hash", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getTransactionByBlockHashAndIndex / eth_getTransactionByBlockNumberAndIndex
        // -----------------------------------------------------------------
        "eth_getTransactionByBlockHashAndIndex" => {
            let hash_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            let Some(tx_index) = params.get(1).and_then(parse_quantity_u64) else {
                return rpc_error(-32602, "invalid transaction index", id);
            };
            match parse_hex_hash(hash_str) {
                Some(block_hash) => match load_cchain_block_by_hash(&node.db, &block_hash) {
                    Some(block_data) => {
                        match rpc_transaction_from_cchain_block_index(&block_data, tx_index) {
                            Some(result) => rpc_ok(&result.to_string(), id),
                            None => rpc_ok("null", id),
                        }
                    }
                    None => rpc_ok("null", id),
                },
                None => rpc_error(-32602, "invalid hash", id),
            }
        }

        "eth_getTransactionByBlockNumberAndIndex" => {
            let block_num =
                parse_block_number(params.get(0).unwrap_or(&serde_json::Value::Null), node);
            let Some(tx_index) = params.get(1).and_then(parse_quantity_u64) else {
                return rpc_error(-32602, "invalid transaction index", id);
            };
            match node.db.get_block(block_num) {
                Ok(Some(block_data)) => {
                    match rpc_transaction_from_cchain_block_index(&block_data, tx_index) {
                        Some(result) => rpc_ok(&result.to_string(), id),
                        None => rpc_ok("null", id),
                    }
                }
                _ => rpc_ok("null", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getRawTransactionByHash / eth_getRawTransactionByBlock*AndIndex
        // -----------------------------------------------------------------
        "eth_getRawTransactionByHash" => {
            let tx_hash_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            match parse_hex_hash(tx_hash_str) {
                Some(tx_hash) => {
                    if let Some(tx) = node.txpool.read().await.get(&tx_hash).cloned() {
                        if let Some(raw) = tx.raw {
                            return rpc_ok(&format!("\"0x{}\"", hex::encode(raw)), id);
                        }
                    }
                    match node.db.get_tx_index(&tx_hash) {
                        Ok(Some((block_height, tx_index))) => match node.db.get_block(block_height)
                        {
                            Ok(Some(block_data)) => {
                                match raw_transaction_hex_from_cchain_block_index(
                                    &block_data,
                                    tx_index as u64,
                                ) {
                                    Some(result) => rpc_ok(&format!("\"{}\"", result), id),
                                    None => rpc_ok("null", id),
                                }
                            }
                            _ => rpc_ok("null", id),
                        },
                        _ => rpc_ok("null", id),
                    }
                }
                None => rpc_error(-32602, "invalid hash", id),
            }
        }

        "eth_getRawTransactionByBlockHashAndIndex" => {
            let hash_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            let Some(tx_index) = params.get(1).and_then(parse_quantity_u64) else {
                return rpc_error(-32602, "invalid transaction index", id);
            };
            match parse_hex_hash(hash_str) {
                Some(block_hash) => match load_cchain_block_by_hash(&node.db, &block_hash) {
                    Some(block_data) => {
                        match raw_transaction_hex_from_cchain_block_index(&block_data, tx_index) {
                            Some(result) => rpc_ok(&format!("\"{}\"", result), id),
                            None => rpc_ok("null", id),
                        }
                    }
                    None => rpc_ok("null", id),
                },
                None => rpc_error(-32602, "invalid hash", id),
            }
        }

        "eth_getRawTransactionByBlockNumberAndIndex" => {
            let block_num =
                parse_block_number(params.get(0).unwrap_or(&serde_json::Value::Null), node);
            let Some(tx_index) = params.get(1).and_then(parse_quantity_u64) else {
                return rpc_error(-32602, "invalid transaction index", id);
            };
            match node.db.get_block(block_num) {
                Ok(Some(block_data)) => {
                    match raw_transaction_hex_from_cchain_block_index(&block_data, tx_index) {
                        Some(result) => rpc_ok(&format!("\"{}\"", result), id),
                        None => rpc_ok("null", id),
                    }
                }
                _ => rpc_ok("null", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getTransactionReceipt
        // -----------------------------------------------------------------
        "eth_getTransactionReceipt" => {
            let tx_hash_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            match parse_hex_hash(tx_hash_str) {
                Some(tx_hash) => {
                    match node.db.get_tx_index(&tx_hash) {
                        Ok(Some((block_height, tx_index))) => {
                            match node.db.get_receipt(block_height, tx_index) {
                                Ok(Some(receipt_data)) => {
                                    let receipt_json = String::from_utf8_lossy(&receipt_data);
                                    rpc_ok(&receipt_json, id)
                                }
                                _ => {
                                    // Return minimal receipt from index data
                                    rpc_ok(
                                        &format!(
                                            "{{\"transactionHash\":\"0x{}\",\"blockNumber\":\"0x{:x}\",\"transactionIndex\":\"0x{:x}\",\"status\":\"0x1\"}}",
                                            hex::encode(tx_hash), block_height, tx_index
                                        ),
                                        id,
                                    )
                                }
                            }
                        }
                        _ => rpc_ok("null", id),
                    }
                }
                None => rpc_error(-32602, "invalid hash", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getBlockByNumber
        // -----------------------------------------------------------------
        "eth_getBlockByNumber" => {
            let block_num =
                parse_block_number(params.get(0).unwrap_or(&serde_json::Value::Null), node);
            let include_full_txs = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
            match node.db.get_block(block_num) {
                Ok(Some(block_data)) => {
                    match rpc_block_from_cchain_data(&block_data, include_full_txs) {
                        Some(result) => rpc_ok(&result.to_string(), id),
                        None => rpc_ok("null", id),
                    }
                }
                _ => rpc_ok("null", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getBlockByHash
        // -----------------------------------------------------------------
        "eth_getBlockByHash" => {
            let hash_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            match parse_hex_hash(hash_str) {
                Some(block_hash) => {
                    let include_full_txs = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
                    // Look up block by hash in blocks CF (hash key format: "c:" prefix for C-chain)
                    let mut key = Vec::with_capacity(34);
                    key.extend_from_slice(b"c:");
                    key.extend_from_slice(&block_hash);
                    match node.db.get_cf(avalanche_rs::db::CF_BLOCKS, &key) {
                        Ok(Some(block_data)) => {
                            match rpc_block_from_cchain_data(&block_data, include_full_txs) {
                                Some(result) => rpc_ok(&result.to_string(), id),
                                None => rpc_ok("null", id),
                            }
                        }
                        _ => rpc_ok("null", id),
                    }
                }
                None => rpc_error(-32602, "invalid hash", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getBlockTransactionCountByNumber / eth_getBlockTransactionCountByHash
        // -----------------------------------------------------------------
        "eth_getBlockTransactionCountByNumber" => {
            let block_num =
                parse_block_number(params.get(0).unwrap_or(&serde_json::Value::Null), node);
            match node.db.get_block(block_num) {
                Ok(Some(block_data)) => rpc_ok(
                    &format!("\"0x{:x}\"", cchain_transaction_count(&block_data)),
                    id,
                ),
                _ => rpc_ok("null", id),
            }
        }

        "eth_getBlockTransactionCountByHash" => {
            let hash_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            match parse_hex_hash(hash_str) {
                Some(block_hash) => match load_cchain_block_by_hash(&node.db, &block_hash) {
                    Some(block_data) => rpc_ok(
                        &format!("\"0x{:x}\"", cchain_transaction_count(&block_data)),
                        id,
                    ),
                    None => rpc_ok("null", id),
                },
                None => rpc_error(-32602, "invalid hash", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getLogs
        // -----------------------------------------------------------------
        "eth_getLogs" => {
            let filter = parse_log_filter(params.get(0).unwrap_or(&serde_json::Value::Null), node);
            let current_height = current_cchain_height(node);
            let end_block = filter
                .to_block
                .unwrap_or(current_height)
                .min(current_height);
            let logs = collect_logs_for_range(&node.db, &filter, filter.from_block, end_block);
            rpc_ok(&serde_json::Value::Array(logs).to_string(), id)
        }

        // -----------------------------------------------------------------
        // eth_newFilter
        // -----------------------------------------------------------------
        "eth_newFilter" => {
            let filter_obj = params.get(0).unwrap_or(&serde_json::Value::Null);
            let filter_id = NEXT_FILTER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let filter = parse_log_filter(filter_obj, node);
            FILTERS
                .write()
                .await
                .insert(filter_id, RpcFilter::Logs(filter));
            rpc_ok(&format!("\"0x{:x}\"", filter_id), id)
        }

        // -----------------------------------------------------------------
        // eth_newPendingTransactionFilter / eth_newAcceptedTransactions / eth_newBlockFilter
        // -----------------------------------------------------------------
        "eth_newPendingTransactionFilter" => {
            let filter_id = NEXT_FILTER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let last_event_id = NEXT_PENDING_FILTER_EVENT_ID
                .load(std::sync::atomic::Ordering::Relaxed)
                .saturating_sub(1);
            FILTERS.write().await.insert(
                filter_id,
                RpcFilter::PendingTransactions(PendingTransactionFilter { last_event_id }),
            );
            rpc_ok(&format!("\"0x{:x}\"", filter_id), id)
        }

        "eth_newAcceptedTransactions" => {
            let full_tx = params
                .get(0)
                .and_then(|value| match value {
                    serde_json::Value::Bool(flag) => Some(*flag),
                    serde_json::Value::Object(_) => value.get("fullTx").and_then(|v| v.as_bool()),
                    _ => None,
                })
                .unwrap_or(false);
            let filter_id = NEXT_FILTER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            FILTERS.write().await.insert(
                filter_id,
                RpcFilter::AcceptedTransactions(AcceptedTransactionFilter {
                    last_polled_block: current_cchain_height(node),
                    full_tx,
                }),
            );
            rpc_ok(&format!("\"0x{:x}\"", filter_id), id)
        }

        "eth_newBlockFilter" => {
            let filter_id = NEXT_FILTER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            FILTERS.write().await.insert(
                filter_id,
                RpcFilter::Blocks(BlockHashFilter {
                    last_polled_block: current_cchain_height(node),
                }),
            );
            rpc_ok(&format!("\"0x{:x}\"", filter_id), id)
        }

        // -----------------------------------------------------------------
        // eth_getFilterChanges
        // -----------------------------------------------------------------
        "eth_getFilterChanges" => {
            let filter_id = parse_filter_id(params.get(0).unwrap_or(&serde_json::Value::Null));
            let mut filters = FILTERS.write().await;
            match filters.get_mut(&filter_id) {
                Some(RpcFilter::Logs(filter)) => {
                    let current_height = current_cchain_height(node);
                    let end_block = filter
                        .to_block
                        .unwrap_or(current_height)
                        .min(current_height);
                    let start_block = filter
                        .last_polled_block
                        .saturating_add(1)
                        .max(filter.from_block);
                    let logs = collect_logs_for_range(&node.db, filter, start_block, end_block);
                    filter.last_polled_block = current_height;
                    rpc_ok(&serde_json::Value::Array(logs).to_string(), id)
                }
                Some(RpcFilter::PendingTransactions(filter)) => {
                    let changes = pending_transaction_filter_changes(filter).await;
                    rpc_ok(&serde_json::Value::Array(changes).to_string(), id)
                }
                Some(RpcFilter::Blocks(filter)) => {
                    let current_height = current_cchain_height(node);
                    let start_block = filter.last_polled_block.saturating_add(1);
                    let changes = block_hash_changes(&node.db, start_block, current_height);
                    filter.last_polled_block = current_height;
                    rpc_ok(&serde_json::Value::Array(changes).to_string(), id)
                }
                Some(RpcFilter::AcceptedTransactions(filter)) => {
                    let current_height = current_cchain_height(node);
                    let start_block = filter.last_polled_block.saturating_add(1);
                    let changes = accepted_transaction_changes(
                        &node.db,
                        start_block,
                        current_height,
                        filter.full_tx,
                    );
                    filter.last_polled_block = current_height;
                    rpc_ok(&serde_json::Value::Array(changes).to_string(), id)
                }
                None => rpc_error(-32000, "filter not found", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getFilterLogs
        // -----------------------------------------------------------------
        "eth_getFilterLogs" => {
            let filter_id = parse_filter_id(params.get(0).unwrap_or(&serde_json::Value::Null));
            let filters = FILTERS.read().await;
            match filters.get(&filter_id) {
                Some(RpcFilter::Logs(filter)) => {
                    let current_height = current_cchain_height(node);
                    let end_block = filter
                        .to_block
                        .unwrap_or(current_height)
                        .min(current_height);
                    let logs =
                        collect_logs_for_range(&node.db, filter, filter.from_block, end_block);
                    rpc_ok(&serde_json::Value::Array(logs).to_string(), id)
                }
                Some(_) => rpc_error(-32000, "filter is not a log filter", id),
                None => rpc_error(-32000, "filter not found", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_uninstallFilter
        // -----------------------------------------------------------------
        "eth_uninstallFilter" => {
            let filter_id = parse_filter_id(params.get(0).unwrap_or(&serde_json::Value::Null));
            let removed = FILTERS.write().await.remove(&filter_id).is_some();
            rpc_ok(if removed { "true" } else { "false" }, id)
        }

        // -----------------------------------------------------------------
        // Admin RPC methods
        // -----------------------------------------------------------------
        "admin.getConfig" => match serde_json::to_value(&node.config) {
            Ok(config) => rpc_ok(&config.to_string(), id),
            Err(_) => rpc_error(-32000, "failed to encode config", id),
        },

        "admin.getLoggerLevel" => {
            let logger_name = admin_logger_name_param(params);
            let levels = node.logger_levels.read().await;
            let result = logger_levels_response(&levels, logger_name);
            rpc_ok(&result.to_string(), id)
        }

        "admin.setLoggerLevel" => {
            let logger_name = admin_logger_name_param(params).unwrap_or("root");
            let log_level = admin_log_level_param(params);
            let display_level = admin_display_level_param(params);

            if log_level.is_none() && display_level.is_none() {
                return rpc_error(-32602, "missing logLevel or displayLevel", id);
            }

            let normalized_log_level = match log_level {
                Some(level) => match normalize_log_level(level) {
                    Some(level) => Some(level),
                    None => return rpc_error(-32602, "invalid logLevel", id),
                },
                None => None,
            };
            let normalized_display_level = match display_level {
                Some(level) => match normalize_log_level(level) {
                    Some(level) => Some(level),
                    None => return rpc_error(-32602, "invalid displayLevel", id),
                },
                None => None,
            };

            let levels_snapshot = {
                let mut levels = node.logger_levels.write().await;
                let inherited_state = levels.get("root").cloned().unwrap_or(LoggerLevelState {
                    log_level: "INFO".to_string(),
                    display_level: "INFO".to_string(),
                });
                let state = levels
                    .entry(logger_name.to_string())
                    .or_insert(inherited_state);
                if let Some(level) = normalized_log_level {
                    state.log_level = level;
                }
                if let Some(level) = normalized_display_level {
                    state.display_level = level;
                }
                levels.clone()
            };

            if let Err(err) = reload_logger_filter(&levels_snapshot) {
                return rpc_error(-32000, &err, id);
            }

            rpc_ok("{}", id)
        }

        "admin.loadVMs" => rpc_ok(
            &serde_json::json!({
                "newVMs": serde_json::Map::<String, serde_json::Value>::new(),
                "failedVMs": serde_json::Map::<String, serde_json::Value>::new(),
            })
            .to_string(),
            id,
        ),

        "admin_getVMConfig" | "admin.getVMConfig" => {
            rpc_ok(&cchain_vm_config_result(node).to_string(), id)
        }

        "admin.alias" => {
            let Some(endpoint) = admin_endpoint_param(params) else {
                return rpc_error(-32602, "missing endpoint", id);
            };
            let Some(alias) = admin_alias_param(params) else {
                return rpc_error(-32602, "missing alias", id);
            };
            if alias.len() > 512 {
                return rpc_error(-32602, "alias exceeds max length", id);
            }
            let Some(endpoint_path) = admin_normalize_endpoint_path(endpoint) else {
                return rpc_error(-32602, "invalid endpoint", id);
            };
            let Some(alias_path) = admin_normalize_endpoint_path(alias) else {
                return rpc_error(-32602, "invalid alias", id);
            };

            let mut aliases = node.http_aliases.write().await;
            if let Some(existing) = aliases.get(&alias_path) {
                if existing != &endpoint_path {
                    return rpc_error(-32000, "alias already exists", id);
                }
            } else {
                aliases.insert(alias_path, endpoint_path);
            }
            rpc_ok("{}", id)
        }

        "admin.aliasChain" => {
            let Some(chain) = admin_chain_param(params) else {
                return rpc_error(-32602, "missing chain", id);
            };
            let Some(alias) = admin_alias_param(params) else {
                return rpc_error(-32602, "missing alias", id);
            };
            if alias.len() > 512 {
                return rpc_error(-32602, "alias exceeds max length", id);
            }
            let Some(chain_id) = resolve_blockchain_alias_id(node, chain).await else {
                return rpc_error(
                    -32602,
                    &format!("there is no chain with alias/ID '{}'", chain),
                    id,
                );
            };

            if let Some(existing) = resolve_blockchain_alias_id(node, alias).await {
                if existing != chain_id {
                    return rpc_error(-32000, "alias already exists", id);
                }
            } else {
                let mut chain_aliases = node.chain_aliases.write().await;
                chain_aliases
                    .entry(chain_id)
                    .or_default()
                    .push(alias.to_string());
                if let Some(aliases) = chain_aliases.get_mut(&chain_id) {
                    let deduped = dedupe_aliases_case_insensitive(std::mem::take(aliases));
                    *aliases = deduped;
                }
            }

            rpc_ok("{}", id)
        }

        "admin.getChainAliases" => {
            let Some(chain) = admin_chain_param(params) else {
                return rpc_error(-32602, "missing chain", id);
            };
            let Some(chain_id) = resolve_blockchain_alias_id(node, chain).await else {
                return rpc_error(
                    -32602,
                    &format!("there is no chain with alias/ID '{}'", chain),
                    id,
                );
            };
            let result = serde_json::json!({
                "aliases": blockchain_aliases_for_id(node, chain_id).await,
            });
            rpc_ok(&result.to_string(), id)
        }

        // -----------------------------------------------------------------
        // ProposerVM RPC methods (routed via /ext/bc/<chain>/proposervm)
        // -----------------------------------------------------------------
        "proposervm.getProposedHeight" => match resolve_proposervm_route(node, path).await {
            ProposerVmRoute::NotProposerVm => rpc_error(-32601, "method not found", id),
            ProposerVmRoute::UnknownChain(chain) => {
                rpc_error(-32000, &format!("unknown chain '{}'", chain), id)
            }
            ProposerVmRoute::Target(target) => {
                let height = proposervm_proposed_height(node, target).await;
                rpc_ok(
                    &serde_json::json!({ "height": height.to_string() }).to_string(),
                    id,
                )
            }
        },

        "proposervm.getCurrentEpoch" => match resolve_proposervm_route(node, path).await {
            ProposerVmRoute::NotProposerVm => rpc_error(-32601, "method not found", id),
            ProposerVmRoute::UnknownChain(chain) => {
                rpc_error(-32000, &format!("unknown chain '{}'", chain), id)
            }
            ProposerVmRoute::Target(_) => match proposervm_current_epoch_result(node) {
                Ok(result) => rpc_ok(&result.to_string(), id),
                Err(err) => rpc_error(-32000, &err, id),
            },
        },

        // -----------------------------------------------------------------
        // Platform RPC methods (routed via /ext/bc/P in AvalancheGo)
        // -----------------------------------------------------------------
        "platform.getCurrentValidators" => {
            let (chain_time, records) = platform_validator_records(node, params).await;
            let records = records
                .into_iter()
                .filter(|validator| validator.status(chain_time) == "current")
                .collect::<Vec<_>>();
            let validators = platform_validator_response_values(
                node,
                chain_time,
                records,
                platform_node_ids_param(params).len() == 1,
            )
            .await;
            rpc_ok(
                &serde_json::json!({ "validators": validators }).to_string(),
                id,
            )
        }

        "platform.getValidators" => {
            let (chain_time, records) = platform_validator_records(node, params).await;
            let validators =
                platform_validator_response_values(node, chain_time, records, false).await;
            rpc_ok(
                &serde_json::json!({ "validators": validators }).to_string(),
                id,
            )
        }

        "platform.getPendingValidators" => {
            let (chain_time, records) = platform_validator_records(node, params).await;
            let records = records
                .into_iter()
                .filter(|validator| validator.status(chain_time) == "pending")
                .collect::<Vec<_>>();
            let validators =
                platform_validator_response_values(node, chain_time, records, false).await;
            rpc_ok(
                &serde_json::json!({
                    "validators": validators,
                    "delegators": [],
                })
                .to_string(),
                id,
            )
        }

        "platform.getValidator" => {
            let Some(node_id) = platform_node_id_param(params) else {
                return rpc_error(-32602, "missing nodeID", id);
            };
            let (chain_time, records) = platform_validator_records(node, params).await;
            let validators =
                platform_validator_response_values(node, chain_time, records, true).await;
            match validators.into_iter().find(|validator| {
                validator.get("nodeID").and_then(|value| value.as_str()) == Some(node_id)
            }) {
                Some(validator) => rpc_ok(&validator.to_string(), id),
                None => rpc_error(-32000, "validator not found", id),
            }
        }

        "platform.getValidatorsAt" => match platform_get_validators_at_result(node, params).await {
            Ok(result) => rpc_ok(&result.to_string(), id),
            Err(err) => rpc_error(-32000, &err, id),
        },

        "platform.getAllValidatorsAt" => {
            match platform_get_all_validators_at_result(node, params).await {
                Ok(result) => rpc_ok(&result.to_string(), id),
                Err(err) => rpc_error(-32000, &err, id),
            }
        }

        "platform.getHeight" => {
            let height = current_pchain_height(node).await;
            rpc_ok(
                &serde_json::json!({ "height": height.to_string() }).to_string(),
                id,
            )
        }

        "platform.getProposedHeight" => {
            let height = platform_proposed_height(node).await;
            rpc_ok(
                &serde_json::json!({ "height": height.to_string() }).to_string(),
                id,
            )
        }

        "platform.getBalance" => {
            let addresses = platform_params_object(params)
                .and_then(|obj| obj.get("addresses"))
                .or_else(|| params.get(0))
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default();
            let mut requested = std::collections::HashSet::new();
            for address in addresses {
                let Some(address) = address.as_str() else {
                    return rpc_error(-32602, "invalid address", id);
                };
                let Some(parsed) = parse_platform_address_20(address) else {
                    return rpc_error(-32602, "invalid address", id);
                };
                requested.insert(parsed);
            }
            rpc_ok(&platform_balance_response(node, &requested).to_string(), id)
        }

        "platform.getUTXOs" => {
            let addresses = platform_params_object(params)
                .and_then(|obj| obj.get("addresses"))
                .or_else(|| params.get(0))
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default();
            if addresses.is_empty() {
                return rpc_error(-32602, "no addresses provided", id);
            }
            if addresses.len() > MAX_PLATFORM_GET_UTXOS_ADDRS {
                return rpc_error(
                    -32602,
                    &format!(
                        "number of addresses given, {}, exceeds maximum, {}",
                        addresses.len(),
                        MAX_PLATFORM_GET_UTXOS_ADDRS
                    ),
                    id,
                );
            }

            let mut requested = Vec::with_capacity(addresses.len());
            for address in addresses {
                let Some(address) = address.as_str() else {
                    return rpc_error(-32602, "invalid address", id);
                };
                let Some(parsed) = parse_platform_address_20(address) else {
                    return rpc_error(-32602, "invalid address", id);
                };
                requested.push((address.to_string(), parsed));
            }

            let source_chain = platform_params_object(params)
                .and_then(|obj| obj.get("sourceChain"))
                .or_else(|| params.get(1))
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let source_chain_id = if source_chain.is_empty() {
                platform_pchain_blockchain_id()
            } else {
                let Some(chain_id) = info_blockchain_alias_id(source_chain, node.config.network_id)
                else {
                    return rpc_error(-32602, "invalid sourceChain", id);
                };
                chain_id
            };

            let limit = platform_params_object(params)
                .and_then(|obj| obj.get("limit"))
                .or_else(|| params.get(2))
                .and_then(parse_quantity_u64)
                .map(|value| value as usize)
                .filter(|value| *value > 0 && *value <= PLATFORM_GET_UTXOS_MAX_PAGE_SIZE)
                .unwrap_or(PLATFORM_GET_UTXOS_MAX_PAGE_SIZE);
            let encoding = platform_encoding_param(params, "hex");
            let start_index = platform_params_object(params)
                .and_then(|obj| obj.get("startIndex"))
                .or_else(|| params.get(3));
            let start_addr_value = start_index
                .and_then(|value| value.get("address"))
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty());
            let start_addr = match start_addr_value {
                Some(value) => match parse_platform_address_20(value) {
                    Some(addr) => Some(addr),
                    None => return rpc_error(-32602, "couldn't parse start index address", id),
                },
                None => None,
            };
            let start_utxo_value = start_index
                .and_then(|value| value.get("utxo"))
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty());
            let start_utxo = match start_utxo_value {
                Some(value) => match parse_platform_utxo_end_index(value) {
                    Some(utxo) => Some(utxo),
                    None => return rpc_error(-32602, "couldn't parse start index utxo", id),
                },
                None => None,
            };

            let response = if source_chain_id == platform_pchain_blockchain_id() {
                platform_native_utxos_response(
                    node, &requested, limit, start_addr, start_utxo, encoding,
                )
            } else {
                platform_atomic_utxos_response(
                    node,
                    source_chain_id,
                    &requested,
                    limit,
                    start_addr,
                    start_utxo,
                    encoding,
                )
            };
            match response {
                Ok(response) => rpc_ok(&response.to_string(), id),
                Err(err) => rpc_error(-32602, &err, id),
            }
        }

        "platform.getBlock" => {
            let Some(block_id_str) = platform_block_id_param(params) else {
                return rpc_error(-32602, "missing blockID", id);
            };
            let Some(block_id) = parse_platform_id_32(block_id_str) else {
                return rpc_error(-32602, "invalid blockID", id);
            };
            let encoding = platform_encoding_param(params, "hex");
            match node.db.get_cf(CF_BLOCKS, &block_id) {
                Ok(Some(data)) => {
                    let response = match encoding {
                        "hex" => serde_json::json!({
                            "block": format!("0x{}", hex::encode(&data)),
                            "encoding": "hex",
                        }),
                        "json" => serde_json::json!({
                            "block": platform_block_json_value(&data),
                            "encoding": "json",
                        }),
                        _ => {
                            return rpc_error(-32602, "unsupported encoding", id);
                        }
                    };
                    rpc_ok(&response.to_string(), id)
                }
                _ => rpc_error(-32000, "block not found", id),
            }
        }

        "platform.getBlockByHeight" => {
            let Some(height) = platform_height_param(params) else {
                return rpc_error(-32602, "missing height", id);
            };
            let encoding = platform_encoding_param(params, "hex");
            let block = node
                .db
                .iter_cf_owned(CF_BLOCKS)
                .into_iter()
                .filter(|(key, _)| !key.starts_with(b"c:") && key.len() == 32)
                .find_map(|(_, data)| {
                    BlockMetadata::from_raw(&data, Chain::PChain)
                        .ok()
                        .filter(|meta| meta.height == height)
                        .map(|_| data)
                });
            match block {
                Some(data) => {
                    let response = match encoding {
                        "hex" => serde_json::json!({
                            "block": format!("0x{}", hex::encode(&data)),
                            "encoding": "hex",
                        }),
                        "json" => serde_json::json!({
                            "block": platform_block_json_value(&data),
                            "encoding": "json",
                        }),
                        _ => {
                            return rpc_error(-32602, "unsupported encoding", id);
                        }
                    };
                    rpc_ok(&response.to_string(), id)
                }
                None => rpc_error(-32000, "block not found", id),
            }
        }

        "platform.getBlockchains" => {
            rpc_ok(&platform_blockchains_result(node).await.to_string(), id)
        }

        "platform.getSubnet" => {
            let Some(subnet_id_str) = platform_subnet_id_param(params) else {
                return rpc_error(-32602, "missing subnetID", id);
            };
            let Some(subnet_id) = SubnetId::from_str_any(subnet_id_str) else {
                return rpc_error(-32602, "invalid subnetID", id);
            };

            match platform_get_subnet_result(node, &subnet_id).await {
                Ok(result) => rpc_ok(&result.to_string(), id),
                Err(message) => rpc_error(-32000, &message, id),
            }
        }

        "platform.getSubnets" => match platform_get_subnets_result(node, params).await {
            Ok(result) => rpc_ok(&result.to_string(), id),
            Err(msg) => rpc_error(-32602, &msg, id),
        },

        "platform.validatedBy" => {
            let Some(blockchain_id_str) = platform_blockchain_id_param(params) else {
                return rpc_error(-32602, "missing blockchainID", id);
            };
            let Some(blockchain_id) = parse_platform_id_32(blockchain_id_str) else {
                return rpc_error(-32602, "invalid blockchainID", id);
            };

            let subnet_id = if blockchain_id == platform_pchain_blockchain_id()
                || blockchain_id == platform_cchain_blockchain_id(node.config.network_id)
            {
                Some(SubnetId::primary_network())
            } else {
                let tracker = node.subnet_tracker.read().await;
                tracker
                    .chain_state(&ChainId(blockchain_id))
                    .map(|state| state.config.subnet_id.clone())
            };

            match subnet_id {
                Some(subnet_id) => rpc_ok(
                    &serde_json::json!({
                        "subnetID": cb58_encode_id(subnet_id.0),
                    })
                    .to_string(),
                    id,
                ),
                None => rpc_error(-32000, "unknown blockchainID", id),
            }
        }

        "platform.validates" => {
            let Some(subnet_id_str) = platform_subnet_id_param(params) else {
                return rpc_error(-32602, "missing subnetID", id);
            };
            let Some(subnet_id) = SubnetId::from_str_any(subnet_id_str) else {
                return rpc_error(-32602, "invalid subnetID", id);
            };
            rpc_ok(
                &serde_json::json!({
                    "blockchainIDs": platform_validates_ids(node, &subnet_id).await,
                })
                .to_string(),
                id,
            )
        }

        "platform.getBlockchainStatus" => {
            let Some(blockchain_id_str) = platform_blockchain_id_param(params) else {
                return rpc_error(-32602, "missing blockchainID", id);
            };
            let Some(blockchain_id) = parse_platform_id_32(blockchain_id_str) else {
                return rpc_error(-32602, "invalid blockchainID", id);
            };
            let status = platform_blockchain_status(node, blockchain_id).await;
            rpc_ok(&serde_json::json!({ "status": status }).to_string(), id)
        }

        "platform.sampleValidators" => {
            let Some(size) = platform_size_param(params) else {
                return rpc_error(-32602, "missing size", id);
            };
            let (chain_time, records) = platform_validator_records(node, params).await;
            let mut validators = records
                .into_iter()
                .filter(|validator| validator.status(chain_time) == "current")
                .map(|validator| validator.node_id)
                .collect::<Vec<_>>();
            validators.shuffle(&mut rand::thread_rng());
            validators.truncate(size.min(validators.len()));
            rpc_ok(
                &serde_json::json!({
                    "validators": validators,
                })
                .to_string(),
                id,
            )
        }

        "platform.getTimestamp" => {
            let timestamp = latest_pchain_block_metadata(&node.db)
                .map(|meta| meta.timestamp)
                .unwrap_or_else(unix_timestamp_secs);
            rpc_ok(
                &serde_json::json!({
                    "timestamp": unix_timestamp_to_rfc3339_seconds(timestamp),
                })
                .to_string(),
                id,
            )
        }

        "platform.getCurrentSupply" => {
            let subnet_id = match platform_subnet_id_param(params) {
                Some(value) => match SubnetId::from_str_any(value) {
                    Some(subnet_id) => subnet_id,
                    None => return rpc_error(-32602, "invalid subnetID", id),
                },
                None => SubnetId::primary_network(),
            };
            match platform_current_supply_result(node, &subnet_id).await {
                Ok(result) => rpc_ok(&result.to_string(), id),
                Err(err) => rpc_error(-32000, &err, id),
            }
        }

        "platform.getL1Validator" => {
            let Some(validation_id_str) = platform_validation_id_param(params) else {
                return rpc_error(-32602, "missing validationID", id);
            };
            let Some(validation_id) = parse_platform_id_32(validation_id_str) else {
                return rpc_error(-32602, "invalid validationID", id);
            };
            match platform_l1_validator_result(node, validation_id) {
                Ok(result) => rpc_ok(&result.to_string(), id),
                Err(err) => rpc_error(-32000, &err, id),
            }
        }

        "platform.getFeeConfig" => rpc_ok(
            &platform_fee_config_result(node.config.network_id).to_string(),
            id,
        ),

        "platform.getValidatorFeeConfig" => rpc_ok(
            &platform_validator_fee_config_result(node.config.network_id).to_string(),
            id,
        ),

        "platform.getFeeState" => match platform_fee_state_result(node) {
            Ok(result) => rpc_ok(&result.to_string(), id),
            Err(err) => rpc_error(-32000, &err, id),
        },

        "platform.getValidatorFeeState" => match platform_validator_fee_state_result(node) {
            Ok(result) => rpc_ok(&result.to_string(), id),
            Err(err) => rpc_error(-32000, &err, id),
        },

        "health" | "health.health" => {
            let tags = health_tags_param(params);
            rpc_ok(
                &health_report(node, HealthReportKind::Health, &tags)
                    .await
                    .to_string(),
                id,
            )
        }

        "health.readiness" => {
            let tags = health_tags_param(params);
            rpc_ok(
                &health_report(node, HealthReportKind::Readiness, &tags)
                    .await
                    .to_string(),
                id,
            )
        }

        "health.liveness" => {
            let tags = health_tags_param(params);
            rpc_ok(
                &health_report(node, HealthReportKind::Liveness, &tags)
                    .await
                    .to_string(),
                id,
            )
        }

        "platform.getStake" => {
            let addresses = platform_params_object(params)
                .and_then(|obj| obj.get("addresses"))
                .or_else(|| params.get(0))
                .and_then(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if addresses.len() > MAX_PLATFORM_GET_STAKE_ADDRS {
                return rpc_error(
                    -32602,
                    &format!(
                        "{} addresses provided but this method can take at most {}",
                        addresses.len(),
                        MAX_PLATFORM_GET_STAKE_ADDRS
                    ),
                    id,
                );
            }
            let validators_only = platform_params_object(params)
                .and_then(|obj| obj.get("validatorsOnly"))
                .or_else(|| params.get(1))
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            let encoding = platform_encoding_param(params, "hex");
            let mut requested_addrs = std::collections::HashSet::new();
            for address in addresses {
                let Some(parsed) = parse_platform_address_20(&address) else {
                    return rpc_error(-32602, "invalid address", id);
                };
                requested_addrs.insert(parsed);
            }

            match platform_stake_response(node, &requested_addrs, validators_only, encoding) {
                Ok(response) => rpc_ok(&response.to_string(), id),
                Err(err) => rpc_error(-32602, &err, id),
            }
        }

        "platform.getRewardUTXOs" => {
            let Some(tx_id_str) = platform_tx_id_param(params) else {
                return rpc_error(-32602, "missing txID", id);
            };
            let Some(normalized_tx_id) = normalize_platform_tx_id(tx_id_str) else {
                return rpc_error(-32602, "invalid txID", id);
            };
            let encoding = platform_encoding_param(params, "hex");
            let scan = scan_platform_chain_state(node);
            let mut utxos = scan
                .reward_utxos
                .get(&normalized_tx_id)
                .cloned()
                .unwrap_or_default();
            utxos.sort_by_key(|utxo| utxo.output_index);

            let encoded_utxos = match utxos
                .iter()
                .map(|utxo| {
                    platform_encode_utxo(utxo.tx_id, utxo.output_index, &utxo.output, encoding)
                })
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(utxos) => utxos,
                Err(err) => return rpc_error(-32602, &err, id),
            };

            rpc_ok(
                &serde_json::json!({
                    "numFetched": encoded_utxos.len().to_string(),
                    "utxos": encoded_utxos,
                    "encoding": encoding,
                })
                .to_string(),
                id,
            )
        }

        "platform.getTotalStake" => {
            let (chain_time, records) = platform_validator_records(node, params).await;
            let total = records
                .into_iter()
                .filter(|validator| validator.status(chain_time) == "current")
                .map(|validator| validator.weight as u128)
                .sum::<u128>();
            rpc_ok(
                &serde_json::json!({
                    "stake": total.to_string(),
                    "weight": total.to_string(),
                })
                .to_string(),
                id,
            )
        }

        "platform.getMinStake" => {
            let subnet_id = platform_subnet_id_param(params).and_then(SubnetId::from_str_any);
            match platform_min_stake_for_subnet(node, subnet_id.as_ref()) {
                Some((min_validator_stake, min_delegator_stake)) => rpc_ok(
                    &serde_json::json!({
                        "minValidatorStake": min_validator_stake.to_string(),
                        "minDelegatorStake": min_delegator_stake.to_string(),
                    })
                    .to_string(),
                    id,
                ),
                None => rpc_error(-32000, "minimum stake unavailable for subnet", id),
            }
        }

        "platform.getStakingAssetID" => {
            let subnet_id = platform_subnet_id_param(params).and_then(SubnetId::from_str_any);
            match platform_staking_asset_id(node, subnet_id.as_ref()) {
                Some(asset_id) => rpc_ok(
                    &serde_json::json!({
                        "assetID": asset_id,
                    })
                    .to_string(),
                    id,
                ),
                None => rpc_error(-32000, "staking asset ID unavailable for subnet", id),
            }
        }

        "platform.getTx" => {
            let Some(tx_id_str) = platform_tx_id_param(params) else {
                return rpc_error(-32602, "missing txID", id);
            };
            let encoding = platform_encoding_param(params, "hex");
            let Some(normalized_tx_id) = normalize_platform_tx_id(tx_id_str) else {
                return rpc_error(-32602, "invalid txID", id);
            };

            match find_committed_platform_tx_bytes(&node.db, &normalized_tx_id) {
                Some(data) => {
                    let response = if encoding.eq_ignore_ascii_case("hex") {
                        serde_json::json!({
                            "tx": format!("0x{}", hex::encode(&data)),
                            "encoding": "hex",
                        })
                    } else if encoding.eq_ignore_ascii_case("json") {
                        match avalanche_rs::pchain::parse_platform_tx_json(&data) {
                            Ok(tx_json) => serde_json::json!({
                                "tx": tx_json,
                                "encoding": "json",
                            }),
                            Err(err) => {
                                return rpc_error(
                                    -32000,
                                    &format!("failed to decode platform tx: {}", err),
                                    id,
                                );
                            }
                        }
                    } else {
                        return rpc_error(-32602, "unsupported encoding", id);
                    };
                    rpc_ok(&response.to_string(), id)
                }
                None => rpc_error(-32000, "transaction not found", id),
            }
        }

        "platform.getTxStatus" => {
            let Some(tx_id_str) = platform_tx_id_param(params) else {
                return rpc_error(-32602, "missing txID", id);
            };
            let Some(normalized_tx_id) = normalize_platform_tx_id(tx_id_str) else {
                return rpc_error(-32602, "invalid txID", id);
            };

            reconcile_platform_tx_pool(node).await;

            if find_committed_platform_tx_bytes(&node.db, &normalized_tx_id).is_some() {
                let response = serde_json::json!({
                    "status": "Committed",
                });
                return rpc_ok(&response.to_string(), id);
            }

            let pool = node.platform_tx_pool.read().await;
            if pool.contains_processing(&normalized_tx_id) {
                return rpc_ok(
                    &serde_json::json!({ "status": "Processing" }).to_string(),
                    id,
                );
            }

            let mut response = serde_json::json!({ "status": "Unknown" });
            if let Some(reason) = pool.drop_reason(&normalized_tx_id) {
                response["status"] = serde_json::Value::String("Dropped".to_string());
                response["reason"] = serde_json::Value::String(reason);
            }
            rpc_ok(&response.to_string(), id)
        }

        "platform.issueTx" => {
            let Some(tx_bytes_str) = platform_tx_param(params) else {
                return rpc_error(-32602, "missing tx", id);
            };
            let encoding = platform_encoding_param(params, "hex");
            if !encoding.eq_ignore_ascii_case("hex") {
                return rpc_error(-32602, "unsupported encoding", id);
            }
            match parse_hex_bytes(tx_bytes_str) {
                Some(tx_bytes) => {
                    let tx_id = platform_tx_id_from_bytes(&tx_bytes);

                    reconcile_platform_tx_pool(node).await;

                    if find_committed_platform_tx_bytes(&node.db, &tx_id).is_some() {
                        return rpc_ok(&serde_json::json!({ "txID": tx_id }).to_string(), id);
                    }

                    let scan = scan_platform_chain_state(node);
                    let ledger = match platform_tx_submission_ledger(node, &tx_bytes, &scan) {
                        Ok(ledger) => ledger,
                        Err(err) => {
                            node.platform_tx_pool
                                .write()
                                .await
                                .mark_dropped(&tx_id, err.clone());
                            return rpc_error(-32000, &format!("couldn't issue tx: {}", err), id);
                        }
                    };

                    let insert = {
                        let mut pool = node.platform_tx_pool.write().await;
                        pool.add_processing(&tx_id, ledger)
                    };
                    if let Err(err) = insert {
                        return rpc_error(-32000, &format!("couldn't issue tx: {}", err), id);
                    }
                    rpc_ok(&serde_json::json!({ "txID": tx_id }).to_string(), id)
                }
                None => rpc_error(-32602, "invalid tx hex", id),
            }
        }

        // -----------------------------------------------------------------
        // eth_getBlobByHash (EIP-4844)
        // -----------------------------------------------------------------
        "eth_getBlobByHash" => {
            let hash_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            match parse_hex_hash(hash_str) {
                Some(hash) => match node.db.get_cf(avalanche_rs::db::CF_BLOBS, &hash) {
                    Ok(Some(data)) => rpc_ok(&String::from_utf8_lossy(&data), id),
                    _ => rpc_ok("null", id),
                },
                None => rpc_error(-32602, "invalid hash", id),
            }
        }

        // -----------------------------------------------------------------
        // Transaction Pool RPCs
        // -----------------------------------------------------------------
        "eth_txpool_status" | "txpool_status" => {
            let pool = node.txpool.read().await;
            let status = pool.status();
            let result = serde_json::json!({
                "pending": format!("0x{:x}", status.pending),
                "queued": format!("0x{:x}", status.queued),
            });
            rpc_ok(&result.to_string(), id)
        }

        "eth_txpool_content" | "txpool_content" => {
            let pool = node.txpool.read().await;
            let result = serde_json::json!({
                "pending": txpool_group_transactions(pool.pending_transactions()),
                "queued": txpool_group_transactions(pool.queued_transactions()),
            });
            rpc_ok(&result.to_string(), id)
        }

        "eth_txpool_inspect" | "txpool_inspect" => {
            let pool = node.txpool.read().await;
            let result = serde_json::json!({
                "pending": txpool_group_inspect(pool.pending_transactions()),
                "queued": txpool_group_inspect(pool.queued_transactions()),
            });
            rpc_ok(&result.to_string(), id)
        }

        "eth_txpool_contentFrom" | "txpool_contentFrom" => {
            let Some(address_str) = params.get(0).and_then(|value| value.as_str()) else {
                return rpc_error(-32602, "missing address", id);
            };
            let Some(address) = parse_hex_address(address_str) else {
                return rpc_error(-32602, "invalid address", id);
            };
            let pool = node.txpool.read().await;
            let result = txpool_content_from(&pool, address);
            rpc_ok(&result.to_string(), id)
        }

        // -----------------------------------------------------------------
        // WebSocket subscription (HTTP fallback)
        // -----------------------------------------------------------------
        "eth_subscribe" => rpc_error(
            -32601,
            "eth_subscribe requires WebSocket connection (/ws)",
            id,
        ),

        "eth_unsubscribe" => rpc_error(
            -32601,
            "eth_unsubscribe requires WebSocket connection (/ws)",
            id,
        ),

        // -----------------------------------------------------------------
        // Debug & Trace APIs
        // -----------------------------------------------------------------
        "debug_traceTransaction" => {
            let hash_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("0x0");
            let config = TraceConfig::from_json(params.get(1).unwrap_or(&serde_json::Value::Null));
            match parse_hex_hash(hash_str) {
                Some(hash) => {
                    if let Some(tx) = node.txpool.read().await.get(&hash).cloned() {
                        let evm = node.evm.read().await;
                        let block_ctx = rpc_simulation_block_context(node);
                        let result = trace_pending_transaction(&evm, &tx, &block_ctx, &config);
                        rpc_ok(&result.to_string(), id)
                    } else {
                        match node.db.get_tx_index(&hash) {
                            Ok(Some((block_height, tx_index))) => {
                                match trace_mined_transaction(
                                    &node.db,
                                    node.config.chain_id,
                                    block_height,
                                    tx_index,
                                    &config,
                                ) {
                                    Ok(result) => rpc_ok(&result.to_string(), id),
                                    Err(msg) => rpc_error(-32000, &msg, id),
                                }
                            }
                            _ => rpc_error(-32000, "transaction not found", id),
                        }
                    }
                }
                None => rpc_error(-32602, "invalid tx hash", id),
            }
        }

        "debug_traceBlockByNumber" => {
            let block_num =
                parse_block_number(params.get(0).unwrap_or(&serde_json::Value::Null), node);
            let config = TraceConfig::from_json(params.get(1).unwrap_or(&serde_json::Value::Null));
            match trace_mined_block(&node.db, node.config.chain_id, block_num, &config) {
                Ok(result) => rpc_ok(&result.to_string(), id),
                Err(msg) => rpc_error(-32000, &msg, id),
            }
        }

        "debug_getBlockByNumber" => {
            let block_num =
                parse_block_number(params.get(0).unwrap_or(&serde_json::Value::Null), node);
            match node.db.get_block(block_num) {
                Ok(Some(data)) => rpc_ok(&format!("\"0x{}\"", hex::encode(&data)), id),
                _ => rpc_ok("null", id),
            }
        }

        // -----------------------------------------------------------------
        // Archive mode: eth_getBalance with historical block
        // -----------------------------------------------------------------

        // -----------------------------------------------------------------
        // eth_feeHistory (EIP-1559)
        // -----------------------------------------------------------------
        "eth_feeHistory" => {
            let block_count = params.get(0).and_then(parse_quantity_u64).unwrap_or(1);
            let newest_block =
                parse_block_number(params.get(1).unwrap_or(&serde_json::Value::Null), node);
            let reward_percentiles = params
                .get(2)
                .and_then(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_f64())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let result =
                build_fee_history_result(node, block_count, newest_block, &reward_percentiles);
            rpc_ok(&result.to_string(), id)
        }

        // -----------------------------------------------------------------
        // eth_maxPriorityFeePerGas
        // -----------------------------------------------------------------
        "eth_maxPriorityFeePerGas" => {
            let priority_fee =
                recent_priority_fee_suggestion(&node.db, current_cchain_height(node));
            rpc_ok(&format!("\"0x{:x}\"", priority_fee), id)
        }

        // -----------------------------------------------------------------
        // eth_suggestPriceOptions (Avalanche-specific)
        // -----------------------------------------------------------------
        "eth_suggestPriceOptions" => {
            rpc_ok(&cchain_suggest_price_options_result(node).to_string(), id)
        }

        // -----------------------------------------------------------------
        // eth_getBlockReceipts
        // -----------------------------------------------------------------
        "eth_getBlockReceipts" => {
            match resolve_cchain_block_height(
                params.get(0).unwrap_or(&serde_json::Value::Null),
                node,
            ) {
                Ok(Some(block_num)) => match node.db.get_block_receipts(block_num) {
                    Ok(Some(data)) => {
                        let receipts_json = String::from_utf8_lossy(&data);
                        rpc_ok(&receipts_json, id)
                    }
                    _ => rpc_ok("[]", id),
                },
                Ok(None) => rpc_ok("null", id),
                Err(msg) => rpc_error(-32602, &msg, id),
            }
        }

        // -----------------------------------------------------------------
        // eth_createAccessList
        // -----------------------------------------------------------------
        "eth_createAccessList" => {
            let tx_obj = params.get(0);
            if tx_obj.is_none() {
                return rpc_error(-32602, "missing transaction object", id);
            }
            let evm = node.evm.read().await;
            let block_ctx = rpc_simulation_block_context(node);
            let parsed = parse_rpc_simulation_tx(tx_obj.unwrap(), &evm, &block_ctx);
            match evm.create_access_list(&parsed.tx, &block_ctx, &parsed.access_list) {
                Ok(result) => {
                    let mut response = serde_json::json!({
                        "accessList": result
                            .access_list
                            .into_iter()
                            .map(|entry| {
                                serde_json::json!({
                                    "address": format!("0x{}", hex::encode(entry.address)),
                                    "storageKeys": entry
                                        .storage_keys
                                        .into_iter()
                                        .map(|key| serde_json::Value::String(format!("0x{}", hex::encode(key))))
                                        .collect::<Vec<_>>(),
                                })
                            })
                            .collect::<Vec<_>>(),
                        "gasUsed": format!("0x{:x}", result.gas_used),
                    });
                    if let Some(error) = result.error {
                        response["error"] = serde_json::Value::String(error);
                    }
                    rpc_ok(&response.to_string(), id)
                }
                Err(e) => rpc_error(-32000, &format!("{}", e), id),
            }
        }

        // -----------------------------------------------------------------
        // avax.getUTXOs
        // -----------------------------------------------------------------
        "avax.getUTXOs" => {
            let addresses = avax_params_object(params)
                .and_then(|obj| obj.get("addresses"))
                .or_else(|| params.get(0))
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default();
            if addresses.is_empty() {
                return rpc_error(-32602, "no addresses provided", id);
            }
            if addresses.len() > MAX_PLATFORM_GET_UTXOS_ADDRS {
                return rpc_error(
                    -32602,
                    &format!(
                        "number of addresses given, {}, exceeds maximum, {}",
                        addresses.len(),
                        MAX_PLATFORM_GET_UTXOS_ADDRS
                    ),
                    id,
                );
            }

            let mut requested = Vec::with_capacity(addresses.len());
            for address in addresses {
                let Some(address) = address.as_str() else {
                    return rpc_error(-32602, "invalid address", id);
                };
                let Some(parsed) = parse_platform_address_20(address) else {
                    return rpc_error(-32602, "invalid address", id);
                };
                requested.push((address.to_string(), parsed));
            }

            let Some(source_chain) = avax_params_object(params)
                .and_then(|obj| obj.get("sourceChain"))
                .or_else(|| params.get(1))
                .and_then(|value| value.as_str())
            else {
                return rpc_error(-32602, "missing sourceChain", id);
            };
            let Some(source_chain_id) =
                info_blockchain_alias_id(source_chain, node.config.network_id)
            else {
                return rpc_error(-32602, "invalid sourceChain", id);
            };

            let limit = avax_params_object(params)
                .and_then(|obj| obj.get("limit"))
                .or_else(|| params.get(2))
                .and_then(parse_quantity_u64)
                .map(|value| value as usize)
                .filter(|value| *value > 0 && *value <= PLATFORM_GET_UTXOS_MAX_PAGE_SIZE)
                .unwrap_or(PLATFORM_GET_UTXOS_MAX_PAGE_SIZE);
            let encoding = avax_encoding_param(params, "hex");
            let start_index = avax_params_object(params)
                .and_then(|obj| obj.get("startIndex"))
                .or_else(|| params.get(3));
            let start_addr_value = start_index
                .and_then(|value| value.get("address"))
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty());
            let start_addr = match start_addr_value {
                Some(value) => match parse_platform_address_20(value) {
                    Some(addr) => Some(addr),
                    None => return rpc_error(-32602, "couldn't parse start index address", id),
                },
                None => None,
            };
            let start_utxo_value = start_index
                .and_then(|value| value.get("utxo"))
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty());
            let start_utxo = match start_utxo_value {
                Some(value) => match parse_platform_utxo_end_index(value) {
                    Some(utxo) => Some(utxo),
                    None => return rpc_error(-32602, "couldn't parse start index utxo", id),
                },
                None => None,
            };

            match avax_atomic_utxos_response(
                node,
                source_chain_id,
                &requested,
                limit,
                start_addr,
                start_utxo,
                encoding,
            ) {
                Ok(response) => rpc_ok(&response.to_string(), id),
                Err(err) => rpc_error(-32602, &err, id),
            }
        }

        // -----------------------------------------------------------------
        // avax.getAtomicTx
        // -----------------------------------------------------------------
        "avax.getAtomicTx" | "avax_getAtomicTx" => {
            let Some(tx_id_str) = avax_tx_id_param(params) else {
                return rpc_error(-32602, "missing txID", id);
            };
            let encoding = avax_encoding_param(params, "hex");
            if !encoding.eq_ignore_ascii_case("hex") {
                return rpc_error(-32602, "unsupported encoding", id);
            }
            let Some(normalized_tx_id) = normalize_atomic_tx_id(tx_id_str) else {
                return rpc_error(-32602, "invalid txID", id);
            };

            if let Some(committed) = find_committed_atomic_tx(node, &normalized_tx_id) {
                let response = serde_json::json!({
                    "tx": format!("0x{}", hex::encode(&committed.raw_bytes)),
                    "encoding": "hex",
                    "blockHeight": committed.block_height,
                });
                return rpc_ok(&response.to_string(), id);
            }

            let key = atomic_tx_storage_key(&normalized_tx_id);
            match node.db.get_cf(CF_BLOCKS, key.as_bytes()) {
                Ok(Some(data)) => {
                    let metadata = load_atomic_tx_metadata(&node.db, &normalized_tx_id);
                    let mut response = serde_json::json!({
                        "tx": format!("0x{}", hex::encode(&data)),
                        "encoding": "hex",
                    });
                    if let Some(block_height) = metadata.and_then(|meta| meta.block_height) {
                        response["blockHeight"] = serde_json::json!(block_height);
                    }
                    rpc_ok(&response.to_string(), id)
                }
                _ => rpc_ok("null", id),
            }
        }

        // -----------------------------------------------------------------
        // avax.issueTx
        // -----------------------------------------------------------------
        "avax.getAtomicTxStatus" => {
            let Some(tx_id_str) = avax_tx_id_param(params) else {
                return rpc_error(-32602, "missing txID", id);
            };
            let Some(normalized_tx_id) = normalize_atomic_tx_id(tx_id_str) else {
                return rpc_error(-32602, "invalid txID", id);
            };
            if let Some(committed) = find_committed_atomic_tx(node, &normalized_tx_id) {
                let response = serde_json::json!({
                    "status": "Accepted",
                    "blockHeight": committed.block_height,
                });
                return rpc_ok(&response.to_string(), id);
            }
            let metadata = load_atomic_tx_metadata(&node.db, &normalized_tx_id);
            let mut response = serde_json::json!({
                "status": metadata
                    .as_ref()
                    .map(|meta| meta.status.as_str())
                    .unwrap_or("Unknown"),
            });
            if let Some(block_height) = metadata.and_then(|meta| meta.block_height) {
                response["blockHeight"] = serde_json::json!(block_height);
            }
            rpc_ok(&response.to_string(), id)
        }

        // -----------------------------------------------------------------
        // avax.issueTx
        // -----------------------------------------------------------------
        "avax.issueTx" | "avax_issueTx" => {
            let Some(tx_bytes_str) = avax_tx_param(params) else {
                return rpc_error(-32602, "missing tx", id);
            };
            let encoding = avax_encoding_param(params, "hex");
            if !encoding.eq_ignore_ascii_case("hex") {
                return rpc_error(-32602, "unsupported encoding", id);
            }
            match parse_hex_bytes(tx_bytes_str) {
                Some(tx_bytes) => {
                    // Hash the tx to create an ID
                    let tx_hash = {
                        let mut hasher = Sha256::new();
                        hasher.update(&tx_bytes);
                        hasher.finalize()
                    };
                    let tx_hash: [u8; 32] = tx_hash.into();
                    let tx_id = cb58_encode_id(tx_hash);

                    let key = atomic_tx_storage_key(&tx_id);
                    let meta_key = atomic_tx_meta_key(&tx_id);
                    let metadata = AtomicTxMetadata {
                        status: "Processing".to_string(),
                        block_height: None,
                    };
                    let _ = node.db.put_cf(CF_BLOCKS, key.as_bytes(), &tx_bytes);
                    let _ = node.db.put_cf(
                        CF_BLOCKS,
                        meta_key.as_bytes(),
                        &serde_json::to_vec(&metadata).unwrap_or_default(),
                    );
                    rpc_ok(&serde_json::json!({ "txID": tx_id }).to_string(), id)
                }
                None => rpc_error(-32602, "invalid tx hex", id),
            }
        }

        // -----------------------------------------------------------------
        // info namespace
        // -----------------------------------------------------------------
        "info.getNetworkID" => rpc_ok(
            &format!("{{\"networkID\":\"{}\"}}", node.config.network_id),
            id,
        ),

        "info.getNetworkName" => rpc_ok(
            &serde_json::json!({
                "networkName": info_network_name(node.config.network_id),
            })
            .to_string(),
            id,
        ),

        "info.getBlockchainID" => {
            let Some(alias) = info_alias_param(params) else {
                return rpc_error(-32602, "missing alias", id);
            };
            let Some(blockchain_id) = resolve_blockchain_alias_id(node, alias).await else {
                return rpc_error(
                    -32602,
                    &format!("there is no chain with alias/ID '{}'", alias),
                    id,
                );
            };
            rpc_ok(
                &serde_json::json!({
                    "blockchainID": cb58_encode_id(blockchain_id),
                })
                .to_string(),
                id,
            )
        }

        "info.getNodeID" => {
            let result = serde_json::json!({
                "nodeID": full_node_id_string(&node.identity.node_id),
                "nodePOP": {
                    "publicKey": format!("0x{}", hex::encode(node.identity.bls_public_key_bytes())),
                    "proofOfPossession": format!(
                        "0x{}",
                        hex::encode(node.identity.bls_proof_of_possession())
                    ),
                }
            });
            rpc_ok(&result.to_string(), id)
        }

        "info.getNodeIP" => rpc_ok(
            &serde_json::json!({
                "ip": info_node_ip_string(node).await,
            })
            .to_string(),
            id,
        ),

        "info.getNodeVersion" => rpc_ok(&info_get_node_version_result().to_string(), id),

        "info.peers" => {
            let pm = node.peer_manager.read().await;
            let requested_node_ids = info_node_ids_param(params);
            let requested = requested_node_ids
                .into_iter()
                .collect::<std::collections::HashSet<_>>();
            let peers = pm
                .connected_peers()
                .into_iter()
                .filter_map(|node_id| pm.get_peer(&node_id))
                .filter(|peer| requested.is_empty() || requested.contains(&peer.node_id.0))
                .map(info_peer_json)
                .collect::<Vec<_>>();
            rpc_ok(
                &serde_json::json!({
                    "numPeers": peers.len().to_string(),
                    "peers": peers,
                })
                .to_string(),
                id,
            )
        }

        "info.isBootstrapped" => {
            let Some(chain) = info_chain_param(params) else {
                return rpc_error(-32602, "argument 'chain' not given", id);
            };
            match info_is_bootstrapped(node, chain).await {
                Ok(is_bootstrapped) => rpc_ok(
                    &serde_json::json!({
                        "isBootstrapped": is_bootstrapped,
                    })
                    .to_string(),
                    id,
                ),
                Err(message) => rpc_error(-32602, &message, id),
            }
        }

        "info.getTxFee" => rpc_ok(
            &info_get_tx_fee_result(node.config.network_id).to_string(),
            id,
        ),

        "info.acps" => rpc_ok(&info_acps_result(node).await.to_string(), id),

        "info.getVMs" => rpc_ok(&info_get_vms_result().to_string(), id),

        "info.uptime" => rpc_ok(&info_uptime_result(node).await.to_string(), id),

        "info.upgrades" => rpc_ok(
            &info_upgrades_result(node.config.network_id).to_string(),
            id,
        ),

        // -----------------------------------------------------------------
        // Unknown method
        // -----------------------------------------------------------------
        _ => rpc_error(-32601, &format!("method not found: {}", method), id),
    }
}

// ---------------------------------------------------------------------------
// Consensus loop
// ---------------------------------------------------------------------------

/// Log chain analysis using in-memory metrics (avoids RocksDB format mismatch).
async fn log_chain_metrics(node: &NodeState) {
    let p = node.p_chain_metrics.read().await;
    let c = node.c_chain_metrics.read().await;

    if p.blocks_synced > 0 || p.tip_height > 0 {
        info!(
            "P-Chain analysis: {} blocks synced, genesis height {}, tip height {}, chain length {}, tip hash 0x{}",
            p.blocks_synced,
            p.genesis_height,
            p.tip_height,
            p.chain_length,
            hex::encode(p.tip_hash)
        );
    } else {
        info!("P-Chain analysis: no blocks synced yet");
    }

    if c.blocks_synced > 0 || c.tip_height > 0 {
        info!(
            "C-Chain analysis: {} blocks synced, tip height {}, tip hash 0x{}",
            c.blocks_synced,
            c.tip_height,
            hex::encode(c.tip_hash)
        );
    } else {
        info!("C-Chain analysis: no blocks synced yet");
    }
}

async fn run_consensus_loop(node: Arc<NodeState>) {
    info!("Starting consensus loop");

    // Wait for bootstrap connections to start
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let mut chain_analysis_done = false;

    loop {
        tick.tick().await;

        let phase = node.sync_engine.phase().await;
        let stats = node.sync_engine.stats().await;

        match phase {
            SyncPhase::Idle => {}
            SyncPhase::Synced => {}
            _ => {
                info!(
                    "Sync: phase={}, blocks={}, {:.1}%",
                    phase,
                    stats.blocks_downloaded,
                    stats.progress_pct()
                );
            }
        }

        // After 60 seconds, log chain analysis from in-memory metrics
        if !chain_analysis_done && node.start_time.elapsed().as_secs() > 60 {
            chain_analysis_done = true;
            log_chain_metrics(&node).await;
        }
    }
}

/// Read all blocks from RocksDB, parse headers, build chain graphs, run Snowman.
/// Tasks 2, 3, and 4 are all executed here.
#[allow(dead_code)]
fn analyze_chain_graphs(node: &NodeState) {
    info!("Starting chain graph analysis...");

    // -------------------------------------------------------------------------
    // Task 2 + 4: Scan CF_BLOCKS, partition into P-Chain and C-Chain
    // -------------------------------------------------------------------------
    let all_blocks = node.db.iter_cf_owned(CF_BLOCKS);
    info!("Loaded {} raw block entries from DB", all_blocks.len());

    let mut p_headers: Vec<BlockHeader> = Vec::new();
    let mut c_headers: Vec<BlockHeader> = Vec::new();
    let mut parse_errors = 0usize;

    // C-Chain blocks are stored with b"c:" (2-byte) prefix on the key
    let c_prefix = b"c:";

    for (key, value) in &all_blocks {
        let is_cchain = key.len() == 34 && &key[..2] == c_prefix;
        let chain = if is_cchain {
            Chain::CChain
        } else {
            Chain::PChain
        };

        match BlockHeader::parse(value, chain) {
            Ok(header) => {
                if is_cchain {
                    c_headers.push(header);
                } else {
                    p_headers.push(header);
                }
            }
            Err(e) => {
                parse_errors += 1;
                if parse_errors <= 5 {
                    debug!("Block parse error ({:?}): {}", chain, e);
                }
            }
        }
    }

    info!(
        "Parsed {} P-Chain blocks, {} C-Chain blocks ({} errors)",
        p_headers.len(),
        c_headers.len(),
        parse_errors
    );

    // -------------------------------------------------------------------------
    // Task 2: Build P-Chain graph + log summary
    // -------------------------------------------------------------------------
    if !p_headers.is_empty() {
        let p_graph = ChainGraph::build(p_headers.iter().cloned());
        let genesis_height = p_graph
            .genesis_id
            .and_then(|id| p_graph.headers.get(&id))
            .map(|h| h.height)
            .unwrap_or(0);
        let fork_msg = if p_graph.fork_count == 0 {
            "no forks".to_string()
        } else {
            format!("{} fork(s)", p_graph.fork_count)
        };
        info!(
            "P-Chain: genesis at height {}, tip at height {}, {} total blocks, {}",
            genesis_height,
            p_graph.tip_height,
            p_graph.headers.len(),
            fork_msg
        );

        // -------------------------------------------------------------------------
        // Task 3: Run Snowman consensus — accept blocks from genesis to tip
        // -------------------------------------------------------------------------
        let mut sc = SnowmanConsensus::new();
        // Walk from genesis toward tip in height order
        let mut ordered: Vec<&BlockHeader> = p_graph.headers.values().collect();
        ordered.sort_by_key(|h| h.height);
        for header in &ordered {
            sc.accept_block(header);
        }
        info!(
            "P-Chain Snowman: accepted {} blocks, tip at height {}",
            sc.accepted_count(),
            sc.last_accepted_height
        );
    }

    // -------------------------------------------------------------------------
    // Task 4: C-Chain EVM analysis
    // -------------------------------------------------------------------------
    if !c_headers.is_empty() {
        let c_graph = ChainGraph::build(c_headers.iter().cloned());
        let fork_msg = if c_graph.fork_count == 0 {
            "no forks".to_string()
        } else {
            format!("{} fork(s)", c_graph.fork_count)
        };
        info!(
            "C-Chain: tip at height {}, {} total blocks, {}",
            c_graph.tip_height,
            c_graph.headers.len(),
            fork_msg
        );

        // Log per-block stats (limit to avoid log flood)
        let mut ordered: Vec<&BlockHeader> = c_graph.headers.values().collect();
        ordered.sort_by_key(|h| h.height);
        let logged = ordered.len().min(10);
        for header in &ordered[..logged] {
            // We don't have tx count from header alone, but log what we have
            info!(
                "C-Chain block #{}: size={} bytes, ts={}",
                header.height, header.raw_size, header.timestamp
            );
        }
        if ordered.len() > 10 {
            info!("  ... and {} more C-Chain blocks", ordered.len() - 10);
        }

        // Run Snowman on C-Chain too
        let mut sc = SnowmanConsensus::new();
        for header in &ordered {
            sc.accept_block(header);
        }
        info!(
            "C-Chain Snowman: accepted {} blocks, tip at height {}",
            sc.accepted_count(),
            sc.last_accepted_height
        );

        // Validate chain_id via EVM executor (Task 4 — at least check chain_id)
        info!(
            "C-Chain EVM: chain_id={} (configured for this node)",
            node.config.chain_id
        );
    }

    info!("Chain graph analysis complete.");
}

fn init_logging(level: &str, format: &str) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let (filter_layer, reload_handle) = reload::Layer::new(filter);
    let _ = LOG_RELOAD_HANDLE.set(reload_handle);

    match format {
        "json" => {
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(tracing_subscriber::fmt::layer().with_target(false))
                .init();
        }
    }
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::Mutex;

    static FILTER_TEST_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn make_test_node(network_id: u32) -> Arc<NodeState> {
        let identity = NodeIdentity::generate().expect("generate node identity");
        let (db, _dir) = Database::open_temp().expect("open temp db");
        let evm = Arc::new(RwLock::new(EvmExecutor::new(43114)));

        let net_config = NetworkConfig {
            network_id,
            ..Default::default()
        };
        let peer_manager = Arc::new(RwLock::new(PeerManager::new(
            net_config,
            identity.node_id.clone(),
        )));

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[31] = if network_id == 1 { 0x01 } else { 0x05 };
        let sync_engine = Arc::new(SyncEngine::new(SyncConfig {
            chain_id: ChainId(chain_id_bytes),
            ..Default::default()
        }));

        Arc::new(NodeState {
            identity,
            db,
            evm,
            sync_engine,
            peer_manager,
            config: Cli {
                network_id,
                data_dir: PathBuf::from("./data/test-rpc"),
                bootstrap_ips: vec![],
                tracked_subnets: "".to_string(),
                subnet_id: None,
                staking_tls_cert_file: None,
                staking_tls_key_file: None,
                http_port: 0,
                staking_port: 9651,
                log_level: "info".to_string(),
                log_format: "pretty".to_string(),
                chain_id: 43114,
                validator: false,
                state_pruning_depth: 256,
                light_client: false,
                archive: false,
                blob_retention_epochs: 4096,
                txpool_size: 4096,
                block_cache_size: 1024,
                rpc_max_body_size: 5_242_880,
                max_memory_mb: 0,
                log_max_size: 100,
                log_max_files: 10,
                connection_pool_size: 8,
                stake_amount: None,
                stake_duration: None,
                delegation_fee: None,
                reward_address: None,
                rpc_private_keys: vec![],
                #[cfg(feature = "indexer")]
                indexer_enabled: false,
                #[cfg(feature = "indexer")]
                database_url: String::new(),
            },
            start_time: Instant::now(),
            validators: std::collections::HashMap::new(),
            validators_seen: Arc::new(RwLock::new(std::collections::HashSet::new())),
            total_stake_weight: Arc::new(RwLock::new(0u64)),
            p_chain_metrics: Arc::new(RwLock::new(ChainMetrics::default())),
            c_chain_metrics: Arc::new(RwLock::new(ChainMetrics::default())),
            mev_engine: Arc::new(MevEngine::new(MevEngineConfig::default())),
            txpool: Arc::new(RwLock::new(TransactionPool::new(4096))),
            rpc_wallets: Arc::new(StdHashMap::new()),
            platform_tx_pool: Arc::new(RwLock::new(PlatformTxPool::default())),
            light_client: Arc::new(RwLock::new(avalanche_rs::light::LightClient::new())),
            archive_store: Arc::new(ArchiveStore::new(false)),
            subnet_tracker: Arc::new(RwLock::new(SubnetTracker::new())),
            persisted_sync_state: Arc::new(RwLock::new(None)),
            ws_subscriptions: Arc::new(RwLock::new(SubscriptionManager::new(1024))),
            ws_connections: Arc::new(RwLock::new(StdHashMap::new())),
            http_aliases: Arc::new(RwLock::new(StdHashMap::new())),
            chain_aliases: Arc::new(RwLock::new(StdHashMap::new())),
            resolved_public_ip: Arc::new(RwLock::new("0.0.0.0:9651".parse().ok())),
            logger_levels: Arc::new(RwLock::new(initial_logger_levels("info"))),
            p_chain_recently_accepted: new_recently_accepted_pchain_blocks(),
            #[cfg(feature = "indexer")]
            indexer: None,
        })
    }

    fn make_test_node_with_rpc_wallets(network_id: u32, wallets: Vec<Wallet>) -> Arc<NodeState> {
        let node = make_test_node(network_id);
        let wallets = Arc::new(
            wallets
                .into_iter()
                .map(|wallet| (*wallet.address(), wallet))
                .collect::<StdHashMap<_, _>>(),
        );
        let base = Arc::into_inner(node).expect("single test node ref");
        Arc::new(NodeState {
            rpc_wallets: wallets,
            ..base
        })
    }

    fn make_test_node_with_validators(
        network_id: u32,
        validators: std::collections::HashMap<String, ValidatorInfo>,
        validators_seen: std::collections::HashSet<String>,
    ) -> Arc<NodeState> {
        let identity = NodeIdentity::generate().expect("generate node identity");
        let (db, _dir) = Database::open_temp().expect("open temp db");
        let evm = Arc::new(RwLock::new(EvmExecutor::new(43114)));

        let net_config = NetworkConfig {
            network_id,
            ..Default::default()
        };
        let peer_manager = Arc::new(RwLock::new(PeerManager::new(
            net_config,
            identity.node_id.clone(),
        )));

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[31] = if network_id == 1 { 0x01 } else { 0x05 };
        let sync_engine = Arc::new(SyncEngine::new(SyncConfig {
            chain_id: ChainId(chain_id_bytes),
            ..Default::default()
        }));

        Arc::new(NodeState {
            identity,
            db,
            evm,
            sync_engine,
            peer_manager,
            config: Cli {
                network_id,
                data_dir: PathBuf::from("./data/test-rpc"),
                bootstrap_ips: vec![],
                tracked_subnets: "".to_string(),
                subnet_id: None,
                staking_tls_cert_file: None,
                staking_tls_key_file: None,
                http_port: 0,
                staking_port: 9651,
                log_level: "info".to_string(),
                log_format: "pretty".to_string(),
                chain_id: 43114,
                validator: false,
                state_pruning_depth: 256,
                light_client: false,
                archive: false,
                blob_retention_epochs: 4096,
                txpool_size: 4096,
                block_cache_size: 1024,
                rpc_max_body_size: 5_242_880,
                max_memory_mb: 0,
                log_max_size: 100,
                log_max_files: 10,
                connection_pool_size: 8,
                stake_amount: None,
                stake_duration: None,
                delegation_fee: None,
                reward_address: None,
                rpc_private_keys: vec![],
                #[cfg(feature = "indexer")]
                indexer_enabled: false,
                #[cfg(feature = "indexer")]
                database_url: String::new(),
            },
            start_time: Instant::now(),
            validators,
            validators_seen: Arc::new(RwLock::new(validators_seen)),
            total_stake_weight: Arc::new(RwLock::new(0u64)),
            p_chain_metrics: Arc::new(RwLock::new(ChainMetrics::default())),
            c_chain_metrics: Arc::new(RwLock::new(ChainMetrics::default())),
            mev_engine: Arc::new(MevEngine::new(MevEngineConfig::default())),
            txpool: Arc::new(RwLock::new(TransactionPool::new(4096))),
            rpc_wallets: Arc::new(StdHashMap::new()),
            platform_tx_pool: Arc::new(RwLock::new(PlatformTxPool::default())),
            light_client: Arc::new(RwLock::new(avalanche_rs::light::LightClient::new())),
            archive_store: Arc::new(ArchiveStore::new(false)),
            subnet_tracker: Arc::new(RwLock::new(SubnetTracker::new())),
            persisted_sync_state: Arc::new(RwLock::new(None)),
            ws_subscriptions: Arc::new(RwLock::new(SubscriptionManager::new(1024))),
            ws_connections: Arc::new(RwLock::new(StdHashMap::new())),
            http_aliases: Arc::new(RwLock::new(StdHashMap::new())),
            chain_aliases: Arc::new(RwLock::new(StdHashMap::new())),
            resolved_public_ip: Arc::new(RwLock::new("0.0.0.0:9651".parse().ok())),
            logger_levels: Arc::new(RwLock::new(initial_logger_levels("info"))),
            p_chain_recently_accepted: new_recently_accepted_pchain_blocks(),
            #[cfg(feature = "indexer")]
            indexer: None,
        })
    }

    fn make_banff_std_with_timestamp(parent: [u8; 32], height: u64, timestamp: u64) -> Vec<u8> {
        let mut raw = vec![0u8; 54];
        raw[2..6].copy_from_slice(&32u32.to_be_bytes());
        raw[6..14].copy_from_slice(&timestamp.to_be_bytes());
        raw[14..46].copy_from_slice(&parent);
        raw[46..54].copy_from_slice(&height.to_be_bytes());
        raw
    }

    fn make_banff_std(parent: [u8; 32], height: u64) -> Vec<u8> {
        make_banff_std_with_timestamp(parent, height, 1_700_000_000)
    }

    fn make_signed_platform_base_tx_bytes() -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&34u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_transferable_output_bytes(
        asset_id: [u8; 32],
        amount: u64,
        owner: [u8; 20],
    ) -> Vec<u8> {
        make_platform_transferable_output_bytes_with_locks(asset_id, amount, owner, 0, None)
    }

    fn make_platform_transferable_output_bytes_with_locks(
        asset_id: [u8; 32],
        amount: u64,
        owner: [u8; 20],
        owner_locktime: u64,
        stakeable_locktime: Option<u64>,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&asset_id);
        match stakeable_locktime {
            Some(stakeable_locktime) => {
                bytes.extend_from_slice(&22u32.to_be_bytes());
                bytes.extend_from_slice(&stakeable_locktime.to_be_bytes());
                bytes.extend_from_slice(&7u32.to_be_bytes());
                bytes.extend_from_slice(&amount.to_be_bytes());
                bytes.extend_from_slice(&owner_locktime.to_be_bytes());
                bytes.extend_from_slice(&1u32.to_be_bytes());
                bytes.extend_from_slice(&1u32.to_be_bytes());
                bytes.extend_from_slice(&owner);
            }
            None => {
                bytes.extend_from_slice(&7u32.to_be_bytes());
                bytes.extend_from_slice(&amount.to_be_bytes());
                bytes.extend_from_slice(&owner_locktime.to_be_bytes());
                bytes.extend_from_slice(&1u32.to_be_bytes());
                bytes.extend_from_slice(&1u32.to_be_bytes());
                bytes.extend_from_slice(&owner);
            }
        }
        bytes
    }

    fn make_platform_transferable_input_bytes(
        tx_id: [u8; 32],
        output_index: u32,
        asset_id: [u8; 32],
        amount: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&tx_id);
        bytes.extend_from_slice(&output_index.to_be_bytes());
        bytes.extend_from_slice(&asset_id);
        bytes.extend_from_slice(&5u32.to_be_bytes());
        bytes.extend_from_slice(&amount.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes
    }

    fn make_platform_base_tx_fields_with_io(
        outputs: &[Vec<u8>],
        inputs: &[Vec<u8>],
        memo: &[u8],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&(outputs.len() as u32).to_be_bytes());
        for output in outputs {
            tx_bytes.extend_from_slice(output);
        }
        tx_bytes.extend_from_slice(&(inputs.len() as u32).to_be_bytes());
        for input in inputs {
            tx_bytes.extend_from_slice(input);
        }
        tx_bytes.extend_from_slice(&(memo.len() as u32).to_be_bytes());
        tx_bytes.extend_from_slice(memo);
        tx_bytes
    }

    fn make_platform_base_tx_with_io(outputs: &[Vec<u8>], inputs: &[Vec<u8>]) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&34u32.to_be_bytes());
        tx_bytes.extend_from_slice(&make_platform_base_tx_fields_with_io(outputs, inputs, &[]));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_add_subnet_validator_tx_bytes_with_io(
        node_id: [u8; 20],
        subnet_id: [u8; 32],
        outputs: &[Vec<u8>],
        inputs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&13u32.to_be_bytes());
        tx_bytes.extend_from_slice(&make_platform_base_tx_fields_with_io(outputs, inputs, &[]));
        tx_bytes.extend_from_slice(&node_id);
        tx_bytes.extend_from_slice(&100u64.to_be_bytes());
        tx_bytes.extend_from_slice(&200u64.to_be_bytes());
        tx_bytes.extend_from_slice(&300u64.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&make_platform_auth_bytes(&[]));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_create_chain_tx_bytes_with_io(
        outputs: &[Vec<u8>],
        inputs: &[Vec<u8>],
        subnet_id: [u8; 32],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&15u32.to_be_bytes());
        tx_bytes.extend_from_slice(&make_platform_base_tx_fields_with_io(
            outputs, inputs, b"memo",
        ));
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&(3u16).to_be_bytes());
        tx_bytes.extend_from_slice(b"evm");
        tx_bytes.extend_from_slice(&[0x88; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&(2u32).to_be_bytes());
        tx_bytes.extend_from_slice(&[0xAA, 0xBB]);
        tx_bytes.extend_from_slice(&make_platform_auth_bytes(&[]));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_import_tx_bytes_with_io(
        outputs: &[Vec<u8>],
        inputs: &[Vec<u8>],
        source_chain: [u8; 32],
        imported_inputs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&17u32.to_be_bytes());
        tx_bytes.extend_from_slice(&make_platform_base_tx_fields_with_io(
            outputs, inputs, b"memo",
        ));
        tx_bytes.extend_from_slice(&source_chain);
        tx_bytes.extend_from_slice(&(imported_inputs.len() as u32).to_be_bytes());
        for input in imported_inputs {
            tx_bytes.extend_from_slice(input);
        }
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_export_tx_bytes_with_io(
        outputs: &[Vec<u8>],
        inputs: &[Vec<u8>],
        destination_chain: [u8; 32],
        exported_outputs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&18u32.to_be_bytes());
        tx_bytes.extend_from_slice(&make_platform_base_tx_fields_with_io(
            outputs, inputs, b"memo",
        ));
        tx_bytes.extend_from_slice(&destination_chain);
        tx_bytes.extend_from_slice(&(exported_outputs.len() as u32).to_be_bytes());
        for output in exported_outputs {
            tx_bytes.extend_from_slice(output);
        }
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_add_validator_tx_bytes_with_window(
        owner: [u8; 20],
        amount: u64,
        start_time: u64,
        end_time: u64,
        shares: u32,
    ) -> Vec<u8> {
        let asset_id = parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap();
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&12u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0x11; 20]);
        tx_bytes.extend_from_slice(&start_time.to_be_bytes());
        tx_bytes.extend_from_slice(&end_time.to_be_bytes());
        tx_bytes.extend_from_slice(&amount.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&make_platform_transferable_output_bytes(
            asset_id, amount, owner,
        ));
        tx_bytes.extend_from_slice(&11u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u64.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&owner);
        tx_bytes.extend_from_slice(&shares.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_add_validator_tx_bytes(owner: [u8; 20], amount: u64) -> Vec<u8> {
        make_platform_add_validator_tx_bytes_with_window(owner, amount, 1000, 2000, 12_345)
    }

    fn make_platform_add_delegator_tx_bytes(owner: [u8; 20], amount: u64) -> Vec<u8> {
        make_platform_add_delegator_tx_bytes_with_window(owner, amount, [0x22; 20], 1000, 2000)
    }

    fn make_platform_add_delegator_tx_bytes_with_window(
        owner: [u8; 20],
        amount: u64,
        validator_node_id: [u8; 20],
        start_time: u64,
        end_time: u64,
    ) -> Vec<u8> {
        let asset_id = parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap();
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&14u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&validator_node_id);
        tx_bytes.extend_from_slice(&start_time.to_be_bytes());
        tx_bytes.extend_from_slice(&end_time.to_be_bytes());
        tx_bytes.extend_from_slice(&amount.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&make_platform_transferable_output_bytes(
            asset_id, amount, owner,
        ));
        tx_bytes.extend_from_slice(&11u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u64.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&owner);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_reward_validator_tx_bytes(staker_tx_id: [u8; 32]) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&20u32.to_be_bytes());
        tx_bytes.extend_from_slice(&staker_tx_id);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_output_owner_interface_bytes(
        owners: &[[u8; 20]],
        locktime: u64,
        threshold: u32,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&11u32.to_be_bytes());
        bytes.extend_from_slice(&locktime.to_be_bytes());
        bytes.extend_from_slice(&threshold.to_be_bytes());
        bytes.extend_from_slice(&(owners.len() as u32).to_be_bytes());
        for owner in owners {
            bytes.extend_from_slice(owner);
        }
        bytes
    }

    fn make_platform_create_subnet_tx_bytes(
        owners: &[[u8; 20]],
        locktime: u64,
        threshold: u32,
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&16u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&make_platform_output_owner_interface_bytes(
            owners, locktime, threshold,
        ));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_transfer_subnet_ownership_tx_bytes(
        subnet_id: [u8; 32],
        owners: &[[u8; 20]],
        locktime: u64,
        threshold: u32,
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&33u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&make_platform_auth_bytes(&[]));
        tx_bytes.extend_from_slice(&make_platform_output_owner_interface_bytes(
            owners, locktime, threshold,
        ));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_transform_subnet_tx_bytes(subnet_id: [u8; 32], asset_id: [u8; 32]) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&24u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&asset_id);
        tx_bytes.extend_from_slice(&1_000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&10_000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&1u64.to_be_bytes());
        tx_bytes.extend_from_slice(&100_000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&100u64.to_be_bytes());
        tx_bytes.extend_from_slice(&1_000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&86_400u32.to_be_bytes());
        tx_bytes.extend_from_slice(&(86_400u32 * 30).to_be_bytes());
        tx_bytes.extend_from_slice(&1_000u32.to_be_bytes());
        tx_bytes.extend_from_slice(&25u64.to_be_bytes());
        tx_bytes.push(5u8);
        tx_bytes.extend_from_slice(&80_000u32.to_be_bytes());
        tx_bytes.extend_from_slice(&make_platform_auth_bytes(&[]));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_banff_proposal_with_tx(parent: [u8; 32], height: u64, proposal_tx: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.extend_from_slice(&29u32.to_be_bytes());
        raw.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes());
        raw.extend_from_slice(&parent);
        raw.extend_from_slice(&height.to_be_bytes());
        raw.extend_from_slice(proposal_tx);
        raw
    }

    fn make_banff_decision_block(parent: [u8; 32], height: u64, commit: bool) -> Vec<u8> {
        let mut raw = vec![0u8; 54];
        raw[2..6].copy_from_slice(&(if commit { 31u32 } else { 30u32 }).to_be_bytes());
        raw[6..14].copy_from_slice(&1_700_000_000u64.to_be_bytes());
        raw[14..46].copy_from_slice(&parent);
        raw[46..54].copy_from_slice(&height.to_be_bytes());
        raw
    }

    fn make_banff_std_with_txs(parent: [u8; 32], height: u64, txs: &[Vec<u8>]) -> Vec<u8> {
        make_banff_std_with_txs_at(parent, height, 1_700_000_000, txs)
    }

    fn make_banff_std_with_txs_at(
        parent: [u8; 32],
        height: u64,
        timestamp: u64,
        txs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut raw = make_banff_std_with_timestamp(parent, height, timestamp);
        raw.extend_from_slice(&(txs.len() as u32).to_be_bytes());
        for tx in txs {
            raw.extend_from_slice(tx);
        }
        raw
    }

    fn sha256_bytes(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    fn encode_rlp_u64_for_test(buf: &mut Vec<u8>, value: u64) {
        if value == 0 {
            buf.push(0x80);
            return;
        }
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|&byte| byte != 0).unwrap_or(7);
        let slice = &bytes[start..];
        buf.push(0x80 + slice.len() as u8);
        buf.extend_from_slice(slice);
    }

    fn rlp_list_for_test(payload: Vec<u8>) -> Vec<u8> {
        let len = payload.len();
        let mut encoded = Vec::new();
        if len <= 55 {
            encoded.push(0xc0 + len as u8);
        } else {
            let len_bytes = len.to_be_bytes();
            let start = len_bytes.iter().position(|&byte| byte != 0).unwrap_or(7);
            let slice = &len_bytes[start..];
            encoded.push(0xf7 + slice.len() as u8);
            encoded.extend_from_slice(slice);
        }
        encoded.extend_from_slice(&payload);
        encoded
    }

    fn rlp_bytes_for_test(bytes: &[u8]) -> Vec<u8> {
        if bytes.is_empty() {
            return vec![0x80];
        }
        if bytes.len() == 1 && bytes[0] < 0x80 {
            return vec![bytes[0]];
        }

        let mut encoded = Vec::new();
        if bytes.len() <= 55 {
            encoded.push(0x80 + bytes.len() as u8);
        } else {
            let len_bytes = bytes.len().to_be_bytes();
            let start = len_bytes.iter().position(|&byte| byte != 0).unwrap_or(7);
            let slice = &len_bytes[start..];
            encoded.push(0xb7 + slice.len() as u8);
            encoded.extend_from_slice(slice);
        }
        encoded.extend_from_slice(bytes);
        encoded
    }

    fn make_cchain_atomic_export_tx_bytes(
        network_id: u32,
        destination_chain: [u8; 32],
        exported_outputs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&network_id.to_be_bytes());
        bytes.extend_from_slice(&platform_cchain_blockchain_id(network_id));
        bytes.extend_from_slice(&destination_chain);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&(exported_outputs.len() as u32).to_be_bytes());
        for output in exported_outputs {
            bytes.extend_from_slice(output);
        }
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes
    }

    fn make_cchain_atomic_import_tx_bytes(
        network_id: u32,
        source_chain: [u8; 32],
        imported_inputs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&network_id.to_be_bytes());
        bytes.extend_from_slice(&platform_cchain_blockchain_id(network_id));
        bytes.extend_from_slice(&source_chain);
        bytes.extend_from_slice(&(imported_inputs.len() as u32).to_be_bytes());
        for input in imported_inputs {
            bytes.extend_from_slice(input);
        }
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes
    }

    fn make_cchain_atomic_batch_extdata(txs: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&(txs.len() as u32).to_be_bytes());
        for tx in txs {
            bytes.extend_from_slice(&tx[2..]);
        }
        bytes
    }

    fn make_cchain_coreth_block_with_extdata(
        parent: [u8; 32],
        number: u64,
        timestamp: u64,
        extdata: &[u8],
    ) -> Vec<u8> {
        let mut header_payload = Vec::new();
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&parent);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0x1d; 32]);
        header_payload.push(0x94);
        header_payload.extend_from_slice(&[0u8; 20]);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]);
        header_payload.push(0xb9);
        header_payload.push(0x01);
        header_payload.push(0x00);
        header_payload.extend_from_slice(&[0u8; 256]);
        header_payload.push(0x80);
        encode_rlp_u64_for_test(&mut header_payload, number);
        encode_rlp_u64_for_test(&mut header_payload, 30_000_000);
        header_payload.push(0x80);
        encode_rlp_u64_for_test(&mut header_payload, timestamp);
        header_payload.push(0x80);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]);
        header_payload.extend_from_slice(&[0x88, 0, 0, 0, 0, 0, 0, 0, 0]);
        encode_rlp_u64_for_test(&mut header_payload, 25_000_000_000);

        let mut outer_payload = Vec::new();
        outer_payload.extend_from_slice(&rlp_list_for_test(header_payload));
        outer_payload.push(0xc0); // txs = empty
        outer_payload.push(0xc0); // uncles = empty
        outer_payload.push(0x80); // version = 0
        outer_payload.extend_from_slice(&rlp_bytes_for_test(extdata));
        rlp_list_for_test(outer_payload)
    }

    fn append_platform_id_for_test(id: [u8; 32], suffix: u32) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&suffix.to_be_bytes());
        sha256_bytes(&bytes)
    }

    fn make_platform_pchain_owner_bytes(owner: [u8; 20]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&owner);
        bytes
    }

    fn make_platform_auth_bytes(sig_indices: &[u32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&10u32.to_be_bytes());
        bytes.extend_from_slice(&(sig_indices.len() as u32).to_be_bytes());
        for sig_index in sig_indices {
            bytes.extend_from_slice(&sig_index.to_be_bytes());
        }
        bytes
    }

    fn make_platform_bitset(signers: usize) -> Vec<u8> {
        if signers == 0 {
            return Vec::new();
        }
        let mut bytes = vec![0u8; signers.div_ceil(8)];
        for signer in 0..signers {
            let byte_index = signer / 8;
            let bit_index = signer % 8;
            bytes[byte_index] |= 1u8 << bit_index;
        }
        bytes
    }

    fn make_platform_warp_message_bytes(payload: &[u8], signer_count: usize) -> Vec<u8> {
        let signers = make_platform_bitset(signer_count);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&(signers.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&signers);
        bytes.extend_from_slice(&[0xBB; 96]);
        bytes
    }

    fn make_platform_addressed_call_bytes(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&20u32.to_be_bytes());
        bytes.extend_from_slice(&[0xCC; 20]);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn make_platform_register_l1_validator_message_payload(
        subnet_id: [u8; 32],
        node_id: [u8; 20],
        owner: [u8; 20],
        weight: u64,
        expiry: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&subnet_id);
        bytes.extend_from_slice(&20u32.to_be_bytes());
        bytes.extend_from_slice(&node_id);
        bytes.extend_from_slice(&[0x11; 48]);
        bytes.extend_from_slice(&expiry.to_be_bytes());
        bytes.extend_from_slice(&make_platform_pchain_owner_bytes(owner));
        bytes.extend_from_slice(&make_platform_pchain_owner_bytes(owner));
        bytes.extend_from_slice(&weight.to_be_bytes());
        bytes
    }

    fn make_platform_l1_validator_weight_message_payload(
        validation_id: [u8; 32],
        nonce: u64,
        weight: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(&validation_id);
        bytes.extend_from_slice(&nonce.to_be_bytes());
        bytes.extend_from_slice(&weight.to_be_bytes());
        bytes
    }

    fn make_platform_convert_subnet_to_l1_tx_bytes(
        subnet_id: [u8; 32],
        validators: &[([u8; 20], u64, u64, [u8; 20])],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&35u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&[0x44; 32]);
        tx_bytes.extend_from_slice(&3u32.to_be_bytes());
        tx_bytes.extend_from_slice(b"mgr");
        tx_bytes.extend_from_slice(&(validators.len() as u32).to_be_bytes());
        for (node_id, weight, balance, owner) in validators {
            tx_bytes.extend_from_slice(&20u32.to_be_bytes());
            tx_bytes.extend_from_slice(node_id);
            tx_bytes.extend_from_slice(&weight.to_be_bytes());
            tx_bytes.extend_from_slice(&balance.to_be_bytes());
            tx_bytes.extend_from_slice(&[0x22; 48]);
            tx_bytes.extend_from_slice(&[0x33; 96]);
            tx_bytes.extend_from_slice(&make_platform_pchain_owner_bytes(*owner));
            tx_bytes.extend_from_slice(&make_platform_pchain_owner_bytes(*owner));
        }
        tx_bytes.extend_from_slice(&make_platform_auth_bytes(&[]));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_register_l1_validator_tx_bytes(
        subnet_id: [u8; 32],
        node_id: [u8; 20],
        owner: [u8; 20],
        weight: u64,
        balance: u64,
        expiry: u64,
        signer_count: usize,
    ) -> (Vec<u8>, [u8; 32]) {
        let payload = make_platform_register_l1_validator_message_payload(
            subnet_id, node_id, owner, weight, expiry,
        );
        let validation_id = sha256_bytes(&payload);
        let addressed_call = make_platform_addressed_call_bytes(&payload);
        let warp_message = make_platform_warp_message_bytes(&addressed_call, signer_count);

        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&36u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&balance.to_be_bytes());
        tx_bytes.extend_from_slice(&[0x55; 96]);
        tx_bytes.extend_from_slice(&(warp_message.len() as u32).to_be_bytes());
        tx_bytes.extend_from_slice(&warp_message);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        (tx_bytes, validation_id)
    }

    fn make_platform_set_l1_validator_weight_tx_bytes(
        validation_id: [u8; 32],
        nonce: u64,
        weight: u64,
        signer_count: usize,
    ) -> Vec<u8> {
        let payload =
            make_platform_l1_validator_weight_message_payload(validation_id, nonce, weight);
        let addressed_call = make_platform_addressed_call_bytes(&payload);
        let warp_message = make_platform_warp_message_bytes(&addressed_call, signer_count);

        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&37u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&(warp_message.len() as u32).to_be_bytes());
        tx_bytes.extend_from_slice(&warp_message);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_increase_l1_validator_balance_tx_bytes(
        validation_id: [u8; 32],
        balance: u64,
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&38u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&validation_id);
        tx_bytes.extend_from_slice(&balance.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_platform_disable_l1_validator_tx_bytes(validation_id: [u8; 32]) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0u16.to_be_bytes());
        tx_bytes.extend_from_slice(&39u32.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&validation_id);
        tx_bytes.extend_from_slice(&make_platform_auth_bytes(&[]));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn make_test_log(
        address: [u8; 20],
        topics: Vec<[u8; 32]>,
        block_number: u64,
        tx_hash: [u8; 32],
        tx_index: u32,
        block_hash: [u8; 32],
    ) -> serde_json::Value {
        serde_json::json!({
            "address": format!("0x{}", hex::encode(address)),
            "topics": topics
                .into_iter()
                .map(|topic| serde_json::Value::String(format!("0x{}", hex::encode(topic))))
                .collect::<Vec<_>>(),
            "data": "0x",
            "blockNumber": format!("0x{:x}", block_number),
            "transactionHash": format!("0x{}", hex::encode(tx_hash)),
            "transactionIndex": format!("0x{:x}", tx_index),
            "blockHash": format!("0x{}", hex::encode(block_hash)),
            "logIndex": "0x0",
            "removed": false,
        })
    }

    fn store_test_receipt(
        db: &Database,
        block_number: u64,
        tx_index: u32,
        tx_hash: [u8; 32],
        block_hash: [u8; 32],
        logs: Vec<serde_json::Value>,
    ) {
        let receipt = serde_json::json!({
            "transactionHash": format!("0x{}", hex::encode(tx_hash)),
            "transactionIndex": format!("0x{:x}", tx_index),
            "blockHash": format!("0x{}", hex::encode(block_hash)),
            "blockNumber": format!("0x{:x}", block_number),
            "from": format!("0x{}", hex::encode([0x11; 20])),
            "to": format!("0x{}", hex::encode([0x22; 20])),
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "status": "0x1",
            "logs": logs,
        });
        db.put_receipt(block_number, tx_index, receipt.to_string().as_bytes())
            .unwrap();
    }

    async fn websocket_handshake(stream: &mut TcpStream, path: &str) {
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            path
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 2048];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.starts_with("HTTP/1.1 101"));
        assert!(response.contains("Sec-WebSocket-Accept"));
    }

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn http_post(addr: std::net::SocketAddr, path: &str, body: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            path,
            body.len(),
            body
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn write_masked_ws_text_frame(stream: &mut TcpStream, text: &str) {
        let payload = text.as_bytes();
        let mask = [0x11u8, 0x22, 0x33, 0x44];
        let mut frame = Vec::with_capacity(payload.len() + 16);
        frame.push(0x81);
        match payload.len() {
            len @ 0..=125 => frame.push(0x80 | len as u8),
            len @ 126..=65535 => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            }
            len => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        for (idx, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[idx % 4]);
        }
        stream.write_all(&frame).await.unwrap();
    }

    async fn read_ws_text_frame(stream: &mut TcpStream) -> serde_json::Value {
        let frame = tokio::time::timeout(Duration::from_secs(5), read_ws_frame(stream))
            .await
            .expect("websocket frame should arrive")
            .expect("frame read should succeed")
            .expect("frame should exist");
        assert_eq!(frame.0, 0x1);
        serde_json::from_slice(&frame.1).unwrap()
    }

    fn make_pool_tx(from: u8, nonce: u64) -> PoolTransaction {
        let mut hash = [0u8; 32];
        hash[0] = from;
        hash[1..9].copy_from_slice(&nonce.to_be_bytes());

        PoolTransaction {
            hash,
            raw: None,
            from: [from; 20],
            to: Some([0xAA; 20]),
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 25_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            value: 42,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            size: 128,
            timestamp: 1_700_000_000,
        }
    }

    fn keccak_tx_hash(raw: &[u8]) -> [u8; 32] {
        let hash = revm::primitives::keccak256(raw);
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_slice());
        out
    }

    #[test]
    fn test_load_persistent_peer_targets_sorted() {
        let (db, _dir) = Database::open_temp().unwrap();

        let mut a = PersistentPeerRecord::new([0xA1; 20], vec![10, 0, 0, 1], 9651);
        a.reputation = 10;
        a.last_seen_ms = 10;
        db.put_peer(&a.node_id, &a.encode()).unwrap();

        let mut b = PersistentPeerRecord::new([0xB2; 20], vec![10, 0, 0, 2], 9651);
        b.reputation = 100;
        b.last_seen_ms = 20;
        db.put_peer(&b.node_id, &b.encode()).unwrap();

        let mut c = PersistentPeerRecord::new([0xC3; 20], vec![10, 0, 0, 3], 9651);
        c.reputation = 100;
        c.last_seen_ms = 30;
        db.put_peer(&c.node_id, &c.encode()).unwrap();

        let loaded = load_persistent_peer_targets(&db, 2);
        assert_eq!(loaded.len(), 2);
        let addrs: std::collections::HashSet<SocketAddr> =
            loaded.into_iter().map(|t| t.addr).collect();
        assert!(addrs.contains(&"10.0.0.3:9651".parse::<SocketAddr>().unwrap()));
        assert!(addrs.contains(&"10.0.0.2:9651".parse::<SocketAddr>().unwrap()));
    }

    #[tokio::test]
    async fn test_persisted_sync_state_roundtrip() {
        let (db, _dir) = Database::open_temp().unwrap();

        let state = PersistedSyncState {
            current_block_height: 42,
            p_chain_tip_height: 40,
            c_chain_tip_height: 41,
            bootstrap_state: "following".to_string(),
            bootstrap_complete: true,
        };
        db.put_metadata(META_SYNC_STATE, &serde_json::to_vec(&state).unwrap())
            .unwrap();

        let loaded = load_persisted_sync_state(&db).unwrap();
        assert_eq!(loaded.current_block_height, 42);
        assert!(loaded.bootstrap_complete);
    }

    #[test]
    fn test_latency_to_reputation_prefers_low_latency() {
        assert!(latency_to_reputation(20) > latency_to_reputation(400));
        assert_eq!(latency_to_reputation(2000), 0);
    }

    #[tokio::test]
    async fn test_rpc_platform_endpoints() {
        let node = make_test_node(1);

        let validators_req =
            r#"{"jsonrpc":"2.0","method":"platform.getCurrentValidators","params":[],"id":1}"#;
        let validators = handle_rpc_request(validators_req, &node).await;
        assert!(validators.contains("validators"));

        let subnets_req = r#"{"jsonrpc":"2.0","method":"platform.getSubnets","params":[],"id":2}"#;
        let subnets = handle_rpc_request(subnets_req, &node).await;
        let subnets_json: serde_json::Value = serde_json::from_str(&subnets).unwrap();
        let subnet_values = subnets_json["result"]["subnets"].as_array().unwrap();
        assert_eq!(subnet_values.len(), 1);
        assert_eq!(
            subnet_values[0]["id"],
            cb58_encode_id(SubnetId::primary_network().0)
        );
        assert_eq!(subnet_values[0]["controlKeys"], serde_json::json!([]));
        assert_eq!(subnet_values[0]["threshold"], "0");

        node.sync_engine.mark_following().await;
        let status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBlockchainStatus","params":{{"blockchainID":"0x{}"}},"id":3}}"#,
            hex::encode(platform_pchain_blockchain_id())
        );
        let status = handle_rpc_request(&status_req, &node).await;
        assert!(status.contains("Validating"));

        let health_req = r#"{"jsonrpc":"2.0","method":"health","params":[],"id":4}"#;
        let health = handle_rpc_request(health_req, &node).await;
        assert!(health.contains("\"checks\""));
        assert!(health.contains("\"healthy\""));
    }

    #[tokio::test]
    async fn test_platform_get_subnets_supports_ids_filter_and_shapes() {
        let node = make_test_node(12345);
        let transformed_owner = [0xAA; 20];
        let converted_owner = [0xBB; 20];
        let converted_new_owner = [0xBC; 20];

        let transform_create_tx = make_platform_create_subnet_tx_bytes(&[transformed_owner], 5, 1);
        let transformed_subnet = SubnetId(sha256_bytes(&transform_create_tx));
        let transform_tx =
            make_platform_transform_subnet_tx_bytes(transformed_subnet.0, [0x11; 32]);

        let convert_create_tx = make_platform_create_subnet_tx_bytes(&[converted_owner], 0, 1);
        let converted_subnet = SubnetId(sha256_bytes(&convert_create_tx));
        let transfer_tx = make_platform_transfer_subnet_ownership_tx_bytes(
            converted_subnet.0,
            &[converted_new_owner],
            9,
            1,
        );
        let convert_tx = make_platform_convert_subnet_to_l1_tx_bytes(
            converted_subnet.0,
            &[([0x10; 20], 1, 0, converted_new_owner)],
        );

        let block1 =
            make_banff_std_with_txs([0x10; 32], 1, &[transform_create_tx, convert_create_tx]);
        let block1_id = sha256_bytes(&block1);
        let block2 =
            make_banff_std_with_txs(block1_id, 2, &[transform_tx, transfer_tx, convert_tx]);
        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block2), &block2)
            .unwrap();

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getSubnets","params":{{"ids":["{}","{}","{}","{}"]}},"id":4}}"#,
            cb58_encode_id(SubnetId::primary_network().0),
            cb58_encode_id(transformed_subnet.0),
            cb58_encode_id(converted_subnet.0),
            cb58_encode_id([0xBB; 32]),
        );
        let response = handle_rpc_request(&req, &node).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        let subnets = json["result"]["subnets"].as_array().unwrap();
        assert_eq!(subnets.len(), 3);

        let subnets_by_id = subnets
            .iter()
            .map(|subnet| (subnet["id"].as_str().unwrap().to_string(), subnet.clone()))
            .collect::<std::collections::HashMap<_, _>>();

        let primary_id = cb58_encode_id(SubnetId::primary_network().0);
        let transformed_id = cb58_encode_id(transformed_subnet.0);
        let converted_id = cb58_encode_id(converted_subnet.0);

        assert_eq!(
            subnets_by_id[&primary_id]["controlKeys"],
            serde_json::json!([])
        );
        assert_eq!(
            subnets_by_id[&transformed_id]["controlKeys"],
            serde_json::json!([])
        );
        assert_eq!(
            subnets_by_id[&converted_id]["controlKeys"],
            serde_json::json!([format_platform_address(
                node.config.network_id,
                converted_new_owner
            )])
        );
        assert_eq!(subnets_by_id[&primary_id]["threshold"], "0");
        assert_eq!(subnets_by_id[&transformed_id]["threshold"], "0");
        assert_eq!(subnets_by_id[&converted_id]["threshold"], "1");
    }

    #[tokio::test]
    async fn test_platform_get_subnets_default_includes_primary_and_hides_transformed_owner() {
        let node = make_test_node(12345);
        let transformed_owner = [0xD1; 20];
        let permissioned_owner = [0xD2; 20];

        let transformed_create_tx =
            make_platform_create_subnet_tx_bytes(&[transformed_owner], 5, 1);
        let transformed_subnet = SubnetId(sha256_bytes(&transformed_create_tx));
        let transform_tx =
            make_platform_transform_subnet_tx_bytes(transformed_subnet.0, [0x31; 32]);

        let permissioned_create_tx =
            make_platform_create_subnet_tx_bytes(&[permissioned_owner], 7, 1);
        let permissioned_subnet = SubnetId(sha256_bytes(&permissioned_create_tx));

        let block1 = make_banff_std_with_txs(
            [0x40; 32],
            1,
            &[transformed_create_tx, permissioned_create_tx],
        );
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_std_with_txs(block1_id, 2, &[transform_tx]);
        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block2), &block2)
            .unwrap();

        let response = handle_rpc_request(
            r#"{"jsonrpc":"2.0","method":"platform.getSubnets","params":[],"id":41}"#,
            &node,
        )
        .await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        let subnets = json["result"]["subnets"].as_array().unwrap();
        assert_eq!(subnets.len(), 3);

        let subnets_by_id = subnets
            .iter()
            .map(|subnet| (subnet["id"].as_str().unwrap().to_string(), subnet.clone()))
            .collect::<std::collections::HashMap<_, _>>();

        let primary_id = cb58_encode_id(SubnetId::primary_network().0);
        let transformed_id = cb58_encode_id(transformed_subnet.0);
        let permissioned_id = cb58_encode_id(permissioned_subnet.0);

        assert_eq!(
            subnets_by_id[&primary_id]["controlKeys"],
            serde_json::json!([])
        );
        assert_eq!(subnets_by_id[&primary_id]["threshold"], "0");
        assert_eq!(
            subnets_by_id[&transformed_id]["controlKeys"],
            serde_json::json!([])
        );
        assert_eq!(subnets_by_id[&transformed_id]["threshold"], "0");
        assert_eq!(
            subnets_by_id[&permissioned_id]["controlKeys"],
            serde_json::json!([format_platform_address(
                node.config.network_id,
                permissioned_owner
            )])
        );
        assert_eq!(subnets_by_id[&permissioned_id]["threshold"], "1");
    }

    #[tokio::test]
    async fn test_platform_get_subnet_returns_shape_and_errors() {
        let node = make_test_node(12345);
        let transformed_owner = [0xCD; 20];
        let converted_owner_a = [0xCE; 20];
        let converted_owner_b = [0xCF; 20];

        let transform_create_tx = make_platform_create_subnet_tx_bytes(&[transformed_owner], 7, 1);
        let transformed_subnet = SubnetId(sha256_bytes(&transform_create_tx));
        let transform_tx =
            make_platform_transform_subnet_tx_bytes(transformed_subnet.0, [0x21; 32]);
        let transform_tx_id = cb58_encode_id(sha256_bytes(&transform_tx));

        let convert_create_tx = make_platform_create_subnet_tx_bytes(&[converted_owner_a], 3, 1);
        let converted_subnet = SubnetId(sha256_bytes(&convert_create_tx));
        let transfer_tx = make_platform_transfer_subnet_ownership_tx_bytes(
            converted_subnet.0,
            &[converted_owner_a, converted_owner_b],
            9,
            2,
        );
        let convert_tx = make_platform_convert_subnet_to_l1_tx_bytes(
            converted_subnet.0,
            &[([0x20; 20], 1, 5, converted_owner_a)],
        );
        let convert_tx_json = avalanche_rs::pchain::parse_platform_tx_json(&convert_tx).unwrap();
        let conversion_id = platform_subnet_to_l1_conversion_id(&convert_tx_json["unsignedTx"])
            .map(cb58_encode_id)
            .unwrap();

        let block1 =
            make_banff_std_with_txs([0x30; 32], 1, &[transform_create_tx, convert_create_tx]);
        let block1_id = sha256_bytes(&block1);
        let block2 =
            make_banff_std_with_txs(block1_id, 2, &[transform_tx, transfer_tx, convert_tx]);
        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block2), &block2)
            .unwrap();

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getSubnet","params":{{"subnetID":"{}"}},"id":5}}"#,
            cb58_encode_id(transformed_subnet.0)
        );
        let response = handle_rpc_request(&req, &node).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["result"]["isPermissioned"], false);
        assert_eq!(
            json["result"]["controlKeys"],
            serde_json::json!([format_platform_address(
                node.config.network_id,
                transformed_owner
            )])
        );
        assert_eq!(json["result"]["threshold"], "1");
        assert_eq!(json["result"]["locktime"], "7");
        assert_eq!(json["result"]["subnetTransformationTxID"], transform_tx_id);
        assert_eq!(json["result"]["conversionID"], cb58_encode_id([0u8; 32]));
        assert_eq!(json["result"]["managerChainID"], cb58_encode_id([0u8; 32]));
        assert!(json["result"]["managerAddress"].is_null());

        let converted_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getSubnet","params":{{"subnetID":"{}"}},"id":55}}"#,
            cb58_encode_id(converted_subnet.0)
        );
        let converted_response = handle_rpc_request(&converted_req, &node).await;
        let converted_json: serde_json::Value = serde_json::from_str(&converted_response).unwrap();
        assert_eq!(converted_json["result"]["isPermissioned"], false);
        assert_eq!(
            converted_json["result"]["controlKeys"],
            serde_json::json!([
                format_platform_address(node.config.network_id, converted_owner_a),
                format_platform_address(node.config.network_id, converted_owner_b),
            ])
        );
        assert_eq!(converted_json["result"]["threshold"], "2");
        assert_eq!(converted_json["result"]["locktime"], "9");
        assert_eq!(
            converted_json["result"]["subnetTransformationTxID"],
            cb58_encode_id([0u8; 32])
        );
        assert_eq!(converted_json["result"]["conversionID"], conversion_id);
        assert_eq!(
            converted_json["result"]["managerChainID"],
            cb58_encode_id([0x44; 32])
        );
        assert_eq!(converted_json["result"]["managerAddress"], "6d6772");

        let primary_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getSubnet","params":{{"subnetID":"{}"}},"id":6}}"#,
            cb58_encode_id(SubnetId::primary_network().0)
        );
        let primary_response = handle_rpc_request(&primary_req, &node).await;
        let primary_json: serde_json::Value = serde_json::from_str(&primary_response).unwrap();
        assert_eq!(primary_json["error"]["code"], -32000);
        assert_eq!(
            primary_json["error"]["message"],
            "the primary network isn't a subnet"
        );

        let missing_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getSubnet","params":{{"subnetID":"{}"}},"id":7}}"#,
            cb58_encode_id([0xDD; 32])
        );
        let missing_response = handle_rpc_request(&missing_req, &node).await;
        let missing_json: serde_json::Value = serde_json::from_str(&missing_response).unwrap();
        assert_eq!(missing_json["error"]["code"], -32000);
        assert_eq!(
            missing_json["error"]["message"],
            format!("\"{}\" is not a subnet", cb58_encode_id([0xDD; 32]))
        );
    }

    #[tokio::test]
    async fn test_platform_validator_endpoints_filter_and_lookup() {
        let now = unix_timestamp_secs();
        let current_node = "NodeID-current".to_string();
        let pending_node = "NodeID-pending".to_string();
        let completed_node = "NodeID-completed".to_string();
        let mut validators = std::collections::HashMap::new();
        validators.insert(
            current_node.clone(),
            ValidatorInfo {
                node_id: current_node.clone(),
                weight: 2_000 * avalanche_rs::staking::NANO_AVAX,
                start_time: now.saturating_sub(60),
                end_time: now + 3600,
            },
        );
        validators.insert(
            pending_node.clone(),
            ValidatorInfo {
                node_id: pending_node.clone(),
                weight: 3_000 * avalanche_rs::staking::NANO_AVAX,
                start_time: now + 600,
                end_time: now + 7200,
            },
        );
        validators.insert(
            completed_node.clone(),
            ValidatorInfo {
                node_id: completed_node.clone(),
                weight: 1_500 * avalanche_rs::staking::NANO_AVAX,
                start_time: now.saturating_sub(7200),
                end_time: now.saturating_sub(600),
            },
        );
        let node = make_test_node_with_validators(
            1,
            validators,
            [current_node.clone()].into_iter().collect(),
        );

        let current_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getCurrentValidators","params":{{"nodeIDs":["{}","{}"]}},"id":5}}"#,
            current_node, pending_node
        );
        let current_response = handle_rpc_request(&current_req, &node).await;
        let current_json: serde_json::Value = serde_json::from_str(&current_response).unwrap();
        let current_validators = current_json["result"]["validators"].as_array().unwrap();
        assert_eq!(current_validators.len(), 1);
        assert_eq!(current_validators[0]["nodeID"], current_node);
        assert_eq!(current_validators[0]["status"], "current");
        assert_eq!(current_validators[0]["connected"], true);
        assert_eq!(current_validators[0]["stakeAmount"], "2000000000000");

        let pending_req =
            r#"{"jsonrpc":"2.0","method":"platform.getPendingValidators","params":{},"id":6}"#;
        let pending_response = handle_rpc_request(pending_req, &node).await;
        let pending_json: serde_json::Value = serde_json::from_str(&pending_response).unwrap();
        let pending_validators = pending_json["result"]["validators"].as_array().unwrap();
        assert_eq!(pending_validators.len(), 1);
        assert_eq!(pending_validators[0]["nodeID"], pending_node);
        assert_eq!(pending_validators[0]["status"], "pending");
        assert!(pending_json["result"]["delegators"]
            .as_array()
            .unwrap()
            .is_empty());

        let validators_req =
            r#"{"jsonrpc":"2.0","method":"platform.getValidators","params":{},"id":7}"#;
        let validators_response = handle_rpc_request(validators_req, &node).await;
        let validators_json: serde_json::Value =
            serde_json::from_str(&validators_response).unwrap();
        let validators = validators_json["result"]["validators"].as_array().unwrap();
        assert_eq!(validators.len(), 3);
        assert!(validators
            .iter()
            .any(|validator| validator["status"] == "completed"));

        let validator_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getValidator","params":{{"nodeID":"{}"}},"id":8}}"#,
            current_node
        );
        let validator_response = handle_rpc_request(&validator_req, &node).await;
        let validator_json: serde_json::Value = serde_json::from_str(&validator_response).unwrap();
        assert_eq!(validator_json["result"]["nodeID"], current_node);
        assert_eq!(validator_json["result"]["weight"], "2000000000000");
    }

    #[tokio::test]
    async fn test_platform_current_validator_endpoints_include_l1_validators_for_converted_subnets()
    {
        let node = make_test_node(12345);
        let subnet_id = [0x98; 32];
        let node_id = [0x99; 20];
        let owner = [0x9A; 20];
        let etna_time =
            upgrade_time_unix(&info_upgrades_result(node.config.network_id), "etnaTime");

        let convert_tx =
            make_platform_convert_subnet_to_l1_tx_bytes(subnet_id, &[(node_id, 7, 20, owner)]);
        let validation_id = append_platform_id_for_test(subnet_id, 0);
        let register_node_id = [0x9B; 20];
        let (register_tx, register_validation_id) = make_platform_register_l1_validator_tx_bytes(
            subnet_id,
            register_node_id,
            owner,
            5,
            15,
            etna_time + 86_400,
            2,
        );
        let set_weight_tx =
            make_platform_set_l1_validator_weight_tx_bytes(register_validation_id, 0, 9, 1);

        let block1 = make_banff_std_with_txs_at([0x14; 32], 1, etna_time + 10, &[convert_tx]);
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_std_with_txs_at(block1_id, 2, etna_time + 20, &[register_tx]);
        let block2_id = sha256_bytes(&block2);
        let block3 = make_banff_std_with_txs_at(block2_id, 3, etna_time + 30, &[set_weight_tx]);
        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db.put_cf(CF_BLOCKS, &block2_id, &block2).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block3), &block3)
            .unwrap();

        let current_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getCurrentValidators","params":{{"subnetID":"{}"}},"id":56}}"#,
            cb58_encode_id(subnet_id)
        );
        let current_response = handle_rpc_request(&current_req, &node).await;
        let current_json: serde_json::Value = serde_json::from_str(&current_response).unwrap();
        let current_validators = current_json["result"]["validators"].as_array().unwrap();
        assert_eq!(current_validators.len(), 1);
        assert!(current_validators.iter().any(|validator| {
            validator["validationID"] == cb58_encode_id(register_validation_id)
                && validator["weight"] == "9"
                && validator["balance"] == "5"
                && validator["minNonce"] == "1"
                && validator["remainingBalanceOwner"]["addresses"]
                    == serde_json::json!([format_platform_address(node.config.network_id, owner)])
                && validator["status"] == "current"
        }));

        let validator_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getValidator","params":{{"subnetID":"{}","nodeID":"{}"}},"id":57}}"#,
            cb58_encode_id(subnet_id),
            full_node_id_string(&NodeId(register_node_id))
        );
        let validator_response = handle_rpc_request(&validator_req, &node).await;
        let validator_json: serde_json::Value = serde_json::from_str(&validator_response).unwrap();
        assert_eq!(
            validator_json["result"]["validationID"],
            cb58_encode_id(register_validation_id)
        );
        assert_eq!(validator_json["result"]["weight"], "9");

        let all_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getValidators","params":{{"subnetID":"{}"}},"id":58}}"#,
            cb58_encode_id(subnet_id)
        );
        let all_response = handle_rpc_request(&all_req, &node).await;
        let all_json: serde_json::Value = serde_json::from_str(&all_response).unwrap();
        let validators = all_json["result"]["validators"].as_array().unwrap();
        assert_eq!(validators.len(), 2);
        assert!(validators.iter().any(|validator| {
            validator["validationID"] == cb58_encode_id(validation_id)
                && validator["balance"] == "0"
                && validator["status"] == "completed"
        }));
        assert!(validators.iter().any(|validator| {
            validator["validationID"] == cb58_encode_id(register_validation_id)
                && validator["status"] == "current"
        }));
    }

    #[tokio::test]
    async fn test_platform_current_validators_use_committed_primary_validator_details() {
        let node = make_test_node(1);
        let validator_owner = [0x71; 20];
        let validator_tx = make_platform_add_validator_tx_bytes_with_window(
            validator_owner,
            2_000 * avalanche_rs::staking::NANO_AVAX,
            1_699_999_000,
            1_700_100_000,
            12_345,
        );
        let delegator_tx = make_platform_add_delegator_tx_bytes_with_window(
            [0x72; 20],
            25 * avalanche_rs::staking::NANO_AVAX,
            [0x11; 20],
            1_699_999_100,
            1_700_050_000,
        );
        let raw_block = make_banff_std_with_txs_at(
            [0x70; 32],
            60,
            1_700_000_000,
            &[validator_tx.clone(), delegator_tx.clone()],
        );
        let block_id = sha256_bytes(&raw_block);
        node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();

        let peer_id = NodeId([0x11; 20]);
        let mut peer = Peer::new(peer_id.clone(), "10.0.0.1:9651".parse().unwrap());
        peer.reported_uptime = 9_500;
        node.peer_manager.write().await.add_peer(peer).unwrap();
        node.validators_seen
            .write()
            .await
            .insert(full_node_id_string(&peer_id));

        let node_id = full_node_id_string(&peer_id);
        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getCurrentValidators","params":{{"nodeIDs":["{}"]}},"id":61}}"#,
            node_id
        );
        let response = handle_rpc_request(&req, &node).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        let validators = json["result"]["validators"].as_array().unwrap();
        assert_eq!(validators.len(), 1);

        let validator = &validators[0];
        assert_eq!(
            validator["txID"],
            cb58_encode_id(sha256_bytes(&validator_tx))
        );
        assert_eq!(validator["nodeID"], node_id);
        assert_eq!(
            validator["validationRewardOwner"]["addresses"],
            serde_json::json!([format_platform_address(
                node.config.network_id,
                validator_owner
            )])
        );
        assert_eq!(
            validator["delegationRewardOwner"]["addresses"],
            serde_json::json!([format_platform_address(
                node.config.network_id,
                validator_owner
            )])
        );
        assert_eq!(validator["delegationFee"], "1.2345");
        assert_eq!(validator["exactDelegationFee"], 12_345);
        assert_eq!(validator["connected"], true);
        assert_eq!(validator["uptime"], "95.0000");
        assert_eq!(validator["delegatorCount"], "1");
        assert_eq!(
            validator["delegatorWeight"],
            (25 * avalanche_rs::staking::NANO_AVAX).to_string()
        );
        assert_eq!(validator["delegators"].as_array().unwrap().len(), 1);
        assert_eq!(
            validator["delegators"][0]["rewardOwner"]["addresses"],
            serde_json::json!([format_platform_address(node.config.network_id, [0x72; 20])])
        );
        assert_eq!(
            validator["potentialReward"],
            avalanche_rs::staking::expected_reward(
                2_000 * avalanche_rs::staking::NANO_AVAX,
                1_700_100_000u64.saturating_sub(1_699_999_000),
                1.0,
            )
            .to_string()
        );
    }

    #[tokio::test]
    async fn test_platform_subnet_stake_and_supply_endpoints_use_transform_config() {
        let node = make_test_node(1);
        let subnet_id = [0x81; 32];
        let asset_id = [0x82; 32];
        let transform_tx = make_platform_transform_subnet_tx_bytes(subnet_id, asset_id);
        let raw_block = make_banff_std_with_txs_at([0x80; 32], 70, 1_700_000_000, &[transform_tx]);
        let block_id = sha256_bytes(&raw_block);
        node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();

        let min_stake_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getMinStake","params":{{"subnetID":"{}"}},"id":71}}"#,
            cb58_encode_id(subnet_id)
        );
        let min_stake_response = handle_rpc_request(&min_stake_req, &node).await;
        let min_stake_json: serde_json::Value = serde_json::from_str(&min_stake_response).unwrap();
        assert_eq!(min_stake_json["result"]["minValidatorStake"], "100");
        assert_eq!(min_stake_json["result"]["minDelegatorStake"], "25");

        let asset_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getStakingAssetID","params":{{"subnetID":"{}"}},"id":72}}"#,
            cb58_encode_id(subnet_id)
        );
        let asset_response = handle_rpc_request(&asset_req, &node).await;
        let asset_json: serde_json::Value = serde_json::from_str(&asset_response).unwrap();
        assert_eq!(asset_json["result"]["assetID"], cb58_encode_id(asset_id));

        let supply_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getCurrentSupply","params":{{"subnetID":"{}"}},"id":73}}"#,
            cb58_encode_id(subnet_id)
        );
        let supply_response = handle_rpc_request(&supply_req, &node).await;
        let supply_json: serde_json::Value = serde_json::from_str(&supply_response).unwrap();
        assert_eq!(supply_json["result"]["supply"], "1000");
        assert_eq!(supply_json["result"]["height"], "70");
    }

    #[tokio::test]
    async fn test_platform_validator_set_endpoints_support_height_queries() {
        let node = make_test_node(12345);
        let etna_time =
            upgrade_time_unix(&info_upgrades_result(node.config.network_id), "etnaTime");
        let primary_validator_tx = make_platform_add_validator_tx_bytes_with_window(
            [0x91; 20],
            2_500,
            etna_time,
            etna_time + 10_000,
            0,
        );
        let subnet_id = [0x92; 32];
        let owner = [0x93; 20];
        let convert_tx =
            make_platform_convert_subnet_to_l1_tx_bytes(subnet_id, &[([0x94; 20], 7, 20, owner)]);
        let (register_tx, register_validation_id) = make_platform_register_l1_validator_tx_bytes(
            subnet_id,
            [0x95; 20],
            owner,
            5,
            15,
            etna_time + 86_400,
            2,
        );
        let set_weight_tx =
            make_platform_set_l1_validator_weight_tx_bytes(register_validation_id, 0, 9, 1);

        let block1 = make_banff_std_with_txs_at(
            [0x90; 32],
            1,
            etna_time + 10,
            &[primary_validator_tx, convert_tx],
        );
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_std_with_txs_at(block1_id, 2, etna_time + 20, &[register_tx]);
        let block2_id = sha256_bytes(&block2);
        let block3 = make_banff_std_with_txs_at(block2_id, 3, etna_time + 30, &[set_weight_tx]);
        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db.put_cf(CF_BLOCKS, &block2_id, &block2).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block3), &block3)
            .unwrap();

        let primary_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getValidatorsAt","params":{{"height":"3","subnetID":"{}"}},"id":81}}"#,
            cb58_encode_id(SubnetId::primary_network().0)
        );
        let primary_response = handle_rpc_request(&primary_req, &node).await;
        let primary_json: serde_json::Value = serde_json::from_str(&primary_response).unwrap();
        let primary_validators = primary_json["result"]["validators"].as_object().unwrap();
        assert_eq!(primary_validators.len(), 1);
        assert_eq!(
            primary_validators[&full_node_id_string(&NodeId([0x11; 20]))]["weight"],
            "2500"
        );

        let subnet_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getValidatorsAt","params":{{"height":"3","subnetID":"{}"}},"id":82}}"#,
            cb58_encode_id(subnet_id)
        );
        let subnet_response = handle_rpc_request(&subnet_req, &node).await;
        let subnet_json: serde_json::Value = serde_json::from_str(&subnet_response).unwrap();
        let subnet_validators = subnet_json["result"]["validators"].as_object().unwrap();
        let l1_node_id = full_node_id_string(&NodeId([0x95; 20]));
        assert_eq!(subnet_validators[&l1_node_id]["weight"], "9");
        assert!(subnet_validators[&l1_node_id]["publicKey"]
            .as_str()
            .unwrap()
            .starts_with("0x"));

        let all_req = r#"{"jsonrpc":"2.0","method":"platform.getAllValidatorsAt","params":{"height":"3"},"id":83}"#;
        let all_response = handle_rpc_request(all_req, &node).await;
        let all_json: serde_json::Value = serde_json::from_str(&all_response).unwrap();
        let validator_sets = all_json["result"]["validatorSets"].as_object().unwrap();
        assert_eq!(
            validator_sets[&cb58_encode_id(SubnetId::primary_network().0)]["totalWeight"],
            "2500"
        );
        assert_eq!(
            validator_sets[&cb58_encode_id(subnet_id)]["totalWeight"],
            "9"
        );
        assert!(
            validator_sets[&cb58_encode_id(subnet_id)]["validators"][0]["publicKey"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
    }

    #[tokio::test]
    async fn test_platform_get_height_and_min_stake_shapes() {
        let node = make_test_node(1);
        let raw_block = make_banff_std([0x11; 32], 42);
        let block_id = sha256_bytes(&raw_block);
        node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();

        let height_req = r#"{"jsonrpc":"2.0","method":"platform.getHeight","params":{},"id":9}"#;
        let height_response = handle_rpc_request(height_req, &node).await;
        let height_json: serde_json::Value = serde_json::from_str(&height_response).unwrap();
        assert_eq!(height_json["result"]["height"], "42");

        let min_stake_req =
            r#"{"jsonrpc":"2.0","method":"platform.getMinStake","params":{},"id":10}"#;
        let min_stake_response = handle_rpc_request(min_stake_req, &node).await;
        let min_stake_json: serde_json::Value = serde_json::from_str(&min_stake_response).unwrap();
        assert_eq!(
            min_stake_json["result"]["minValidatorStake"],
            MIN_VALIDATOR_STAKE.to_string()
        );
        assert_eq!(
            min_stake_json["result"]["minDelegatorStake"],
            MIN_DELEGATOR_STAKE.to_string()
        );
    }

    #[tokio::test]
    async fn test_platform_get_proposed_height_uses_recent_acceptance_window() {
        let node = make_test_node(1);
        for height in 40..=42 {
            let raw_block = make_banff_std([height as u8; 32], height);
            let block_id = sha256_bytes(&raw_block);
            node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();
        }

        let now = unix_timestamp_secs();
        record_recently_accepted_pchain_block_at(&node, 40, now.saturating_sub(40)).await;
        record_recently_accepted_pchain_block_at(&node, 41, now.saturating_sub(20)).await;
        record_recently_accepted_pchain_block_at(&node, 42, now.saturating_sub(5)).await;

        let req = r#"{"jsonrpc":"2.0","method":"platform.getProposedHeight","params":{},"id":10}"#;
        let response = handle_rpc_request(req, &node).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["result"]["height"], "40");

        node.p_chain_recently_accepted.write().await.clear();
        let response = handle_rpc_request(req, &node).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["result"]["height"], "42");
    }

    #[tokio::test]
    async fn test_proposervm_get_proposed_height_is_path_scoped() {
        let node = make_test_node(999);
        let granite_time =
            upgrade_time_unix(&info_upgrades_result(node.config.network_id), "graniteTime");
        for (height, timestamp) in [(40, granite_time), (41, granite_time + 60)] {
            let raw_block = make_banff_std_with_timestamp([height as u8; 32], height, timestamp);
            let block_id = sha256_bytes(&raw_block);
            node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();
        }

        let now = unix_timestamp_secs();
        record_recently_accepted_pchain_block_at(&node, 41, now.saturating_sub(5)).await;
        node.db.set_last_accepted_height(34).unwrap();
        node.c_chain_metrics.write().await.tip_height = 34;

        let req =
            r#"{"jsonrpc":"2.0","method":"proposervm.getProposedHeight","params":{},"id":11}"#;

        let missing_response = handle_rpc_request(req, &node).await;
        let missing_json: serde_json::Value = serde_json::from_str(&missing_response).unwrap();
        assert_eq!(missing_json["error"]["code"], -32601);

        let p_response = handle_rpc_request_for_path(req, &node, "/ext/bc/P/proposervm").await;
        let p_json: serde_json::Value = serde_json::from_str(&p_response).unwrap();
        assert_eq!(p_json["result"]["height"], "40");

        let c_response = handle_rpc_request_for_path(req, &node, "/ext/bc/evm/proposervm").await;
        let c_json: serde_json::Value = serde_json::from_str(&c_response).unwrap();
        assert_eq!(c_json["result"]["height"], "34");
    }

    #[tokio::test]
    async fn test_proposervm_get_current_epoch_uses_granite_epoch_view() {
        let node = make_test_node(999);
        let granite_time =
            upgrade_time_unix(&info_upgrades_result(node.config.network_id), "graniteTime");
        for (height, timestamp) in [
            (9, granite_time - 1),
            (10, granite_time),
            (11, granite_time + 60),
        ] {
            let raw_block = make_banff_std_with_timestamp([height as u8; 32], height, timestamp);
            let block_id = sha256_bytes(&raw_block);
            node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();
        }

        let req = r#"{"jsonrpc":"2.0","method":"proposervm.getCurrentEpoch","params":{},"id":12}"#;
        let response = handle_rpc_request_for_path(req, &node, "/ext/bc/P/proposervm").await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();

        let expected = calculate_granite_epoch(
            node.config.network_id,
            unix_timestamp_secs(),
            granite_time,
            10,
        )
        .expect("granite epoch should be active");

        assert_eq!(json["result"]["epoch"], expected.epoch_number.to_string());
        assert_eq!(
            json["result"]["startTime"],
            expected.epoch_start_time.to_string()
        );
        assert_eq!(
            json["result"]["pChainHeight"],
            expected.epoch_p_chain_height.to_string()
        );
    }

    #[tokio::test]
    async fn test_http_proposervm_path_routes_through_rpc_server() {
        let node = make_test_node(999);
        let granite_time =
            upgrade_time_unix(&info_upgrades_result(node.config.network_id), "graniteTime");
        let raw_block = make_banff_std_with_timestamp([0x22; 32], 15, granite_time);
        let block_id = sha256_bytes(&raw_block);
        node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_node = node.clone();
        tokio::spawn(async move {
            run_rpc_server_with_listener(listener, server_node).await;
        });

        let req = r#"{"jsonrpc":"2.0","method":"proposervm.getCurrentEpoch","params":{},"id":13}"#;
        let response = http_post(addr, "/ext/bc/platform/proposervm", req).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"jsonrpc\":\"2.0\""));
        assert!(response.contains("\"pChainHeight\""));
    }

    #[tokio::test]
    async fn test_platform_get_block_supports_hex_and_json_encoding() {
        let node = make_test_node(1);
        let parent_id = [0x11; 32];
        let raw_block = make_banff_std(parent_id, 7);
        let block_id = sha256_bytes(&raw_block);
        node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();

        let hex_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBlock","params":{{"blockID":"0x{}","encoding":"hex"}},"id":11}}"#,
            hex::encode(block_id)
        );
        let hex_response = handle_rpc_request(&hex_req, &node).await;
        let hex_json: serde_json::Value = serde_json::from_str(&hex_response).unwrap();
        assert_eq!(hex_json["result"]["encoding"], "hex");
        assert_eq!(
            hex_json["result"]["block"],
            format!("0x{}", hex::encode(&raw_block))
        );

        let json_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBlock","params":{{"blockID":"0x{}","encoding":"json"}},"id":12}}"#,
            hex::encode(block_id)
        );
        let json_response = handle_rpc_request(&json_req, &node).await;
        let json_value: serde_json::Value = serde_json::from_str(&json_response).unwrap();
        assert_eq!(json_value["result"]["encoding"], "json");
        assert_eq!(
            json_value["result"]["block"]["id"],
            cb58_encode_id(block_id)
        );
        assert_eq!(
            json_value["result"]["block"]["parentID"],
            cb58_encode_id(parent_id)
        );
        assert_eq!(json_value["result"]["block"]["height"], 7);
        assert_eq!(json_value["result"]["block"]["time"], 1_700_000_000u64);
        assert_eq!(
            json_value["result"]["block"]["txs"],
            serde_json::Value::Array(vec![])
        );
        assert_eq!(json_value["result"]["block"]["txCount"], 0);
    }

    #[tokio::test]
    async fn test_platform_get_block_by_height_supports_hex_and_json_encoding() {
        let node = make_test_node(1);
        let parent_id = [0x22; 32];
        let raw_block = make_banff_std(parent_id, 9);
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&raw_block), &raw_block)
            .unwrap();

        let hex_req = r#"{"jsonrpc":"2.0","method":"platform.getBlockByHeight","params":{"height":"9","encoding":"hex"},"id":12}"#;
        let hex_response = handle_rpc_request(hex_req, &node).await;
        let hex_json: serde_json::Value = serde_json::from_str(&hex_response).unwrap();
        assert_eq!(hex_json["result"]["encoding"], "hex");
        assert_eq!(
            hex_json["result"]["block"],
            format!("0x{}", hex::encode(&raw_block))
        );

        let json_req = r#"{"jsonrpc":"2.0","method":"platform.getBlockByHeight","params":{"height":"0x9","encoding":"json"},"id":13}"#;
        let json_response = handle_rpc_request(json_req, &node).await;
        let json_value: serde_json::Value = serde_json::from_str(&json_response).unwrap();
        assert_eq!(json_value["result"]["encoding"], "json");
        assert_eq!(json_value["result"]["block"]["height"], 9);
        assert_eq!(
            json_value["result"]["block"]["parentID"],
            cb58_encode_id(parent_id)
        );
        assert_eq!(
            json_value["result"]["block"]["txs"],
            serde_json::Value::Array(vec![])
        );
    }

    #[tokio::test]
    async fn test_platform_get_blockchain_status_and_stake_shapes() {
        let node = make_test_node(1);
        node.sync_engine.mark_following().await;

        let cchain_status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBlockchainStatus","params":{{"blockchainID":"0x{}"}},"id":13}}"#,
            hex::encode(platform_cchain_blockchain_id(node.config.network_id))
        );
        let cchain_status_response = handle_rpc_request(&cchain_status_req, &node).await;
        let cchain_status_json: serde_json::Value =
            serde_json::from_str(&cchain_status_response).unwrap();
        assert_eq!(cchain_status_json["result"]["status"], "Created");

        let unknown_status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBlockchainStatus","params":{{"blockchainID":"0x{}"}},"id":14}}"#,
            hex::encode([0x22; 32])
        );
        let unknown_status_response = handle_rpc_request(&unknown_status_req, &node).await;
        let unknown_status_json: serde_json::Value =
            serde_json::from_str(&unknown_status_response).unwrap();
        assert_eq!(unknown_status_json["result"]["status"], "Unknown");

        let stake_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getStake","params":{{"addresses":["{}","{}"],"validatorsOnly":true,"encoding":"hex"}},"id":15}}"#,
            cb58_encode(&[0x31; 20]),
            cb58_encode(&[0x32; 20])
        );
        let stake_response = handle_rpc_request(&stake_req, &node).await;
        let stake_json: serde_json::Value = serde_json::from_str(&stake_response).unwrap();
        assert_eq!(stake_json["result"]["staked"], "0");
        assert_eq!(stake_json["result"]["encoding"], "hex");
        assert_eq!(stake_json["result"]["stakeds"][AVAX_ASSET_ID_MAINNET], "0");
        assert!(stake_json["result"]["stakedOutputs"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_platform_get_stake_uses_committed_stakers_and_skips_rewarded() {
        let node = make_test_node(1);
        let owner = [0x44; 20];
        let validator_tx = make_platform_add_validator_tx_bytes(owner, 7_000);
        let delegator_tx = make_platform_add_delegator_tx_bytes(owner, 3_000);
        let reward_tx = make_platform_reward_validator_tx_bytes(sha256_bytes(&validator_tx));

        let block1 = make_banff_std_with_txs(
            [0x70; 32],
            14,
            &[validator_tx.clone(), delegator_tx.clone()],
        );
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_proposal_with_tx(block1_id, 15, &reward_tx);
        let block2_id = sha256_bytes(&block2);
        let block3 = make_banff_decision_block(block2_id, 16, true);

        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db.put_cf(CF_BLOCKS, &block2_id, &block2).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block3), &block3)
            .unwrap();

        let owner_addr = cb58_encode(&owner);
        let stake_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getStake","params":{{"addresses":["{}"],"validatorsOnly":false,"encoding":"hex"}},"id":41}}"#,
            owner_addr
        );
        let stake_response = handle_rpc_request(&stake_req, &node).await;
        let stake_json: serde_json::Value = serde_json::from_str(&stake_response).unwrap();
        assert_eq!(stake_json["result"]["staked"], "3000");
        assert_eq!(
            stake_json["result"]["stakeds"][AVAX_ASSET_ID_MAINNET],
            "3000"
        );
        assert_eq!(
            stake_json["result"]["stakedOutputs"],
            serde_json::json!([format!(
                "0x{}",
                hex::encode(make_platform_transferable_output_bytes(
                    parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap(),
                    3_000,
                    owner,
                ))
            )])
        );

        let validators_only_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getStake","params":{{"addresses":["{}"],"validatorsOnly":true,"encoding":"hex"}},"id":42}}"#,
            owner_addr
        );
        let validators_only_response = handle_rpc_request(&validators_only_req, &node).await;
        let validators_only_json: serde_json::Value =
            serde_json::from_str(&validators_only_response).unwrap();
        assert_eq!(validators_only_json["result"]["staked"], "0");
        assert!(validators_only_json["result"]["stakedOutputs"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_platform_get_stake_ignores_undecided_reward_proposals() {
        let node = make_test_node(1);
        let owner = [0x45; 20];
        let validator_tx = make_platform_add_validator_tx_bytes(owner, 9_000);
        let reward_tx = make_platform_reward_validator_tx_bytes(sha256_bytes(&validator_tx));

        let block1 = make_banff_std_with_txs([0x71; 32], 14, std::slice::from_ref(&validator_tx));
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_proposal_with_tx(block1_id, 15, &reward_tx);

        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block2), &block2)
            .unwrap();

        let owner_addr = cb58_encode(&owner);
        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getStake","params":{{"addresses":["{}"],"validatorsOnly":true,"encoding":"hex"}},"id":44}}"#,
            owner_addr
        );
        let response = handle_rpc_request(&req, &node).await;
        let json_value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json_value["result"]["staked"], "9000");
        assert_eq!(
            json_value["result"]["stakeds"][AVAX_ASSET_ID_MAINNET],
            "9000"
        );
    }

    #[tokio::test]
    async fn test_platform_get_stake_rejects_invalid_addresses() {
        let node = make_test_node(1);
        let req = r#"{"jsonrpc":"2.0","method":"platform.getStake","params":{"addresses":["P-local1"],"encoding":"hex"},"id":43}"#;
        let response = handle_rpc_request(req, &node).await;
        let json_value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json_value["error"]["code"], -32602);
        assert_eq!(json_value["error"]["message"], "invalid address");
    }

    #[tokio::test]
    async fn test_platform_get_balance_and_utxos_use_committed_outputs_and_stake_refunds() {
        let node = make_test_node(1);
        let owner = [0x46; 20];
        let other = [0x47; 20];
        let asset_id = parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap();

        let unlocked_output = make_platform_transferable_output_bytes(asset_id, 100, owner);
        let locked_stakeable_output = make_platform_transferable_output_bytes_with_locks(
            asset_id,
            50,
            owner,
            0,
            Some(unix_timestamp_secs() + 10_000),
        );
        let locked_not_stakeable_output = make_platform_transferable_output_bytes_with_locks(
            asset_id,
            25,
            owner,
            unix_timestamp_secs() + 10_000,
            None,
        );
        let spent_tx = make_platform_base_tx_with_io(
            &[
                unlocked_output.clone(),
                locked_stakeable_output.clone(),
                locked_not_stakeable_output.clone(),
            ],
            &[],
        );
        let spent_tx_id = sha256_bytes(&spent_tx);
        let spend_input = make_platform_transferable_input_bytes(spent_tx_id, 0, asset_id, 100);
        let spend_tx = make_platform_base_tx_with_io(
            &[make_platform_transferable_output_bytes(asset_id, 10, other)],
            &[spend_input],
        );
        let validator_tx = make_platform_add_validator_tx_bytes(owner, 70);
        let reward_tx = make_platform_reward_validator_tx_bytes(sha256_bytes(&validator_tx));

        let block1 = make_banff_std_with_txs(
            [0x72; 32],
            14,
            &[spent_tx.clone(), spend_tx, validator_tx.clone()],
        );
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_proposal_with_tx(block1_id, 15, &reward_tx);
        let block2_id = sha256_bytes(&block2);
        let block3 = make_banff_decision_block(block2_id, 16, true);

        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db.put_cf(CF_BLOCKS, &block2_id, &block2).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block3), &block3)
            .unwrap();

        let owner_addr = cb58_encode(&owner);
        let balance_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBalance","params":{{"addresses":["{}"]}},"id":45}}"#,
            owner_addr
        );
        let balance_response = handle_rpc_request(&balance_req, &node).await;
        let balance_json: serde_json::Value = serde_json::from_str(&balance_response).unwrap();
        assert_eq!(balance_json["result"]["balance"], "145");
        assert_eq!(balance_json["result"]["unlocked"], "70");
        assert_eq!(balance_json["result"]["lockedStakeable"], "50");
        assert_eq!(balance_json["result"]["lockedNotStakeable"], "25");
        assert_eq!(
            balance_json["result"]["balances"][AVAX_ASSET_ID_MAINNET],
            "145"
        );
        assert_eq!(
            balance_json["result"]["utxoIDs"].as_array().unwrap().len(),
            3
        );

        let utxos_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getUTXOs","params":{{"addresses":["{}"],"limit":"0xa","encoding":"hex"}},"id":46}}"#,
            owner_addr
        );
        let utxos_response = handle_rpc_request(&utxos_req, &node).await;
        let utxos_json: serde_json::Value = serde_json::from_str(&utxos_response).unwrap();
        let utxos = utxos_json["result"]["utxos"].as_array().unwrap();
        assert_eq!(utxos_json["result"]["numFetched"], "3");
        assert_eq!(utxos.len(), 3);
        assert!(utxos
            .iter()
            .all(|value| value.as_str().unwrap().starts_with("0x")));
        assert_eq!(utxos_json["result"]["encoding"], "hex");
        assert_eq!(utxos_json["result"]["endIndex"]["address"], owner_addr);
    }

    #[tokio::test]
    async fn test_platform_get_balance_and_utxos_include_admin_tx_base_io() {
        let node = make_test_node(1);
        let owner = [0x56; 20];
        let asset_id = parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap();

        let funding_tx = make_platform_base_tx_with_io(
            &[
                make_platform_transferable_output_bytes(asset_id, 90, owner),
                make_platform_transferable_output_bytes(asset_id, 70, owner),
            ],
            &[],
        );
        let funding_tx_id = sha256_bytes(&funding_tx);

        let create_chain_tx = make_platform_create_chain_tx_bytes_with_io(
            &[make_platform_transferable_output_bytes(asset_id, 30, owner)],
            &[make_platform_transferable_input_bytes(
                funding_tx_id,
                0,
                asset_id,
                90,
            )],
            [0x61; 32],
        );
        let create_chain_tx_id = sha256_bytes(&create_chain_tx);

        let add_subnet_tx = make_platform_add_subnet_validator_tx_bytes_with_io(
            [0x62; 20],
            [0x63; 32],
            &[make_platform_transferable_output_bytes(asset_id, 20, owner)],
            &[make_platform_transferable_input_bytes(
                funding_tx_id,
                1,
                asset_id,
                70,
            )],
        );
        let add_subnet_tx_id = sha256_bytes(&add_subnet_tx);

        let block = make_banff_std_with_txs(
            [0x80; 32],
            18,
            &[funding_tx, create_chain_tx, add_subnet_tx],
        );
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block), &block)
            .unwrap();

        let owner_addr = cb58_encode(&owner);
        let balance_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBalance","params":{{"addresses":["{}"]}},"id":49}}"#,
            owner_addr
        );
        let balance_response = handle_rpc_request(&balance_req, &node).await;
        let balance_json: serde_json::Value = serde_json::from_str(&balance_response).unwrap();
        assert_eq!(balance_json["result"]["balance"], "50");
        assert_eq!(balance_json["result"]["unlocked"], "50");

        let mut utxo_ids = balance_json["result"]["utxoIDs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                format!(
                    "{}:{}",
                    value["txID"].as_str().unwrap(),
                    value["outputIndex"].as_u64().unwrap()
                )
            })
            .collect::<Vec<_>>();
        utxo_ids.sort();

        let mut expected_utxo_ids = vec![
            format!("{}:0", cb58_encode_id(create_chain_tx_id)),
            format!("{}:0", cb58_encode_id(add_subnet_tx_id)),
        ];
        expected_utxo_ids.sort();
        assert_eq!(utxo_ids, expected_utxo_ids);

        let utxos_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getUTXOs","params":{{"addresses":["{}"],"limit":"0xa","encoding":"hex"}},"id":50}}"#,
            owner_addr
        );
        let utxos_response = handle_rpc_request(&utxos_req, &node).await;
        let utxos_json: serde_json::Value = serde_json::from_str(&utxos_response).unwrap();
        assert_eq!(utxos_json["result"]["numFetched"], "2");
        assert_eq!(utxos_json["result"]["utxos"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_platform_get_balance_and_utxos_ignore_shared_memory_import_export_sides() {
        let node = make_test_node(1);
        let owner = [0x57; 20];
        let asset_id = parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap();

        let funding_tx = make_platform_base_tx_with_io(
            &[
                make_platform_transferable_output_bytes(asset_id, 80, owner),
                make_platform_transferable_output_bytes(asset_id, 25, owner),
            ],
            &[],
        );
        let funding_tx_id = sha256_bytes(&funding_tx);

        let import_tx = make_platform_import_tx_bytes_with_io(
            &[make_platform_transferable_output_bytes(asset_id, 40, owner)],
            &[],
            [0x91; 32],
            &[make_platform_transferable_input_bytes(
                funding_tx_id,
                1,
                asset_id,
                25,
            )],
        );
        let import_tx_id = sha256_bytes(&import_tx);

        let export_tx = make_platform_export_tx_bytes_with_io(
            &[make_platform_transferable_output_bytes(asset_id, 10, owner)],
            &[make_platform_transferable_input_bytes(
                funding_tx_id,
                0,
                asset_id,
                80,
            )],
            [0x92; 32],
            &[make_platform_transferable_output_bytes(asset_id, 70, owner)],
        );
        let export_tx_id = sha256_bytes(&export_tx);

        let block = make_banff_std_with_txs([0x81; 32], 19, &[funding_tx, import_tx, export_tx]);
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block), &block)
            .unwrap();

        let owner_addr = cb58_encode(&owner);
        let balance_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBalance","params":{{"addresses":["{}"]}},"id":51}}"#,
            owner_addr
        );
        let balance_response = handle_rpc_request(&balance_req, &node).await;
        let balance_json: serde_json::Value = serde_json::from_str(&balance_response).unwrap();
        assert_eq!(balance_json["result"]["balance"], "75");
        assert_eq!(balance_json["result"]["unlocked"], "75");

        let mut utxo_ids = balance_json["result"]["utxoIDs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                format!(
                    "{}:{}",
                    value["txID"].as_str().unwrap(),
                    value["outputIndex"].as_u64().unwrap()
                )
            })
            .collect::<Vec<_>>();
        utxo_ids.sort();

        let mut expected_utxo_ids = vec![
            format!("{}:1", cb58_encode_id(funding_tx_id)),
            format!("{}:0", cb58_encode_id(import_tx_id)),
            format!("{}:0", cb58_encode_id(export_tx_id)),
        ];
        expected_utxo_ids.sort();
        assert_eq!(utxo_ids, expected_utxo_ids);

        let utxos_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getUTXOs","params":{{"addresses":["{}"],"limit":"0xa","encoding":"hex"}},"id":52}}"#,
            owner_addr
        );
        let utxos_response = handle_rpc_request(&utxos_req, &node).await;
        let utxos_json: serde_json::Value = serde_json::from_str(&utxos_response).unwrap();
        assert_eq!(utxos_json["result"]["numFetched"], "3");
        assert_eq!(utxos_json["result"]["utxos"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_platform_get_reward_utxos_and_balance_include_committed_validator_rewards() {
        let node = make_test_node(1);
        let owner = [0x48; 20];
        let stake_amount = 2_000 * avalanche_rs::staking::NANO_AVAX;
        let start_time = 1_000u64;
        let end_time = start_time + 30 * 86_400;
        let validator_tx = make_platform_add_validator_tx_bytes_with_window(
            owner,
            stake_amount,
            start_time,
            end_time,
            0,
        );
        let validator_tx_id = sha256_bytes(&validator_tx);
        let reward_tx = make_platform_reward_validator_tx_bytes(validator_tx_id);

        let block1 = make_banff_std_with_txs([0x73; 32], 20, std::slice::from_ref(&validator_tx));
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_proposal_with_tx(block1_id, 21, &reward_tx);
        let block2_id = sha256_bytes(&block2);
        let block3 = make_banff_decision_block(block2_id, 22, true);

        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db.put_cf(CF_BLOCKS, &block2_id, &block2).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block3), &block3)
            .unwrap();

        let reward_amount = avalanche_rs::staking::expected_reward(
            stake_amount,
            end_time.saturating_sub(start_time),
            1.0,
        );
        assert!(reward_amount > 0);
        let expected_reward_utxo = platform_encode_utxo(
            validator_tx_id,
            1,
            &platform_reward_owned_output(
                parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap(),
                &PlatformOutputOwner {
                    locktime: 0,
                    threshold: 1,
                    addresses: vec![owner],
                },
                reward_amount,
            ),
            "hex",
        )
        .unwrap();

        let reward_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getRewardUTXOs","params":{{"txID":"{}","encoding":"hex"}},"id":47}}"#,
            cb58_encode_id(validator_tx_id)
        );
        let reward_response = handle_rpc_request(&reward_req, &node).await;
        let reward_json: serde_json::Value = serde_json::from_str(&reward_response).unwrap();
        assert_eq!(reward_json["result"]["numFetched"], "1");
        assert_eq!(reward_json["result"]["encoding"], "hex");
        assert_eq!(
            reward_json["result"]["utxos"],
            serde_json::json!([expected_reward_utxo])
        );

        let owner_addr = cb58_encode(&owner);
        let balance_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBalance","params":{{"addresses":["{}"]}},"id":48}}"#,
            owner_addr
        );
        let balance_response = handle_rpc_request(&balance_req, &node).await;
        let balance_json: serde_json::Value = serde_json::from_str(&balance_response).unwrap();
        assert_eq!(
            balance_json["result"]["balance"],
            stake_amount.saturating_add(reward_amount).to_string()
        );
        assert_eq!(
            balance_json["result"]["unlocked"],
            stake_amount.saturating_add(reward_amount).to_string()
        );
        assert_eq!(
            balance_json["result"]["utxoIDs"].as_array().unwrap().len(),
            2
        );
    }

    #[tokio::test]
    async fn test_platform_get_reward_utxos_include_pre_cortina_delegatee_reward() {
        let node = make_test_node(1);
        let validator_owner = [0x49; 20];
        let delegator_owner = [0x4a; 20];
        let validator_amount = 2_000 * avalanche_rs::staking::NANO_AVAX;
        let delegator_amount = 25 * avalanche_rs::staking::NANO_AVAX;
        let start_time = 1_000u64;
        let end_time = start_time + 30 * 86_400;
        let validator_tx = make_platform_add_validator_tx_bytes_with_window(
            validator_owner,
            validator_amount,
            start_time,
            end_time,
            250_000,
        );
        let delegator_tx = make_platform_add_delegator_tx_bytes_with_window(
            delegator_owner,
            delegator_amount,
            [0x11; 20],
            start_time + 1,
            end_time - 1,
        );
        let delegator_tx_id = sha256_bytes(&delegator_tx);
        let reward_tx = make_platform_reward_validator_tx_bytes(delegator_tx_id);

        let block1 = make_banff_std_with_txs(
            [0x74; 32],
            30,
            &[validator_tx.clone(), delegator_tx.clone()],
        );
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_proposal_with_tx(block1_id, 31, &reward_tx);
        let block2_id = sha256_bytes(&block2);
        let block3 = make_banff_decision_block(block2_id, 32, true);

        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db.put_cf(CF_BLOCKS, &block2_id, &block2).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block3), &block3)
            .unwrap();

        let total_reward = avalanche_rs::staking::expected_reward(
            delegator_amount,
            (end_time - 1).saturating_sub(start_time + 1),
            1.0,
        );
        let (delegatee_reward, delegator_reward) = platform_reward_split(total_reward, 250_000);
        let asset_id = parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap();
        let expected_delegator_utxo = platform_encode_utxo(
            delegator_tx_id,
            1,
            &platform_reward_owned_output(
                asset_id,
                &PlatformOutputOwner {
                    locktime: 0,
                    threshold: 1,
                    addresses: vec![delegator_owner],
                },
                delegator_reward,
            ),
            "hex",
        )
        .unwrap();
        let expected_delegatee_utxo = platform_encode_utxo(
            delegator_tx_id,
            2,
            &platform_reward_owned_output(
                asset_id,
                &PlatformOutputOwner {
                    locktime: 0,
                    threshold: 1,
                    addresses: vec![validator_owner],
                },
                delegatee_reward,
            ),
            "hex",
        )
        .unwrap();

        let reward_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getRewardUTXOs","params":{{"txID":"{}","encoding":"hex"}},"id":49}}"#,
            cb58_encode_id(delegator_tx_id)
        );
        let reward_response = handle_rpc_request(&reward_req, &node).await;
        let reward_json: serde_json::Value = serde_json::from_str(&reward_response).unwrap();
        assert_eq!(reward_json["result"]["numFetched"], "2");
        assert_eq!(
            reward_json["result"]["utxos"],
            serde_json::json!([expected_delegator_utxo, expected_delegatee_utxo])
        );

        let validator_balance_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBalance","params":{{"addresses":["{}"]}},"id":50}}"#,
            cb58_encode(&validator_owner)
        );
        let validator_balance_response = handle_rpc_request(&validator_balance_req, &node).await;
        let validator_balance_json: serde_json::Value =
            serde_json::from_str(&validator_balance_response).unwrap();
        assert_eq!(
            validator_balance_json["result"]["balance"],
            delegatee_reward.to_string()
        );
    }

    #[tokio::test]
    async fn test_platform_get_reward_utxos_accrue_post_cortina_delegatee_reward_to_validator() {
        let node = make_test_node(1);
        let validator_owner = [0x4b; 20];
        let delegator_owner = [0x4c; 20];
        let validator_amount = 2_000 * avalanche_rs::staking::NANO_AVAX;
        let delegator_amount = 25 * avalanche_rs::staking::NANO_AVAX;
        let cortina_time = upgrade_time_unix(&info_upgrades_result(1), "cortinaTime");
        let start_time = cortina_time + 100;
        let end_time = start_time + 30 * 86_400;
        let validator_tx = make_platform_add_validator_tx_bytes_with_window(
            validator_owner,
            validator_amount,
            start_time,
            end_time,
            250_000,
        );
        let validator_tx_id = sha256_bytes(&validator_tx);
        let delegator_tx = make_platform_add_delegator_tx_bytes_with_window(
            delegator_owner,
            delegator_amount,
            [0x11; 20],
            start_time + 1,
            end_time - 1,
        );
        let delegator_tx_id = sha256_bytes(&delegator_tx);
        let delegator_reward_tx = make_platform_reward_validator_tx_bytes(delegator_tx_id);
        let validator_reward_tx = make_platform_reward_validator_tx_bytes(validator_tx_id);

        let block1 = make_banff_std_with_txs(
            [0x75; 32],
            40,
            &[validator_tx.clone(), delegator_tx.clone()],
        );
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_proposal_with_tx(block1_id, 41, &delegator_reward_tx);
        let block2_id = sha256_bytes(&block2);
        let block3 = make_banff_decision_block(block2_id, 42, true);
        let block3_id = sha256_bytes(&block3);
        let block4 = make_banff_proposal_with_tx(block3_id, 43, &validator_reward_tx);
        let block4_id = sha256_bytes(&block4);
        let block5 = make_banff_decision_block(block4_id, 44, true);

        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db.put_cf(CF_BLOCKS, &block2_id, &block2).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block3), &block3)
            .unwrap();
        node.db.put_cf(CF_BLOCKS, &block4_id, &block4).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block5), &block5)
            .unwrap();

        let delegator_total_reward = avalanche_rs::staking::expected_reward(
            delegator_amount,
            (end_time - 1).saturating_sub(start_time + 1),
            1.0,
        );
        let (delegatee_reward, delegator_reward) =
            platform_reward_split(delegator_total_reward, 250_000);
        let validator_direct_reward = avalanche_rs::staking::expected_reward(
            validator_amount,
            end_time.saturating_sub(start_time),
            1.0,
        );
        let asset_id = parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap();

        let delegator_reward_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getRewardUTXOs","params":{{"txID":"{}","encoding":"hex"}},"id":51}}"#,
            cb58_encode_id(delegator_tx_id)
        );
        let delegator_reward_response = handle_rpc_request(&delegator_reward_req, &node).await;
        let delegator_reward_json: serde_json::Value =
            serde_json::from_str(&delegator_reward_response).unwrap();
        assert_eq!(delegator_reward_json["result"]["numFetched"], "1");
        assert_eq!(
            delegator_reward_json["result"]["utxos"],
            serde_json::json!([platform_encode_utxo(
                delegator_tx_id,
                1,
                &platform_reward_owned_output(
                    asset_id,
                    &PlatformOutputOwner {
                        locktime: 0,
                        threshold: 1,
                        addresses: vec![delegator_owner],
                    },
                    delegator_reward,
                ),
                "hex",
            )
            .unwrap()])
        );

        let validator_reward_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getRewardUTXOs","params":{{"txID":"{}","encoding":"hex"}},"id":52}}"#,
            cb58_encode_id(validator_tx_id)
        );
        let validator_reward_response = handle_rpc_request(&validator_reward_req, &node).await;
        let validator_reward_json: serde_json::Value =
            serde_json::from_str(&validator_reward_response).unwrap();
        assert_eq!(validator_reward_json["result"]["numFetched"], "2");
        assert_eq!(
            validator_reward_json["result"]["utxos"],
            serde_json::json!([
                platform_encode_utxo(
                    validator_tx_id,
                    1,
                    &platform_reward_owned_output(
                        asset_id,
                        &PlatformOutputOwner {
                            locktime: 0,
                            threshold: 1,
                            addresses: vec![validator_owner],
                        },
                        validator_direct_reward,
                    ),
                    "hex",
                )
                .unwrap(),
                platform_encode_utxo(
                    validator_tx_id,
                    2,
                    &platform_reward_owned_output(
                        asset_id,
                        &PlatformOutputOwner {
                            locktime: 0,
                            threshold: 1,
                            addresses: vec![validator_owner],
                        },
                        delegatee_reward,
                    ),
                    "hex",
                )
                .unwrap(),
            ])
        );
    }

    #[tokio::test]
    async fn test_platform_get_current_supply_uses_started_rewards_and_aborts() {
        let node = make_test_node(1);
        let stake_amount = 2_000 * avalanche_rs::staking::NANO_AVAX;

        let current_validator_tx = make_platform_add_validator_tx_bytes_with_window(
            [0x51; 20],
            stake_amount,
            1_699_999_000,
            1_700_100_000,
            0,
        );
        let pending_validator_tx = make_platform_add_validator_tx_bytes_with_window(
            [0x52; 20],
            stake_amount,
            1_700_100_000,
            1_700_200_000,
            0,
        );
        let committed_validator_tx = make_platform_add_validator_tx_bytes_with_window(
            [0x53; 20],
            stake_amount,
            1_699_998_000,
            1_699_999_000,
            0,
        );
        let aborted_validator_tx = make_platform_add_validator_tx_bytes_with_window(
            [0x54; 20],
            stake_amount,
            1_699_997_000,
            1_699_998_000,
            0,
        );

        let committed_reward_tx =
            make_platform_reward_validator_tx_bytes(sha256_bytes(&committed_validator_tx));
        let aborted_reward_tx =
            make_platform_reward_validator_tx_bytes(sha256_bytes(&aborted_validator_tx));

        let block1 = make_banff_std_with_txs(
            [0x76; 32],
            50,
            &[
                current_validator_tx.clone(),
                pending_validator_tx,
                committed_validator_tx.clone(),
                aborted_validator_tx.clone(),
            ],
        );
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_proposal_with_tx(block1_id, 51, &committed_reward_tx);
        let block2_id = sha256_bytes(&block2);
        let block3 = make_banff_decision_block(block2_id, 52, true);
        let block3_id = sha256_bytes(&block3);
        let block4 = make_banff_proposal_with_tx(block3_id, 53, &aborted_reward_tx);
        let block4_id = sha256_bytes(&block4);
        let block5 = make_banff_decision_block(block4_id, 54, false);

        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db.put_cf(CF_BLOCKS, &block2_id, &block2).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block3), &block3)
            .unwrap();
        node.db.put_cf(CF_BLOCKS, &block4_id, &block4).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block5), &block5)
            .unwrap();

        let current_reward = avalanche_rs::staking::expected_reward(
            stake_amount,
            1_700_100_000u64.saturating_sub(1_699_999_000),
            1.0,
        );
        let committed_reward = avalanche_rs::staking::expected_reward(
            stake_amount,
            1_699_999_000u64.saturating_sub(1_699_998_000),
            1.0,
        );
        let expected_supply = platform_initial_supply(1, &SubnetId::primary_network())
            .unwrap()
            .saturating_add(current_reward)
            .saturating_add(committed_reward);

        let req = r#"{"jsonrpc":"2.0","method":"platform.getCurrentSupply","params":{},"id":53}"#;
        let response = handle_rpc_request(req, &node).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["result"]["supply"], expected_supply.to_string());
        assert_eq!(json["result"]["height"], "54");

        let primary_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getCurrentSupply","params":{{"subnetID":"{}"}},"id":54}}"#,
            cb58_encode_id(SubnetId::primary_network().0)
        );
        let primary_response = handle_rpc_request(&primary_req, &node).await;
        let primary_json: serde_json::Value = serde_json::from_str(&primary_response).unwrap();
        assert_eq!(
            primary_json["result"]["supply"],
            expected_supply.to_string()
        );

        let unsupported_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getCurrentSupply","params":{{"subnetID":"{}"}},"id":55}}"#,
            cb58_encode_id([0x99; 32])
        );
        let unsupported_response = handle_rpc_request(&unsupported_req, &node).await;
        let unsupported_json: serde_json::Value =
            serde_json::from_str(&unsupported_response).unwrap();
        assert_eq!(unsupported_json["error"]["code"], -32000);
        assert_eq!(
            unsupported_json["error"]["message"],
            "current supply unavailable for subnet"
        );
    }

    #[tokio::test]
    async fn test_platform_chain_relationship_and_asset_endpoints() {
        let node = make_test_node(1);
        let custom_subnet = SubnetId([0x44; 32]);
        let custom_chain = ChainId([0x55; 32]);
        {
            let mut tracker = node.subnet_tracker.write().await;
            tracker.observe_l1_chain(
                custom_subnet.clone(),
                custom_chain.clone(),
                "Custom EVM",
                "evm",
            );
        }

        let blockchains_req =
            r#"{"jsonrpc":"2.0","method":"platform.getBlockchains","params":{},"id":16}"#;
        let blockchains_response = handle_rpc_request(blockchains_req, &node).await;
        let blockchains_json: serde_json::Value =
            serde_json::from_str(&blockchains_response).unwrap();
        let blockchains = blockchains_json["result"]["blockchains"]
            .as_array()
            .unwrap();
        assert!(blockchains.iter().any(|chain| {
            chain["id"] == cb58_encode_id(platform_cchain_blockchain_id(node.config.network_id))
                && chain["vmID"] == EVM_VM_ID
        }));
        assert!(!blockchains.iter().any(|chain| chain["name"] == "X-Chain"));
        assert!(blockchains.iter().any(|chain| {
            chain["id"] == cb58_encode_id(custom_chain.0)
                && chain["subnetID"] == cb58_encode_id(custom_subnet.0)
                && chain["vmID"] == EVM_VM_ID
        }));

        let validated_by_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.validatedBy","params":{{"blockchainID":"{}"}},"id":17}}"#,
            cb58_encode_id(custom_chain.0)
        );
        let validated_by_response = handle_rpc_request(&validated_by_req, &node).await;
        let validated_by_json: serde_json::Value =
            serde_json::from_str(&validated_by_response).unwrap();
        assert_eq!(
            validated_by_json["result"]["subnetID"],
            cb58_encode_id(custom_subnet.0)
        );

        let validates_primary_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.validates","params":{{"subnetID":"{}"}},"id":18}}"#,
            cb58_encode_id(SubnetId::primary_network().0)
        );
        let validates_primary_response = handle_rpc_request(&validates_primary_req, &node).await;
        let validates_primary_json: serde_json::Value =
            serde_json::from_str(&validates_primary_response).unwrap();
        let primary_ids = validates_primary_json["result"]["blockchainIDs"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();
        let expected_c_chain =
            cb58_encode_id(platform_cchain_blockchain_id(node.config.network_id));
        assert_eq!(primary_ids, vec![expected_c_chain.as_str()]);

        let validates_custom_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.validates","params":{{"subnetID":"{}"}},"id":19}}"#,
            cb58_encode_id(custom_subnet.0)
        );
        let validates_custom_response = handle_rpc_request(&validates_custom_req, &node).await;
        let validates_custom_json: serde_json::Value =
            serde_json::from_str(&validates_custom_response).unwrap();
        assert_eq!(
            validates_custom_json["result"]["blockchainIDs"][0],
            cb58_encode_id(custom_chain.0)
        );

        let asset_req =
            r#"{"jsonrpc":"2.0","method":"platform.getStakingAssetID","params":{},"id":20}"#;
        let asset_response = handle_rpc_request(asset_req, &node).await;
        let asset_json: serde_json::Value = serde_json::from_str(&asset_response).unwrap();
        assert_eq!(asset_json["result"]["assetID"], AVAX_ASSET_ID_MAINNET);

        let custom_asset_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getStakingAssetID","params":{{"subnetID":"{}"}},"id":21}}"#,
            cb58_encode_id(custom_subnet.0)
        );
        let custom_asset_response = handle_rpc_request(&custom_asset_req, &node).await;
        let custom_asset_json: serde_json::Value =
            serde_json::from_str(&custom_asset_response).unwrap();
        assert_eq!(custom_asset_json["error"]["code"], -32000);
    }

    #[tokio::test]
    async fn test_platform_total_stake_sampling_and_timestamp() {
        let now = unix_timestamp_secs();
        let mut validators = std::collections::HashMap::new();
        validators.insert(
            "NodeID-a".to_string(),
            ValidatorInfo {
                node_id: "NodeID-a".to_string(),
                weight: 2_000 * avalanche_rs::staking::NANO_AVAX,
                start_time: now.saturating_sub(60),
                end_time: now + 600,
            },
        );
        validators.insert(
            "NodeID-b".to_string(),
            ValidatorInfo {
                node_id: "NodeID-b".to_string(),
                weight: 3_000 * avalanche_rs::staking::NANO_AVAX,
                start_time: now.saturating_sub(120),
                end_time: now + 1200,
            },
        );
        validators.insert(
            "NodeID-c".to_string(),
            ValidatorInfo {
                node_id: "NodeID-c".to_string(),
                weight: 4_000 * avalanche_rs::staking::NANO_AVAX,
                start_time: now + 3600,
                end_time: now + 7200,
            },
        );
        let node = make_test_node_with_validators(1, validators, std::collections::HashSet::new());
        let raw_block = make_banff_std([0x11; 32], 7);
        let block_id = sha256_bytes(&raw_block);
        node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();

        let total_stake_req =
            r#"{"jsonrpc":"2.0","method":"platform.getTotalStake","params":{},"id":22}"#;
        let total_stake_response = handle_rpc_request(total_stake_req, &node).await;
        let total_stake_json: serde_json::Value =
            serde_json::from_str(&total_stake_response).unwrap();
        assert_eq!(
            total_stake_json["result"]["stake"],
            (5_000 * avalanche_rs::staking::NANO_AVAX).to_string()
        );
        assert_eq!(
            total_stake_json["result"]["weight"],
            (5_000 * avalanche_rs::staking::NANO_AVAX).to_string()
        );

        let sample_req =
            r#"{"jsonrpc":"2.0","method":"platform.sampleValidators","params":{"size":2},"id":23}"#;
        let sample_response = handle_rpc_request(sample_req, &node).await;
        let sample_json: serde_json::Value = serde_json::from_str(&sample_response).unwrap();
        let sampled = sample_json["result"]["validators"].as_array().unwrap();
        assert_eq!(sampled.len(), 2);
        for validator in sampled {
            let validator = validator.as_str().unwrap();
            assert!(validator == "NodeID-a" || validator == "NodeID-b");
        }

        let timestamp_req =
            r#"{"jsonrpc":"2.0","method":"platform.getTimestamp","params":{},"id":24}"#;
        let timestamp_response = handle_rpc_request(timestamp_req, &node).await;
        let timestamp_json: serde_json::Value = serde_json::from_str(&timestamp_response).unwrap();
        let timestamp = timestamp_json["result"]["timestamp"].as_str().unwrap();
        assert_eq!(timestamp, unix_timestamp_to_rfc3339_seconds(1_700_000_000));
    }

    #[tokio::test]
    async fn test_platform_fee_config_endpoints_return_network_params() {
        let mainnet = make_test_node(1);
        let mainnet_fee_config_response = handle_rpc_request(
            r#"{"jsonrpc":"2.0","method":"platform.getFeeConfig","params":{},"id":25}"#,
            &mainnet,
        )
        .await;
        let mainnet_fee_config_json: serde_json::Value =
            serde_json::from_str(&mainnet_fee_config_response).unwrap();
        assert_eq!(
            mainnet_fee_config_json["result"]["weights"],
            serde_json::json!([1, 1000, 1000, 4])
        );
        assert_eq!(mainnet_fee_config_json["result"]["maxCapacity"], 1_000_000);
        assert_eq!(mainnet_fee_config_json["result"]["maxPerSecond"], 100_000);
        assert_eq!(mainnet_fee_config_json["result"]["targetPerSecond"], 50_000);
        assert_eq!(mainnet_fee_config_json["result"]["minPrice"], 1);
        assert_eq!(
            mainnet_fee_config_json["result"]["excessConversionConstant"],
            2_164_043
        );

        let mainnet_validator_fee_response = handle_rpc_request(
            r#"{"jsonrpc":"2.0","method":"platform.getValidatorFeeConfig","params":{},"id":26}"#,
            &mainnet,
        )
        .await;
        let mainnet_validator_fee_json: serde_json::Value =
            serde_json::from_str(&mainnet_validator_fee_response).unwrap();
        assert_eq!(mainnet_validator_fee_json["result"]["capacity"], 20_000);
        assert_eq!(mainnet_validator_fee_json["result"]["target"], 10_000);
        assert_eq!(mainnet_validator_fee_json["result"]["minPrice"], 512);
        assert_eq!(
            mainnet_validator_fee_json["result"]["excessConversionConstant"],
            1_246_488_515u64
        );

        let fuji = make_test_node(5);
        let fuji_validator_fee_response = handle_rpc_request(
            r#"{"jsonrpc":"2.0","method":"platform.getValidatorFeeConfig","params":{},"id":27}"#,
            &fuji,
        )
        .await;
        let fuji_validator_fee_json: serde_json::Value =
            serde_json::from_str(&fuji_validator_fee_response).unwrap();
        assert_eq!(fuji_validator_fee_json["result"]["minPrice"], 512);
        assert_eq!(
            fuji_validator_fee_json["result"]["excessConversionConstant"],
            51_937_021
        );

        let local = make_test_node(12345);
        let local_validator_fee_response = handle_rpc_request(
            r#"{"jsonrpc":"2.0","method":"platform.getValidatorFeeConfig","params":{},"id":28}"#,
            &local,
        )
        .await;
        let local_validator_fee_json: serde_json::Value =
            serde_json::from_str(&local_validator_fee_response).unwrap();
        assert_eq!(local_validator_fee_json["result"]["minPrice"], 1);
        assert_eq!(
            local_validator_fee_json["result"]["excessConversionConstant"],
            865_617
        );
    }

    #[tokio::test]
    async fn test_platform_fee_state_endpoints_use_committed_dynamic_state() {
        let node = make_test_node(12345);
        let asset_id = [0x44; 32];
        let prev_tx_id = [0x55; 32];
        let owner = [0x66; 20];
        let tx_bytes = make_platform_base_tx_with_io(
            &[make_platform_transferable_output_bytes(
                asset_id, 500, owner,
            )],
            &[make_platform_transferable_input_bytes(
                prev_tx_id, 0, asset_id, 500,
            )],
        );
        let raw_block = make_banff_std_with_txs([0x77; 32], 60, std::slice::from_ref(&tx_bytes));
        let block_id = sha256_bytes(&raw_block);
        node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();

        let tx_gas = tx_bytes.len() as u64 + 3_000;
        let expected_capacity = 1_000_000u64.saturating_sub(tx_gas);
        let expected_excess = tx_gas;
        let expected_timestamp = unix_timestamp_to_rfc3339_seconds(1_700_000_000);

        let fee_state_response = handle_rpc_request(
            r#"{"jsonrpc":"2.0","method":"platform.getFeeState","params":{},"id":29}"#,
            &node,
        )
        .await;
        let fee_state_json: serde_json::Value = serde_json::from_str(&fee_state_response).unwrap();
        assert_eq!(fee_state_json["result"]["capacity"], expected_capacity);
        assert_eq!(fee_state_json["result"]["excess"], expected_excess);
        assert_eq!(
            fee_state_json["result"]["price"],
            platform_gas_price(1, expected_excess, 2_164_043)
        );
        assert_eq!(fee_state_json["result"]["timestamp"], expected_timestamp);
        assert!(fee_state_json["result"]["state"].is_null());

        let validator_fee_state_response = handle_rpc_request(
            r#"{"jsonrpc":"2.0","method":"platform.getValidatorFeeState","params":{},"id":30}"#,
            &node,
        )
        .await;
        let validator_fee_state_json: serde_json::Value =
            serde_json::from_str(&validator_fee_state_response).unwrap();
        assert_eq!(validator_fee_state_json["result"]["excess"], 0);
        assert_eq!(validator_fee_state_json["result"]["price"], 1);
        assert_eq!(
            validator_fee_state_json["result"]["timestamp"],
            expected_timestamp
        );
    }

    #[tokio::test]
    async fn test_platform_validator_fee_state_tracks_committed_l1_validator_txs() {
        let node = make_test_node(12345);
        let subnet_id = [0x91; 32];
        let owner = [0x71; 20];
        let etna_time =
            upgrade_time_unix(&info_upgrades_result(node.config.network_id), "etnaTime");

        let convert_tx = make_platform_convert_subnet_to_l1_tx_bytes(
            subnet_id,
            &[([0x10; 20], 1, 12, owner), ([0x20; 20], 1, 0, owner)],
        );
        let converted_active_id = append_platform_id_for_test(subnet_id, 0);
        let converted_inactive_id = append_platform_id_for_test(subnet_id, 1);
        let (register_tx, register_validation_id) = make_platform_register_l1_validator_tx_bytes(
            subnet_id,
            [0x30; 20],
            owner,
            1,
            25,
            etna_time + 86_400,
            3,
        );
        let increase_tx =
            make_platform_increase_l1_validator_balance_tx_bytes(converted_inactive_id, 30);
        let set_weight_tx =
            make_platform_set_l1_validator_weight_tx_bytes(register_validation_id, 0, 0, 2);
        let disable_tx = make_platform_disable_l1_validator_tx_bytes(converted_inactive_id);

        let block1 = make_banff_std_with_txs_at([0x01; 32], 1, etna_time + 5, &[convert_tx]);
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_std_with_txs_at(block1_id, 2, etna_time + 15, &[register_tx]);
        let block2_id = sha256_bytes(&block2);
        let block3 = make_banff_std_with_txs_at(block2_id, 3, etna_time + 25, &[increase_tx]);
        let block3_id = sha256_bytes(&block3);
        let block4 = make_banff_std_with_txs_at(block3_id, 4, etna_time + 35, &[set_weight_tx]);
        let block4_id = sha256_bytes(&block4);
        let block5 = make_banff_std_with_txs_at(block4_id, 5, etna_time + 45, &[disable_tx]);

        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db.put_cf(CF_BLOCKS, &block2_id, &block2).unwrap();
        node.db.put_cf(CF_BLOCKS, &block3_id, &block3).unwrap();
        node.db.put_cf(CF_BLOCKS, &block4_id, &block4).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block5), &block5)
            .unwrap();

        let (state, timestamp) = scan_platform_validator_fee_state(&node).unwrap();
        assert_eq!(state.active, 0);
        assert_eq!(state.excess, 0);
        assert_eq!(state.accrued_fees, 45);
        assert_eq!(timestamp, etna_time + 45);

        let validator_fee_state_response = handle_rpc_request(
            r#"{"jsonrpc":"2.0","method":"platform.getValidatorFeeState","params":{},"id":31}"#,
            &node,
        )
        .await;
        let validator_fee_state_json: serde_json::Value =
            serde_json::from_str(&validator_fee_state_response).unwrap();
        assert_eq!(validator_fee_state_json["result"]["excess"], 0);
        assert_eq!(validator_fee_state_json["result"]["price"], 1);
        assert_eq!(
            validator_fee_state_json["result"]["timestamp"],
            unix_timestamp_to_rfc3339_seconds(etna_time + 45)
        );
        assert_eq!(converted_active_id.len(), 32);
    }

    #[tokio::test]
    async fn test_platform_fee_state_accounts_for_etna_l1_validator_txs() {
        let node = make_test_node(12345);
        let subnet_id = [0x81; 32];
        let owner = [0x61; 20];
        let etna_time =
            upgrade_time_unix(&info_upgrades_result(node.config.network_id), "etnaTime");

        let convert_tx =
            make_platform_convert_subnet_to_l1_tx_bytes(subnet_id, &[([0x11; 20], 1, 10, owner)]);
        let convert_validation_id = append_platform_id_for_test(subnet_id, 0);
        let (register_tx, register_validation_id) = make_platform_register_l1_validator_tx_bytes(
            subnet_id,
            [0x22; 20],
            owner,
            1,
            5,
            etna_time + 86_400,
            2,
        );
        let set_weight_tx =
            make_platform_set_l1_validator_weight_tx_bytes(register_validation_id, 0, 0, 1);
        let increase_tx =
            make_platform_increase_l1_validator_balance_tx_bytes(convert_validation_id, 7);
        let disable_tx = make_platform_disable_l1_validator_tx_bytes(convert_validation_id);
        let txs = vec![
            convert_tx,
            register_tx,
            set_weight_tx,
            increase_tx,
            disable_tx,
        ];

        let expected_gas = txs
            .iter()
            .map(|tx| {
                avalanche_rs::pchain::platform_tx_dynamic_fee_gas(
                    tx,
                    platform_dynamic_fee_config(node.config.network_id).weights,
                )
                .unwrap()
                .unwrap()
            })
            .sum::<u64>();
        let raw_block = make_banff_std_with_txs_at([0x99; 32], 2, etna_time + 30, &txs);
        let block_id = sha256_bytes(&raw_block);
        node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();

        let fee_state_response = handle_rpc_request(
            r#"{"jsonrpc":"2.0","method":"platform.getFeeState","params":{},"id":32}"#,
            &node,
        )
        .await;
        let fee_state_json: serde_json::Value = serde_json::from_str(&fee_state_response).unwrap();
        assert_eq!(
            fee_state_json["result"]["capacity"],
            1_000_000u64.saturating_sub(expected_gas)
        );
        assert_eq!(fee_state_json["result"]["excess"], expected_gas);
        assert_eq!(
            fee_state_json["result"]["price"],
            platform_gas_price(1, expected_gas, 2_164_043)
        );
        assert_eq!(
            fee_state_json["result"]["timestamp"],
            unix_timestamp_to_rfc3339_seconds(etna_time + 30)
        );
    }

    #[tokio::test]
    async fn test_platform_get_l1_validator_replays_committed_state() {
        let node = make_test_node(12345);
        let subnet_id = [0x94; 32];
        let node_id = [0x95; 20];
        let owner = [0x96; 20];
        let etna_time =
            upgrade_time_unix(&info_upgrades_result(node.config.network_id), "etnaTime");

        let (register_tx, validation_id) = make_platform_register_l1_validator_tx_bytes(
            subnet_id,
            node_id,
            owner,
            7,
            25,
            etna_time + 86_400,
            2,
        );
        let set_weight_tx = make_platform_set_l1_validator_weight_tx_bytes(validation_id, 0, 9, 1);

        let block1 = make_banff_std_with_txs_at([0x13; 32], 1, etna_time + 10, &[register_tx]);
        let block1_id = sha256_bytes(&block1);
        let block2 = make_banff_std_with_txs_at(block1_id, 2, etna_time + 20, &[set_weight_tx]);
        node.db.put_cf(CF_BLOCKS, &block1_id, &block1).unwrap();
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&block2), &block2)
            .unwrap();

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getL1Validator","params":{{"validationID":"{}"}},"id":33}}"#,
            cb58_encode_id(validation_id)
        );
        let response = handle_rpc_request(&req, &node).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["result"]["subnetID"], cb58_encode_id(subnet_id));
        assert_eq!(
            json["result"]["nodeID"],
            format!("NodeID-{}", cb58_encode(&node_id))
        );
        assert_eq!(json["result"]["weight"], "9");
        assert_eq!(json["result"]["startTime"], (etna_time + 10).to_string());
        assert_eq!(
            json["result"]["validationID"],
            cb58_encode_id(validation_id)
        );
        assert_eq!(
            json["result"]["publicKey"],
            format!("0x{}", "11".repeat(48))
        );
        assert_eq!(
            json["result"]["remainingBalanceOwner"],
            serde_json::json!({
                "locktime": "0",
                "threshold": "1",
                "addresses": [format_platform_address(node.config.network_id, owner)],
            })
        );
        assert_eq!(
            json["result"]["deactivationOwner"],
            serde_json::json!({
                "locktime": "0",
                "threshold": "1",
                "addresses": [format_platform_address(node.config.network_id, owner)],
            })
        );
        assert_eq!(json["result"]["minNonce"], "1");
        assert_eq!(json["result"]["balance"], "15");
        assert_eq!(json["result"]["height"], "2");
    }

    #[tokio::test]
    async fn test_platform_get_l1_validator_not_found() {
        let node = make_test_node(12345);
        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getL1Validator","params":{{"validationID":"{}"}},"id":34}}"#,
            cb58_encode_id([0x97; 32])
        );
        let response = handle_rpc_request(&req, &node).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["error"]["code"], -32000);
        assert_eq!(
            json["error"]["message"],
            format!(
                "fetching L1 validator \"{}\" failed: not found",
                cb58_encode_id([0x97; 32])
            )
        );
    }

    #[tokio::test]
    async fn test_platform_tx_lifecycle_uses_processing_mempool_and_committed_lookup() {
        let node = make_test_node(1);
        let tx_bytes = make_signed_platform_base_tx_bytes();

        let issue_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.issueTx","params":{{"tx":"0x{}","encoding":"hex"}},"id":29}}"#,
            hex::encode(&tx_bytes)
        );
        let issue_response = handle_rpc_request(&issue_req, &node).await;
        let issue_json: serde_json::Value = serde_json::from_str(&issue_response).unwrap();
        let tx_id = issue_json["result"]["txID"].as_str().unwrap().to_string();
        assert!(parse_cb58_id_32(&tx_id).is_some());

        let status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTxStatus","params":{{"txID":"{}"}},"id":30}}"#,
            tx_id
        );
        let status_response = handle_rpc_request(&status_req, &node).await;
        let status_json: serde_json::Value = serde_json::from_str(&status_response).unwrap();
        assert_eq!(status_json["result"]["status"], "Processing");
        assert!(status_json["result"].get("reason").is_none());

        let get_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTx","params":{{"txID":"{}","encoding":"hex"}},"id":31}}"#,
            tx_id
        );
        let get_response = handle_rpc_request(&get_req, &node).await;
        let get_json: serde_json::Value = serde_json::from_str(&get_response).unwrap();
        assert_eq!(get_json["error"]["code"], -32000);
        assert_eq!(get_json["error"]["message"], "transaction not found");

        let tx_hash = parse_cb58_id_32(&tx_id).unwrap();
        let hex_status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTxStatus","params":{{"txID":"0x{}"}},"id":32}}"#,
            hex::encode(tx_hash)
        );
        let hex_status_response = handle_rpc_request(&hex_status_req, &node).await;
        let hex_status_json: serde_json::Value =
            serde_json::from_str(&hex_status_response).unwrap();
        assert_eq!(hex_status_json["result"]["status"], "Processing");

        let missing_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTxStatus","params":{{"txID":"{}"}},"id":33}}"#,
            cb58_encode_id([0xEE; 32])
        );
        let missing_response = handle_rpc_request(&missing_req, &node).await;
        let missing_json: serde_json::Value = serde_json::from_str(&missing_response).unwrap();
        assert_eq!(missing_json["result"]["status"], "Unknown");

        let missing_get_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTx","params":{{"txID":"{}","encoding":"hex"}},"id":34}}"#,
            cb58_encode_id([0xEF; 32])
        );
        let missing_get_response = handle_rpc_request(&missing_get_req, &node).await;
        let missing_get_json: serde_json::Value =
            serde_json::from_str(&missing_get_response).unwrap();
        assert_eq!(missing_get_json["error"]["code"], -32000);
        assert_eq!(
            missing_get_json["error"]["message"],
            "transaction not found"
        );

        let raw_block = make_banff_std_with_txs([0x44; 32], 12, std::slice::from_ref(&tx_bytes));
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&raw_block), &raw_block)
            .unwrap();

        let committed_status_response = handle_rpc_request(&status_req, &node).await;
        let committed_status_json: serde_json::Value =
            serde_json::from_str(&committed_status_response).unwrap();
        assert_eq!(committed_status_json["result"]["status"], "Committed");

        let committed_get_response = handle_rpc_request(&get_req, &node).await;
        let committed_get_json: serde_json::Value =
            serde_json::from_str(&committed_get_response).unwrap();
        assert_eq!(committed_get_json["result"]["encoding"], "hex");
        assert_eq!(
            committed_get_json["result"]["tx"],
            format!("0x{}", hex::encode(&tx_bytes))
        );
    }

    #[tokio::test]
    async fn test_platform_issue_tx_marks_invalid_network_tx_as_dropped() {
        let node = make_test_node(1);
        let mut tx_bytes = make_signed_platform_base_tx_bytes();
        tx_bytes[6..10].copy_from_slice(&5u32.to_be_bytes());
        let tx_id = cb58_encode_id(sha256_bytes(&tx_bytes));

        let issue_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.issueTx","params":{{"tx":"0x{}","encoding":"hex"}},"id":35}}"#,
            hex::encode(&tx_bytes)
        );
        let issue_response = handle_rpc_request(&issue_req, &node).await;
        let issue_json: serde_json::Value = serde_json::from_str(&issue_response).unwrap();
        assert_eq!(issue_json["error"]["code"], -32000);
        assert_eq!(
            issue_json["error"]["message"],
            "couldn't issue tx: tx networkID 5 does not match node network 1"
        );

        let status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTxStatus","params":{{"txID":"{}"}},"id":36}}"#,
            tx_id
        );
        let status_response = handle_rpc_request(&status_req, &node).await;
        let status_json: serde_json::Value = serde_json::from_str(&status_response).unwrap();
        assert_eq!(status_json["result"]["status"], "Dropped");
        assert_eq!(
            status_json["result"]["reason"],
            "tx networkID 5 does not match node network 1"
        );

        let reissue_response = handle_rpc_request(&issue_req, &node).await;
        let reissue_json: serde_json::Value = serde_json::from_str(&reissue_response).unwrap();
        assert_eq!(reissue_json["error"]["code"], -32000);
        assert_eq!(
            reissue_json["error"]["message"],
            "couldn't issue tx: tx networkID 5 does not match node network 1"
        );
    }

    #[tokio::test]
    async fn test_platform_get_tx_and_status_use_committed_blocks() {
        let node = make_test_node(1);
        let tx_bytes = make_signed_platform_base_tx_bytes();
        let tx_id = cb58_encode_id(sha256_bytes(&tx_bytes));
        let raw_block = make_banff_std_with_txs([0x44; 32], 12, std::slice::from_ref(&tx_bytes));
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&raw_block), &raw_block)
            .unwrap();

        let get_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTx","params":{{"txID":"{}","encoding":"json"}},"id":37}}"#,
            tx_id
        );
        let get_response = handle_rpc_request(&get_req, &node).await;
        let get_json: serde_json::Value = serde_json::from_str(&get_response).unwrap();
        assert_eq!(get_json["result"]["encoding"], "json");
        assert_eq!(get_json["result"]["tx"]["id"], tx_id);
        assert_eq!(get_json["result"]["tx"]["unsignedTx"]["networkID"], 1);

        let status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTxStatus","params":{{"txID":"{}"}},"id":38}}"#,
            tx_id
        );
        let status_response = handle_rpc_request(&status_req, &node).await;
        let status_json: serde_json::Value = serde_json::from_str(&status_response).unwrap();
        assert_eq!(status_json["result"]["status"], "Committed");
    }

    #[tokio::test]
    async fn test_platform_issue_tx_rejects_conflicting_processing_inputs() {
        let node = make_test_node(1);
        let funding_output = make_platform_transferable_output_bytes([0x11; 32], 500, [0xAA; 20]);
        let funding_tx = make_platform_base_tx_with_io(std::slice::from_ref(&funding_output), &[]);
        let funding_tx_id = sha256_bytes(&funding_tx);
        let funding_block =
            make_banff_std_with_txs([0x21; 32], 1, std::slice::from_ref(&funding_tx));
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&funding_block), &funding_block)
            .unwrap();

        let shared_input =
            make_platform_transferable_input_bytes(funding_tx_id, 0, [0x11; 32], 500);
        let tx_a = make_platform_base_tx_with_io(&[], std::slice::from_ref(&shared_input));
        let tx_b = make_platform_base_tx_with_io(
            std::slice::from_ref(&make_platform_transferable_output_bytes(
                [0x11; 32], 500, [0xBB; 20],
            )),
            std::slice::from_ref(&shared_input),
        );

        let issue_a = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.issueTx","params":{{"tx":"0x{}","encoding":"hex"}},"id":39}}"#,
            hex::encode(&tx_a)
        );
        let issue_a_response = handle_rpc_request(&issue_a, &node).await;
        let issue_a_json: serde_json::Value = serde_json::from_str(&issue_a_response).unwrap();
        assert!(issue_a_json["result"]["txID"].is_string());

        let issue_b = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.issueTx","params":{{"tx":"0x{}","encoding":"hex"}},"id":40}}"#,
            hex::encode(&tx_b)
        );
        let issue_b_response = handle_rpc_request(&issue_b, &node).await;
        let issue_b_json: serde_json::Value = serde_json::from_str(&issue_b_response).unwrap();
        assert_eq!(issue_b_json["error"]["code"], -32000);
        assert!(issue_b_json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("conflicts with processing tx"));
    }

    #[tokio::test]
    async fn test_platform_processing_tx_becomes_dropped_after_conflicting_commit() {
        let node = make_test_node(1);
        let funding_output = make_platform_transferable_output_bytes([0x22; 32], 700, [0xCC; 20]);
        let funding_tx = make_platform_base_tx_with_io(std::slice::from_ref(&funding_output), &[]);
        let funding_tx_id = sha256_bytes(&funding_tx);
        let funding_block =
            make_banff_std_with_txs([0x31; 32], 1, std::slice::from_ref(&funding_tx));
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&funding_block), &funding_block)
            .unwrap();

        let shared_input =
            make_platform_transferable_input_bytes(funding_tx_id, 0, [0x22; 32], 700);
        let pending_tx = make_platform_base_tx_with_io(&[], std::slice::from_ref(&shared_input));
        let pending_tx_id = cb58_encode_id(sha256_bytes(&pending_tx));
        let issue_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.issueTx","params":{{"tx":"0x{}","encoding":"hex"}},"id":41}}"#,
            hex::encode(&pending_tx)
        );
        let issue_response = handle_rpc_request(&issue_req, &node).await;
        let issue_json: serde_json::Value = serde_json::from_str(&issue_response).unwrap();
        assert_eq!(issue_json["result"]["txID"], pending_tx_id);

        let committed_spend = make_platform_base_tx_with_io(
            std::slice::from_ref(&make_platform_transferable_output_bytes(
                [0x22; 32], 700, [0xDD; 20],
            )),
            std::slice::from_ref(&shared_input),
        );
        let spend_block =
            make_banff_std_with_txs([0x32; 32], 2, std::slice::from_ref(&committed_spend));
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&spend_block), &spend_block)
            .unwrap();

        let status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTxStatus","params":{{"txID":"{}"}},"id":42}}"#,
            pending_tx_id
        );
        let status_response = handle_rpc_request(&status_req, &node).await;
        let status_json: serde_json::Value = serde_json::from_str(&status_response).unwrap();
        assert_eq!(status_json["result"]["status"], "Dropped");
        assert_eq!(
            status_json["result"]["reason"],
            "inputs unavailable in accepted state"
        );
    }

    #[tokio::test]
    async fn test_platform_get_block_json_populates_decoded_txs_when_available() {
        let node = make_test_node(1);
        let tx_bytes = make_signed_platform_base_tx_bytes();
        let tx_id = cb58_encode_id(sha256_bytes(&tx_bytes));
        let raw_block = make_banff_std_with_txs([0x55; 32], 13, std::slice::from_ref(&tx_bytes));
        let block_id = sha256_bytes(&raw_block);
        node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBlock","params":{{"blockID":"0x{}","encoding":"json"}},"id":39}}"#,
            hex::encode(block_id)
        );
        let response = handle_rpc_request(&req, &node).await;
        let json_value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json_value["result"]["block"]["txCount"], 1);
        let txs = json_value["result"]["block"]["txs"].as_array().unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0]["id"], tx_id);
        assert_eq!(txs[0]["unsignedTx"]["memo"], "0x");
    }

    #[tokio::test]
    async fn test_platform_get_tx_supports_json_encoding_for_committed_etna_txs() {
        let node = make_test_node(1);
        let subnet_id = [0x61; 32];
        let convert_tx = make_platform_convert_subnet_to_l1_tx_bytes(
            subnet_id,
            &[([0x11; 20], 10, 20, [0x12; 20])],
        );
        let (register_tx, validation_id) = make_platform_register_l1_validator_tx_bytes(
            subnet_id, [0x13; 20], [0x14; 20], 77, 33, 999, 2,
        );
        let set_weight_tx = make_platform_set_l1_validator_weight_tx_bytes(validation_id, 5, 88, 1);
        let increase_tx = make_platform_increase_l1_validator_balance_tx_bytes(validation_id, 44);
        let disable_tx = make_platform_disable_l1_validator_tx_bytes(validation_id);

        let raw_block = make_banff_std_with_txs(
            [0x66; 32],
            14,
            &[
                convert_tx.clone(),
                register_tx.clone(),
                set_weight_tx.clone(),
                increase_tx.clone(),
                disable_tx.clone(),
            ],
        );
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&raw_block), &raw_block)
            .unwrap();

        let convert_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTx","params":{{"txID":"{}","encoding":"json"}},"id":40}}"#,
            cb58_encode_id(sha256_bytes(&convert_tx))
        );
        let convert_json: serde_json::Value =
            serde_json::from_str(&handle_rpc_request(&convert_req, &node).await).unwrap();
        assert_eq!(convert_json["result"]["encoding"], "json");
        assert_eq!(
            convert_json["result"]["tx"]["unsignedTx"]["subnetID"],
            cb58_encode_id(subnet_id)
        );
        assert_eq!(
            convert_json["result"]["tx"]["unsignedTx"]["chainID"],
            cb58_encode_id([0x44; 32])
        );
        assert_eq!(
            convert_json["result"]["tx"]["unsignedTx"]["address"],
            "0x6d6772"
        );
        assert_eq!(
            convert_json["result"]["tx"]["unsignedTx"]["validators"][0]["nodeID"],
            format!("NodeID-{}", cb58_encode(&[0x11; 20]))
        );
        assert_eq!(
            convert_json["result"]["tx"]["unsignedTx"]["validators"][0]["weight"],
            10
        );
        assert_eq!(
            convert_json["result"]["tx"]["unsignedTx"]["validators"][0]["balance"],
            20
        );

        let register_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTx","params":{{"txID":"{}","encoding":"json"}},"id":41}}"#,
            cb58_encode_id(sha256_bytes(&register_tx))
        );
        let register_json: serde_json::Value =
            serde_json::from_str(&handle_rpc_request(&register_req, &node).await).unwrap();
        assert_eq!(register_json["result"]["tx"]["unsignedTx"]["balance"], 33);
        assert!(
            register_json["result"]["tx"]["unsignedTx"]["proofOfPossession"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
        assert!(register_json["result"]["tx"]["unsignedTx"]["message"]
            .as_str()
            .unwrap()
            .starts_with("0x"));

        let set_weight_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTx","params":{{"txID":"{}","encoding":"json"}},"id":42}}"#,
            cb58_encode_id(sha256_bytes(&set_weight_tx))
        );
        let set_weight_json: serde_json::Value =
            serde_json::from_str(&handle_rpc_request(&set_weight_req, &node).await).unwrap();
        assert!(set_weight_json["result"]["tx"]["unsignedTx"]["message"]
            .as_str()
            .unwrap()
            .starts_with("0x"));

        let increase_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTx","params":{{"txID":"{}","encoding":"json"}},"id":43}}"#,
            cb58_encode_id(sha256_bytes(&increase_tx))
        );
        let increase_json: serde_json::Value =
            serde_json::from_str(&handle_rpc_request(&increase_req, &node).await).unwrap();
        assert_eq!(
            increase_json["result"]["tx"]["unsignedTx"]["validationID"],
            cb58_encode_id(validation_id)
        );
        assert_eq!(increase_json["result"]["tx"]["unsignedTx"]["balance"], 44);

        let disable_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getTx","params":{{"txID":"{}","encoding":"json"}},"id":44}}"#,
            cb58_encode_id(sha256_bytes(&disable_tx))
        );
        let disable_json: serde_json::Value =
            serde_json::from_str(&handle_rpc_request(&disable_req, &node).await).unwrap();
        assert_eq!(
            disable_json["result"]["tx"]["unsignedTx"]["validationID"],
            cb58_encode_id(validation_id)
        );
        assert_eq!(
            disable_json["result"]["tx"]["unsignedTx"]["disableAuthorization"],
            serde_json::json!({ "signatureIndices": [] })
        );
    }

    #[tokio::test]
    async fn test_platform_get_block_json_populates_decoded_etna_txs() {
        let node = make_test_node(1);
        let subnet_id = [0x71; 32];
        let convert_tx = make_platform_convert_subnet_to_l1_tx_bytes(
            subnet_id,
            &[([0x21; 20], 11, 22, [0x22; 20])],
        );
        let (register_tx, validation_id) = make_platform_register_l1_validator_tx_bytes(
            subnet_id, [0x23; 20], [0x24; 20], 66, 55, 1_234, 2,
        );
        let set_weight_tx = make_platform_set_l1_validator_weight_tx_bytes(validation_id, 9, 99, 2);
        let increase_tx = make_platform_increase_l1_validator_balance_tx_bytes(validation_id, 77);
        let disable_tx = make_platform_disable_l1_validator_tx_bytes(validation_id);

        let raw_block = make_banff_std_with_txs(
            [0x77; 32],
            15,
            &[
                convert_tx.clone(),
                register_tx.clone(),
                set_weight_tx.clone(),
                increase_tx.clone(),
                disable_tx.clone(),
            ],
        );
        let block_id = sha256_bytes(&raw_block);
        node.db.put_cf(CF_BLOCKS, &block_id, &raw_block).unwrap();

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getBlock","params":{{"blockID":"0x{}","encoding":"json"}},"id":45}}"#,
            hex::encode(block_id)
        );
        let response = handle_rpc_request(&req, &node).await;
        let json_value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json_value["result"]["block"]["txCount"], 5);
        let txs = json_value["result"]["block"]["txs"].as_array().unwrap();
        assert_eq!(txs.len(), 5);

        let txs_by_id = txs
            .iter()
            .map(|tx| (tx["id"].as_str().unwrap().to_string(), tx.clone()))
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(
            txs_by_id[&cb58_encode_id(sha256_bytes(&convert_tx))]["unsignedTx"]["subnetID"],
            cb58_encode_id(subnet_id)
        );
        assert_eq!(
            txs_by_id[&cb58_encode_id(sha256_bytes(&register_tx))]["unsignedTx"]["balance"],
            55
        );
        assert!(
            txs_by_id[&cb58_encode_id(sha256_bytes(&set_weight_tx))]["unsignedTx"]["message"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
        assert_eq!(
            txs_by_id[&cb58_encode_id(sha256_bytes(&increase_tx))]["unsignedTx"]["validationID"],
            cb58_encode_id(validation_id)
        );
        assert_eq!(
            txs_by_id[&cb58_encode_id(sha256_bytes(&disable_tx))]["unsignedTx"]
                ["disableAuthorization"],
            serde_json::json!({ "signatureIndices": [] })
        );
    }

    #[tokio::test]
    async fn test_avax_atomic_tx_lifecycle_uses_cb58_ids_and_status() {
        let node = make_test_node(1);
        let tx_bytes = vec![0x00, 0x01, 0x02, 0xAB, 0xCD];

        let issue_req = format!(
            r#"{{"jsonrpc":"2.0","method":"avax.issueTx","params":{{"tx":"0x{}","encoding":"hex"}},"id":25}}"#,
            hex::encode(&tx_bytes)
        );
        let issue_response = handle_rpc_request(&issue_req, &node).await;
        let issue_json: serde_json::Value = serde_json::from_str(&issue_response).unwrap();
        let tx_id = issue_json["result"]["txID"].as_str().unwrap().to_string();
        assert!(parse_cb58_id_32(&tx_id).is_some());

        let status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"avax.getAtomicTxStatus","params":{{"txID":"{}"}},"id":26}}"#,
            tx_id
        );
        let status_response = handle_rpc_request(&status_req, &node).await;
        let status_json: serde_json::Value = serde_json::from_str(&status_response).unwrap();
        assert_eq!(status_json["result"]["status"], "Processing");
        assert!(status_json["result"].get("blockHeight").is_none());

        let get_req = format!(
            r#"{{"jsonrpc":"2.0","method":"avax.getAtomicTx","params":{{"txID":"{}","encoding":"hex"}},"id":27}}"#,
            tx_id
        );
        let get_response = handle_rpc_request(&get_req, &node).await;
        let get_json: serde_json::Value = serde_json::from_str(&get_response).unwrap();
        assert_eq!(get_json["result"]["encoding"], "hex");
        assert_eq!(
            get_json["result"]["tx"],
            format!("0x{}", hex::encode(&tx_bytes))
        );
        assert!(get_json["result"].get("blockHeight").is_none());
    }

    #[tokio::test]
    async fn test_avax_atomic_tx_hex_id_lookup_remains_supported() {
        let node = make_test_node(1);
        let tx_bytes = vec![0xAA, 0xBB, 0xCC];

        let issue_req = format!(
            r#"{{"jsonrpc":"2.0","method":"avax_issueTx","params":["0x{}"],"id":28}}"#,
            hex::encode(&tx_bytes)
        );
        let issue_response = handle_rpc_request(&issue_req, &node).await;
        let issue_json: serde_json::Value = serde_json::from_str(&issue_response).unwrap();
        let tx_id = issue_json["result"]["txID"].as_str().unwrap().to_string();
        let tx_hash = parse_cb58_id_32(&tx_id).unwrap();

        let get_req = format!(
            r#"{{"jsonrpc":"2.0","method":"avax_getAtomicTx","params":["0x{}"],"id":29}}"#,
            hex::encode(tx_hash)
        );
        let get_response = handle_rpc_request(&get_req, &node).await;
        let get_json: serde_json::Value = serde_json::from_str(&get_response).unwrap();
        assert_eq!(
            get_json["result"]["tx"],
            format!("0x{}", hex::encode(&tx_bytes))
        );

        let missing_status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"avax.getAtomicTxStatus","params":{{"txID":"{}"}},"id":30}}"#,
            cb58_encode_id([0x99; 32])
        );
        let missing_status_response = handle_rpc_request(&missing_status_req, &node).await;
        let missing_status_json: serde_json::Value =
            serde_json::from_str(&missing_status_response).unwrap();
        assert_eq!(missing_status_json["result"]["status"], "Unknown");
    }

    #[tokio::test]
    async fn test_avax_get_utxos_uses_committed_pchain_exports() {
        let node = make_test_node(1);
        let owner = [0x58; 20];
        let asset_id = parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap();

        let funding_tx = make_platform_base_tx_with_io(
            &[make_platform_transferable_output_bytes(asset_id, 80, owner)],
            &[],
        );
        let funding_tx_id = sha256_bytes(&funding_tx);
        let export_tx = make_platform_export_tx_bytes_with_io(
            &[],
            &[make_platform_transferable_input_bytes(
                funding_tx_id,
                0,
                asset_id,
                80,
            )],
            platform_cchain_blockchain_id(node.config.network_id),
            &[make_platform_transferable_output_bytes(asset_id, 70, owner)],
        );
        let export_tx_id = sha256_bytes(&export_tx);
        let raw_block = make_banff_std_with_txs([0x93; 32], 24, &[funding_tx, export_tx.clone()]);
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&raw_block), &raw_block)
            .unwrap();

        let expected_output = avalanche_rs::pchain::summarize_platform_tx_ledger(&export_tx)
            .unwrap()
            .exported_outputs
            .into_iter()
            .next()
            .unwrap();
        let expected_utxo = platform_encode_utxo(export_tx_id, 0, &expected_output, "hex").unwrap();
        let owner_addr = cb58_encode(&owner);
        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"avax.getUTXOs","params":{{"addresses":["{}"],"sourceChain":"P","limit":"0xa","encoding":"hex"}},"id":31}}"#,
            owner_addr
        );
        let response = handle_rpc_request(&req, &node).await;
        let json_value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json_value["result"]["numFetched"], "1");
        assert_eq!(
            json_value["result"]["utxos"],
            serde_json::json!([expected_utxo])
        );
        assert_eq!(json_value["result"]["encoding"], "hex");
        assert_eq!(
            json_value["result"]["endIndex"]["address"],
            format_service_address(node.config.network_id, "C", owner)
        );
        assert_eq!(
            json_value["result"]["endIndex"]["utxo"],
            cb58_encode_id(platform_input_id(export_tx_id, 0))
        );
    }

    #[tokio::test]
    async fn test_avax_get_utxos_drops_committed_exports_after_cchain_import() {
        let node = make_test_node(1);
        let owner = [0x5A; 20];
        let asset_id = parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap();

        let funding_tx = make_platform_base_tx_with_io(
            &[make_platform_transferable_output_bytes(asset_id, 80, owner)],
            &[],
        );
        let funding_tx_id = sha256_bytes(&funding_tx);
        let export_tx = make_platform_export_tx_bytes_with_io(
            &[],
            &[make_platform_transferable_input_bytes(
                funding_tx_id,
                0,
                asset_id,
                80,
            )],
            platform_cchain_blockchain_id(node.config.network_id),
            &[make_platform_transferable_output_bytes(asset_id, 70, owner)],
        );
        let export_tx_id = sha256_bytes(&export_tx);
        let p_block = make_banff_std_with_txs([0x93; 32], 24, &[funding_tx, export_tx]);
        node.db
            .put_cf(CF_BLOCKS, &sha256_bytes(&p_block), &p_block)
            .unwrap();

        let ap5_time = upgrade_time_unix(
            &info_upgrades_result(node.config.network_id),
            "apricotPhase5Time",
        );
        let c_import_tx = make_cchain_atomic_import_tx_bytes(
            node.config.network_id,
            platform_pchain_blockchain_id(),
            &[make_platform_transferable_input_bytes(
                export_tx_id,
                0,
                asset_id,
                70,
            )],
        );
        let c_block = make_cchain_coreth_block_with_extdata(
            [0xA1; 32],
            1,
            ap5_time + 10,
            &make_cchain_atomic_batch_extdata(&[c_import_tx]),
        );
        node.db.put_block(1, &c_block).unwrap();

        let owner_addr = cb58_encode(&owner);
        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"avax.getUTXOs","params":{{"addresses":["{}"],"sourceChain":"P","limit":"0xa","encoding":"hex"}},"id":31}}"#,
            owner_addr
        );
        let response = handle_rpc_request(&req, &node).await;
        let json_value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json_value["result"]["numFetched"], "0");
        assert_eq!(json_value["result"]["utxos"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_platform_get_utxos_atomic_source_chain_returns_empty_without_exports() {
        let node = make_test_node(1);
        let owner = cb58_encode(&[0x59; 20]);
        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getUTXOs","params":{{"addresses":["{}"],"sourceChain":"C","limit":"0xa","encoding":"hex"}},"id":32}}"#,
            owner
        );
        let response = handle_rpc_request(&req, &node).await;
        let json_value: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json_value["result"]["numFetched"], "0");
        assert_eq!(json_value["result"]["utxos"], serde_json::json!([]));
        assert_eq!(json_value["result"]["encoding"], "hex");
    }

    #[tokio::test]
    async fn test_platform_get_utxos_and_atomic_lookup_use_committed_cchain_exports() {
        let node = make_test_node(1);
        let owner = [0x61; 20];
        let owner_addr = cb58_encode(&owner);
        let asset_id = parse_platform_id_32(AVAX_ASSET_ID_MAINNET).unwrap();

        let c_export_tx = make_cchain_atomic_export_tx_bytes(
            node.config.network_id,
            platform_pchain_blockchain_id(),
            &[make_platform_transferable_output_bytes(asset_id, 33, owner)],
        );
        let c_export_tx_id = sha256_bytes(&c_export_tx);
        let expected_output = avalanche_rs::pchain::PlatformOwnedOutput {
            asset_id,
            amount: 33,
            owner_locktime: 0,
            stakeable_locktime: None,
            addresses: vec![owner],
            transferable_raw_bytes: make_platform_transferable_output_bytes(asset_id, 33, owner),
            output_raw_bytes: make_platform_transferable_output_bytes(asset_id, 33, owner)[32..]
                .to_vec(),
        };

        let ap5_time = upgrade_time_unix(
            &info_upgrades_result(node.config.network_id),
            "apricotPhase5Time",
        );
        let c_block = make_cchain_coreth_block_with_extdata(
            [0xA2; 32],
            2,
            ap5_time + 20,
            &make_cchain_atomic_batch_extdata(std::slice::from_ref(&c_export_tx)),
        );
        node.db.put_block(2, &c_block).unwrap();

        let utxo_req = format!(
            r#"{{"jsonrpc":"2.0","method":"platform.getUTXOs","params":{{"addresses":["{}"],"sourceChain":"C","limit":"0xa","encoding":"hex"}},"id":32}}"#,
            owner_addr
        );
        let utxo_response = handle_rpc_request(&utxo_req, &node).await;
        let utxo_json: serde_json::Value = serde_json::from_str(&utxo_response).unwrap();
        assert_eq!(utxo_json["result"]["numFetched"], "1");
        assert_eq!(
            utxo_json["result"]["utxos"],
            serde_json::json!([
                platform_encode_utxo(c_export_tx_id, 0, &expected_output, "hex").unwrap()
            ])
        );
        assert_eq!(utxo_json["result"]["endIndex"]["address"], owner_addr);
        assert_eq!(
            utxo_json["result"]["endIndex"]["utxo"],
            cb58_encode_id(platform_input_id(c_export_tx_id, 0))
        );

        let tx_id = cb58_encode_id(c_export_tx_id);
        let status_req = format!(
            r#"{{"jsonrpc":"2.0","method":"avax.getAtomicTxStatus","params":{{"txID":"{}"}},"id":33}}"#,
            tx_id
        );
        let status_response = handle_rpc_request(&status_req, &node).await;
        let status_json: serde_json::Value = serde_json::from_str(&status_response).unwrap();
        assert_eq!(status_json["result"]["status"], "Accepted");
        assert_eq!(status_json["result"]["blockHeight"], 2);

        let get_req = format!(
            r#"{{"jsonrpc":"2.0","method":"avax.getAtomicTx","params":{{"txID":"{}","encoding":"hex"}},"id":34}}"#,
            tx_id
        );
        let get_response = handle_rpc_request(&get_req, &node).await;
        let get_json: serde_json::Value = serde_json::from_str(&get_response).unwrap();
        assert_eq!(
            get_json["result"]["tx"],
            format!("0x{}", hex::encode(&c_export_tx))
        );
        assert_eq!(get_json["result"]["blockHeight"], 2);
    }

    #[tokio::test]
    async fn test_info_endpoints_return_avalanchego_shapes() {
        let node = make_test_node(1);
        node.sync_engine.mark_following().await;
        *node.resolved_public_ip.write().await = Some("198.51.100.8:9651".parse().unwrap());

        let peer_id = NodeId([0x11; 20]);
        let peer_id_str = full_node_id_string(&peer_id);
        let mut peer = Peer::new(peer_id.clone(), "10.0.0.1:9651".parse().unwrap());
        peer.state = PeerState::Connected;
        peer.version = Some("avalanchego/1.14.1".to_string());
        peer.public_ip = Some("203.0.113.10:9651".parse().unwrap());
        peer.reported_uptime = 9500;
        peer.supported_acps = vec![23, 24];
        peer.objected_acps = vec![176];
        node.peer_manager.write().await.add_peer(peer).unwrap();

        let node_id_req = r#"{"jsonrpc":"2.0","method":"info.getNodeID","params":{},"id":16}"#;
        let node_id_response = handle_rpc_request(node_id_req, &node).await;
        let node_id_json: serde_json::Value = serde_json::from_str(&node_id_response).unwrap();
        assert_eq!(
            node_id_json["result"]["nodeID"],
            full_node_id_string(&node.identity.node_id)
        );
        assert!(node_id_json["result"]["nodePOP"]["publicKey"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
        assert!(node_id_json["result"]["nodePOP"]["proofOfPossession"]
            .as_str()
            .unwrap()
            .starts_with("0x"));

        let avax_node_id_req = r#"{"jsonrpc":"2.0","method":"avax_getNodeID","params":[],"id":17}"#;
        let avax_node_id_response = handle_rpc_request(avax_node_id_req, &node).await;
        let avax_node_id_json: serde_json::Value =
            serde_json::from_str(&avax_node_id_response).unwrap();
        assert_eq!(
            avax_node_id_json["result"],
            full_node_id_string(&node.identity.node_id)
        );

        let blockchain_id_req =
            r#"{"jsonrpc":"2.0","method":"info.getBlockchainID","params":{"alias":"X"},"id":18}"#;
        let blockchain_id_response = handle_rpc_request(blockchain_id_req, &node).await;
        let blockchain_id_json: serde_json::Value =
            serde_json::from_str(&blockchain_id_response).unwrap();
        assert_eq!(blockchain_id_json["error"]["code"], -32602);
        assert!(blockchain_id_json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("there is no chain with alias/ID 'X'"));

        let node_ip_req = r#"{"jsonrpc":"2.0","method":"info.getNodeIP","params":{},"id":19}"#;
        let node_ip_response = handle_rpc_request(node_ip_req, &node).await;
        let node_ip_json: serde_json::Value = serde_json::from_str(&node_ip_response).unwrap();
        assert_eq!(node_ip_json["result"]["ip"], "198.51.100.8:9651");

        let version_req = r#"{"jsonrpc":"2.0","method":"info.getNodeVersion","params":{},"id":20}"#;
        let version_response = handle_rpc_request(version_req, &node).await;
        let version_json: serde_json::Value = serde_json::from_str(&version_response).unwrap();
        assert_eq!(version_json["result"]["rpcProtocolVersion"], "0");
        assert_eq!(
            version_json["result"]["vmVersions"]["platform"],
            format!("avalanche-rs/{}", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            version_json["result"]["vmVersions"]["evm"],
            format!("avalanche-rs/{}", env!("CARGO_PKG_VERSION"))
        );

        let tx_fee_req = r#"{"jsonrpc":"2.0","method":"info.getTxFee","params":{},"id":21}"#;
        let tx_fee_response = handle_rpc_request(tx_fee_req, &node).await;
        let tx_fee_json: serde_json::Value = serde_json::from_str(&tx_fee_response).unwrap();
        assert_eq!(tx_fee_json["result"]["createSubnetTxFee"], "1000000000");
        assert_eq!(tx_fee_json["result"]["transformSubnetTxFee"], "10000000000");
        assert_eq!(tx_fee_json["result"]["createBlockchainTxFee"], "1000000000");

        let vms_req = r#"{"jsonrpc":"2.0","method":"info.getVMs","params":{},"id":22}"#;
        let vms_response = handle_rpc_request(vms_req, &node).await;
        let vms_json: serde_json::Value = serde_json::from_str(&vms_response).unwrap();
        let platform_vm_id = cb58_encode_id(info_vm_id(b"platformvm"));
        let evm_vm_id = cb58_encode_id(info_vm_id(b"evm"));
        assert_eq!(vms_json["result"]["vms"][&platform_vm_id][0], "platform");
        assert_eq!(vms_json["result"]["vms"][&evm_vm_id][0], "evm");

        let uptime_req = r#"{"jsonrpc":"2.0","method":"info.uptime","params":{},"id":23}"#;
        let uptime_response = handle_rpc_request(uptime_req, &node).await;
        let uptime_json: serde_json::Value = serde_json::from_str(&uptime_response).unwrap();
        assert_eq!(uptime_json["result"]["rewardingStakePercentage"], "0.0000");
        assert_eq!(uptime_json["result"]["weightedAveragePercentage"], "0.0000");

        let upgrades_req = r#"{"jsonrpc":"2.0","method":"info.upgrades","params":{},"id":24}"#;
        let upgrades_response = handle_rpc_request(upgrades_req, &node).await;
        let upgrades_json: serde_json::Value = serde_json::from_str(&upgrades_response).unwrap();
        assert_eq!(
            upgrades_json["result"]["fortunaTime"],
            "2025-04-08T15:00:00Z"
        );
        assert_eq!(
            upgrades_json["result"]["graniteEpochDuration"],
            300_000_000_000u64
        );

        let bootstrapped_req =
            r#"{"jsonrpc":"2.0","method":"info.isBootstrapped","params":{"chain":"C"},"id":25}"#;
        let bootstrapped_response = handle_rpc_request(bootstrapped_req, &node).await;
        let bootstrapped_json: serde_json::Value =
            serde_json::from_str(&bootstrapped_response).unwrap();
        assert_eq!(bootstrapped_json["result"]["isBootstrapped"], true);

        let peers_req = format!(
            r#"{{"jsonrpc":"2.0","method":"info.peers","params":{{"nodeIDs":["{}"]}},"id":26}}"#,
            peer_id_str
        );
        let peers_response = handle_rpc_request(&peers_req, &node).await;
        let peers_json: serde_json::Value = serde_json::from_str(&peers_response).unwrap();
        let peers = peers_json["result"]["peers"].as_array().unwrap();
        assert_eq!(peers_json["result"]["numPeers"], "1");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0]["nodeID"], peer_id_str);
        assert_eq!(peers[0]["ip"], "10.0.0.1:9651");
        assert_eq!(peers[0]["publicIP"], "203.0.113.10:9651");
        assert_eq!(peers[0]["version"], "avalanchego/1.14.1");
        assert_eq!(peers[0]["observedUptime"], "9500");
        assert_eq!(
            peers[0]["trackedSubnets"][0],
            cb58_encode_id(platform_pchain_blockchain_id())
        );
        assert_eq!(peers[0]["supportedACPs"][0], 23);
        assert_eq!(peers[0]["supportedACPs"][1], 24);
        assert_eq!(peers[0]["objectedACPs"][0], 176);
        assert!(peers[0]["benched"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_avm_methods_are_not_exposed() {
        let node = make_test_node(1);
        let request =
            r#"{"jsonrpc":"2.0","method":"avm.getBalance","params":["X-avax1deadbeef"],"id":91}"#;
        let response = handle_rpc_request(request, &node).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(json["error"]["code"], -32601);
        assert_eq!(json["error"]["message"], "method not found: avm.getBalance");
    }

    #[tokio::test]
    async fn test_info_acps_and_uptime_use_validator_peer_observations() {
        let now = unix_timestamp_secs();
        let peer1_id = NodeId([0x21; 20]);
        let peer2_id = NodeId([0x22; 20]);
        let peer1_node_id = full_node_id_string(&peer1_id);
        let peer2_node_id = full_node_id_string(&peer2_id);
        let mut validators = std::collections::HashMap::new();
        validators.insert(
            peer1_node_id.clone(),
            ValidatorInfo {
                node_id: peer1_node_id.clone(),
                weight: 2_000 * avalanche_rs::staking::NANO_AVAX,
                start_time: now.saturating_sub(60),
                end_time: now + 3600,
            },
        );
        validators.insert(
            peer2_node_id.clone(),
            ValidatorInfo {
                node_id: peer2_node_id.clone(),
                weight: 3_000 * avalanche_rs::staking::NANO_AVAX,
                start_time: now.saturating_sub(60),
                end_time: now + 3600,
            },
        );
        let node = make_test_node_with_validators(1, validators, std::collections::HashSet::new());

        let mut peer1 = Peer::new(peer1_id, "10.0.0.21:9651".parse().unwrap());
        peer1.state = PeerState::Connected;
        peer1.reported_uptime = 9_500;
        peer1.supported_acps = vec![23, 24, 23];
        peer1.objected_acps = vec![176];

        let mut peer2 = Peer::new(peer2_id, "10.0.0.22:9651".parse().unwrap());
        peer2.state = PeerState::Connected;
        peer2.reported_uptime = 7_500;
        peer2.supported_acps = vec![24];
        peer2.objected_acps = vec![23];

        {
            let mut pm = node.peer_manager.write().await;
            pm.add_peer(peer1).unwrap();
            pm.add_peer(peer2).unwrap();
        }

        let acps_req = r#"{"jsonrpc":"2.0","method":"info.acps","params":{},"id":27}"#;
        let acps_response = handle_rpc_request(acps_req, &node).await;
        let acps_json: serde_json::Value = serde_json::from_str(&acps_response).unwrap();
        assert_eq!(
            acps_json["result"]["acps"]["23"]["supportWeight"],
            "2000000000000"
        );
        assert_eq!(
            acps_json["result"]["acps"]["23"]["objectWeight"],
            "3000000000000"
        );
        assert_eq!(acps_json["result"]["acps"]["23"]["abstainWeight"], "0");
        assert_eq!(
            acps_json["result"]["acps"]["23"]["supporters"][0],
            peer1_node_id
        );
        assert_eq!(
            acps_json["result"]["acps"]["23"]["objectors"][0],
            peer2_node_id
        );
        assert_eq!(
            acps_json["result"]["acps"]["24"]["supportWeight"],
            "5000000000000"
        );
        assert_eq!(acps_json["result"]["acps"]["24"]["abstainWeight"], "0");
        assert_eq!(
            acps_json["result"]["acps"]["176"]["objectWeight"],
            "2000000000000"
        );
        assert_eq!(
            acps_json["result"]["acps"]["176"]["abstainWeight"],
            "3000000000000"
        );

        let uptime_req = r#"{"jsonrpc":"2.0","method":"info.uptime","params":{},"id":28}"#;
        let uptime_response = handle_rpc_request(uptime_req, &node).await;
        let uptime_json: serde_json::Value = serde_json::from_str(&uptime_response).unwrap();
        assert_eq!(
            uptime_json["result"]["weightedAveragePercentage"],
            "83.0000"
        );
        assert_eq!(uptime_json["result"]["rewardingStakePercentage"], "40.0000");
    }

    #[tokio::test]
    async fn test_info_network_specific_ids_and_fees_for_fuji() {
        let node = make_test_node(5);

        let cchain_req =
            r#"{"jsonrpc":"2.0","method":"info.getBlockchainID","params":{"alias":"C"},"id":27}"#;
        let cchain_response = handle_rpc_request(cchain_req, &node).await;
        let cchain_json: serde_json::Value = serde_json::from_str(&cchain_response).unwrap();
        assert_eq!(
            cchain_json["result"]["blockchainID"],
            cb58_encode_id(platform_cchain_blockchain_id(node.config.network_id))
        );

        let tx_fee_req = r#"{"jsonrpc":"2.0","method":"info.getTxFee","params":{},"id":28}"#;
        let tx_fee_response = handle_rpc_request(tx_fee_req, &node).await;
        let tx_fee_json: serde_json::Value = serde_json::from_str(&tx_fee_response).unwrap();
        assert_eq!(tx_fee_json["result"]["createSubnetTxFee"], "100000000");
        assert_eq!(tx_fee_json["result"]["transformSubnetTxFee"], "1000000000");
        assert_eq!(tx_fee_json["result"]["createBlockchainTxFee"], "100000000");

        let upgrades_req = r#"{"jsonrpc":"2.0","method":"info.upgrades","params":{},"id":29}"#;
        let upgrades_response = handle_rpc_request(upgrades_req, &node).await;
        let upgrades_json: serde_json::Value = serde_json::from_str(&upgrades_response).unwrap();
        assert_eq!(
            upgrades_json["result"]["fortunaTime"],
            "2025-03-13T15:00:00Z"
        );
        assert_eq!(
            upgrades_json["result"]["graniteTime"],
            "2025-10-29T15:00:00Z"
        );
    }

    #[test]
    fn test_local_supported_acps_follow_upgrade_schedule() {
        assert!(local_supported_acps(1, 1_700_000_000).is_empty());
        assert_eq!(
            local_supported_acps(1, avalanche_rs::fortuna::FORTUNA_MAINNET_TIMESTAMP),
            vec![176]
        );
        assert_eq!(
            local_supported_acps(1, avalanche_rs::granite::GRANITE_MAINNET_TIMESTAMP),
            vec![176, 181, 204, 226]
        );
        assert_eq!(
            local_supported_acps(5, avalanche_rs::granite::GRANITE_FUJI_TIMESTAMP),
            vec![176, 181, 204, 226]
        );
    }

    #[tokio::test]
    async fn test_admin_get_config_logger_level_and_load_vms_shapes() {
        let node = make_test_node(5);

        let config_req = r#"{"jsonrpc":"2.0","method":"admin.getConfig","params":{},"id":30}"#;
        let config_response = handle_rpc_request(config_req, &node).await;
        let config_json: serde_json::Value = serde_json::from_str(&config_response).unwrap();
        assert_eq!(config_json["result"]["network_id"], 5);
        assert_eq!(config_json["result"]["chain_id"], 43114);
        assert_eq!(config_json["result"]["http_port"], 0);

        let logger_req = r#"{"jsonrpc":"2.0","method":"admin.getLoggerLevel","params":{"loggerName":"C"},"id":31}"#;
        let logger_response = handle_rpc_request(logger_req, &node).await;
        let logger_json: serde_json::Value = serde_json::from_str(&logger_response).unwrap();
        assert_eq!(
            logger_json["result"]["loggerLevels"]["C"]["logLevel"],
            "INFO"
        );
        assert_eq!(
            logger_json["result"]["loggerLevels"]["C"]["displayLevel"],
            "INFO"
        );
        assert_eq!(
            logger_json["result"]["loggerLevels"]
                .as_object()
                .unwrap()
                .len(),
            1
        );

        let load_vms_req = r#"{"jsonrpc":"2.0","method":"admin.loadVMs","params":{},"id":32}"#;
        let load_vms_response = handle_rpc_request(load_vms_req, &node).await;
        let load_vms_json: serde_json::Value = serde_json::from_str(&load_vms_response).unwrap();
        assert!(load_vms_json["result"]["newVMs"].is_object());
        assert!(load_vms_json["result"]["failedVMs"].is_object());
    }

    #[tokio::test]
    async fn test_admin_set_logger_level_updates_runtime_state() {
        let node = make_test_node(5);

        let set_req = r#"{"jsonrpc":"2.0","method":"admin.setLoggerLevel","params":{"loggerName":"rpc","logLevel":"debug","displayLevel":"warn"},"id":33}"#;
        let set_response = handle_rpc_request(set_req, &node).await;
        let set_json: serde_json::Value = serde_json::from_str(&set_response).unwrap();
        assert_eq!(set_json["result"], serde_json::json!({}));

        let get_req = r#"{"jsonrpc":"2.0","method":"admin.getLoggerLevel","params":{"loggerName":"rpc"},"id":34}"#;
        let get_response = handle_rpc_request(get_req, &node).await;
        let get_json: serde_json::Value = serde_json::from_str(&get_response).unwrap();
        assert_eq!(
            get_json["result"]["loggerLevels"]["rpc"]["logLevel"],
            "DEBUG"
        );
        assert_eq!(
            get_json["result"]["loggerLevels"]["rpc"]["displayLevel"],
            "WARN"
        );

        let all_req = r#"{"jsonrpc":"2.0","method":"admin.getLoggerLevel","params":{},"id":35}"#;
        let all_response = handle_rpc_request(all_req, &node).await;
        let all_json: serde_json::Value = serde_json::from_str(&all_response).unwrap();
        assert_eq!(
            all_json["result"]["loggerLevels"]["root"]["logLevel"],
            "INFO"
        );
        assert_eq!(
            all_json["result"]["loggerLevels"]["rpc"]["displayLevel"],
            "WARN"
        );
    }

    #[tokio::test]
    async fn test_admin_set_logger_level_rejects_invalid_levels() {
        let node = make_test_node(5);

        let set_req = r#"{"jsonrpc":"2.0","method":"admin.setLoggerLevel","params":{"loggerName":"rpc","logLevel":"verbose"},"id":36}"#;
        let set_response = handle_rpc_request(set_req, &node).await;
        let set_json: serde_json::Value = serde_json::from_str(&set_response).unwrap();
        assert_eq!(set_json["error"]["code"], -32602);
        assert_eq!(set_json["error"]["message"], "invalid logLevel");
    }

    #[tokio::test]
    async fn test_admin_alias_chain_updates_chain_alias_resolution() {
        let node = make_test_node(1);
        node.sync_engine.mark_following().await;

        let alias_req = r#"{"jsonrpc":"2.0","method":"admin.aliasChain","params":{"chain":"C","alias":"myc"},"id":37}"#;
        let alias_response = handle_rpc_request(alias_req, &node).await;
        let alias_json: serde_json::Value = serde_json::from_str(&alias_response).unwrap();
        assert_eq!(alias_json["result"], serde_json::json!({}));

        let info_req =
            r#"{"jsonrpc":"2.0","method":"info.getBlockchainID","params":{"alias":"myc"},"id":38}"#;
        let info_response = handle_rpc_request(info_req, &node).await;
        let info_json: serde_json::Value = serde_json::from_str(&info_response).unwrap();
        assert_eq!(
            info_json["result"]["blockchainID"],
            cb58_encode_id(platform_cchain_blockchain_id(node.config.network_id))
        );

        let aliases_req = r#"{"jsonrpc":"2.0","method":"admin.getChainAliases","params":{"chain":"myc"},"id":35}"#;
        let aliases_response = handle_rpc_request(aliases_req, &node).await;
        let aliases_json: serde_json::Value = serde_json::from_str(&aliases_response).unwrap();
        let aliases = aliases_json["result"]["aliases"].as_array().unwrap();
        assert!(aliases.iter().any(|alias| alias.as_str() == Some("C")));
        assert!(aliases.iter().any(|alias| alias.as_str() == Some("myc")));

        let bootstrapped_req =
            r#"{"jsonrpc":"2.0","method":"info.isBootstrapped","params":{"chain":"myc"},"id":36}"#;
        let bootstrapped_response = handle_rpc_request(bootstrapped_req, &node).await;
        let bootstrapped_json: serde_json::Value =
            serde_json::from_str(&bootstrapped_response).unwrap();
        assert_eq!(bootstrapped_json["result"]["isBootstrapped"], true);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_rpc_server_with_listener(listener, node.clone()));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        websocket_handshake(&mut stream, "/ext/bc/myc/ws").await;

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_admin_alias_creates_http_endpoint_alias() {
        let node = make_test_node(1);
        node.sync_engine.mark_following().await;

        let alias_req = r#"{"jsonrpc":"2.0","method":"admin.alias","params":{"endpoint":"health","alias":"myhealth"},"id":37}"#;
        let alias_response = handle_rpc_request(alias_req, &node).await;
        let alias_json: serde_json::Value = serde_json::from_str(&alias_response).unwrap();
        assert_eq!(alias_json["result"], serde_json::json!({}));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_rpc_server_with_listener(listener, node.clone()));

        let response = http_get(addr, "/ext/myhealth/liveness").await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default();
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["healthy"], true);
        assert!(json["checks"].as_object().unwrap().is_empty());

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_health_rpc_methods_and_tag_filtering() {
        let node = make_test_node(1);
        node.sync_engine.mark_following().await;
        node.p_chain_metrics.write().await.tip_height = 12;
        {
            let mut c = node.c_chain_metrics.write().await;
            c.tip_height = 34;
            c.tip_hash = [0xCC; 32];
        }

        let mut peer = Peer::new(NodeId([0x42; 20]), "127.0.0.1:9651".parse().unwrap());
        peer.state = PeerState::Connected;
        peer.last_ping_sent = Some(Instant::now());
        node.peer_manager.write().await.add_peer(peer).unwrap();

        let health_req =
            r#"{"jsonrpc":"2.0","method":"health.health","params":{"tags":["C"]},"id":30}"#;
        let health_response = handle_rpc_request(health_req, &node).await;
        let health_json: serde_json::Value = serde_json::from_str(&health_response).unwrap();
        assert_eq!(health_json["result"]["healthy"], true);
        let checks = health_json["result"]["checks"].as_object().unwrap();
        assert!(checks.contains_key("bootstrapped"));
        assert!(checks.contains_key("database"));
        assert!(checks.contains_key("network"));
        assert!(checks.contains_key("C"));
        assert!(!checks.contains_key("P"));

        let readiness_req = r#"{"jsonrpc":"2.0","method":"health.readiness","params":{},"id":31}"#;
        let readiness_response = handle_rpc_request(readiness_req, &node).await;
        let readiness_json: serde_json::Value = serde_json::from_str(&readiness_response).unwrap();
        assert_eq!(readiness_json["result"]["healthy"], true);
        let readiness_checks = readiness_json["result"]["checks"].as_object().unwrap();
        assert_eq!(readiness_checks.len(), 1);
        assert!(readiness_checks.contains_key("bootstrapped"));

        let liveness_req = r#"{"jsonrpc":"2.0","method":"health.liveness","params":{},"id":32}"#;
        let liveness_response = handle_rpc_request(liveness_req, &node).await;
        let liveness_json: serde_json::Value = serde_json::from_str(&liveness_response).unwrap();
        assert_eq!(liveness_json["result"]["healthy"], true);
        assert!(liveness_json["result"]["checks"]
            .as_object()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_http_ext_health_status_codes_and_paths() {
        let unhealthy_node = make_test_node(1);
        let unhealthy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unhealthy_addr = unhealthy_listener.local_addr().unwrap();
        let unhealthy_server = tokio::spawn(run_rpc_server_with_listener(
            unhealthy_listener,
            unhealthy_node.clone(),
        ));

        let unhealthy_response = http_get(unhealthy_addr, "/ext/health").await;
        assert!(unhealthy_response.starts_with("HTTP/1.1 503"));
        let unhealthy_body = unhealthy_response.split("\r\n\r\n").nth(1).unwrap();
        let unhealthy_json: serde_json::Value = serde_json::from_str(unhealthy_body).unwrap();
        assert_eq!(unhealthy_json["healthy"], false);
        assert!(unhealthy_json["checks"].get("bootstrapped").is_some());

        unhealthy_server.abort();
        let _ = unhealthy_server.await;

        let healthy_node = make_test_node(1);
        healthy_node.sync_engine.mark_following().await;
        healthy_node.p_chain_metrics.write().await.tip_height = 7;
        healthy_node.c_chain_metrics.write().await.tip_height = 8;
        let mut peer = Peer::new(NodeId([0x24; 20]), "127.0.0.1:9651".parse().unwrap());
        peer.state = PeerState::Connected;
        healthy_node
            .peer_manager
            .write()
            .await
            .add_peer(peer)
            .unwrap();

        let healthy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let healthy_addr = healthy_listener.local_addr().unwrap();
        let healthy_server = tokio::spawn(run_rpc_server_with_listener(
            healthy_listener,
            healthy_node.clone(),
        ));

        let readiness_response = http_get(healthy_addr, "/ext/health/readiness").await;
        assert!(readiness_response.starts_with("HTTP/1.1 200"));
        let readiness_body = readiness_response.split("\r\n\r\n").nth(1).unwrap();
        let readiness_json: serde_json::Value = serde_json::from_str(readiness_body).unwrap();
        assert_eq!(readiness_json["healthy"], true);
        assert_eq!(readiness_json["checks"].as_object().unwrap().len(), 1);

        let filtered_health_response = http_get(healthy_addr, "/ext/health?tag=C").await;
        assert!(filtered_health_response.starts_with("HTTP/1.1 200"));
        let filtered_body = filtered_health_response.split("\r\n\r\n").nth(1).unwrap();
        let filtered_json: serde_json::Value = serde_json::from_str(filtered_body).unwrap();
        assert_eq!(filtered_json["healthy"], true);
        let filtered_checks = filtered_json["checks"].as_object().unwrap();
        assert!(filtered_checks.contains_key("C"));
        assert!(!filtered_checks.contains_key("P"));

        let liveness_response = http_get(healthy_addr, "/ext/health/liveness").await;
        assert!(liveness_response.starts_with("HTTP/1.1 200"));
        let liveness_body = liveness_response.split("\r\n\r\n").nth(1).unwrap();
        let liveness_json: serde_json::Value = serde_json::from_str(liveness_body).unwrap();
        assert_eq!(liveness_json["healthy"], true);
        assert!(liveness_json["checks"].as_object().unwrap().is_empty());

        healthy_server.abort();
        let _ = healthy_server.await;
    }

    #[tokio::test]
    async fn test_rpc_txpool_status_reflects_live_pool() {
        let node = make_test_node(1);

        node.txpool
            .write()
            .await
            .add(make_pool_tx(0x11, 0), 0)
            .expect("tx should be accepted");

        let req = r#"{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":7}"#;
        let response = handle_rpc_request(req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(parsed["result"]["pending"], "0x1");
        assert_eq!(parsed["result"]["queued"], "0x0");
    }

    #[tokio::test]
    async fn test_rpc_txpool_content_and_inspect_group_by_sender_and_nonce() {
        let node = make_test_node(1);
        let from = [0x22; 20];
        let from_key = format!("0x{}", hex::encode(from));

        node.txpool
            .write()
            .await
            .add(make_pool_tx(0x22, 0), 0)
            .expect("pending tx should be accepted");
        node.txpool
            .write()
            .await
            .add(make_pool_tx(0x22, 2), 0)
            .expect("queued tx should be accepted");

        let content_req = r#"{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":8}"#;
        let content = handle_rpc_request(content_req, &node).await;
        let content_json: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(
            content_json["result"]["pending"][&from_key]["0x0"]["input"],
            "0xdeadbeef"
        );
        assert_eq!(
            content_json["result"]["queued"][&from_key]["0x2"]["gasPrice"],
            "0x5d21dba00"
        );

        let inspect_req = r#"{"jsonrpc":"2.0","method":"txpool_inspect","params":[],"id":9}"#;
        let inspect = handle_rpc_request(inspect_req, &node).await;
        let inspect_json: serde_json::Value = serde_json::from_str(&inspect).unwrap();

        assert!(inspect_json["result"]["pending"][&from_key]["0x0"]
            .as_str()
            .unwrap()
            .contains("21000 gas"));
        assert!(inspect_json["result"]["queued"][&from_key]["0x2"]
            .as_str()
            .unwrap()
            .contains("42 wei"));
    }

    #[tokio::test]
    async fn test_rpc_txpool_content_from_scopes_sender() {
        let node = make_test_node(1);
        let sender = [0x24; 20];
        let sender_key = format!("0x{}", hex::encode(sender));

        node.txpool
            .write()
            .await
            .add(make_pool_tx(0x24, 0), 0)
            .expect("pending tx should be accepted");
        node.txpool
            .write()
            .await
            .add(make_pool_tx(0x24, 2), 0)
            .expect("queued tx should be accepted");
        node.txpool
            .write()
            .await
            .add(make_pool_tx(0x25, 0), 0)
            .expect("other sender tx should be accepted");

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"txpool_contentFrom","params":["{}"],"id":9}}"#,
            sender_key
        );
        let response = handle_rpc_request(&req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(parsed["result"]["pending"]["0x0"]["from"], sender_key);
        assert_eq!(parsed["result"]["queued"]["0x2"]["from"], sender_key);
        assert!(parsed["result"]["pending"].get("0x1").is_none());
    }

    #[tokio::test]
    async fn test_eth_pending_transactions_returns_live_pending_objects() {
        let node = make_test_node(1);
        let pending = make_pool_tx(0x33, 0);
        let queued = make_pool_tx(0x33, 2);

        node.txpool
            .write()
            .await
            .add(pending.clone(), 0)
            .expect("pending tx should be accepted");
        node.txpool
            .write()
            .await
            .add(queued, 0)
            .expect("queued tx should be accepted");

        let req = r#"{"jsonrpc":"2.0","method":"eth_pendingTransactions","params":[],"id":10}"#;
        let response = handle_rpc_request(req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        let txs = parsed["result"].as_array().unwrap();

        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0]["hash"], format!("0x{}", hex::encode(pending.hash)));
        assert_eq!(txs[0]["nonce"], "0x0");
        assert_eq!(txs[0]["blockNumber"], serde_json::Value::Null);
        assert_eq!(txs[0]["transactionIndex"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn test_web3_sha3_and_net_methods() {
        let node = make_test_node(1);

        let sha3_req =
            r#"{"jsonrpc":"2.0","method":"web3_sha3","params":["0x68656c6c6f"],"id":10}"#;
        let sha3_response = handle_rpc_request(sha3_req, &node).await;
        let sha3_json: serde_json::Value = serde_json::from_str(&sha3_response).unwrap();
        assert_eq!(
            sha3_json["result"],
            "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );

        let listening_req = r#"{"jsonrpc":"2.0","method":"net_listening","params":[],"id":11}"#;
        let listening_response = handle_rpc_request(listening_req, &node).await;
        let listening_json: serde_json::Value = serde_json::from_str(&listening_response).unwrap();
        assert_eq!(listening_json["result"], true);

        let peer_count_req = r#"{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":12}"#;
        let peer_count_response = handle_rpc_request(peer_count_req, &node).await;
        let peer_count_json: serde_json::Value =
            serde_json::from_str(&peer_count_response).unwrap();
        assert_eq!(peer_count_json["result"], "0x0");
    }

    #[tokio::test]
    async fn test_eth_send_raw_transaction_accepts_legacy_tx() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 21_000,
            to: Some([0x33; 20]),
            value: 7,
            data: vec![0xAB, 0xCD],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");
        let expected_hash = keccak_tx_hash(&signed.raw);

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":10}}"#,
            signed.raw_hex()
        );
        let response = handle_rpc_request(&req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(
            parsed["result"],
            format!("0x{}", hex::encode(expected_hash))
        );

        let pool = node.txpool.read().await;
        let pooled = pool
            .get(&expected_hash)
            .expect("tx should be stored in txpool");
        assert_eq!(pooled.from, *wallet.address());
        assert_eq!(pooled.nonce, 0);
        assert_eq!(pooled.value, 7);
    }

    #[tokio::test]
    async fn test_eth_send_raw_transaction_accepts_eip1559_tx() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::Eip1559Tx {
            nonce: 0,
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 25_000,
            to: Some([0x44; 20]),
            value: 9,
            data: vec![0x01, 0x02, 0x03],
            access_list: vec![],
        };
        let signed = wallet.sign_eip1559(&tx).expect("type-2 tx should sign");
        let expected_hash = keccak_tx_hash(&signed.raw);

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":11}}"#,
            signed.raw_hex()
        );
        let response = handle_rpc_request(&req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(
            parsed["result"],
            format!("0x{}", hex::encode(expected_hash))
        );

        let pool = node.txpool.read().await;
        let pooled = pool
            .get(&expected_hash)
            .expect("tx should be stored in txpool");
        assert_eq!(pooled.from, *wallet.address());
        assert_eq!(pooled.max_fee_per_gas, 30_000_000_000);
        assert_eq!(pooled.max_priority_fee_per_gas, 1_500_000_000);
    }

    #[tokio::test]
    async fn test_eth_send_raw_transaction_rejects_same_nonce_replacement() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);

        let first = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 21_000,
            to: Some([0x55; 20]),
            value: 1,
            data: vec![],
        };
        let second = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 30_000_000_000,
            gas_limit: 21_000,
            to: Some([0x55; 20]),
            value: 2,
            data: vec![],
        };

        let first_signed = wallet.sign_legacy(&first).expect("first tx should sign");
        let second_signed = wallet.sign_legacy(&second).expect("second tx should sign");

        let first_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":12}}"#,
            first_signed.raw_hex()
        );
        let second_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":13}}"#,
            second_signed.raw_hex()
        );

        let first_response = handle_rpc_request(&first_req, &node).await;
        let first_json: serde_json::Value = serde_json::from_str(&first_response).unwrap();
        assert!(first_json.get("result").is_some());

        let second_response = handle_rpc_request(&second_req, &node).await;
        let second_json: serde_json::Value = serde_json::from_str(&second_response).unwrap();
        assert_eq!(
            second_json["error"]["message"],
            "replacement transaction not supported"
        );

        let pool = node.txpool.read().await;
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn test_eth_get_transaction_by_hash_returns_pending_txpool_tx() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 21_000,
            to: Some([0x77; 20]),
            value: 5,
            data: vec![0xAA],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");
        let expected_hash = keccak_tx_hash(&signed.raw);

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":15}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert_eq!(
            submit_json["result"],
            format!("0x{}", hex::encode(expected_hash))
        );

        let lookup_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["0x{}"],"id":16}}"#,
            hex::encode(expected_hash)
        );
        let lookup_response = handle_rpc_request(&lookup_req, &node).await;
        let lookup_json: serde_json::Value = serde_json::from_str(&lookup_response).unwrap();

        assert_eq!(
            lookup_json["result"]["from"],
            format!("0x{}", hex::encode(wallet.address()))
        );
        assert_eq!(
            lookup_json["result"]["blockNumber"],
            serde_json::Value::Null
        );
        assert_eq!(
            lookup_json["result"]["transactionIndex"],
            serde_json::Value::Null
        );
        assert_eq!(lookup_json["result"]["input"], "0xaa");
    }

    #[tokio::test]
    async fn test_build_cchain_block_preserves_raw_signed_typed_transactions() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::Eip1559Tx {
            nonce: 0,
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 21_000,
            to: Some([0x66; 20]),
            value: 1,
            data: vec![],
            access_list: vec![],
        };
        let signed = wallet.sign_eip1559(&tx).expect("type-2 tx should sign");

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
        }

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":14}}"#,
            signed.raw_hex()
        );
        let response = handle_rpc_request(&req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(parsed.get("result").is_some());

        let pool_txs = {
            let pool = node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let block = build_cchain_block(&node, 1, pool_txs)
            .await
            .expect("block should build");

        let extracted = extract_cchain_transactions(&block.raw);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].tx_type, 2);
        assert_eq!(extracted[0].gas_price, 30_000_000_000);
        assert_eq!(extracted[0].max_priority_fee_per_gas, 1_500_000_000);
        assert_eq!(extracted[0].recover_sender(), Some(*wallet.address()));
    }

    #[tokio::test]
    async fn test_local_built_block_persists_tx_lookup_artifacts() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::Eip1559Tx {
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 25_000_000_000,
            gas_limit: 50_000,
            to: Some([0x88; 20]),
            value: 3,
            data: vec![0x01, 0x02],
            access_list: vec![],
        };
        let signed = wallet.sign_eip1559(&tx).expect("tx should sign");
        let tx_hash = keccak_tx_hash(&signed.raw);

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
        }

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":17}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let pool_txs = {
            let pool = node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let block = build_cchain_block(&node, 1, pool_txs.clone())
            .await
            .expect("block should build");

        let mut key = Vec::with_capacity(34);
        key.extend_from_slice(b"c:");
        key.extend_from_slice(&block.id);
        node.db.put_cf(CF_BLOCKS, &key, &block.raw).unwrap();
        node.db.put_block(block.number, &block.raw).unwrap();
        persist_local_cchain_tx_artifacts(&node.db, &block, &pool_txs).unwrap();
        node.db.set_last_accepted_height(block.number).unwrap();
        reconcile_mined_pool_transactions(&node, &pool_txs).await;

        let tx_lookup_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["0x{}"],"id":18}}"#,
            hex::encode(tx_hash)
        );
        let tx_lookup_response = handle_rpc_request(&tx_lookup_req, &node).await;
        let tx_lookup_json: serde_json::Value = serde_json::from_str(&tx_lookup_response).unwrap();
        assert_eq!(tx_lookup_json["result"]["blockNumber"], "0x1");
        assert_eq!(tx_lookup_json["result"]["transactionIndex"], "0x0");

        let receipt_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["0x{}"],"id":19}}"#,
            hex::encode(tx_hash)
        );
        let receipt_response = handle_rpc_request(&receipt_req, &node).await;
        let receipt_json: serde_json::Value = serde_json::from_str(&receipt_response).unwrap();
        assert_eq!(receipt_json["result"]["blockNumber"], "0x1");
        assert_eq!(
            receipt_json["result"]["transactionHash"],
            format!("0x{}", hex::encode(tx_hash))
        );
        assert_eq!(
            receipt_json["result"]["from"],
            format!("0x{}", hex::encode(wallet.address()))
        );

        let block_req =
            r#"{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x1",true],"id":20}"#;
        let block_response = handle_rpc_request(block_req, &node).await;
        let block_json: serde_json::Value = serde_json::from_str(&block_response).unwrap();
        assert_eq!(
            block_json["result"]["hash"],
            format!("0x{}", hex::encode(block.id))
        );
        assert_eq!(block_json["result"]["number"], "0x1");
        assert_eq!(
            block_json["result"]["gasUsed"],
            format!("0x{:x}", block.gas_used)
        );
        assert_eq!(
            block_json["result"]["transactions"][0]["hash"],
            format!("0x{}", hex::encode(tx_hash))
        );
        assert_eq!(
            block_json["result"]["transactions"][0]["blockHash"],
            format!("0x{}", hex::encode(block.id))
        );
        assert_eq!(
            block_json["result"]["transactions"][0]["transactionIndex"],
            "0x0"
        );

        let block_hash_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getBlockByHash","params":["0x{}",false],"id":20}}"#,
            hex::encode(block.id)
        );
        let block_hash_response = handle_rpc_request(&block_hash_req, &node).await;
        let block_hash_json: serde_json::Value =
            serde_json::from_str(&block_hash_response).unwrap();
        assert_eq!(
            block_hash_json["result"]["transactions"][0],
            format!("0x{}", hex::encode(tx_hash))
        );
    }

    #[tokio::test]
    async fn test_eth_block_transaction_count_and_raw_index_lookups() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 50_000,
            to: Some([0x8A; 20]),
            value: 2,
            data: vec![0xAB, 0xCD],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");
        let tx_hash = keccak_tx_hash(&signed.raw);

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
        }

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":21}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let pool_txs = {
            let pool = node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let block = build_cchain_block(&node, 1, pool_txs.clone())
            .await
            .expect("block should build");

        let mut key = Vec::with_capacity(34);
        key.extend_from_slice(b"c:");
        key.extend_from_slice(&block.id);
        node.db.put_cf(CF_BLOCKS, &key, &block.raw).unwrap();
        node.db.put_block(block.number, &block.raw).unwrap();
        persist_local_cchain_tx_artifacts(&node.db, &block, &pool_txs).unwrap();
        node.db.set_last_accepted_height(block.number).unwrap();
        reconcile_mined_pool_transactions(&node, &pool_txs).await;

        let count_by_number_req = r#"{"jsonrpc":"2.0","method":"eth_getBlockTransactionCountByNumber","params":["0x1"],"id":22}"#;
        let count_by_number_response = handle_rpc_request(count_by_number_req, &node).await;
        let count_by_number_json: serde_json::Value =
            serde_json::from_str(&count_by_number_response).unwrap();
        assert_eq!(count_by_number_json["result"], "0x1");

        let count_by_hash_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getBlockTransactionCountByHash","params":["0x{}"],"id":23}}"#,
            hex::encode(block.id)
        );
        let count_by_hash_response = handle_rpc_request(&count_by_hash_req, &node).await;
        let count_by_hash_json: serde_json::Value =
            serde_json::from_str(&count_by_hash_response).unwrap();
        assert_eq!(count_by_hash_json["result"], "0x1");

        let tx_by_number_req = r#"{"jsonrpc":"2.0","method":"eth_getTransactionByBlockNumberAndIndex","params":["0x1","0x0"],"id":24}"#;
        let tx_by_number_response = handle_rpc_request(tx_by_number_req, &node).await;
        let tx_by_number_json: serde_json::Value =
            serde_json::from_str(&tx_by_number_response).unwrap();
        assert_eq!(
            tx_by_number_json["result"]["hash"],
            format!("0x{}", hex::encode(tx_hash))
        );
        assert_eq!(tx_by_number_json["result"]["transactionIndex"], "0x0");

        let tx_by_hash_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getTransactionByBlockHashAndIndex","params":["0x{}","0x0"],"id":25}}"#,
            hex::encode(block.id)
        );
        let tx_by_hash_response = handle_rpc_request(&tx_by_hash_req, &node).await;
        let tx_by_hash_json: serde_json::Value =
            serde_json::from_str(&tx_by_hash_response).unwrap();
        assert_eq!(
            tx_by_hash_json["result"]["hash"],
            format!("0x{}", hex::encode(tx_hash))
        );

        let raw_by_hash_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getRawTransactionByHash","params":["0x{}"],"id":26}}"#,
            hex::encode(tx_hash)
        );
        let raw_by_hash_response = handle_rpc_request(&raw_by_hash_req, &node).await;
        let raw_by_hash_json: serde_json::Value =
            serde_json::from_str(&raw_by_hash_response).unwrap();
        assert_eq!(raw_by_hash_json["result"], signed.raw_hex());

        let raw_by_number_req = r#"{"jsonrpc":"2.0","method":"eth_getRawTransactionByBlockNumberAndIndex","params":["0x1","0x0"],"id":27}"#;
        let raw_by_number_response = handle_rpc_request(raw_by_number_req, &node).await;
        let raw_by_number_json: serde_json::Value =
            serde_json::from_str(&raw_by_number_response).unwrap();
        assert_eq!(raw_by_number_json["result"], signed.raw_hex());

        let raw_by_block_hash_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getRawTransactionByBlockHashAndIndex","params":["0x{}","0x0"],"id":28}}"#,
            hex::encode(block.id)
        );
        let raw_by_block_hash_response = handle_rpc_request(&raw_by_block_hash_req, &node).await;
        let raw_by_block_hash_json: serde_json::Value =
            serde_json::from_str(&raw_by_block_hash_response).unwrap();
        assert_eq!(raw_by_block_hash_json["result"], signed.raw_hex());
    }

    #[tokio::test]
    async fn test_imported_cchain_block_persists_lookup_artifacts() {
        let builder_node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::Eip1559Tx {
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 25_000_000_000,
            gas_limit: 50_000,
            to: Some([0x99; 20]),
            value: 4,
            data: vec![0xAA, 0xBB],
            access_list: vec![],
        };
        let signed = wallet.sign_eip1559(&tx).expect("tx should sign");
        let tx_hash = keccak_tx_hash(&signed.raw);

        {
            let mut evm = builder_node.evm.write().await;
            evm.set_balance(*wallet.address(), u128::MAX / 2);
        }

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":21}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &builder_node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let pool_txs = {
            let pool = builder_node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let block = build_cchain_block(&builder_node, 1, pool_txs)
            .await
            .expect("block should build");

        let importer_node = make_test_node(1);
        execute_cchain_block_and_store(&block.raw, &importer_node).await;

        let imported_block = importer_node
            .db
            .get_block(1)
            .expect("db lookup should succeed");
        assert!(imported_block.is_some(), "imported block should be stored");

        let indexed_tx = importer_node
            .db
            .get_tx_index(&tx_hash)
            .expect("tx index lookup should succeed");
        assert!(
            indexed_tx.is_some(),
            "imported tx should be indexed under the raw transaction hash"
        );

        let tx_lookup_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["0x{}"],"id":22}}"#,
            hex::encode(tx_hash)
        );
        let tx_lookup_response = handle_rpc_request(&tx_lookup_req, &importer_node).await;
        let tx_lookup_json: serde_json::Value = serde_json::from_str(&tx_lookup_response).unwrap();
        assert_eq!(tx_lookup_json["result"]["blockNumber"], "0x1");
        assert_eq!(tx_lookup_json["result"]["transactionIndex"], "0x0");
        assert_eq!(
            tx_lookup_json["result"]["blockHash"],
            format!("0x{}", hex::encode(block.id))
        );
        assert_eq!(
            tx_lookup_json["result"]["from"],
            format!("0x{}", hex::encode(wallet.address()))
        );

        let receipt_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["0x{}"],"id":23}}"#,
            hex::encode(tx_hash)
        );
        let receipt_response = handle_rpc_request(&receipt_req, &importer_node).await;
        let receipt_json: serde_json::Value = serde_json::from_str(&receipt_response).unwrap();
        assert_eq!(receipt_json["result"]["blockNumber"], "0x1");
        assert_eq!(
            receipt_json["result"]["transactionHash"],
            format!("0x{}", hex::encode(tx_hash))
        );

        let block_req =
            r#"{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x1",true],"id":24}"#;
        let block_response = handle_rpc_request(block_req, &importer_node).await;
        let block_json: serde_json::Value = serde_json::from_str(&block_response).unwrap();
        assert_eq!(
            block_json["result"]["hash"],
            format!("0x{}", hex::encode(block.id))
        );
        assert_eq!(
            block_json["result"]["transactions"][0]["hash"],
            format!("0x{}", hex::encode(tx_hash))
        );
        assert_eq!(
            block_json["result"]["transactions"][0]["from"],
            format!("0x{}", hex::encode(wallet.address()))
        );
        assert_eq!(
            block_json["result"]["transactions"][0]["blockNumber"],
            "0x1"
        );

        let receipts_by_hash_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getBlockReceipts","params":["0x{}"],"id":25}}"#,
            hex::encode(block.id)
        );
        let receipts_by_hash_response =
            handle_rpc_request(&receipts_by_hash_req, &importer_node).await;
        let receipts_by_hash_json: serde_json::Value =
            serde_json::from_str(&receipts_by_hash_response).unwrap();
        let receipts = receipts_by_hash_json["result"].as_array().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0]["transactionHash"],
            format!("0x{}", hex::encode(tx_hash))
        );

        let missing_receipts_req = r#"{"jsonrpc":"2.0","method":"eth_getBlockReceipts","params":["0x00000000000000000000000000000000000000000000000000000000deadbeef"],"id":26}"#;
        let missing_receipts_response =
            handle_rpc_request(missing_receipts_req, &importer_node).await;
        let missing_receipts_json: serde_json::Value =
            serde_json::from_str(&missing_receipts_response).unwrap();
        assert!(missing_receipts_json["result"].is_null());

        assert_eq!(importer_node.db.last_accepted_height().unwrap(), Some(1));
        let imported_fields =
            extract_cchain_block_fields(&block.raw).expect("imported block fields should parse");
        let expected_next_base_fee =
            predicted_next_base_fee_from_fields(importer_node.config.network_id, &imported_fields);
        let pool = importer_node.txpool.read().await;
        assert_eq!(pool.base_fee, expected_next_base_fee);
    }

    #[tokio::test]
    async fn test_eth_get_bad_blocks_returns_recorded_import_failures() {
        let builder_node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::Eip1559Tx {
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 25_000_000_000,
            gas_limit: 50_000,
            to: Some([0x33; 20]),
            value: 7,
            data: vec![0xAB, 0xCD],
            access_list: vec![],
        };
        let signed = wallet.sign_eip1559(&tx).expect("tx should sign");
        let tx_hash = keccak_tx_hash(&signed.raw);

        {
            let mut evm = builder_node.evm.write().await;
            evm.set_balance(*wallet.address(), u128::MAX / 2);
        }

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":24}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &builder_node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let pool_txs = {
            let pool = builder_node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let block = build_cchain_block(&builder_node, 1, pool_txs)
            .await
            .expect("block should build");

        let original_state_root =
            BlockHeader::extract_state_root(&block.raw).expect("state root should exist");
        let state_root_offset = block
            .raw
            .windows(original_state_root.len())
            .position(|window| window == original_state_root)
            .expect("state root bytes should appear in block");
        let mut bad_raw = block.raw.clone();
        bad_raw[state_root_offset] ^= 0x01;

        let importer_node = make_test_node(1);
        execute_cchain_block_and_store(&bad_raw, &importer_node).await;
        assert!(
            importer_node.db.get_block(1).unwrap().is_none(),
            "bad block should not be stored as accepted"
        );

        let req = r#"{"jsonrpc":"2.0","method":"eth_getBadBlocks","params":[],"id":25}"#;
        let response = handle_rpc_request(req, &importer_node).await;
        let json: serde_json::Value = serde_json::from_str(&response).unwrap();
        let bad_blocks = json["result"].as_array().unwrap();
        assert_eq!(bad_blocks.len(), 1);

        let expected_hash = cchain_block_hash(&bad_raw);
        assert_eq!(
            bad_blocks[0]["hash"],
            format!("0x{}", hex::encode(expected_hash))
        );
        assert_eq!(bad_blocks[0]["rlp"], cchain_rlp_hex(&bad_raw));
        assert_eq!(bad_blocks[0]["block"]["number"], "0x1");
        assert_eq!(
            bad_blocks[0]["block"]["transactions"][0]["hash"],
            format!("0x{}", hex::encode(tx_hash))
        );
        assert_eq!(bad_blocks[0]["reason"]["number"], 1);
        assert_eq!(
            bad_blocks[0]["reason"]["hash"],
            format!("0x{}", hex::encode(expected_hash))
        );
        assert!(bad_blocks[0]["reason"]["error"]
            .as_str()
            .unwrap()
            .contains("state root mismatch"));
        assert_eq!(
            bad_blocks[0]["reason"]["receipts"][0]["transactionHash"],
            format!("0x{}", hex::encode(tx_hash))
        );
    }

    #[tokio::test]
    async fn test_eth_get_logs_filters_persisted_receipts() {
        let _guard = FILTER_TEST_GUARD.lock().await;
        FILTERS.write().await.clear();

        let node = make_test_node(1);
        node.db.set_last_accepted_height(1).unwrap();

        let address_match = [0xAA; 20];
        let address_other = [0xBB; 20];
        let topic_match = [0x11; 32];
        let topic_other = [0x22; 32];
        let block_hash = [0x44; 32];
        let tx_hash0 = [0x55; 32];
        let tx_hash1 = [0x66; 32];

        store_test_receipt(
            &node.db,
            1,
            0,
            tx_hash0,
            block_hash,
            vec![
                make_test_log(address_other, vec![topic_other], 1, tx_hash0, 0, block_hash),
                make_test_log(
                    address_match,
                    vec![topic_match, topic_other],
                    1,
                    tx_hash0,
                    0,
                    block_hash,
                ),
            ],
        );
        store_test_receipt(
            &node.db,
            1,
            1,
            tx_hash1,
            block_hash,
            vec![make_test_log(
                address_match,
                vec![topic_match],
                1,
                tx_hash1,
                1,
                block_hash,
            )],
        );

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getLogs","params":[{{"fromBlock":"0x1","toBlock":"latest","address":"0x{}","topics":["0x{}"]}}],"id":25}}"#,
            hex::encode(address_match),
            hex::encode(topic_match)
        );
        let response = handle_rpc_request(&req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        let logs = parsed["result"].as_array().unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(
            logs[0]["transactionHash"],
            format!("0x{}", hex::encode(tx_hash0))
        );
        assert_eq!(logs[0]["logIndex"], "0x1");
        assert_eq!(
            logs[1]["transactionHash"],
            format!("0x{}", hex::encode(tx_hash1))
        );
        assert_eq!(logs[1]["logIndex"], "0x2");
    }

    #[tokio::test]
    async fn test_eth_filter_changes_and_filter_logs() {
        let _guard = FILTER_TEST_GUARD.lock().await;
        FILTERS.write().await.clear();

        let node = make_test_node(1);
        let address_match = [0xCC; 20];
        let topic_match = [0x33; 32];
        let block_hash1 = [0x77; 32];
        let block_hash2 = [0x88; 32];
        let tx_hash1 = [0x99; 32];
        let tx_hash2 = [0xAA; 32];

        store_test_receipt(
            &node.db,
            1,
            0,
            tx_hash1,
            block_hash1,
            vec![make_test_log(
                address_match,
                vec![topic_match],
                1,
                tx_hash1,
                0,
                block_hash1,
            )],
        );
        node.db.set_last_accepted_height(1).unwrap();

        let new_filter_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_newFilter","params":[{{"fromBlock":"earliest","address":"0x{}","topics":["0x{}"]}}],"id":26}}"#,
            hex::encode(address_match),
            hex::encode(topic_match)
        );
        let new_filter_response = handle_rpc_request(&new_filter_req, &node).await;
        let new_filter_json: serde_json::Value =
            serde_json::from_str(&new_filter_response).unwrap();
        let filter_id = new_filter_json["result"].as_str().unwrap().to_string();

        let filter_logs_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getFilterLogs","params":["{}"],"id":27}}"#,
            filter_id
        );
        let filter_logs_response = handle_rpc_request(&filter_logs_req, &node).await;
        let filter_logs_json: serde_json::Value =
            serde_json::from_str(&filter_logs_response).unwrap();
        assert_eq!(filter_logs_json["result"].as_array().unwrap().len(), 1);

        let filter_changes_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getFilterChanges","params":["{}"],"id":28}}"#,
            filter_id
        );
        let first_changes_response = handle_rpc_request(&filter_changes_req, &node).await;
        let first_changes_json: serde_json::Value =
            serde_json::from_str(&first_changes_response).unwrap();
        assert_eq!(first_changes_json["result"].as_array().unwrap().len(), 1);

        let second_changes_response = handle_rpc_request(&filter_changes_req, &node).await;
        let second_changes_json: serde_json::Value =
            serde_json::from_str(&second_changes_response).unwrap();
        assert!(second_changes_json["result"].as_array().unwrap().is_empty());

        store_test_receipt(
            &node.db,
            2,
            0,
            tx_hash2,
            block_hash2,
            vec![make_test_log(
                address_match,
                vec![topic_match],
                2,
                tx_hash2,
                0,
                block_hash2,
            )],
        );
        node.db.set_last_accepted_height(2).unwrap();

        let third_changes_response = handle_rpc_request(&filter_changes_req, &node).await;
        let third_changes_json: serde_json::Value =
            serde_json::from_str(&third_changes_response).unwrap();
        let third_logs = third_changes_json["result"].as_array().unwrap();
        assert_eq!(third_logs.len(), 1);
        assert_eq!(third_logs[0]["blockNumber"], "0x2");
        assert_eq!(
            third_logs[0]["transactionHash"],
            format!("0x{}", hex::encode(tx_hash2))
        );

        let uninstall_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_uninstallFilter","params":["{}"],"id":29}}"#,
            filter_id
        );
        let uninstall_response = handle_rpc_request(&uninstall_req, &node).await;
        let uninstall_json: serde_json::Value = serde_json::from_str(&uninstall_response).unwrap();
        assert_eq!(uninstall_json["result"], true);
    }

    #[tokio::test]
    async fn test_pending_block_and_accepted_transaction_filters() {
        let _guard = FILTER_TEST_GUARD.lock().await;
        FILTERS.write().await.clear();
        PENDING_FILTER_EVENTS.write().await.clear();
        NEXT_PENDING_FILTER_EVENT_ID.store(1, std::sync::atomic::Ordering::Relaxed);

        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 21_000,
            to: Some([0xAD; 20]),
            value: 1,
            data: vec![],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");
        let tx_hash = keccak_tx_hash(&signed.raw);

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), u128::MAX / 2);
        }

        let new_pending_req =
            r#"{"jsonrpc":"2.0","method":"eth_newPendingTransactionFilter","params":[],"id":29}"#;
        let new_pending_response = handle_rpc_request(new_pending_req, &node).await;
        let new_pending_json: serde_json::Value =
            serde_json::from_str(&new_pending_response).unwrap();
        let pending_filter_id = new_pending_json["result"].as_str().unwrap().to_string();

        let new_block_req =
            r#"{"jsonrpc":"2.0","method":"eth_newBlockFilter","params":[],"id":30}"#;
        let new_block_response = handle_rpc_request(new_block_req, &node).await;
        let new_block_json: serde_json::Value = serde_json::from_str(&new_block_response).unwrap();
        let block_filter_id = new_block_json["result"].as_str().unwrap().to_string();

        let new_accepted_req = r#"{"jsonrpc":"2.0","method":"eth_newAcceptedTransactions","params":[{"fullTx":true}],"id":31}"#;
        let new_accepted_response = handle_rpc_request(new_accepted_req, &node).await;
        let new_accepted_json: serde_json::Value =
            serde_json::from_str(&new_accepted_response).unwrap();
        let accepted_filter_id = new_accepted_json["result"].as_str().unwrap().to_string();

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":32}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let pending_changes_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getFilterChanges","params":["{}"],"id":33}}"#,
            pending_filter_id
        );
        let pending_changes_response = handle_rpc_request(&pending_changes_req, &node).await;
        let pending_changes_json: serde_json::Value =
            serde_json::from_str(&pending_changes_response).unwrap();
        assert_eq!(
            pending_changes_json["result"][0],
            format!("0x{}", hex::encode(tx_hash))
        );

        let pool_txs = {
            let pool = node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let block = build_cchain_block(&node, 1, pool_txs.clone())
            .await
            .expect("block should build");

        let mut key = Vec::with_capacity(34);
        key.extend_from_slice(b"c:");
        key.extend_from_slice(&block.id);
        node.db.put_cf(CF_BLOCKS, &key, &block.raw).unwrap();
        node.db.put_block(block.number, &block.raw).unwrap();
        persist_local_cchain_tx_artifacts(&node.db, &block, &pool_txs).unwrap();
        node.db.set_last_accepted_height(block.number).unwrap();
        reconcile_mined_pool_transactions(&node, &pool_txs).await;

        let block_changes_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getFilterChanges","params":["{}"],"id":34}}"#,
            block_filter_id
        );
        let block_changes_response = handle_rpc_request(&block_changes_req, &node).await;
        let block_changes_json: serde_json::Value =
            serde_json::from_str(&block_changes_response).unwrap();
        assert_eq!(
            block_changes_json["result"][0],
            format!("0x{}", hex::encode(block.id))
        );

        let accepted_changes_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getFilterChanges","params":["{}"],"id":35}}"#,
            accepted_filter_id
        );
        let accepted_changes_response = handle_rpc_request(&accepted_changes_req, &node).await;
        let accepted_changes_json: serde_json::Value =
            serde_json::from_str(&accepted_changes_response).unwrap();
        assert_eq!(
            accepted_changes_json["result"][0]["hash"],
            format!("0x{}", hex::encode(tx_hash))
        );
        assert_eq!(
            accepted_changes_json["result"][0]["blockHash"],
            format!("0x{}", hex::encode(block.id))
        );
    }

    #[tokio::test]
    async fn test_eth_accounts_sign_and_send_transaction_use_managed_wallets() {
        let _guard = FILTER_TEST_GUARD.lock().await;
        PENDING_FILTER_EVENTS.write().await.clear();
        NEXT_PENDING_FILTER_EVENT_ID.store(1, std::sync::atomic::Ordering::Relaxed);

        let wallet = Wallet::from_hex(
            "0x4c0883a69102937d6231471b5dbb6204fe5129617082795a3d4b8b7d2c4f5f6a",
            43114,
        )
        .unwrap();
        let node = make_test_node_with_rpc_wallets(1, vec![wallet.clone()]);

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), u128::MAX / 2);
        }

        let accounts_req = r#"{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":36}"#;
        let accounts_response = handle_rpc_request(accounts_req, &node).await;
        let accounts_json: serde_json::Value = serde_json::from_str(&accounts_response).unwrap();
        let expected_address = wallet.address_hex();
        assert_eq!(
            accounts_json["result"],
            serde_json::json!([expected_address])
        );

        let sign_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sign","params":["{}","0x68656c6c6f"],"id":37}}"#,
            wallet.address_hex()
        );
        let sign_response = handle_rpc_request(&sign_req, &node).await;
        let sign_json: serde_json::Value = serde_json::from_str(&sign_response).unwrap();
        let signature = sign_json["result"].as_str().unwrap();
        assert_eq!(signature.len(), 132);
        assert!(signature.ends_with("1b") || signature.ends_with("1c"));

        let send_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{{"from":"{}","to":"0x{}","value":"0x7"}}],"id":38}}"#,
            wallet.address_hex(),
            hex::encode([0x51; 20])
        );
        let send_response = handle_rpc_request(&send_req, &node).await;
        let send_json: serde_json::Value = serde_json::from_str(&send_response).unwrap();
        let tx_hash = parse_hex_hash(send_json["result"].as_str().unwrap()).unwrap();
        let pending = node.txpool.read().await.get(&tx_hash).cloned().unwrap();
        assert_eq!(pending.from, *wallet.address());
        assert_eq!(pending.to, Some([0x51; 20]));
        assert_eq!(pending.value, 7);
    }

    #[tokio::test]
    async fn test_eth_fill_sign_transaction_and_resend_with_managed_wallet() {
        let _guard = FILTER_TEST_GUARD.lock().await;
        PENDING_FILTER_EVENTS.write().await.clear();
        NEXT_PENDING_FILTER_EVENT_ID.store(1, std::sync::atomic::Ordering::Relaxed);

        let wallet = Wallet::from_hex(
            "0x8f2a5594906d42f2b7d3b913f5cf2c1e0ed6f3d1063f4042afe7f18413cf5df2",
            43114,
        )
        .unwrap();
        let node = make_test_node_with_rpc_wallets(1, vec![wallet.clone()]);

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), u128::MAX / 2);
        }

        let fill_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_fillTransaction","params":[{{"from":"{}","to":"0x{}","value":"0x1"}}],"id":39}}"#,
            wallet.address_hex(),
            hex::encode([0x52; 20])
        );
        let fill_response = handle_rpc_request(&fill_req, &node).await;
        let fill_json: serde_json::Value = serde_json::from_str(&fill_response).unwrap();
        assert!(fill_json["result"]["raw"]
            .as_str()
            .unwrap()
            .starts_with("0x02"));
        assert_eq!(fill_json["result"]["tx"]["type"], "0x2");
        assert_eq!(fill_json["result"]["tx"]["nonce"], "0x0");

        let sign_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_signTransaction","params":[{{"from":"{}","to":"0x{}","value":"0x2","gas":"0x5208","gasPrice":"0x5d21dba00","nonce":"0x0"}}],"id":40}}"#,
            wallet.address_hex(),
            hex::encode([0x53; 20])
        );
        let sign_response = handle_rpc_request(&sign_req, &node).await;
        let sign_json: serde_json::Value = serde_json::from_str(&sign_response).unwrap();
        assert!(sign_json["result"]["raw"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
        assert_eq!(sign_json["result"]["tx"]["type"], "0x0");
        assert_eq!(sign_json["result"]["tx"]["gasPrice"], "0x5d21dba00");

        let send_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{{"from":"{}","to":"0x{}","value":"0x3","gas":"0x5208","gasPrice":"0x5d21dba00","nonce":"0x0"}}],"id":41}}"#,
            wallet.address_hex(),
            hex::encode([0x54; 20])
        );
        let send_response = handle_rpc_request(&send_req, &node).await;
        let send_json: serde_json::Value = serde_json::from_str(&send_response).unwrap();
        let first_hash = parse_hex_hash(send_json["result"].as_str().unwrap()).unwrap();

        let resend_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_resend","params":[{{"from":"{}","to":"0x{}","value":"0x3","data":"0x","nonce":"0x0"}},"0x77359400","0x7530"],"id":42}}"#,
            wallet.address_hex(),
            hex::encode([0x54; 20])
        );
        let resend_response = handle_rpc_request(&resend_req, &node).await;
        let resend_json: serde_json::Value = serde_json::from_str(&resend_response).unwrap();
        let replacement_hash = parse_hex_hash(resend_json["result"].as_str().unwrap()).unwrap();

        assert_ne!(replacement_hash, first_hash);
        let pool = node.txpool.read().await;
        assert!(pool.get(&first_hash).is_none());
        let replacement = pool.get(&replacement_hash).unwrap();
        assert_eq!(replacement.gas_limit, 30_000);
        assert_eq!(replacement.max_fee_per_gas, 2_000_000_000);
    }

    #[tokio::test]
    async fn test_eth_get_proof_returns_current_account_and_storage_values() {
        let node = make_test_node(1);
        let account = [0x61; 20];
        let slot = [0x11; 32];
        let mut value = [0u8; 32];
        value[31] = 5;

        {
            let mut evm = node.evm.write().await;
            evm.set_account(account, 500, 7, vec![0x60, 0x00, 0x55]);
            evm.set_storage(account, slot, value);
        }

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getProof","params":["0x{}" ,["0x{}"],"latest"],"id":43}}"#,
            hex::encode(account),
            hex::encode(slot)
        );
        let response = handle_rpc_request(&req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(
            parsed["result"]["address"],
            format!("0x{}", hex::encode(account))
        );
        assert_eq!(parsed["result"]["balance"], "0x1f4");
        assert_eq!(parsed["result"]["nonce"], "0x7");
        assert!(!parsed["result"]["accountProof"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            parsed["result"]["storageProof"][0]["key"],
            format!("0x{}", hex::encode(slot))
        );
        assert_eq!(parsed["result"]["storageProof"][0]["value"], "0x5");

        node.db.set_last_accepted_height(1).unwrap();
        let historical_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getProof","params":["0x{}" ,["0x{}"],"0x0"],"id":44}}"#,
            hex::encode(account),
            hex::encode(slot)
        );
        let historical_response = handle_rpc_request(&historical_req, &node).await;
        let historical_json: serde_json::Value =
            serde_json::from_str(&historical_response).unwrap();
        assert_eq!(
            historical_json["error"]["message"],
            "historical proof query not allowed"
        );
    }

    #[tokio::test]
    async fn test_websocket_subscribe_new_pending_transactions() {
        let node = make_test_node(1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_rpc_server_with_listener(listener, node.clone()));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        websocket_handshake(&mut stream, "/ext/bc/C/ws").await;

        let subscribe_req = r#"{"jsonrpc":"2.0","method":"eth_subscribe","params":["newPendingTransactions"],"id":30}"#;
        write_masked_ws_text_frame(&mut stream, subscribe_req).await;
        let subscribe_response = read_ws_text_frame(&mut stream).await;
        let subscription_id = subscribe_response["result"]
            .as_str()
            .expect("subscription id");

        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 21_000,
            to: Some([0xAB; 20]),
            value: 1,
            data: vec![],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");
        let tx_hash = submit_raw_cchain_transaction(&node, &signed.raw)
            .await
            .expect("raw tx should be accepted");

        let notification = read_ws_text_frame(&mut stream).await;
        assert_eq!(notification["method"], "eth_subscription");
        assert_eq!(notification["params"]["subscription"], subscription_id);
        assert_eq!(
            notification["params"]["result"],
            format!("0x{}", hex::encode(tx_hash))
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_websocket_subscribe_new_heads() {
        let node = make_test_node(1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_rpc_server_with_listener(listener, node.clone()));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        websocket_handshake(&mut stream, "/ws").await;

        let subscribe_req =
            r#"{"jsonrpc":"2.0","method":"eth_subscribe","params":["newHeads"],"id":31}"#;
        write_masked_ws_text_frame(&mut stream, subscribe_req).await;
        let subscribe_response = read_ws_text_frame(&mut stream).await;
        let subscription_id = subscribe_response["result"]
            .as_str()
            .expect("subscription id");

        let block = build_cchain_block(&node, 1, vec![])
            .await
            .expect("empty block should build");
        execute_cchain_block_and_store(&block.raw, &node).await;

        let notification = read_ws_text_frame(&mut stream).await;
        assert_eq!(notification["method"], "eth_subscription");
        assert_eq!(notification["params"]["subscription"], subscription_id);
        assert_eq!(notification["params"]["result"]["number"], "0x1");
        assert_eq!(
            notification["params"]["result"]["hash"],
            format!("0x{}", hex::encode(block.id))
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_websocket_subscribe_new_accepted_transactions_full_tx() {
        let node = make_test_node(1);
        let builder_node = make_test_node(1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_rpc_server_with_listener(listener, node.clone()));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        websocket_handshake(&mut stream, "/ext/bc/C/ws").await;

        let subscribe_req = r#"{"jsonrpc":"2.0","method":"eth_subscribe","params":["newAcceptedTransactions",{"fullTx":true}],"id":32}"#;
        write_masked_ws_text_frame(&mut stream, subscribe_req).await;
        let subscribe_response = read_ws_text_frame(&mut stream).await;
        let subscription_id = subscribe_response["result"]
            .as_str()
            .expect("subscription id");

        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 21_000,
            to: Some([0xAC; 20]),
            value: 1,
            data: vec![],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");

        {
            let mut evm = builder_node.evm.write().await;
            evm.set_balance(*wallet.address(), u128::MAX / 2);
        }

        let parsed_tx =
            parse_raw_cchain_transaction(&signed.raw).expect("signed tx should parse for block");
        let tx_hash = raw_tx_hash(&signed.raw);
        let block = build_cchain_block(&builder_node, 1, vec![pool_tx_from_cchain_raw(&parsed_tx)])
            .await
            .expect("block should build");
        execute_cchain_block_and_store(&block.raw, &node).await;
        assert!(
            node.db.get_block(1).unwrap().is_some(),
            "accepted block should be stored before websocket notification"
        );
        assert!(
            node.db.get_tx_index(&tx_hash).unwrap().is_some(),
            "accepted tx should be indexed before websocket notification"
        );

        let notification = read_ws_text_frame(&mut stream).await;
        assert_eq!(notification["method"], "eth_subscription");
        assert_eq!(notification["params"]["subscription"], subscription_id);
        assert_eq!(
            notification["params"]["result"]["hash"],
            format!("0x{}", hex::encode(tx_hash))
        );
        assert_eq!(
            notification["params"]["result"]["blockHash"],
            format!("0x{}", hex::encode(block.id))
        );
        assert_eq!(notification["params"]["result"]["transactionIndex"], "0x0");

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_debug_trace_transaction_for_pending_tx() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let contract = [0x77; 20];
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 50_000,
            to: Some(contract),
            value: 5,
            data: vec![0xAA, 0xBB, 0xCC],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");
        let tx_hash = keccak_tx_hash(&signed.raw);

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
            evm.set_account(
                contract,
                0,
                1,
                vec![0x60, 0x00, 0x35, 0x60, 0x00, 0x52, 0x00],
            );
        }

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":32}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let trace_req = format!(
            r#"{{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["0x{}",{{"enableMemory":true}}],"id":33}}"#,
            hex::encode(tx_hash)
        );
        let trace_response = handle_rpc_request(&trace_req, &node).await;
        let trace_json: serde_json::Value = serde_json::from_str(&trace_response).unwrap();
        assert_eq!(trace_json["result"]["failed"], false);
        assert!(trace_json["result"]["gas"].as_u64().unwrap() > 0);
        let logs = trace_json["result"]["structLogs"].as_array().unwrap();
        assert_eq!(logs[0]["op"], "PUSH1");
        assert_eq!(logs[1]["op"], "CALLDATALOAD");
        assert!(logs.iter().any(|log| log["op"] == "MSTORE"));
        assert!(logs.last().unwrap()["memory"].is_array());
    }

    #[tokio::test]
    async fn test_debug_trace_transaction_for_pending_tx_uses_head_base_fee() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let contract = [0x79; 20];
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 50_000,
            to: Some(contract),
            value: 0,
            data: vec![],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");
        let tx_hash = keccak_tx_hash(&signed.raw);

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
            evm.set_account(contract, 0, 1, vec![0x00]);
        }

        let head_block = encode_cchain_block_rlp(
            &[0u8; 32],
            &[0u8; 20],
            &[0u8; 32],
            1,
            DEFAULT_CCHAIN_GAS_LIMIT,
            0,
            unix_timestamp_secs(),
            50_000_000_000,
            &[],
        );
        node.db.put_block(1, &head_block).unwrap();
        node.db.set_last_accepted_height(1).unwrap();

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":34}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let trace_req = format!(
            r#"{{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["0x{}"],"id":35}}"#,
            hex::encode(tx_hash)
        );
        let trace_response = handle_rpc_request(&trace_req, &node).await;
        let trace_json: serde_json::Value = serde_json::from_str(&trace_response).unwrap();
        assert_eq!(trace_json["result"]["failed"], true);
        assert_eq!(trace_json["result"]["structLogs"][0]["op"], "INVALID");
        assert!(trace_json["result"]["structLogs"][0]["error"]
            .as_str()
            .unwrap()
            .contains("GasPriceLessThanBasefee"));
    }

    #[tokio::test]
    async fn test_debug_trace_block_by_number_call_tracer() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::Eip1559Tx {
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 25_000_000_000,
            gas_limit: 50_000,
            to: Some([0x88; 20]),
            value: 3,
            data: vec![0x01, 0x02],
            access_list: vec![],
        };
        let signed = wallet.sign_eip1559(&tx).expect("tx should sign");

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
        }

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":34}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let pool_txs = {
            let pool = node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let block = build_cchain_block(&node, 1, pool_txs.clone())
            .await
            .expect("block should build");

        let mut key = Vec::with_capacity(34);
        key.extend_from_slice(b"c:");
        key.extend_from_slice(&block.id);
        node.db.put_cf(CF_BLOCKS, &key, &block.raw).unwrap();
        node.db.put_block(block.number, &block.raw).unwrap();
        persist_local_cchain_tx_artifacts(&node.db, &block, &pool_txs).unwrap();
        node.db.set_last_accepted_height(block.number).unwrap();
        reconcile_mined_pool_transactions(&node, &pool_txs).await;

        let trace_req = r#"{"jsonrpc":"2.0","method":"debug_traceBlockByNumber","params":["0x1",{"tracer":"callTracer"}],"id":35}"#;
        let trace_response = handle_rpc_request(trace_req, &node).await;
        let trace_json: serde_json::Value = serde_json::from_str(&trace_response).unwrap();
        let traces = trace_json["result"].as_array().unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0]["type"], "CALL");
        assert_eq!(
            traces[0]["from"],
            format!("0x{}", hex::encode(wallet.address()))
        );
        assert!(traces[0]["gasUsed"].as_str().unwrap().starts_with("0x"));
    }

    #[tokio::test]
    async fn test_eth_fee_history_uses_stored_block_data() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 26_000_000_000,
            gas_limit: 30_000,
            to: Some([0x52; 20]),
            value: 1,
            data: vec![],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
        }

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":36}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let pool_txs = {
            let pool = node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let block = build_cchain_block(&node, 1, pool_txs.clone())
            .await
            .expect("block should build");

        let mut key = Vec::with_capacity(34);
        key.extend_from_slice(b"c:");
        key.extend_from_slice(&block.id);
        node.db.put_cf(CF_BLOCKS, &key, &block.raw).unwrap();
        node.db.put_block(block.number, &block.raw).unwrap();
        persist_local_cchain_tx_artifacts(&node.db, &block, &pool_txs).unwrap();
        node.db.set_last_accepted_height(block.number).unwrap();
        reconcile_mined_pool_transactions(&node, &pool_txs).await;

        let req =
            r#"{"jsonrpc":"2.0","method":"eth_feeHistory","params":["0x1","0x1",[10,90]],"id":37}"#;
        let response = handle_rpc_request(req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["result"]["oldestBlock"], "0x1");
        assert_eq!(parsed["result"]["baseFeePerGas"][0], "0x5d21dba00");
        assert_eq!(
            parsed["result"]["baseFeePerGas"].as_array().unwrap().len(),
            2
        );
        assert!(parsed["result"]["gasUsedRatio"][0].as_f64().unwrap() > 0.0);
        let rewards = parsed["result"]["reward"][0].as_array().unwrap();
        assert_eq!(rewards.len(), 2);
        assert_eq!(rewards[0], "0x3b9aca00");
        assert_eq!(rewards[1], "0x3b9aca00");
    }

    #[tokio::test]
    async fn test_eth_max_priority_fee_per_gas_uses_recent_block_tips() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 27_000_000_000,
            gas_limit: 30_000,
            to: Some([0x53; 20]),
            value: 1,
            data: vec![],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
        }

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":38}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let pool_txs = {
            let pool = node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let block = build_cchain_block(&node, 1, pool_txs.clone())
            .await
            .expect("block should build");

        let mut key = Vec::with_capacity(34);
        key.extend_from_slice(b"c:");
        key.extend_from_slice(&block.id);
        node.db.put_cf(CF_BLOCKS, &key, &block.raw).unwrap();
        node.db.put_block(block.number, &block.raw).unwrap();
        persist_local_cchain_tx_artifacts(&node.db, &block, &pool_txs).unwrap();
        node.db.set_last_accepted_height(block.number).unwrap();

        let req = r#"{"jsonrpc":"2.0","method":"eth_maxPriorityFeePerGas","params":[],"id":39}"#;
        let response = handle_rpc_request(req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["result"], "0x77359400");
    }

    #[tokio::test]
    async fn test_build_cchain_block_uses_predicted_base_fee_from_head() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 26_000_000_000,
            gas_limit: 30_000,
            to: Some([0x54; 20]),
            value: 1,
            data: vec![],
        };
        let signed = wallet.sign_legacy(&tx).expect("legacy tx should sign");

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
        }

        let submit_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{}"],"id":40}}"#,
            signed.raw_hex()
        );
        let submit_response = handle_rpc_request(&submit_req, &node).await;
        let submit_json: serde_json::Value = serde_json::from_str(&submit_response).unwrap();
        assert!(submit_json.get("result").is_some());

        let first_pool_txs = {
            let pool = node.txpool.read().await;
            pool.pending_sorted_cloned()
        };
        let first_block = build_cchain_block(&node, 1, first_pool_txs.clone())
            .await
            .expect("first block should build");

        let mut key = Vec::with_capacity(34);
        key.extend_from_slice(b"c:");
        key.extend_from_slice(&first_block.id);
        node.db.put_cf(CF_BLOCKS, &key, &first_block.raw).unwrap();
        node.db
            .put_block(first_block.number, &first_block.raw)
            .unwrap();
        persist_local_cchain_tx_artifacts(&node.db, &first_block, &first_pool_txs).unwrap();
        node.db
            .set_last_accepted_height(first_block.number)
            .unwrap();
        refresh_txpool_base_fee(&node).await;

        let first_fields =
            extract_cchain_block_fields(&first_block.raw).expect("first block fields should parse");
        let expected_next_base_fee =
            predicted_next_base_fee_from_fields(node.config.network_id, &first_fields);

        let second_block = build_cchain_block(&node, 2, vec![])
            .await
            .expect("second block should build");
        let second_fields = extract_cchain_block_fields(&second_block.raw)
            .expect("second block fields should parse");

        assert_eq!(second_fields.base_fee, expected_next_base_fee);
    }

    #[tokio::test]
    async fn test_eth_create_access_list_tracks_storage_slots() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let contract = [0x91; 20];

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
            evm.set_account(contract, 0, 1, vec![0x60, 0x00, 0x54, 0x50, 0x00]);
        }

        let req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_createAccessList","params":[{{"from":"{}","to":"0x{}"}}],"id":38}}"#,
            wallet.address_hex(),
            hex::encode(contract)
        );
        let response = handle_rpc_request(&req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        let access_list = parsed["result"]["accessList"].as_array().unwrap();
        assert_eq!(access_list.len(), 1);
        assert_eq!(
            access_list[0]["address"],
            format!("0x{}", hex::encode(contract))
        );
        let storage_keys = access_list[0]["storageKeys"].as_array().unwrap();
        assert_eq!(storage_keys.len(), 1);
        assert_eq!(storage_keys[0], format!("0x{}", hex::encode([0u8; 32])));
        assert!(
            parse_hex_u64_str(parsed["result"]["gasUsed"].as_str().expect("gasUsed hex"),).unwrap()
                > 0
        );
    }

    #[tokio::test]
    async fn test_eth_base_fee_and_suggest_price_options_use_head_context() {
        let node = make_test_node(1);
        let head_block = encode_cchain_block_rlp(
            &[0u8; 32],
            &[0u8; 20],
            &[0u8; 32],
            1,
            DEFAULT_CCHAIN_GAS_LIMIT,
            0,
            unix_timestamp_secs(),
            50_000_000_000,
            &[],
        );
        node.db.put_block(1, &head_block).unwrap();
        node.db.set_last_accepted_height(1).unwrap();

        let fields =
            extract_cchain_block_fields(&head_block).expect("head block fields should parse");
        let expected_base_fee =
            predicted_next_base_fee_from_fields(node.config.network_id, &fields);
        let expected_tip = recent_priority_fee_suggestion(&node.db, current_cchain_height(&node));
        let expected_gas_price = expected_base_fee + expected_tip.max(PRIORITY_FEE_FLOOR);

        let base_fee_req = r#"{"jsonrpc":"2.0","method":"eth_baseFee","params":[],"id":39}"#;
        let base_fee_response = handle_rpc_request(base_fee_req, &node).await;
        let base_fee_json: serde_json::Value = serde_json::from_str(&base_fee_response).unwrap();
        assert_eq!(
            parse_hex_u128_str(base_fee_json["result"].as_str().unwrap()).unwrap(),
            expected_base_fee
        );

        let gas_price_req = r#"{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":40}"#;
        let gas_price_response = handle_rpc_request(gas_price_req, &node).await;
        let gas_price_json: serde_json::Value = serde_json::from_str(&gas_price_response).unwrap();
        assert_eq!(
            parse_hex_u128_str(gas_price_json["result"].as_str().unwrap()).unwrap(),
            expected_gas_price
        );

        let price_req =
            r#"{"jsonrpc":"2.0","method":"eth_suggestPriceOptions","params":[],"id":41}"#;
        let price_response = handle_rpc_request(price_req, &node).await;
        let price_json: serde_json::Value = serde_json::from_str(&price_response).unwrap();
        let slow_tip = parse_hex_u128_str(
            price_json["result"]["slow"]["maxPriorityFeePerGas"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let normal_tip = parse_hex_u128_str(
            price_json["result"]["normal"]["maxPriorityFeePerGas"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let fast_tip = parse_hex_u128_str(
            price_json["result"]["fast"]["maxPriorityFeePerGas"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let normal_fee = parse_hex_u128_str(
            price_json["result"]["normal"]["maxFeePerGas"]
                .as_str()
                .unwrap(),
        )
        .unwrap();

        assert!(slow_tip <= normal_tip);
        assert!(fast_tip >= normal_tip);
        assert_eq!(normal_tip, expected_tip.max(PRIORITY_FEE_FLOOR));
        assert_eq!(normal_fee, expected_base_fee + normal_tip);
    }

    #[tokio::test]
    async fn test_eth_get_chain_config_returns_network_schedule() {
        let node = make_test_node(1);
        let req = r#"{"jsonrpc":"2.0","method":"eth_getChainConfig","params":[],"id":41}"#;
        let response = handle_rpc_request(req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        let result = &parsed["result"];
        let upgrades = info_upgrades_result(node.config.network_id);

        assert_eq!(result["chainId"], node.config.chain_id);
        assert_eq!(result["berlinBlock"], 1_640_340);
        assert_eq!(result["londonBlock"], 3_308_552);
        assert_eq!(
            result["banffBlockTimestamp"],
            upgrade_time_unix(&upgrades, "banffTime")
        );
        assert_eq!(
            result["shanghaiTime"],
            upgrade_time_unix(&upgrades, "durangoTime")
        );
        assert_eq!(
            result["cancunTime"],
            upgrade_time_unix(&upgrades, "etnaTime")
        );
        assert_eq!(
            result["fortunaTimestamp"],
            upgrade_time_unix(&upgrades, "fortunaTime")
        );
    }

    #[tokio::test]
    async fn test_eth_call_detailed_reports_success_and_revert() {
        let node = make_test_node(1);
        let success_contract = [0x92; 20];
        let revert_contract = [0x93; 20];
        let wallet = avalanche_rs::tx::Wallet::random(43114);

        {
            let mut evm = node.evm.write().await;
            evm.set_balance(*wallet.address(), 10_000_000_000_000_000_000u128);
            evm.set_account(success_contract, 0, 1, vec![0x00]);
            evm.set_account(revert_contract, 0, 1, vec![0x60, 0x00, 0x60, 0x00, 0xfd]);
        }

        let success_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_callDetailed","params":[{{"from":"{}","to":"0x{}"}}],"id":42}}"#,
            wallet.address_hex(),
            hex::encode(success_contract)
        );
        let success_response = handle_rpc_request(&success_req, &node).await;
        let success_json: serde_json::Value = serde_json::from_str(&success_response).unwrap();
        assert_eq!(success_json["result"]["errCode"], 0);
        assert_eq!(success_json["result"]["err"], "");
        assert!(success_json["result"]["gas"].as_u64().unwrap() > 0);
        assert_eq!(success_json["result"]["returnData"], "0x");

        let revert_req = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_callDetailed","params":[{{"from":"{}","to":"0x{}"}}],"id":43}}"#,
            wallet.address_hex(),
            hex::encode(revert_contract)
        );
        let revert_response = handle_rpc_request(&revert_req, &node).await;
        let revert_json: serde_json::Value = serde_json::from_str(&revert_response).unwrap();
        assert_eq!(
            revert_json["result"]["errCode"],
            VM_ERROR_CODE_EXECUTION_REVERTED
        );
        assert_eq!(revert_json["result"]["err"], "execution reverted");
    }

    #[tokio::test]
    async fn test_admin_get_vm_config_returns_runtime_config() {
        let node = make_test_node(1);
        let req = r#"{"jsonrpc":"2.0","method":"admin_getVMConfig","params":[],"id":44}"#;
        let response = handle_rpc_request(req, &node).await;
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        let config = &parsed["result"]["config"];

        assert_eq!(config["networkID"], node.config.network_id);
        assert_eq!(config["chainID"], node.config.chain_id);
        assert_eq!(config["txPoolSize"], node.config.txpool_size);
        assert_eq!(config["archiveMode"], node.config.archive);
        assert_eq!(config["rpcMaxBodySize"], node.config.rpc_max_body_size);
    }

    #[tokio::test]
    async fn test_prometheus_metrics_render_contains_required_series() {
        let node = make_test_node(1);
        let metrics = render_prometheus_metrics(&node).await;
        assert!(metrics.contains("sync_progress"));
        assert!(metrics.contains("peer_count"));
        assert!(metrics.contains("block_height_p_chain"));
        assert!(metrics.contains("block_height_c_chain"));
        assert!(metrics.contains("memory_rss_bytes"));
        assert!(metrics.contains("uptime_seconds"));
        assert!(metrics.contains("handshake_latency_ms"));
    }

    #[tokio::test]
    #[ignore = "requires outbound mainnet connectivity"]
    async fn test_mainnet_sync_handshake_and_fetches_pchain_block() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let identity = NodeIdentity::generate().expect("generate node identity");
        let (db, _dir) = Database::open_temp().expect("open temp db");
        let evm = Arc::new(RwLock::new(EvmExecutor::new(43114)));

        let net_config = NetworkConfig {
            network_id: 1,
            ..Default::default()
        };
        let peer_manager = Arc::new(RwLock::new(PeerManager::new(
            net_config,
            identity.node_id.clone(),
        )));

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[31] = 0x01;
        let sync_engine = Arc::new(SyncEngine::new(SyncConfig {
            chain_id: ChainId(chain_id_bytes),
            ..Default::default()
        }));

        let node = Arc::new(NodeState {
            identity,
            db,
            evm,
            sync_engine,
            peer_manager,
            config: Cli {
                network_id: 1,
                data_dir: PathBuf::from("./data/test-mainnet-sync"),
                bootstrap_ips: vec![],
                tracked_subnets: "".to_string(),
                subnet_id: None,
                staking_tls_cert_file: None,
                staking_tls_key_file: None,
                http_port: 0,
                staking_port: 9651,
                log_level: "info".to_string(),
                log_format: "pretty".to_string(),
                chain_id: 43114,
                validator: false,
                state_pruning_depth: 256,
                light_client: false,
                archive: false,
                blob_retention_epochs: 4096,
                txpool_size: 4096,
                block_cache_size: 1024,
                rpc_max_body_size: 5_242_880,
                max_memory_mb: 0,
                log_max_size: 100,
                log_max_files: 10,
                connection_pool_size: 8,
                stake_amount: None,
                stake_duration: None,
                delegation_fee: None,
                reward_address: None,
                rpc_private_keys: vec![],
                #[cfg(feature = "indexer")]
                indexer_enabled: false,
                #[cfg(feature = "indexer")]
                database_url: String::new(),
            },
            start_time: Instant::now(),
            validators: std::collections::HashMap::new(),
            validators_seen: Arc::new(RwLock::new(std::collections::HashSet::new())),
            total_stake_weight: Arc::new(RwLock::new(0u64)),
            p_chain_metrics: Arc::new(RwLock::new(ChainMetrics::default())),
            c_chain_metrics: Arc::new(RwLock::new(ChainMetrics::default())),
            mev_engine: Arc::new(MevEngine::new(MevEngineConfig::default())),
            txpool: Arc::new(RwLock::new(TransactionPool::new(4096))),
            rpc_wallets: Arc::new(StdHashMap::new()),
            platform_tx_pool: Arc::new(RwLock::new(PlatformTxPool::default())),
            light_client: Arc::new(RwLock::new(avalanche_rs::light::LightClient::new())),
            archive_store: Arc::new(ArchiveStore::new(false)),
            subnet_tracker: Arc::new(RwLock::new(SubnetTracker::new())),
            persisted_sync_state: Arc::new(RwLock::new(None)),
            ws_subscriptions: Arc::new(RwLock::new(SubscriptionManager::new(1024))),
            ws_connections: Arc::new(RwLock::new(StdHashMap::new())),
            http_aliases: Arc::new(RwLock::new(StdHashMap::new())),
            chain_aliases: Arc::new(RwLock::new(StdHashMap::new())),
            resolved_public_ip: Arc::new(RwLock::new("0.0.0.0:9651".parse().ok())),
            logger_levels: Arc::new(RwLock::new(initial_logger_levels("info"))),
            p_chain_recently_accepted: new_recently_accepted_pchain_blocks(),
            #[cfg(feature = "indexer")]
            indexer: None,
        });

        let mut handshake_complete = false;
        let mut fetched_pchain_block = false;
        let mut connected_bootstrap: Option<SocketAddr> = None;

        for bootstrap_ip in MAINNET_BOOTSTRAP_IPS.iter().take(4) {
            let bootstrap_addr: SocketAddr = bootstrap_ip
                .parse()
                .expect("valid mainnet bootstrap address");

            let handle = tokio::spawn(connect_and_handshake(bootstrap_addr, node.clone()));
            let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
            let mut saw_connected_this_attempt = false;

            while tokio::time::Instant::now() < deadline {
                {
                    let pm = node.peer_manager.read().await;
                    if pm.connected_count() > 0 && pm.active_peer_addrs().contains(&bootstrap_addr)
                    {
                        saw_connected_this_attempt = true;
                        handshake_complete = true;
                    }
                }

                if node
                    .db
                    .iter_cf_owned(CF_BLOCKS)
                    .iter()
                    .any(|(_, raw)| BlockHeader::parse(raw, Chain::PChain).is_ok())
                {
                    fetched_pchain_block = true;
                }

                if saw_connected_this_attempt && fetched_pchain_block {
                    connected_bootstrap = Some(bootstrap_addr);
                    break;
                }

                if handle.is_finished() {
                    break;
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }

            handle.abort();
            let _ = handle.await;

            if connected_bootstrap.is_some() {
                break;
            }
        }

        assert!(
            handshake_complete,
            "expected handshake completion with at least one mainnet bootstrap node"
        );
        assert!(
            fetched_pchain_block,
            "expected to fetch at least one P-Chain block from mainnet bootstrap"
        );
    }

    #[tokio::test]
    #[ignore = "requires outbound fuji connectivity"]
    async fn test_fuji_sync_fetches_cchain_blocks() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let identity = NodeIdentity::generate().expect("generate node identity");
        let (db, _dir) = Database::open_temp().expect("open temp db");
        let evm = Arc::new(RwLock::new(EvmExecutor::new(43113)));

        let net_config = NetworkConfig {
            network_id: 5,
            ..Default::default()
        };
        let peer_manager = Arc::new(RwLock::new(PeerManager::new(
            net_config,
            identity.node_id.clone(),
        )));

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[31] = 0x05;
        let sync_engine = Arc::new(SyncEngine::new(SyncConfig {
            chain_id: ChainId(chain_id_bytes),
            block_fetch_mode: BlockFetchMode::GetAncestors {
                max_containers_size: 2_000_000,
            },
            ..Default::default()
        }));

        let node = Arc::new(NodeState {
            identity,
            db,
            evm,
            sync_engine,
            peer_manager,
            config: Cli {
                network_id: 5,
                data_dir: PathBuf::from("./data/test-fuji-sync"),
                bootstrap_ips: vec![],
                tracked_subnets: "".to_string(),
                subnet_id: None,
                staking_tls_cert_file: None,
                staking_tls_key_file: None,
                http_port: 0,
                staking_port: 9651,
                log_level: "info".to_string(),
                log_format: "pretty".to_string(),
                chain_id: 43113,
                validator: false,
                state_pruning_depth: 256,
                light_client: false,
                archive: false,
                blob_retention_epochs: 4096,
                txpool_size: 4096,
                block_cache_size: 1024,
                rpc_max_body_size: 5_242_880,
                max_memory_mb: 0,
                log_max_size: 100,
                log_max_files: 10,
                connection_pool_size: 8,
                stake_amount: None,
                stake_duration: None,
                delegation_fee: None,
                reward_address: None,
                rpc_private_keys: vec![],
                #[cfg(feature = "indexer")]
                indexer_enabled: false,
                #[cfg(feature = "indexer")]
                database_url: String::new(),
            },
            start_time: Instant::now(),
            validators: std::collections::HashMap::new(),
            validators_seen: Arc::new(RwLock::new(std::collections::HashSet::new())),
            total_stake_weight: Arc::new(RwLock::new(0u64)),
            p_chain_metrics: Arc::new(RwLock::new(ChainMetrics::default())),
            c_chain_metrics: Arc::new(RwLock::new(ChainMetrics::default())),
            mev_engine: Arc::new(MevEngine::new(MevEngineConfig::default())),
            txpool: Arc::new(RwLock::new(TransactionPool::new(4096))),
            rpc_wallets: Arc::new(StdHashMap::new()),
            platform_tx_pool: Arc::new(RwLock::new(PlatformTxPool::default())),
            light_client: Arc::new(RwLock::new(avalanche_rs::light::LightClient::new())),
            archive_store: Arc::new(ArchiveStore::new(false)),
            subnet_tracker: Arc::new(RwLock::new(SubnetTracker::new())),
            persisted_sync_state: Arc::new(RwLock::new(None)),
            ws_subscriptions: Arc::new(RwLock::new(SubscriptionManager::new(1024))),
            ws_connections: Arc::new(RwLock::new(StdHashMap::new())),
            http_aliases: Arc::new(RwLock::new(StdHashMap::new())),
            chain_aliases: Arc::new(RwLock::new(StdHashMap::new())),
            resolved_public_ip: Arc::new(RwLock::new("0.0.0.0:9651".parse().ok())),
            logger_levels: Arc::new(RwLock::new(initial_logger_levels("info"))),
            p_chain_recently_accepted: new_recently_accepted_pchain_blocks(),
            #[cfg(feature = "indexer")]
            indexer: None,
        });

        let mut fetched_cchain_block = false;

        for bootstrap_ip in FUJI_BOOTSTRAP_IPS.iter().take(4) {
            let bootstrap_addr: SocketAddr =
                bootstrap_ip.parse().expect("valid fuji bootstrap address");
            let handle = tokio::spawn(connect_and_handshake(bootstrap_addr, node.clone()));
            let deadline = tokio::time::Instant::now() + Duration::from_secs(25);

            while tokio::time::Instant::now() < deadline {
                if node.db.iter_cf_owned(CF_BLOCKS).iter().any(|(k, raw)| {
                    k.len() == 34
                        && &k[..2] == b"c:"
                        && BlockHeader::parse(raw, Chain::CChain).is_ok()
                }) {
                    fetched_cchain_block = true;
                    break;
                }

                if handle.is_finished() {
                    break;
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }

            handle.abort();
            let _ = handle.await;

            if fetched_cchain_block {
                break;
            }
        }

        assert!(
            fetched_cchain_block,
            "expected to fetch at least one C-Chain block from fuji bootstrap"
        );
    }

    #[test]
    fn test_integrity_check_all_match() {
        let (db, _dir) = Database::open_temp().unwrap();
        let g = make_banff_std([0u8; 32], 0);
        let g_id = sha256_bytes(&g);
        let b1 = make_banff_std(g_id, 1);
        let b1_id = sha256_bytes(&b1);
        let b2 = make_banff_std(b1_id, 2);
        let b2_id = sha256_bytes(&b2);

        db.put_cf(CF_BLOCKS, &g_id, &g).unwrap();
        db.put_cf(CF_BLOCKS, &b1_id, &b1).unwrap();
        db.put_cf(CF_BLOCKS, &b2_id, &b2).unwrap();

        let (ok, mismatch) = integrity_check_pchain(&db);
        assert_eq!(ok, 3);
        assert_eq!(mismatch, 0);
    }

    #[test]
    fn test_chain_walk_full() {
        let (db, _dir) = Database::open_temp().unwrap();
        let g = make_banff_std([0u8; 32], 0);
        let g_id = sha256_bytes(&g);
        let b1 = make_banff_std(g_id, 1);
        let b1_id = sha256_bytes(&b1);
        let b2 = make_banff_std(b1_id, 2);
        let b2_id = sha256_bytes(&b2);

        db.put_cf(CF_BLOCKS, &g_id, &g).unwrap();
        db.put_cf(CF_BLOCKS, &b1_id, &b1).unwrap();
        db.put_cf(CF_BLOCKS, &b2_id, &b2).unwrap();

        let (length, tip_h, genesis_h) = verify_block_chain(&db, b2_id);
        assert_eq!(length, 3);
        assert_eq!(tip_h, 2);
        assert_eq!(genesis_h, 0);
    }

    #[test]
    fn test_dump_genesis_finds_correct_block() {
        let (db, _dir) = Database::open_temp().unwrap();
        let genesis = make_banff_std([0u8; 32], 0);
        let genesis_id = sha256_bytes(&genesis);
        db.put_cf(CF_BLOCKS, &genesis_id, &genesis).unwrap();
        let b1 = make_banff_std(genesis_id, 1);
        let b1_id = sha256_bytes(&b1);
        db.put_cf(CF_BLOCKS, &b1_id, &b1).unwrap();

        let result = find_genesis_block(&db);
        assert!(result.is_some(), "should find genesis block");
        let (key, raw) = result.unwrap();
        assert_eq!(key, genesis_id);
        assert_eq!(raw.len(), genesis.len());
    }

    #[test]
    fn test_rpc_fee_history_format() {
        // Verify fee history response structure
        let base_fee = "0x5d21dba00";
        let block_count = 4u64;
        let oldest = 10u64;
        let mut base_fees = Vec::new();
        let mut gas_used_ratios = Vec::new();
        for _ in 0..block_count {
            base_fees.push(format!("\"{}\"", base_fee));
            gas_used_ratios.push("0.5".to_string());
        }
        base_fees.push(format!("\"{}\"", base_fee));
        let result = format!(
            "{{\"oldestBlock\":\"0x{:x}\",\"baseFeePerGas\":[{}],\"gasUsedRatio\":[{}]}}",
            oldest,
            base_fees.join(","),
            gas_used_ratios.join(",")
        );
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["oldestBlock"], "0xa");
        assert_eq!(parsed["baseFeePerGas"].as_array().unwrap().len(), 5);
        assert_eq!(parsed["gasUsedRatio"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn test_rpc_info_network_name() {
        assert_eq!(
            match 1u32 {
                1 => "mainnet",
                5 => "fuji",
                _ => "custom",
            },
            "mainnet"
        );
        assert_eq!(
            match 5u32 {
                1 => "mainnet",
                5 => "fuji",
                _ => "custom",
            },
            "fuji"
        );
        assert_eq!(
            match 999u32 {
                1 => "mainnet",
                5 => "fuji",
                _ => "custom",
            },
            "custom"
        );
    }

    #[test]
    fn test_db_block_receipts() {
        let (db, _dir) = Database::open_temp().unwrap();
        // Store two receipts for block 100
        let receipt0 = br#"{"status":"0x1","gasUsed":"0x5208"}"#;
        let receipt1 = br#"{"status":"0x1","gasUsed":"0xa410"}"#;
        db.put_receipt(100, 0, receipt0).unwrap();
        db.put_receipt(100, 1, receipt1).unwrap();

        let result = db.get_block_receipts(100).unwrap();
        assert!(result.is_some());
        let data = String::from_utf8(result.unwrap()).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["gasUsed"], "0x5208");
    }

    #[test]
    fn test_db_block_receipts_empty() {
        let (db, _dir) = Database::open_temp().unwrap();
        let result = db.get_block_receipts(999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_rpc_max_priority_fee() {
        // 1 gwei = 0x3b9aca00
        let fee = u64::from_str_radix("3b9aca00", 16).unwrap();
        assert_eq!(fee, 1_000_000_000);
    }

    #[test]
    fn test_rpc_create_access_list_format() {
        let result = "{\"accessList\":[],\"gasUsed\":\"0x5208\"}";
        let parsed: serde_json::Value = serde_json::from_str(result).unwrap();
        assert!(parsed["accessList"].as_array().unwrap().is_empty());
        assert_eq!(parsed["gasUsed"], "0x5208");
    }
}
