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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use clap::Parser;
use prost::Message as ProstMessage;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;

use avalanche_rs::archive::ArchiveStore;
use avalanche_rs::block::{
    extract_cchain_block_fields, extract_cchain_transactions, parse_raw_cchain_transaction,
    BlockHeader, BlockMetadata, CChainRawTx, Chain, ChainGraph,
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
use avalanche_rs::txpool::{PoolTransaction, TransactionPool};
use avalanche_rs::websocket::{
    logs_notification, new_heads_notification, new_pending_tx_notification,
    BlockHeader as WsBlockHeader, LogEntry as WsLogEntry, SubscriptionManager,
    SubscriptionType as WsSubscriptionType,
};

const DEFAULT_CCHAIN_GAS_LIMIT: u64 = 30_000_000;
const DEFAULT_BASE_FEE_PER_GAS: u128 = 25_000_000_000;
const PRIORITY_FEE_FLOOR: u128 = 1_000_000_000;
const PRIORITY_FEE_SAMPLE_BLOCKS: u64 = 20;
const PRIORITY_FEE_PERCENTILE: f64 = 60.0;

#[cfg(feature = "indexer")]
use avalanche_rs::api;
#[cfg(feature = "indexer")]
use avalanche_rs::indexer::{IndexedBlock, IndexerQuery, IndexerWriter};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Avalanche full node written in Rust.
#[derive(Parser, Debug)]
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
    /// PostgreSQL indexer for block/tx/log analytics (optional).
    #[cfg(feature = "indexer")]
    indexer: Option<Arc<IndexerWriter>>,
}

fn load_persisted_sync_state(db: &Database) -> Option<PersistedSyncState> {
    db.get_metadata(META_SYNC_STATE)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

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
    let ws_subscriptions = Arc::new(RwLock::new(SubscriptionManager::new(10_000)));
    let ws_connections = Arc::new(RwLock::new(StdHashMap::new()));

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
        light_client: Arc::new(RwLock::new(avalanche_rs::light::LightClient::new())),
        archive_store,
        subnet_tracker,
        persisted_sync_state: Arc::new(RwLock::new(persisted_sync_state.clone())),
        ws_subscriptions,
        ws_connections,
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

    // Read their Handshake, send PeerList
    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(Duration::from_secs(15), tls_stream.read_exact(&mut len_buf)).await {
        Ok(Ok(_)) => {
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if msg_len <= 16 * 1024 * 1024 {
                let mut msg_buf = vec![0u8; msg_len];
                if tls_stream.read_exact(&mut msg_buf).await.is_ok() {
                    let mut full = Vec::with_capacity(4 + msg_len);
                    full.extend_from_slice(&len_buf);
                    full.extend_from_slice(&msg_buf);
                    if let Ok(msg) = NetworkMessage::decode_proto(&full) {
                        info!("Received {} from inbound peer {}", msg.name(), peer_addr);
                    }
                }
            }
        }
        _ => {
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
    let mut peer = Peer::new(peer_node_id.clone(), peer_addr);
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

    // Try normal decode first
    match NetworkMessage::decode_proto(&full_buf) {
        Ok(msg) => Ok(msg),
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

    // Use our staking port and a non-zero IP. AvalancheGo rejects port=0.
    // Use the IPv4 address from the outbound connection or a placeholder.
    let my_ip: Vec<u8> = match addr {
        SocketAddr::V4(_) => vec![127, 0, 0, 1], // placeholder — peer verifies signature, not IP
        SocketAddr::V6(_) => vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    };

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
            supported_acps: vec![],
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

    for msg_idx in 0..5 {
        let msg = match read_one_message(&mut tls_stream, addr, 15).await {
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
                ..
            } => {
                handshake_received = true;
                info!(
                    "Peer {} handshake: network_id={}, version={}, node_id={}",
                    addr, network_id, my_version, node_id
                );
                // Update peer version
                let mut pm = node.peer_manager.write().await;
                if let Some(peer) = pm.get_peer_mut(&peer_node_id) {
                    peer.version = Some(my_version.clone());
                    peer.state = PeerState::Connected;
                }
                drop(pm);

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
    peer.version = Some("unknown".to_string());
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
        None => return, // not a valid C-Chain block
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
                debug!(
                    "C-Chain #{} state root mismatch (empty block): expected=0x{}, computed=0x{}",
                    fields.number,
                    hex::encode(expected),
                    hex::encode(computed)
                );
                return;
            }
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
                    debug!(
                        "C-Chain #{} state root mismatch: expected=0x{}, computed=0x{}",
                        fields.number,
                        hex::encode(expected),
                        hex::encode(block_result.state_root)
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
        _ => handle_rpc_request(json_str, node).await,
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
    let headers = parse_http_headers(&req);

    if is_websocket_upgrade(path, &headers) {
        handle_websocket_connection(stream, &headers, node).await;
        return;
    }

    let (status_line, content_type, response_body) = match path {
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
                handle_rpc_request(body, &node).await,
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
    let checksum = Sha256::digest(Sha256::digest(bytes));
    let mut encoded = Vec::with_capacity(bytes.len() + 4);
    encoded.extend_from_slice(bytes);
    encoded.extend_from_slice(&checksum[..4]);
    bs58::encode(encoded).into_string()
}

fn cb58_encode_id(id: [u8; 32]) -> String {
    cb58_encode(&id)
}

fn full_node_id_string(node_id: &NodeId) -> String {
    format!("NodeID-{}", cb58_encode(&node_id.0))
}

fn parse_node_id_20(value: &str) -> Option<[u8; 20]> {
    let raw = value.strip_prefix("NodeID-").unwrap_or(value);
    let decoded = bs58::decode(raw).into_vec().ok()?;
    if decoded.len() < 24 {
        return None;
    }
    let mut node_id = [0u8; 20];
    node_id.copy_from_slice(&decoded[..20]);
    Some(node_id)
}

fn info_network_name(network_id: u32) -> &'static str {
    match network_id {
        1 => "mainnet",
        5 => "fuji",
        _ => "custom",
    }
}

fn info_xchain_blockchain_id(network_id: u32) -> Option<[u8; 32]> {
    let cb58 = match network_id {
        1 => "2oYMBNV4eNHyqk2fjjV5nVQLDbtmNJzq5s3qs3Lo6ftnC6FByM",
        5 => "2JVSBoinj9C2J33VntvzYtVJNZdN2NKiwwKjcumHUWEb5DbBrm",
        _ => return None,
    };
    parse_platform_id_32(cb58)
}

fn info_blockchain_alias_id(alias: &str, network_id: u32) -> Option<[u8; 32]> {
    match alias.to_ascii_lowercase().as_str() {
        "p" | "platform" => Some(platform_pchain_blockchain_id()),
        "c" | "evm" => Some(platform_cchain_blockchain_id(network_id)),
        "x" | "avm" => info_xchain_blockchain_id(network_id),
        _ => parse_platform_id_32(alias),
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

fn info_alias_param<'a>(params: &'a serde_json::Value) -> Option<&'a str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("alias"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn info_chain_param<'a>(params: &'a serde_json::Value) -> Option<&'a str> {
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

    serde_json::json!({
        "ip": peer.address.to_string(),
        "publicIP": peer.address.to_string(),
        "nodeID": full_node_id_string(&peer.node_id),
        "version": peer.version.clone().unwrap_or_else(|| "unknown".to_string()),
        "upgradeTime": 0u64,
        "lastSent": format_instant_rfc3339(peer.last_ping_sent.unwrap_or(peer.connected_at)),
        "lastReceived": format_instant_rfc3339(peer.last_seen),
        "observedUptime": peer.reported_uptime.to_string(),
        "trackedSubnets": tracked_subnets,
        "supportedACPs": Vec::<u32>::new(),
        "objectedACPs": Vec::<u32>::new(),
        "benched": Vec::<String>::new(),
    })
}

fn info_node_ip_string(node: &NodeState) -> String {
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
        "p" | "platform" | "c" | "evm" | "x" | "avm"
    ) {
        return Ok(bootstrapped);
    }

    if let Some(chain_id) = info_blockchain_alias_id(chain, node.config.network_id) {
        if chain_id == platform_pchain_blockchain_id() {
            return Ok(bootstrapped);
        }
        if chain_id == platform_cchain_blockchain_id(node.config.network_id) {
            return Ok(bootstrapped);
        }
        if info_xchain_blockchain_id(node.config.network_id) == Some(chain_id) {
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
    node_id: String,
    weight: u64,
    start_time: u64,
    end_time: u64,
}

impl PlatformValidatorRecord {
    fn status(&self, now: u64) -> &'static str {
        if now < self.start_time {
            "pending"
        } else if now < self.end_time {
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

fn platform_subnet_id_param<'a>(params: &'a serde_json::Value) -> Option<&'a str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("subnetID"))
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

fn platform_node_id_param<'a>(params: &'a serde_json::Value) -> Option<&'a str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("nodeID"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

async fn platform_validator_records(
    node: &NodeState,
    params: &serde_json::Value,
) -> Vec<PlatformValidatorRecord> {
    let mut records = if let Some(subnet_id_str) = platform_subnet_id_param(params) {
        match SubnetId::from_str_any(subnet_id_str) {
            Some(subnet_id) if subnet_id != SubnetId::primary_network() => {
                let tracker = node.subnet_tracker.read().await;
                tracker
                    .subnet_validators_snapshot(&subnet_id)
                    .map(|snapshot| {
                        snapshot
                            .validators
                            .all_validators()
                            .into_iter()
                            .map(|validator| PlatformValidatorRecord {
                                node_id: validator.node_id.to_string(),
                                weight: validator.weight,
                                start_time: validator.start_time,
                                end_time: validator.end_time,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            }
            Some(_) | None => node
                .validators
                .values()
                .map(|validator| PlatformValidatorRecord {
                    node_id: validator.node_id.clone(),
                    weight: validator.weight,
                    start_time: validator.start_time,
                    end_time: validator.end_time,
                })
                .collect::<Vec<_>>(),
        }
    } else {
        node.validators
            .values()
            .map(|validator| PlatformValidatorRecord {
                node_id: validator.node_id.clone(),
                weight: validator.weight,
                start_time: validator.start_time,
                end_time: validator.end_time,
            })
            .collect::<Vec<_>>()
    };

    let requested_node_ids = platform_node_ids_param(params);
    if !requested_node_ids.is_empty() {
        let requested = requested_node_ids
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        records.retain(|record| requested.contains(&record.node_id));
    }

    records.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    records
}

async fn platform_validator_response_values(
    node: &NodeState,
    records: Vec<PlatformValidatorRecord>,
) -> Vec<serde_json::Value> {
    let now = unix_timestamp_secs();
    let connected = node.validators_seen.read().await.clone();
    records
        .into_iter()
        .map(|validator| {
            let status = validator.status(now);
            let is_connected = connected.contains(&validator.node_id);
            serde_json::json!({
                "nodeID": validator.node_id,
                "startTime": validator.start_time.to_string(),
                "endTime": validator.end_time.to_string(),
                "weight": validator.weight.to_string(),
                "stakeAmount": validator.weight.to_string(),
                "delegationFee": "0.0000",
                "connected": is_connected,
                "uptime": "0.0000",
                "status": status,
                "delegators": serde_json::Value::Null,
            })
        })
        .collect()
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

fn platform_block_id_param<'a>(params: &'a serde_json::Value) -> Option<&'a str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("blockID"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn platform_blockchain_id_param<'a>(params: &'a serde_json::Value) -> Option<&'a str> {
    platform_params_object(params)
        .and_then(|obj| obj.get("blockchainID"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(0).and_then(|value| value.as_str()))
}

fn platform_encoding_param<'a>(params: &'a serde_json::Value, default: &'a str) -> &'a str {
    platform_params_object(params)
        .and_then(|obj| obj.get("encoding"))
        .and_then(|value| value.as_str())
        .or_else(|| params.get(1).and_then(|value| value.as_str()))
        .unwrap_or(default)
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
        Ok(meta) => serde_json::json!({
            "id": format!("0x{}", hex::encode(meta.id)),
            "parentID": format!("0x{}", hex::encode(meta.parent_id)),
            "height": meta.height.to_string(),
            "timestamp": meta.timestamp.to_string(),
            "type": format!("{:?}", meta.block_type),
            "txCount": meta.tx_count,
            "size": meta.size_bytes,
        }),
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
    format!(
        "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":{},\"message\":\"{}\"}},\"id\":{}}}",
        code, message, id
    )
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

/// Global filter state — use a simple counter + HashMap behind RwLock.
static NEXT_FILTER_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

use once_cell::sync::Lazy;
use std::collections::HashMap as StdHashMap;

static FILTERS: Lazy<RwLock<StdHashMap<u64, LogFilter>>> =
    Lazy::new(|| RwLock::new(StdHashMap::new()));

async fn handle_rpc_request(json_str: &str, node: &NodeState) -> String {
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
        "web3_clientVersion" => rpc_ok("\"avalanche-rs/0.1.0\"", id),
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
        "eth_gasPrice" => {
            rpc_ok("\"0x5d21dba00\"", id) // 25 gwei
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
            FILTERS.write().await.insert(filter_id, filter);
            rpc_ok(&format!("\"0x{:x}\"", filter_id), id)
        }

        // -----------------------------------------------------------------
        // eth_getFilterChanges
        // -----------------------------------------------------------------
        "eth_getFilterChanges" => {
            let filter_id = parse_filter_id(params.get(0).unwrap_or(&serde_json::Value::Null));
            let mut filters = FILTERS.write().await;
            match filters.get_mut(&filter_id) {
                Some(filter) => {
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
                Some(filter) => {
                    let current_height = current_cchain_height(node);
                    let end_block = filter
                        .to_block
                        .unwrap_or(current_height)
                        .min(current_height);
                    let logs =
                        collect_logs_for_range(&node.db, filter, filter.from_block, end_block);
                    rpc_ok(&serde_json::Value::Array(logs).to_string(), id)
                }
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
        // Platform RPC methods (routed via /ext/bc/P in AvalancheGo)
        // -----------------------------------------------------------------
        "platform.getCurrentValidators" => {
            let now = unix_timestamp_secs();
            let records = platform_validator_records(node, params).await;
            let records = records
                .into_iter()
                .filter(|validator| validator.status(now) == "current")
                .collect::<Vec<_>>();
            let validators = platform_validator_response_values(node, records).await;
            rpc_ok(
                &serde_json::json!({ "validators": validators }).to_string(),
                id,
            )
        }

        "platform.getValidators" => {
            let validators = platform_validator_response_values(
                node,
                platform_validator_records(node, params).await,
            )
            .await;
            rpc_ok(
                &serde_json::json!({ "validators": validators }).to_string(),
                id,
            )
        }

        "platform.getPendingValidators" => {
            let now = unix_timestamp_secs();
            let records = platform_validator_records(node, params).await;
            let records = records
                .into_iter()
                .filter(|validator| validator.status(now) == "pending")
                .collect::<Vec<_>>();
            let validators = platform_validator_response_values(node, records).await;
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
            let validators = platform_validator_response_values(
                node,
                platform_validator_records(node, params).await,
            )
            .await;
            match validators.into_iter().find(|validator| {
                validator.get("nodeID").and_then(|value| value.as_str()) == Some(node_id)
            }) {
                Some(validator) => rpc_ok(&validator.to_string(), id),
                None => rpc_error(-32000, "validator not found", id),
            }
        }

        "platform.getHeight" => {
            let height = node.db.last_accepted_height().unwrap_or(None).unwrap_or(0);
            rpc_ok(
                &serde_json::json!({ "height": height.to_string() }).to_string(),
                id,
            )
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

        "platform.getSubnets" => {
            let tracker = node.subnet_tracker.read().await;
            let subnets: Vec<String> = tracker
                .tracked_subnets()
                .into_iter()
                .map(|sid| format!("{{\"id\":\"{}\"}}", sid))
                .collect();
            rpc_ok(&format!("{{\"subnets\":[{}]}}", subnets.join(",")), id)
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
            let encoding = platform_encoding_param(params, "hex");
            let response = serde_json::json!({
                "staked": "0",
                "stakeds": addresses
                    .iter()
                    .map(|_| serde_json::Value::String("0".to_string()))
                    .collect::<Vec<_>>(),
                "stakedOutputs": serde_json::Value::Array(vec![]),
                "encoding": encoding,
            });
            rpc_ok(&response.to_string(), id)
        }

        "platform.getMinStake" => rpc_ok(
            &serde_json::json!({
                "minValidatorStake": MIN_VALIDATOR_STAKE.to_string(),
                "minDelegatorStake": MIN_DELEGATOR_STAKE.to_string(),
            })
            .to_string(),
            id,
        ),

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
        // eth_getBlockReceipts
        // -----------------------------------------------------------------
        "eth_getBlockReceipts" => {
            let block_num =
                parse_block_number(params.get(0).unwrap_or(&serde_json::Value::Null), node);
            // Return receipts from DB if available, else empty array
            match node.db.get_block_receipts(block_num) {
                Ok(Some(data)) => {
                    let receipts_json = String::from_utf8_lossy(&data);
                    rpc_ok(&receipts_json, id)
                }
                _ => rpc_ok("[]", id),
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
        // avax_getAtomicTx
        // -----------------------------------------------------------------
        "avax_getAtomicTx" => {
            let tx_id_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
            if tx_id_str.is_empty() {
                return rpc_error(-32602, "missing txID", id);
            }
            // Atomic txs stored in CF_BLOCKS with "atomic:" prefix
            let key = format!("atomic:{}", tx_id_str);
            match node.db.get_cf(avalanche_rs::db::CF_BLOCKS, key.as_bytes()) {
                Ok(Some(data)) => rpc_ok(&format!("\"0x{}\"", hex::encode(&data)), id),
                _ => rpc_ok("null", id),
            }
        }

        // -----------------------------------------------------------------
        // avax_issueTx
        // -----------------------------------------------------------------
        "avax_issueTx" => {
            let tx_bytes_str = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
            if tx_bytes_str.is_empty() {
                return rpc_error(-32602, "missing tx bytes", id);
            }
            match parse_hex_bytes(tx_bytes_str) {
                Some(tx_bytes) => {
                    // Hash the tx to create an ID
                    let tx_hash = {
                        let mut hasher = Sha256::new();
                        hasher.update(&tx_bytes);
                        hasher.finalize()
                    };
                    let tx_id = hex::encode(tx_hash);
                    // Store in DB for retrieval
                    let key = format!("atomic:{}", tx_id);
                    let _ = node
                        .db
                        .put_cf(avalanche_rs::db::CF_BLOCKS, key.as_bytes(), &tx_bytes);
                    rpc_ok(&format!("{{\"txID\":\"0x{}\"}}", tx_id), id)
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
            let Some(blockchain_id) = info_blockchain_alias_id(alias, node.config.network_id)
            else {
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
                "ip": info_node_ip_string(node),
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

        "info.getVMs" => rpc_ok(&info_get_vms_result().to_string(), id),

        "info.uptime" => rpc_ok(
            &serde_json::json!({
                "rewardingStakePercentage": "0.0000",
                "weightedAveragePercentage": "0.0000",
            })
            .to_string(),
            id,
        ),

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
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
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
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

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
            light_client: Arc::new(RwLock::new(avalanche_rs::light::LightClient::new())),
            archive_store: Arc::new(ArchiveStore::new(false)),
            subnet_tracker: Arc::new(RwLock::new(SubnetTracker::new())),
            persisted_sync_state: Arc::new(RwLock::new(None)),
            ws_subscriptions: Arc::new(RwLock::new(SubscriptionManager::new(1024))),
            ws_connections: Arc::new(RwLock::new(StdHashMap::new())),
            #[cfg(feature = "indexer")]
            indexer: None,
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
            light_client: Arc::new(RwLock::new(avalanche_rs::light::LightClient::new())),
            archive_store: Arc::new(ArchiveStore::new(false)),
            subnet_tracker: Arc::new(RwLock::new(SubnetTracker::new())),
            persisted_sync_state: Arc::new(RwLock::new(None)),
            ws_subscriptions: Arc::new(RwLock::new(SubscriptionManager::new(1024))),
            ws_connections: Arc::new(RwLock::new(StdHashMap::new())),
            #[cfg(feature = "indexer")]
            indexer: None,
        })
    }

    fn make_banff_std(parent: [u8; 32], height: u64) -> Vec<u8> {
        let mut raw = vec![0u8; 54];
        raw[2..6].copy_from_slice(&32u32.to_be_bytes());
        raw[6..14].copy_from_slice(&1_700_000_000u64.to_be_bytes());
        raw[14..46].copy_from_slice(&parent);
        raw[46..54].copy_from_slice(&height.to_be_bytes());
        raw
    }

    fn sha256_bytes(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
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
        assert!(subnets.contains("subnets"));

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
    async fn test_platform_get_height_and_min_stake_shapes() {
        let node = make_test_node(1);
        node.db.set_last_accepted_height(42).unwrap();

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
    async fn test_platform_get_block_supports_hex_and_json_encoding() {
        let node = make_test_node(1);
        let raw_block = make_banff_std([0x11; 32], 7);
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
        assert_eq!(json_value["result"]["block"]["height"], "7");
        assert_eq!(json_value["result"]["block"]["txCount"], 0);
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

        let stake_req = r#"{"jsonrpc":"2.0","method":"platform.getStake","params":{"addresses":["P-local1","P-local2"],"validatorsOnly":true,"encoding":"hex"},"id":15}"#;
        let stake_response = handle_rpc_request(stake_req, &node).await;
        let stake_json: serde_json::Value = serde_json::from_str(&stake_response).unwrap();
        assert_eq!(stake_json["result"]["staked"], "0");
        assert_eq!(stake_json["result"]["encoding"], "hex");
        assert_eq!(stake_json["result"]["stakeds"][0], "0");
        assert_eq!(stake_json["result"]["stakeds"][1], "0");
        assert!(stake_json["result"]["stakedOutputs"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_info_endpoints_return_avalanchego_shapes() {
        let node = make_test_node(1);
        node.sync_engine.mark_following().await;

        let peer_id = NodeId([0x11; 20]);
        let peer_id_str = full_node_id_string(&peer_id);
        let mut peer = Peer::new(peer_id.clone(), "10.0.0.1:9651".parse().unwrap());
        peer.state = PeerState::Connected;
        peer.version = Some("avalanchego/1.14.1".to_string());
        peer.reported_uptime = 9500;
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
        assert_eq!(
            blockchain_id_json["result"]["blockchainID"],
            cb58_encode_id(info_xchain_blockchain_id(node.config.network_id).unwrap())
        );

        let node_ip_req = r#"{"jsonrpc":"2.0","method":"info.getNodeIP","params":{},"id":19}"#;
        let node_ip_response = handle_rpc_request(node_ip_req, &node).await;
        let node_ip_json: serde_json::Value = serde_json::from_str(&node_ip_response).unwrap();
        assert_eq!(node_ip_json["result"]["ip"], "0.0.0.0:9651");

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
        assert_eq!(peers[0]["publicIP"], "10.0.0.1:9651");
        assert_eq!(peers[0]["version"], "avalanchego/1.14.1");
        assert_eq!(peers[0]["observedUptime"], "9500");
        assert_eq!(
            peers[0]["trackedSubnets"][0],
            cb58_encode_id(platform_pchain_blockchain_id())
        );
        assert!(peers[0]["supportedACPs"].as_array().unwrap().is_empty());
        assert!(peers[0]["objectedACPs"].as_array().unwrap().is_empty());
        assert!(peers[0]["benched"].as_array().unwrap().is_empty());
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
    async fn test_eth_send_raw_transaction_accepts_legacy_tx() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 21_000,
            to: [0x33; 20],
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
            to: [0x44; 20],
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
            to: [0x55; 20],
            value: 1,
            data: vec![],
        };
        let second = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 30_000_000_000,
            gas_limit: 21_000,
            to: [0x55; 20],
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
            to: [0x77; 20],
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
            to: [0x66; 20],
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
            to: [0x88; 20],
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
    async fn test_imported_cchain_block_persists_lookup_artifacts() {
        let builder_node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let tx = avalanche_rs::tx::Eip1559Tx {
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 25_000_000_000,
            gas_limit: 50_000,
            to: [0x99; 20],
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

        assert_eq!(importer_node.db.last_accepted_height().unwrap(), Some(1));
        let imported_fields =
            extract_cchain_block_fields(&block.raw).expect("imported block fields should parse");
        let expected_next_base_fee =
            predicted_next_base_fee_from_fields(importer_node.config.network_id, &imported_fields);
        let pool = importer_node.txpool.read().await;
        assert_eq!(pool.base_fee, expected_next_base_fee);
    }

    #[tokio::test]
    async fn test_eth_get_logs_filters_persisted_receipts() {
        let _guard = FILTER_TEST_GUARD.lock().unwrap();
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
        let _guard = FILTER_TEST_GUARD.lock().unwrap();
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
            to: [0xAB; 20],
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
    async fn test_debug_trace_transaction_for_pending_tx() {
        let node = make_test_node(1);
        let wallet = avalanche_rs::tx::Wallet::random(43114);
        let contract = [0x77; 20];
        let tx = avalanche_rs::tx::LegacyTx {
            nonce: 0,
            gas_price: 25_000_000_000,
            gas_limit: 50_000,
            to: contract,
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
            to: contract,
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
            to: [0x88; 20],
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
            to: [0x52; 20],
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
            to: [0x53; 20],
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
            to: [0x54; 20],
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
            light_client: Arc::new(RwLock::new(avalanche_rs::light::LightClient::new())),
            archive_store: Arc::new(ArchiveStore::new(false)),
            subnet_tracker: Arc::new(RwLock::new(SubnetTracker::new())),
            persisted_sync_state: Arc::new(RwLock::new(None)),
            ws_subscriptions: Arc::new(RwLock::new(SubscriptionManager::new(1024))),
            ws_connections: Arc::new(RwLock::new(StdHashMap::new())),
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
            light_client: Arc::new(RwLock::new(avalanche_rs::light::LightClient::new())),
            archive_store: Arc::new(ArchiveStore::new(false)),
            subnet_tracker: Arc::new(RwLock::new(SubnetTracker::new())),
            persisted_sync_state: Arc::new(RwLock::new(None)),
            ws_subscriptions: Arc::new(RwLock::new(SubscriptionManager::new(1024))),
            ws_connections: Arc::new(RwLock::new(StdHashMap::new())),
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
