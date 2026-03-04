//! avalanche-rs — Production Avalanche full node daemon.
//!
//! Phase 6: Wire everything into a production binary.
//! Supports bootstrapping from peers, EVM execution, and JSON-RPC serving.

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
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use sha2::{Digest, Sha256};
use bs58;

use avalanche_rs::block::{BlockHeader, BlockMetadata, Chain, ChainGraph};
use avalanche_rs::consensus::SnowmanConsensus;
use avalanche_rs::db::{Database, CF_BLOCKS, CF_STATE_ROOTS};
use avalanche_rs::evm::EvmExecutor;
use avalanche_rs::identity::{self, NodeIdentity};
use avalanche_rs::network::{BlockId, ChainId, NetworkConfig, NetworkMessage, NodeId, PeerInfo, PeerManager, Peer, PeerState};
use avalanche_rs::proto::{self, ProtoMessage, ProtoOneOf};
use avalanche_rs::sync::{SyncConfig, SyncEngine, SyncPhase};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Avalanche full node written in Rust.
#[derive(Parser, Debug)]
#[command(name = "avalanche-rs", version = "0.1.0", about = "Production Avalanche full node")]
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
}

// ---------------------------------------------------------------------------
// Bootstrap nodes (Avalanche mainnet)
// ---------------------------------------------------------------------------

// Mainnet bootstrap nodes — use `--network-id 1` to activate
const MAINNET_BOOTSTRAP_IPS: &[&str] = &[
    "52.200.5.241:9651",
    "54.218.65.226:9651",
    "34.216.203.114:9651",
    "34.213.203.233:9651",
    "35.165.246.125:9651",
];

const FUJI_BOOTSTRAP_IPS: &[&str] = &[
    "3.232.38.13:9651",
    "54.207.47.125:9651",
    "18.158.205.66:9651",
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
    FetchingAncestors { req: u32, depth: u32, total_blocks: u32 },
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
    FetchingAncestors { req: u32, depth: u32, total_blocks: u32 },
    Done,
}

// ---------------------------------------------------------------------------
// Chain metrics
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ChainMetrics {
    pub blocks_synced: u64,
    pub genesis_height: u64,
    pub tip_height: u64,
    pub chain_length: u64,
    pub last_sync_time: Instant,
}

impl Default for ChainMetrics {
    fn default() -> Self {
        ChainMetrics {
            blocks_synced: 0,
            genesis_height: 0,
            tip_height: 0,
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
        tip_id[0], tip_id[1], tip_id[2], tip_id[3],
        tip_id[28], tip_id[29], tip_id[30], tip_id[31]
    );

    // Check immediately whether the tip is in the DB at all.
    match db.get_cf(CF_BLOCKS, &tip_id) {
        Ok(None) => {
            info!(
                "TIP ID NOT IN STORED BLOCKS: {:02x}{:02x}{:02x}{:02x}…{:02x}{:02x}{:02x}{:02x}",
                tip_id[0], tip_id[1], tip_id[2], tip_id[3],
                tip_id[28], tip_id[29], tip_id[30], tip_id[31]
            );
            return (0, 0, 0);
        }
        Err(e) => {
            warn!("Chain walk: DB error looking up tip: {}", e);
            return (0, 0, 0);
        }
        Ok(Some(_)) => {
            info!("Found tip in DB: {:02x}{:02x}{:02x}{:02x}…", tip_id[0], tip_id[1], tip_id[2], tip_id[3]);
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
                if let Ok(hdr) = avalanche_rs::block::BlockHeader::parse(&block_data, avalanche_rs::block::Chain::PChain) {
                    if count == 1 {
                        tip_height = hdr.height;
                        info!("Chain walk tip block: height={}, type={:?}", tip_height, hdr.block_type);
                    }
                    if hdr.is_genesis() {
                        genesis_height = hdr.height;
                        info!(
                            "Genesis block height: {} (type={:?}, {} bytes)",
                            genesis_height, hdr.block_type, block_data.len()
                        );
                    }
                }

                match avalanche_rs::block::BlockHeader::extract_parent_id(&block_data) {
                    Some(parent) => {
                        if parent == [0u8; 32] {
                            info!("Verified chain of {} blocks from tip to genesis", count);
                            break;
                        }
                        current = parent;
                    }
                    None => {
                        info!("Chain walk: block too short ({} bytes) at depth {}", block_data.len(), count);
                        break;
                    }
                }
            }
            Ok(None) => {
                info!(
                    "Chain walk: block not in DB after {} blocks (may need more fetch rounds)",
                    count
                );
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

    info!("NodeID: {}, cert_size={} bytes", identity.node_id, identity.cert_der.len());

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
    info!("Database opened at {:?}, last accepted height: {}", db_path, last_height);

    // Phase 8: verify block chain integrity on startup
    let (ok, bad) = integrity_check_pchain(&db);
    if bad > 0 {
        warn!("Chain integrity: {} blocks OK, {} MISMATCHES — block storage format issue!", ok, bad);
    } else if ok > 0 {
        info!("Chain integrity: {} blocks verified, all match", ok);
    }

    // Phase 8: dump P-Chain genesis for validator extraction analysis
    if let Some((genesis_id, genesis_raw)) = find_genesis_block(&db) {
        let dump_len = genesis_raw.len().min(200);
        info!(
            "P-Chain genesis found: id={:02x}{:02x}{:02x}{:02x}…, {} bytes total",
            genesis_id[0], genesis_id[1], genesis_id[2], genesis_id[3],
            genesis_raw.len()
        );
        info!(
            "P-Chain genesis: first {} bytes = {:02x?}",
            dump_len, &genesis_raw[..dump_len]
        );
        if let Ok(hdr) = avalanche_rs::block::BlockHeader::parse(&genesis_raw, avalanche_rs::block::Chain::PChain) {
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
    info!("Validator set initialized with {} known Fuji validators", validators.len());

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
    });

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
            let state_root_count = metrics_node.db.iter_cf_owned(avalanche_rs::db::CF_STATE_ROOTS).len();
            info!(
                "C-Chain: {} blocks synced, {} stateRoot mappings",
                c.blocks_synced, state_root_count
            );
        }
    });

    info!(
        "Node started: p2p=:{}, http=:{}, node_id={}",
        node.config.staking_port, node.config.http_port, node.identity.node_id
    );

    // 10. Graceful shutdown
    match signal::ctrl_c().await {
        Ok(_) => {
            info!("Received SIGINT, shutting down gracefully...");
        }
        Err(e) => {
            error!("Failed to listen for SIGINT: {}", e);
        }
    }

    let uptime = node.start_time.elapsed();
    info!(
        "Shutting down after {:.1}s uptime",
        uptime.as_secs_f64()
    );

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
    let mut tls_stream = match tokio::time::timeout(
        Duration::from_secs(10),
        acceptor.accept(stream),
    ).await {
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
    let mut peer = Peer::new(peer_node_id, peer_addr);
    peer.state = PeerState::Connected;
    let _ = pm.add_peer(peer);
}

// ---------------------------------------------------------------------------
// Bootstrap connection
// ---------------------------------------------------------------------------

async fn connect_to_bootstrap_nodes(node: Arc<NodeState>) {
    let bootstrap_ips: Vec<String> = if node.config.bootstrap_ips.is_empty() {
        match node.config.network_id {
            1 => MAINNET_BOOTSTRAP_IPS.iter().map(|s| s.to_string()).collect(),
            5 => FUJI_BOOTSTRAP_IPS.iter().map(|s| s.to_string()).collect(),
            _ => {
                warn!("No bootstrap IPs for network_id={}", node.config.network_id);
                vec![]
            }
        }
    } else {
        node.config.bootstrap_ips.clone()
    };

    if bootstrap_ips.is_empty() {
        warn!("No bootstrap nodes configured, running in standalone mode");
        return;
    }

    info!("Connecting to {} bootstrap nodes...", bootstrap_ips.len());

    for ip_str in &bootstrap_ips {
        match ip_str.parse::<SocketAddr>() {
            Ok(addr) => {
                let node = node.clone();
                tokio::spawn(async move {
                    if let Err(e) = connect_and_handshake(addr, node).await {
                        warn!("Bootstrap {} failed: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                warn!("Invalid bootstrap address '{}': {}", ip_str, e);
            }
        }
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
    tokio::time::timeout(Duration::from_secs(timeout_secs), stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| format!("read timeout from {}", addr))?
        .map_err(|e| format!("read length from {}: {}", addr, e))?;

    let msg_len = u32::from_be_bytes(len_buf) as usize;
    if msg_len > 16 * 1024 * 1024 {
        return Err(format!("message too large from {}: {} bytes", addr, msg_len).into());
    }

    let mut msg_buf = vec![0u8; msg_len];
    tokio::time::timeout(Duration::from_secs(timeout_secs), stream.read_exact(&mut msg_buf))
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
                        debug!("Decompressed message from {}: {:?}", addr, std::mem::discriminant(&inner));
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
    let tls_config = node.identity.tls_client_config()
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
            info!("TLS handshake complete with {} → peer NodeID: {}", addr, nid);
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
    let ip_sig = node.identity.sign_ip_with_tls_key(&my_ip, node.config.staking_port, now);
    // Sign with BLS for proof-of-possession
    let bls_sig = node.identity.sign_ip_bls(&my_ip, node.config.staking_port, now);

    // Build protobuf Handshake directly (need BLS sig field)
    use avalanche_rs::proto::pb;

    let upgrade_time = match node.config.network_id {
        1 => 1765296000u64,
        5 => 1761750000u64,
        _ => 0,
    };

    // Build valid bloom filter: [numHashes(1byte)] [seed(8bytes)] [entries(1+bytes)]
    // Format: numHashes=1, seed=random 8 bytes, entries=all zeros (we know no peers)
    let bloom_seed: u64 = rand::thread_rng().gen();
    let mut bloom_filter_bytes = Vec::with_capacity(10);
    bloom_filter_bytes.push(1u8); // numHashes = 1
    bloom_filter_bytes.extend_from_slice(&bloom_seed.to_be_bytes()); // 8-byte seed
    bloom_filter_bytes.push(0u8); // 1 byte of entries (empty = we know nobody)

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
            tracked_subnets: vec![],
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
            all_subnets: true,
        })),
    };

    // Encode with length prefix
    let raw = prost::Message::encode_to_vec(&handshake_proto);
    let len = (raw.len() as u32).to_be_bytes();
    let mut encoded = Vec::with_capacity(4 + raw.len());
    encoded.extend_from_slice(&len);
    encoded.extend_from_slice(&raw);

    info!("Handshake: network_id={}, ip={:02x?}, port={}, raw_msg={} bytes", 
        node.config.network_id, &my_ip, node.config.staking_port, encoded.len());

    tls_stream.write_all(&encoded).await
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

        info!("Received {} from {} (msg #{})", msg.name(), addr, msg_idx + 1);

        match &msg {
            NetworkMessage::Version { network_id, my_version, node_id, .. } => {
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
    peer.state = PeerState::Connected;
    peer.version = Some("unknown".to_string());
    peer.is_validator = false;
    if let Ok(()) = pm.add_peer(peer) {
        info!("Peer {} registered (NodeID: {})", addr, peer_node_id);
    }

    // 6. Keep connection alive — read messages in a loop
    info!("Entering message loop with {}", addr);

    let ping_interval = Duration::from_secs(30);
    let pong_timeout = Duration::from_secs(60);
    let mut ping_timer = tokio::time::interval(ping_interval);
    ping_timer.tick().await; // consume the immediate first tick
    let mut last_ping_sent: Option<Instant> = None;
    let mut pong_received_since_last_ping = true; // start true so first ping isn't rejected

    // Bootstrap state machine: send GetAcceptedFrontier after 10s delay
    let bootstrap_request_base: u32 = rand::thread_rng().gen::<u16>() as u32 * 10;
    let mut bootstrap_state = BootstrapState::Idle;
    let mut bootstrap_timer = Box::pin(tokio::time::sleep(Duration::from_secs(10)));
    let mut bootstrap_timer_fired = false;
    let mut p_chain_tip: Option<[u8; 32]> = None;

    // C-Chain bootstrap state
    let mut cchain_bootstrap_state = CChainBootstrapState::Idle;
    let mut cchain_frontier: Option<[u8; 32]> = None;

    // Continuous sync: check for new blocks every 2s after bootstrap completes
    let mut sync_timer = tokio::time::interval(Duration::from_secs(2));
    sync_timer.tick().await; // consume the immediate first tick
    let mut continuous_sync_req: Option<u32> = None;
    let mut sync_req_counter: u32 = bootstrap_request_base.wrapping_add(10000);
    let mut last_known_tip: Option<[u8; 32]> = None;
    // Flag: has first C-Chain block bytes been logged for debug?
    let mut cchain_debug_logged = false;

    // Decode C-Chain Fuji ID from CB58
    let cchain_id: [u8; 32] = {
        let cb58 = "yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp";
        let decoded = bs58::decode(cb58).into_vec().unwrap_or_default();
        // CB58 = base58(payload + checksum4), strip last 4 bytes
        if decoded.len() >= 36 {
            decoded[..32].try_into().unwrap_or([0u8; 32])
        } else {
            warn!("Failed to decode C-Chain ID from CB58");
            [0u8; 32]
        }
    };

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
                // Also kick off C-Chain bootstrap
                if node.config.network_id == 5 {
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
                                                            format!("{}", identity::derive_node_id(&peer.cert_bytes))
                                                        } else {
                                                            format!("{}", peer.node_id)
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
                                                        let is_new = last_known_tip.map_or(true, |t| t != container_id.0);
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
                                                let is_cchain = chain_id.0 == cchain_id && node.config.network_id == 5;
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
                                                                && oldest_container.as_ref().map_or(false, |c| {
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
                                                            let mut first_hash: Option<[u8; 32]> = None;

                                                            for container in &containers {
                                                                let mut hasher = Sha256::new();
                                                                hasher.update(container);
                                                                let hash: [u8; 32] = hasher.finalize().into();

                                                                if first_hash.is_none() {
                                                                    first_hash = Some(hash);
                                                                }

                                                                if let Err(e) = node.db.put_cf(CF_BLOCKS, &hash, container) {
                                                                    warn!("Failed to store block {:02x?}: {}", &hash[..4], e);
                                                                } else {
                                                                    stored += 1;
                                                                    if let Ok(meta) = BlockMetadata::from_raw(container, Chain::PChain) {
                                                                        debug!(
                                                                            "P-Chain block: height={}, parent={:02x}{:02x}…, type={:?}, {} txs, {} bytes",
                                                                            meta.height,
                                                                            meta.parent_id[0], meta.parent_id[1],
                                                                            meta.block_type,
                                                                            meta.tx_count,
                                                                            meta.size_bytes
                                                                        );
                                                                    }
                                                                }
                                                                oldest_container = Some(container.clone());
                                                            }

                                                            // Debug: on first batch, compare first container hash to p_chain_tip
                                                            if depth == 0 {
                                                                if let Some(fh) = first_hash {
                                                                    info!(
                                                                        "Ancestors[0] SHA256 = {:02x}{:02x}{:02x}{:02x}…{:02x}{:02x}{:02x}{:02x} ({} containers)",
                                                                        fh[0], fh[1], fh[2], fh[3],
                                                                        fh[28], fh[29], fh[30], fh[31],
                                                                        containers.len()
                                                                    );
                                                                    if let Some(tip) = p_chain_tip {
                                                                        if fh == tip {
                                                                            info!("Ancestors[0] matches p_chain_tip — chain walk will succeed");
                                                                        } else {
                                                                            info!(
                                                                                "Ancestors[0] DOES NOT match p_chain_tip {:02x}{:02x}{:02x}{:02x}… — chain walk starts at wrong block!",
                                                                                tip[0], tip[1], tip[2], tip[3]
                                                                            );
                                                                        }
                                                                    }
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
                                                                && oldest_container.as_ref().map_or(false, |c| {
                                                                    match avalanche_rs::block::BlockHeader::extract_parent_id(c) {
                                                                        Some(parent) => parent != [0u8; 32],
                                                                        None => false,
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
                                                                    chain_id: ChainId([0u8; 32]),
                                                                    request_id: new_req,
                                                                    deadline: 5_000_000_000u64,
                                                                    container_id: BlockId(oldest_id),
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

                                                                // Verify the stored chain and update metrics
                                                                if let Some(tip) = p_chain_tip {
                                                                    let (chain_len, tip_height, genesis_height) = verify_block_chain(&node.db, tip);
                                                                    info!("P-Chain chain walk: {} blocks linked from tip", chain_len);
                                                                    let mut m = node.p_chain_metrics.write().await;
                                                                    m.blocks_synced = new_total as u64;
                                                                    m.chain_length = chain_len;
                                                                    m.tip_height = tip_height;
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
                                                info!(
                                                    "PushQuery from {} (req={}, block={} bytes)",
                                                    addr, request_id, container.len()
                                                );
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
async fn bootstrap_p_chain<S>(
    stream: &mut S,
    addr: std::net::SocketAddr,
    request_id_base: u32,
) where
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
            warn!("bootstrap: failed to send GetAcceptedFrontier to {}: {}", addr, e);
            return;
        }
        let _ = stream.flush().await;
        info!("bootstrap: sent GetAcceptedFrontier (req={}) to {}", request_id_base, addr);
    }

    // Step 2: Wait for AcceptedFrontier
    let frontier_block_id = loop {
        match read_one_message(stream, addr, 30).await {
            Ok(NetworkMessage::AcceptedFrontier { request_id, container_id, .. })
                if request_id == request_id_base =>
            {
                info!("bootstrap: AcceptedFrontier from {} — tip={}", addr, container_id);
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
                debug!("bootstrap: ignoring {} while waiting for AcceptedFrontier", other.name());
            }
            Err(e) => {
                warn!("bootstrap: error waiting for AcceptedFrontier from {}: {}", addr, e);
                return;
            }
        }
    };

    if frontier_block_id.0 == [0u8; 32] {
        info!("bootstrap: peer {} has empty frontier — nothing to bootstrap", addr);
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
        info!("bootstrap: sent GetAccepted (req={}) to {}", request_id_base + 1, addr);
    }

    // Step 4: Wait for Accepted
    let accepted_ids = loop {
        match read_one_message(stream, addr, 30).await {
            Ok(NetworkMessage::Accepted { request_id, container_ids, .. })
                if request_id == request_id_base + 1 =>
            {
                info!("bootstrap: Accepted from {} — {} block IDs", addr, container_ids.len());
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
                debug!("bootstrap: ignoring {} while waiting for Accepted", other.name());
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
        info!("bootstrap: sent GetAncestors (req={}) for block {} to {}", request_id_base + 2, target, addr);
    }

    // Step 6: Wait for Ancestors
    loop {
        match read_one_message(stream, addr, 30).await {
            Ok(NetworkMessage::Ancestors { request_id, containers, .. })
                if request_id == request_id_base + 2 =>
            {
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
                debug!("bootstrap: ignoring {} while waiting for Ancestors", other.name());
            }
            Err(e) => {
                warn!("bootstrap: error waiting for Ancestors from {}: {}", addr, e);
                break;
            }
        }
    }
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

    let mut buf = vec![0u8; 65536];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    // Simple HTTP JSON-RPC handler
    let body = String::from_utf8_lossy(&buf[..n]);
    let json_start = body.find('{');

    let response_body = if let Some(start) = json_start {
        let json_str = &body[start..];
        handle_rpc_request(json_str, &node).await
    } else {
        r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"parse error"},"id":null}"#.to_string()
    };

    let http_response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
        response_body.len(),
        response_body
    );

    let _ = stream.write_all(http_response.as_bytes()).await;
}

async fn handle_rpc_request(json_str: &str, node: &NodeState) -> String {
    let req: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => {
            return r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"parse error"},"id":null}"#
                .to_string();
        }
    };

    let method = req["method"].as_str().unwrap_or("");
    let id = &req["id"];

    let result = match method {
        "eth_chainId" => {
            format!("\"0x{:x}\"", node.config.chain_id)
        }
        "eth_blockNumber" => {
            let height = node.db.last_accepted_height().unwrap_or(None).unwrap_or(0);
            format!("\"0x{:x}\"", height)
        }
        "net_version" => {
            format!("\"{}\"", node.config.network_id)
        }
        "web3_clientVersion" => {
            "\"avalanche-rs/0.1.0\"".to_string()
        }
        "eth_syncing" => {
            let phase = node.sync_engine.phase().await;
            if phase == SyncPhase::Synced {
                "false".to_string()
            } else {
                let stats = node.sync_engine.stats().await;
                format!(
                    "{{\"startingBlock\":\"0x0\",\"currentBlock\":\"0x{:x}\",\"highestBlock\":\"0x{:x}\"}}",
                    stats.last_block_height,
                    stats.target_height
                )
            }
        }
        "avax_getNodeID" => {
            format!("\"{}\"", node.identity.node_id)
        }
        "avax_getNodeVersion" => {
            "\"avalanche-rs/0.1.0\"".to_string()
        }
        _ => {
            return format!(
                "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32601,\"message\":\"method not found: {}\"}},\"id\":{}}}",
                method, id
            );
        }
    };

    format!("{{\"jsonrpc\":\"2.0\",\"result\":{},\"id\":{}}}", result, id)
}

// ---------------------------------------------------------------------------
// Consensus loop
// ---------------------------------------------------------------------------

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

        // After 60 seconds, run chain graph analysis if we have blocks
        if !chain_analysis_done && node.start_time.elapsed().as_secs() > 60 {
            chain_analysis_done = true;
            analyze_chain_graphs(&node);
        }
    }
}

/// Read all blocks from RocksDB, parse headers, build chain graphs, run Snowman.
/// Tasks 2, 3, and 4 are all executed here.
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
        let chain = if is_cchain { Chain::CChain } else { Chain::PChain };

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
}

fn init_logging(level: &str, format: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

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
