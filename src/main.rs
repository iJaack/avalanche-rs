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

use avalanche_rs::db::{Database, CF_BLOCKS};
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

const MAINNET_BOOTSTRAP_IPS: &[&str] = &[
    "54.94.43.49:9651",
    "52.33.47.4:9651",
    "18.203.129.230:9651",
    "3.34.29.75:9651",
    "52.199.17.2:9651",
    "13.244.44.148:9651",
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

    let node = Arc::new(NodeState {
        identity,
        db,
        evm,
        sync_engine: sync_engine.clone(),
        peer_manager,
        config: cli,
        start_time: Instant::now(),
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
                                                if let BootstrapState::WaitingFrontier(req) = bootstrap_state {
                                                    if request_id == req {
                                                        if container_id.0 != [0u8; 32] {
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
                                            NetworkMessage::Accepted { request_id, container_ids, .. } => {
                                                info!("Accepted from {} — {} block IDs", addr, container_ids.len());
                                                if let BootstrapState::WaitingAccepted(req) = bootstrap_state {
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
                                            }
                                            NetworkMessage::Ancestors { request_id, containers, chain_id } => {
                                                let total_bytes: usize = containers.iter().map(|c| c.len()).sum();
                                                info!(
                                                    "Ancestors from {} — {} containers, {} bytes total",
                                                    addr, containers.len(), total_bytes
                                                );

                                                let expected_req = match bootstrap_state {
                                                    BootstrapState::WaitingAncestors(req) => Some((req, 0u32, 0u32)),
                                                    BootstrapState::FetchingAncestors { req, depth, total_blocks } => Some((req, depth, total_blocks)),
                                                    _ => None,
                                                };

                                                if let Some((req, depth, prev_total)) = expected_req {
                                                    if request_id == req {
                                                        // ── Store all containers ─────────────────────────────────────────
                                                        let mut stored = 0u32;
                                                        let mut oldest_container: Option<Vec<u8>> = None;

                                                        for container in &containers {
                                                            let mut hasher = Sha256::new();
                                                            hasher.update(container);
                                                            let hash: [u8; 32] = hasher.finalize().into();

                                                            if let Err(e) = node.db.put_cf(CF_BLOCKS, &hash, container) {
                                                                warn!("Failed to store block {:02x?}: {}", &hash[..4], e);
                                                            } else {
                                                                stored += 1;
                                                            }
                                                            oldest_container = Some(container.clone());
                                                        }

                                                        let new_total = prev_total + stored;
                                                        info!("Bootstrap: stored {} blocks (total: {})", stored, new_total);

                                                        // Update metadata with total stored count
                                                        let _ = node.db.put_metadata(
                                                            b"p_chain_blocks_downloaded",
                                                            &new_total.to_le_bytes(),
                                                        );

                                                        // ── Decide: recurse or finish ────────────────────────────────────
                                                        let should_recurse = depth < 10
                                                            && oldest_container.as_ref().map_or(false, |c| {
                                                                // Extract parent ID: bytes [2..34] after 2-byte codec version
                                                                if c.len() >= 34 {
                                                                    let parent: [u8; 32] = c[2..34].try_into().unwrap_or([0u8; 32]);
                                                                    parent != [0u8; 32]
                                                                } else {
                                                                    false
                                                                }
                                                            });

                                                        if should_recurse {
                                                            let oldest = oldest_container.unwrap();
                                                            // The "block ID" to request ancestors of = SHA-256 of the oldest container
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
                                                        }
                                                    }
                                                }
                                                let _ = chain_id; // suppress unused warning
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

    // Wait a bit for connections to establish
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;

        let phase = node.sync_engine.phase().await;
        let stats = node.sync_engine.stats().await;

        match phase {
            SyncPhase::Idle => {
                // Not started sync yet
            }
            SyncPhase::Synced => {
                // In consensus mode — process new blocks as they come
            }
            _ => {
                info!(
                    "Sync: phase={}, blocks={}, {:.1}%",
                    phase,
                    stats.blocks_downloaded,
                    stats.progress_pct()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

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
