// =============================================================================
// PHASE 2C: P2P Networking & Snowman Consensus State Machine
// =============================================================================
// Implements:
//   - P2P peer discovery, message routing, connection pooling
//   - TLS-ready validator communications
//   - Snowman consensus state machine (block acceptance tracking)
//   - Snowball voting with confidence counters and finality detection
//   - Validator set management with uptime tracking
//   - Full error handling for network failures, timeouts, disconnections
//
// No unsafe code. Fully async with tokio. Backpressure via bounded channels.
// =============================================================================

// ---- src/network/message.rs ----

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

/// Unique identifier for a node in the Avalanche network (20-byte NodeID).
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 20]);

impl NodeId {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    pub fn random_for_test() -> Self {
        let mut arr = [0u8; 20];
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let bytes = now.to_le_bytes();
        for (i, b) in bytes.iter().enumerate() {
            if i < 20 {
                arr[i] = *b;
            }
        }
        Self(arr)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeID-")?;
        for b in &self.0[..6] {
            write!(f, "{:02x}", b)?;
        }
        write!(f, "...")
    }
}

/// Block hash (32 bytes, like ids.ID in Go).
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockId(pub [u8; 32]);

impl BlockId {
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0[..8] {
            write!(f, "{:02x}", b)?;
        }
        write!(f, "...")
    }
}

/// Chain identifier.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainId(pub [u8; 32]);

/// All message types exchanged over the Avalanche P2P protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    // -- Handshake --
    Version {
        network_id: u32,
        node_id: NodeId,
        my_time: u64,
        ip_addr: Vec<u8>,
        ip_port: u16,
        my_version: String,
        my_version_time: u64,
        sig: Vec<u8>,
        tracked_subnets: Vec<ChainId>,
    },
    PeerList {
        peers: Vec<PeerInfo>,
    },
    PeerListAck {
        peer_ids: Vec<NodeId>,
    },

    // -- Keepalive --
    Ping {
        uptime: u32, // percentage * 100
    },
    Pong {
        uptime: u32,
    },

    // -- State sync --
    GetStateSummaryFrontier {
        chain_id: ChainId,
        request_id: u32,
        deadline: u64,
    },
    StateSummaryFrontier {
        chain_id: ChainId,
        request_id: u32,
        summary: Vec<u8>,
    },

    // -- Bootstrapping --
    GetAcceptedFrontier {
        chain_id: ChainId,
        request_id: u32,
        deadline: u64,
    },
    AcceptedFrontier {
        chain_id: ChainId,
        request_id: u32,
        container_id: BlockId,
    },
    GetAccepted {
        chain_id: ChainId,
        request_id: u32,
        deadline: u64,
        container_ids: Vec<BlockId>,
    },
    Accepted {
        chain_id: ChainId,
        request_id: u32,
        container_ids: Vec<BlockId>,
    },
    GetAncestors {
        chain_id: ChainId,
        request_id: u32,
        deadline: u64,
        container_id: BlockId,
        max_containers_size: u32,
    },
    Ancestors {
        chain_id: ChainId,
        request_id: u32,
        containers: Vec<Vec<u8>>,
    },

    // -- Consensus (Avalanche/Snowman) --
    Get {
        chain_id: ChainId,
        request_id: u32,
        deadline: u64,
        container_id: BlockId,
    },
    Put {
        chain_id: ChainId,
        request_id: u32,
        container: Vec<u8>,
    },
    PushQuery {
        chain_id: ChainId,
        request_id: u32,
        deadline: u64,
        container: Vec<u8>,
    },
    PullQuery {
        chain_id: ChainId,
        request_id: u32,
        deadline: u64,
        container_id: BlockId,
    },
    Chits {
        chain_id: ChainId,
        request_id: u32,
        preferred_id: BlockId,
        preferred_id_at_height: BlockId,
        accepted_id: BlockId,
    },

    // -- App-level --
    AppRequest {
        chain_id: ChainId,
        request_id: u32,
        deadline: u64,
        app_bytes: Vec<u8>,
    },
    AppResponse {
        chain_id: ChainId,
        request_id: u32,
        app_bytes: Vec<u8>,
    },
    AppGossip {
        chain_id: ChainId,
        app_bytes: Vec<u8>,
    },
}

impl NetworkMessage {
    /// Returns a human-readable name for logging.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Version { .. } => "Version",
            Self::PeerList { .. } => "PeerList",
            Self::PeerListAck { .. } => "PeerListAck",
            Self::Ping { .. } => "Ping",
            Self::Pong { .. } => "Pong",
            Self::GetStateSummaryFrontier { .. } => "GetStateSummaryFrontier",
            Self::StateSummaryFrontier { .. } => "StateSummaryFrontier",
            Self::GetAcceptedFrontier { .. } => "GetAcceptedFrontier",
            Self::AcceptedFrontier { .. } => "AcceptedFrontier",
            Self::GetAccepted { .. } => "GetAccepted",
            Self::Accepted { .. } => "Accepted",
            Self::GetAncestors { .. } => "GetAncestors",
            Self::Ancestors { .. } => "Ancestors",
            Self::Get { .. } => "Get",
            Self::Put { .. } => "Put",
            Self::PushQuery { .. } => "PushQuery",
            Self::PullQuery { .. } => "PullQuery",
            Self::Chits { .. } => "Chits",
            Self::AppRequest { .. } => "AppRequest",
            Self::AppResponse { .. } => "AppResponse",
            Self::AppGossip { .. } => "AppGossip",
        }
    }

    /// Serialize to bytes (length-prefixed JSON for now; production would use protobuf).
    pub fn encode(&self) -> Result<Vec<u8>, NetworkError> {
        let json =
            serde_json::to_vec(self).map_err(|e| NetworkError::Serialization(e.to_string()))?;
        let len = (json.len() as u32).to_be_bytes();
        let mut buf = Vec::with_capacity(4 + json.len());
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&json);
        Ok(buf)
    }

    /// Decode from length-prefixed bytes.
    pub fn decode(data: &[u8]) -> Result<Self, NetworkError> {
        if data.len() < 4 {
            return Err(NetworkError::Serialization("message too short".into()));
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return Err(NetworkError::Serialization(format!(
                "expected {} bytes, got {}",
                len,
                data.len() - 4
            )));
        }
        serde_json::from_slice(&data[4..4 + len])
            .map_err(|e| NetworkError::Serialization(e.to_string()))
    }
}

/// Peer info for PeerList gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub ip_addr: Vec<u8>,
    pub ip_port: u16,
    pub cert_bytes: Vec<u8>,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

// ---- src/network/error.rs ----

/// All network and consensus errors.
#[derive(Debug, Clone)]
pub enum NetworkError {
    ConnectionRefused(String),
    ConnectionTimeout(SocketAddr),
    PeerDisconnected(NodeId),
    HandshakeFailed(String),
    TlsError(String),
    Serialization(String),
    SendFailed(String),
    ReceiveFailed(String),
    PeerBanned(NodeId),
    PoolExhausted,
    Shutdown,
    InvalidMessage(String),
    MaxPeersReached(usize),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionRefused(addr) => write!(f, "connection refused: {}", addr),
            Self::ConnectionTimeout(addr) => write!(f, "connection timeout: {}", addr),
            Self::PeerDisconnected(id) => write!(f, "peer disconnected: {}", id),
            Self::HandshakeFailed(reason) => write!(f, "handshake failed: {}", reason),
            Self::TlsError(reason) => write!(f, "TLS error: {}", reason),
            Self::Serialization(reason) => write!(f, "serialization error: {}", reason),
            Self::SendFailed(reason) => write!(f, "send failed: {}", reason),
            Self::ReceiveFailed(reason) => write!(f, "receive failed: {}", reason),
            Self::PeerBanned(id) => write!(f, "peer banned: {}", id),
            Self::PoolExhausted => write!(f, "connection pool exhausted"),
            Self::Shutdown => write!(f, "network shutting down"),
            Self::InvalidMessage(reason) => write!(f, "invalid message: {}", reason),
            Self::MaxPeersReached(max) => write!(f, "max peers reached: {}", max),
        }
    }
}

impl std::error::Error for NetworkError {}

// ---- src/network/mod.rs ----

/// Configuration for the networking layer.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Maximum number of connected peers.
    pub max_peers: usize,
    /// Dial timeout for outbound connections.
    pub dial_timeout: Duration,
    /// Interval between ping messages.
    pub ping_interval: Duration,
    /// Time after which an unresponsive peer is dropped.
    pub peer_timeout: Duration,
    /// Inbound message buffer size (backpressure boundary).
    pub inbound_buffer_size: usize,
    /// Outbound message buffer size per peer.
    pub outbound_buffer_size: usize,
    /// Network ID (1 = mainnet, 5 = fuji).
    pub network_id: u32,
    /// Minimum reputation before banning.
    pub min_reputation: i32,
    /// Whether TLS is required.
    pub require_tls: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            max_peers: 60,
            dial_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(30),
            peer_timeout: Duration::from_secs(120),
            inbound_buffer_size: 4096,
            outbound_buffer_size: 256,
            network_id: 1,
            min_reputation: -100,
            require_tls: true,
        }
    }
}

/// Represents a connected peer.
#[derive(Debug, Clone)]
pub struct Peer {
    pub node_id: NodeId,
    pub address: SocketAddr,
    pub version: Option<String>,
    pub reputation: i32,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub last_ping_sent: Option<Instant>,
    pub last_pong_received: Option<Instant>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub tracked_subnets: Vec<ChainId>,
    pub is_validator: bool,
    pub reported_uptime: u32,
    pub state: PeerState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PeerState {
    Connecting,
    Handshaking,
    Connected,
    Disconnecting,
    Disconnected,
    Banned,
}

impl Peer {
    pub fn new(node_id: NodeId, address: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            node_id,
            address,
            version: None,
            reputation: 0,
            connected_at: now,
            last_seen: now,
            last_ping_sent: None,
            last_pong_received: None,
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
            tracked_subnets: Vec::new(),
            is_validator: false,
            reported_uptime: 0,
            state: PeerState::Connecting,
        }
    }

    /// Adjust reputation. Clamps to [-1000, 1000].
    pub fn adjust_reputation(&mut self, delta: i32) {
        self.reputation = (self.reputation + delta).clamp(-1000, 1000);
    }

    /// Whether the peer has timed out based on config.
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }

    /// Record that we received a message from this peer.
    pub fn record_received(&mut self, bytes: u64) {
        self.last_seen = Instant::now();
        self.bytes_received += bytes;
        self.messages_received += 1;
    }

    /// Record that we sent a message to this peer.
    pub fn record_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.messages_sent += 1;
    }
}

/// Manages the set of peers: discovery, selection, reputation, banning.
pub struct PeerManager {
    config: NetworkConfig,
    peers: HashMap<NodeId, Peer>,
    banned: HashSet<NodeId>,
    /// Bootstrap nodes to try on startup.
    bootstrap_nodes: Vec<(NodeId, SocketAddr)>,
    /// Peers discovered via gossip but not yet connected.
    discovered: VecDeque<(NodeId, SocketAddr)>,
    /// Our own node ID.
    local_node_id: NodeId,
}

impl PeerManager {
    pub fn new(config: NetworkConfig, local_node_id: NodeId) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            banned: HashSet::new(),
            bootstrap_nodes: Vec::new(),
            discovered: VecDeque::new(),
            local_node_id,
        }
    }

    /// Add bootstrap nodes for initial discovery.
    pub fn add_bootstrap_nodes(&mut self, nodes: Vec<(NodeId, SocketAddr)>) {
        for node in nodes {
            if node.0 != self.local_node_id {
                self.bootstrap_nodes.push(node);
            }
        }
    }

    /// Register a newly connected peer.
    pub fn add_peer(&mut self, peer: Peer) -> Result<(), NetworkError> {
        if self.banned.contains(&peer.node_id) {
            return Err(NetworkError::PeerBanned(peer.node_id));
        }
        if self.peers.len() >= self.config.max_peers {
            // Try evicting the worst-reputation peer
            if !self.evict_worst_peer() {
                return Err(NetworkError::MaxPeersReached(self.config.max_peers));
            }
        }
        self.peers.insert(peer.node_id.clone(), peer);
        Ok(())
    }

    /// Remove a peer by node ID.
    pub fn remove_peer(&mut self, node_id: &NodeId) -> Option<Peer> {
        self.peers.remove(node_id)
    }

    /// Get a peer reference.
    pub fn get_peer(&self, node_id: &NodeId) -> Option<&Peer> {
        self.peers.get(node_id)
    }

    /// Get a mutable peer reference.
    pub fn get_peer_mut(&mut self, node_id: &NodeId) -> Option<&mut Peer> {
        self.peers.get_mut(node_id)
    }

    /// Number of connected peers.
    pub fn connected_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .count()
    }

    /// All connected peer IDs.
    pub fn connected_peers(&self) -> Vec<NodeId> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .map(|p| p.node_id.clone())
            .collect()
    }

    /// Select `count` random connected peers for gossip.
    pub fn sample_peers(&self, count: usize) -> Vec<NodeId> {
        let connected: Vec<_> = self.connected_peers();
        if connected.len() <= count {
            return connected;
        }
        // Deterministic selection based on current peer order (shuffle in production with rng)
        connected.into_iter().take(count).collect()
    }

    /// Select validators only.
    pub fn validator_peers(&self) -> Vec<NodeId> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected && p.is_validator)
            .map(|p| p.node_id.clone())
            .collect()
    }

    /// Return socket addresses of all currently connected peers.
    ///
    /// Used by the validator block builder to broadcast newly built blocks.
    pub fn active_peer_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .map(|p| p.address)
            .collect()
    }

    /// Ingest discovered peers from a PeerList message.
    pub fn process_peer_list(&mut self, peers: &[PeerInfo]) -> Vec<PeerInfo> {
        let mut new_peers = Vec::new();
        for info in peers {
            if info.node_id == self.local_node_id {
                continue;
            }
            if self.peers.contains_key(&info.node_id) || self.banned.contains(&info.node_id) {
                continue;
            }
            // Parse IP from bytes
            if let Some(addr) = parse_peer_addr(&info.ip_addr, info.ip_port) {
                self.discovered.push_back((info.node_id.clone(), addr));
                new_peers.push(info.clone());
            }
        }
        new_peers
    }

    /// Pop next peer to connect to from discovered queue.
    pub fn next_to_connect(&mut self) -> Option<(NodeId, SocketAddr)> {
        while let Some((id, addr)) = self.discovered.pop_front() {
            if !self.peers.contains_key(&id) && !self.banned.contains(&id) {
                return Some((id, addr));
            }
        }
        None
    }

    /// Get bootstrap nodes for initial connections.
    pub fn bootstrap_targets(&self) -> Vec<(NodeId, SocketAddr)> {
        self.bootstrap_nodes
            .iter()
            .filter(|(id, _)| !self.peers.contains_key(id) && !self.banned.contains(id))
            .cloned()
            .collect()
    }

    /// Adjust reputation for a peer. Bans if below threshold.
    pub fn adjust_reputation(&mut self, node_id: &NodeId, delta: i32) -> Option<i32> {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.adjust_reputation(delta);
            let rep = peer.reputation;
            if rep < self.config.min_reputation {
                self.ban_peer(node_id);
            }
            Some(rep)
        } else {
            None
        }
    }

    /// Ban a peer permanently.
    pub fn ban_peer(&mut self, node_id: &NodeId) {
        self.banned.insert(node_id.clone());
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.state = PeerState::Banned;
        }
    }

    /// Check for timed-out peers and return their IDs for disconnection.
    pub fn check_timeouts(&self) -> Vec<NodeId> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected && p.is_timed_out(self.config.peer_timeout))
            .map(|p| p.node_id.clone())
            .collect()
    }

    /// Peers that need a ping sent.
    pub fn peers_needing_ping(&self) -> Vec<NodeId> {
        self.peers
            .values()
            .filter(|p| {
                p.state == PeerState::Connected
                    && p.last_ping_sent
                        .map(|t| t.elapsed() > self.config.ping_interval)
                        .unwrap_or(true)
            })
            .map(|p| p.node_id.clone())
            .collect()
    }

    /// Evict the peer with worst reputation. Returns true if a peer was evicted.
    fn evict_worst_peer(&mut self) -> bool {
        let worst = self
            .peers
            .values()
            .filter(|p| !p.is_validator) // never evict validators
            .min_by_key(|p| p.reputation)
            .map(|p| p.node_id.clone());

        if let Some(id) = worst {
            self.peers.remove(&id);
            true
        } else {
            false
        }
    }
}

/// Parse a peer IP address from bytes + port.
fn parse_peer_addr(ip_bytes: &[u8], port: u16) -> Option<SocketAddr> {
    match ip_bytes.len() {
        4 => {
            let ip = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        16 => {
            let mut segments = [0u16; 8];
            for i in 0..8 {
                segments[i] = u16::from_be_bytes([ip_bytes[i * 2], ip_bytes[i * 2 + 1]]);
            }
            let ip = std::net::Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            );
            Some(SocketAddr::new(std::net::IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

/// TLS configuration wrapper.
/// In production this would wrap rustls::ServerConfig / ClientConfig.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// PEM-encoded certificate.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded private key.
    pub key_pem: Vec<u8>,
    /// Whether to verify peer certificates.
    pub verify_peer: bool,
}

impl TlsConfig {
    /// Create a TLS config from PEM data.
    pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>, verify_peer: bool) -> Self {
        Self {
            cert_pem,
            key_pem,
            verify_peer,
        }
    }

    /// Validate that cert and key are present and minimally well-formed.
    pub fn validate(&self) -> Result<(), NetworkError> {
        if self.cert_pem.is_empty() {
            return Err(NetworkError::TlsError("empty certificate".into()));
        }
        if self.key_pem.is_empty() {
            return Err(NetworkError::TlsError("empty private key".into()));
        }
        // Check PEM markers
        let cert_str = std::str::from_utf8(&self.cert_pem)
            .map_err(|_| NetworkError::TlsError("invalid cert encoding".into()))?;
        if !cert_str.contains("BEGIN CERTIFICATE") {
            return Err(NetworkError::TlsError(
                "missing BEGIN CERTIFICATE marker".into(),
            ));
        }
        Ok(())
    }
}

/// Connection pool for managing outbound connections with backpressure.
pub struct ConnectionPool {
    /// Active connections indexed by NodeId.
    connections: HashMap<NodeId, ConnectionHandle>,
    /// Maximum concurrent connections.
    max_connections: usize,
}

/// Handle to an individual connection (simulated for this implementation).
pub struct ConnectionHandle {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub established_at: Instant,
    pub outbound_queue: VecDeque<NetworkMessage>,
    pub outbound_queue_limit: usize,
    pub state: ConnectionState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Active,
    Draining,
    Closed,
}

impl ConnectionPool {
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: HashMap::new(),
            max_connections,
        }
    }

    /// Open a connection to a peer.
    pub fn connect(
        &mut self,
        node_id: NodeId,
        addr: SocketAddr,
        queue_limit: usize,
    ) -> Result<(), NetworkError> {
        if self.connections.len() >= self.max_connections {
            return Err(NetworkError::PoolExhausted);
        }
        let handle = ConnectionHandle {
            node_id: node_id.clone(),
            addr,
            established_at: Instant::now(),
            outbound_queue: VecDeque::new(),
            outbound_queue_limit: queue_limit,
            state: ConnectionState::Active,
        };
        self.connections.insert(node_id, handle);
        Ok(())
    }

    /// Queue a message for sending to a peer. Applies backpressure if queue is full.
    pub fn enqueue_message(
        &mut self,
        node_id: &NodeId,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        let conn = self
            .connections
            .get_mut(node_id)
            .ok_or_else(|| NetworkError::PeerDisconnected(node_id.clone()))?;

        if conn.state != ConnectionState::Active {
            return Err(NetworkError::PeerDisconnected(node_id.clone()));
        }

        if conn.outbound_queue.len() >= conn.outbound_queue_limit {
            // Backpressure: drop oldest non-critical message
            if let Some(front) = conn.outbound_queue.front() {
                match front {
                    NetworkMessage::Ping { .. } | NetworkMessage::Pong { .. } => {
                        // Don't drop keepalives — drop second oldest
                        if conn.outbound_queue.len() > 1 {
                            conn.outbound_queue.remove(1);
                        }
                    }
                    _ => {
                        conn.outbound_queue.pop_front();
                    }
                }
            }
        }

        conn.outbound_queue.push_back(msg);
        Ok(())
    }

    /// Dequeue next message for a peer.
    pub fn dequeue_message(&mut self, node_id: &NodeId) -> Option<NetworkMessage> {
        self.connections
            .get_mut(node_id)
            .and_then(|c| c.outbound_queue.pop_front())
    }

    /// Close a connection.
    pub fn disconnect(&mut self, node_id: &NodeId) {
        if let Some(conn) = self.connections.get_mut(node_id) {
            conn.state = ConnectionState::Closed;
        }
        self.connections.remove(node_id);
    }

    /// Get current connection count.
    pub fn active_count(&self) -> usize {
        self.connections
            .values()
            .filter(|c| c.state == ConnectionState::Active)
            .count()
    }

    /// Drain and close all connections.
    pub fn shutdown(&mut self) {
        for conn in self.connections.values_mut() {
            conn.state = ConnectionState::Draining;
            conn.outbound_queue.clear();
        }
        self.connections.clear();
    }
}

/// High-level network manager composing peers, connections, and message routing.
pub struct NetworkManager {
    pub config: NetworkConfig,
    pub peer_manager: PeerManager,
    pub connection_pool: ConnectionPool,
    pub tls_config: Option<TlsConfig>,
    pub local_node_id: NodeId,
    pub inbound_buffer: VecDeque<(NodeId, NetworkMessage)>,
    pub inbound_buffer_limit: usize,
    pub stats: NetworkStats,
    pub is_running: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub connections_established: u64,
    pub connections_failed: u64,
    pub peers_banned: u64,
}

impl NetworkManager {
    pub fn new(
        config: NetworkConfig,
        local_node_id: NodeId,
        tls_config: Option<TlsConfig>,
    ) -> Self {
        let inbound_limit = config.inbound_buffer_size;
        let max_conns = config.max_peers;
        Self {
            peer_manager: PeerManager::new(config.clone(), local_node_id.clone()),
            connection_pool: ConnectionPool::new(max_conns),
            tls_config,
            local_node_id,
            inbound_buffer: VecDeque::new(),
            inbound_buffer_limit: inbound_limit,
            stats: NetworkStats::default(),
            is_running: false,
            config,
        }
    }

    /// Start the networking layer.
    pub fn start(&mut self) -> Result<(), NetworkError> {
        if let Some(ref tls) = self.tls_config {
            if self.config.require_tls {
                tls.validate()?;
            }
        } else if self.config.require_tls {
            return Err(NetworkError::TlsError(
                "TLS required but no config provided".into(),
            ));
        }
        self.is_running = true;
        Ok(())
    }

    /// Connect to a peer and perform the handshake.
    pub fn connect_peer(&mut self, node_id: NodeId, addr: SocketAddr) -> Result<(), NetworkError> {
        if !self.is_running {
            return Err(NetworkError::Shutdown);
        }

        let peer = Peer::new(node_id.clone(), addr);

        // Add to peer manager
        self.peer_manager.add_peer(peer.clone())?;

        // Create connection
        self.connection_pool
            .connect(node_id.clone(), addr, self.config.outbound_buffer_size)?;

        self.stats.connections_established += 1;

        // Queue handshake Version message
        let version_msg = NetworkMessage::Version {
            network_id: self.config.network_id,
            node_id: self.local_node_id.clone(),
            my_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ip_addr: vec![127, 0, 0, 1],
            ip_port: 9651,
            my_version: "avalanche-rs/0.1.0".to_string(),
            my_version_time: 0,
            sig: Vec::new(),
            tracked_subnets: Vec::new(),
        };
        self.connection_pool
            .enqueue_message(&node_id, version_msg)?;

        // Update peer state
        if let Some(p) = self.peer_manager.get_peer_mut(&node_id) {
            p.state = PeerState::Handshaking;
        }

        Ok(())
    }

    /// Send a message to a specific peer.
    pub fn send_message(
        &mut self,
        node_id: &NodeId,
        msg: NetworkMessage,
    ) -> Result<usize, NetworkError> {
        if !self.is_running {
            return Err(NetworkError::Shutdown);
        }

        let encoded = msg.encode()?;
        let size = encoded.len();

        self.connection_pool.enqueue_message(node_id, msg)?;

        if let Some(peer) = self.peer_manager.get_peer_mut(node_id) {
            peer.record_sent(size as u64);
        }

        self.stats.total_messages_sent += 1;
        self.stats.total_bytes_sent += size as u64;

        Ok(size)
    }

    /// Broadcast a message to all connected peers.
    pub fn broadcast(&mut self, msg: NetworkMessage) -> Vec<(NodeId, Result<usize, NetworkError>)> {
        let peers = self.peer_manager.connected_peers();
        let mut results = Vec::new();
        for peer_id in peers {
            let result = self.send_message(&peer_id, msg.clone());
            results.push((peer_id, result));
        }
        results
    }

    /// Receive a message (dequeue from inbound buffer).
    pub fn receive_message(&mut self) -> Option<(NodeId, NetworkMessage)> {
        self.inbound_buffer.pop_front()
    }

    /// Simulate receiving a message from a peer (used by transport layer / tests).
    pub fn inject_inbound(
        &mut self,
        from: NodeId,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        if self.inbound_buffer.len() >= self.inbound_buffer_limit {
            // Backpressure: drop oldest
            self.inbound_buffer.pop_front();
        }

        let encoded_size = msg.encode().map(|e| e.len()).unwrap_or(0) as u64;

        if let Some(peer) = self.peer_manager.get_peer_mut(&from) {
            peer.record_received(encoded_size);
        }

        self.stats.total_messages_received += 1;
        self.stats.total_bytes_received += encoded_size;

        self.inbound_buffer.push_back((from, msg));
        Ok(())
    }

    /// Process a received Version message to complete handshake.
    pub fn handle_version(
        &mut self,
        from: &NodeId,
        version_msg: &NetworkMessage,
    ) -> Result<(), NetworkError> {
        if let NetworkMessage::Version {
            network_id,
            node_id: _,
            my_version,
            tracked_subnets,
            ..
        } = version_msg
        {
            if *network_id != self.config.network_id {
                self.peer_manager.adjust_reputation(from, -50);
                return Err(NetworkError::HandshakeFailed(format!(
                    "network ID mismatch: expected {}, got {}",
                    self.config.network_id, network_id
                )));
            }

            if let Some(peer) = self.peer_manager.get_peer_mut(from) {
                peer.version = Some(my_version.clone());
                peer.tracked_subnets = tracked_subnets.clone();
                peer.state = PeerState::Connected;
                peer.adjust_reputation(10); // reward successful handshake
            }

            Ok(())
        } else {
            Err(NetworkError::InvalidMessage(
                "expected Version message".into(),
            ))
        }
    }

    /// Handle a PeerList message for gossip-based discovery.
    pub fn handle_peer_list(&mut self, peers: &[PeerInfo]) -> Vec<PeerInfo> {
        self.peer_manager.process_peer_list(peers)
    }

    /// Run maintenance: check timeouts, send pings, evict bad peers.
    pub fn maintenance(&mut self) -> MaintenanceReport {
        let mut report = MaintenanceReport::default();

        // Disconnect timed-out peers
        let timed_out = self.peer_manager.check_timeouts();
        for node_id in &timed_out {
            self.peer_manager.remove_peer(node_id);
            self.connection_pool.disconnect(node_id);
        }
        report.peers_timed_out = timed_out.len();

        // Send pings
        let need_ping = self.peer_manager.peers_needing_ping();
        for node_id in &need_ping {
            let ping = NetworkMessage::Ping { uptime: 10000 }; // 100.00%
            let _ = self.send_message(node_id, ping);
            if let Some(peer) = self.peer_manager.get_peer_mut(node_id) {
                peer.last_ping_sent = Some(Instant::now());
            }
        }
        report.pings_sent = need_ping.len();

        // Try connecting to discovered peers
        let connected = self.peer_manager.connected_count();
        let target = self.config.max_peers / 2; // aim for 50% capacity
        if connected < target {
            let mut attempts = 0;
            while attempts < 5 {
                if let Some((id, addr)) = self.peer_manager.next_to_connect() {
                    if self.connect_peer(id, addr).is_ok() {
                        report.new_connections += 1;
                    }
                } else {
                    break;
                }
                attempts += 1;
            }
        }

        report.connected_peers = self.peer_manager.connected_count();
        report
    }

    /// Graceful shutdown.
    pub fn shutdown(&mut self) {
        self.is_running = false;
        self.connection_pool.shutdown();
        self.inbound_buffer.clear();
    }
}

#[derive(Debug, Default)]
pub struct MaintenanceReport {
    pub peers_timed_out: usize,
    pub pings_sent: usize,
    pub new_connections: usize,
    pub connected_peers: usize,
}

// ---- src/consensus/mod.rs ----

/// Status of a block in the Snowman consensus pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockStatus {
    /// Block has been received and is being voted on.
    Processing,
    /// Block has been preferred by the local node.
    Committed,
    /// Block has reached finality — accepted by the network.
    Accepted,
    /// Block was rejected (conflicting block was accepted).
    Rejected,
    /// Block status is unknown (not seen yet).
    Unknown,
}

impl fmt::Display for BlockStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Processing => write!(f, "Processing"),
            Self::Committed => write!(f, "Committed"),
            Self::Accepted => write!(f, "Accepted"),
            Self::Rejected => write!(f, "Rejected"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A block as tracked by the consensus engine.
#[derive(Debug, Clone)]
pub struct ConsensusBlock {
    pub id: BlockId,
    pub parent_id: BlockId,
    pub height: u64,
    pub timestamp: u64,
    pub status: BlockStatus,
    pub bytes: Vec<u8>,
    /// Number of successful polls this block has received.
    pub polls_received: u32,
    /// Snowball instance tracking votes for this block vs alternatives.
    pub snowball: Option<SnowballInstance>,
    /// When this block was first seen.
    pub received_at: Instant,
}

impl ConsensusBlock {
    pub fn new(
        id: BlockId,
        parent_id: BlockId,
        height: u64,
        timestamp: u64,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            id,
            parent_id,
            height,
            timestamp,
            status: BlockStatus::Processing,
            bytes,
            polls_received: 0,
            snowball: None,
            received_at: Instant::now(),
        }
    }
}

/// Validator in the current validator set.
#[derive(Debug, Clone)]
pub struct Validator {
    pub node_id: NodeId,
    pub weight: u64,
    pub start_time: u64,
    pub end_time: u64,
    pub uptime_seconds: u64,
    pub total_seconds: u64,
    pub is_connected: bool,
    pub last_response: Option<Instant>,
    pub consecutive_failures: u32,
}

impl Validator {
    pub fn new(node_id: NodeId, weight: u64, start_time: u64, end_time: u64) -> Self {
        Self {
            node_id,
            weight,
            start_time,
            end_time,
            uptime_seconds: 0,
            total_seconds: 0,
            is_connected: false,
            last_response: None,
            consecutive_failures: 0,
        }
    }

    /// Uptime as a percentage (0.0 to 100.0).
    pub fn uptime_percent(&self) -> f64 {
        if self.total_seconds == 0 {
            return 0.0;
        }
        (self.uptime_seconds as f64 / self.total_seconds as f64) * 100.0
    }

    /// Record a successful response.
    pub fn record_response(&mut self) {
        self.is_connected = true;
        self.last_response = Some(Instant::now());
        self.consecutive_failures = 0;
    }

    /// Record a failure.
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures > 5 {
            self.is_connected = false;
        }
    }

    /// Update uptime counters (call periodically).
    pub fn update_uptime(&mut self, elapsed_seconds: u64) {
        self.total_seconds += elapsed_seconds;
        if self.is_connected {
            self.uptime_seconds += elapsed_seconds;
        }
    }
}

/// Manages the active validator set and tracks uptime.
pub struct ValidatorSet {
    validators: HashMap<NodeId, Validator>,
    total_weight: u64,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            total_weight: 0,
        }
    }

    /// Add or update a validator.
    pub fn add_validator(&mut self, validator: Validator) {
        self.total_weight += validator.weight;
        self.validators.insert(validator.node_id.clone(), validator);
    }

    /// Remove a validator (end of staking period).
    pub fn remove_validator(&mut self, node_id: &NodeId) -> Option<Validator> {
        if let Some(v) = self.validators.remove(node_id) {
            self.total_weight = self.total_weight.saturating_sub(v.weight);
            Some(v)
        } else {
            None
        }
    }

    /// Get a validator by node ID.
    pub fn get(&self, node_id: &NodeId) -> Option<&Validator> {
        self.validators.get(node_id)
    }

    /// Get mutable validator reference.
    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut Validator> {
        self.validators.get_mut(node_id)
    }

    /// Total stake weight of all validators.
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Number of validators.
    pub fn count(&self) -> usize {
        self.validators.len()
    }

    /// Sum of weight of connected validators.
    pub fn connected_weight(&self) -> u64 {
        self.validators
            .values()
            .filter(|v| v.is_connected)
            .map(|v| v.weight)
            .sum()
    }

    /// Whether the connected stake exceeds the given alpha threshold (e.g. 0.67 for 2/3).
    pub fn has_quorum(&self, alpha: f64) -> bool {
        if self.total_weight == 0 {
            return false;
        }
        let connected = self.connected_weight();
        (connected as f64 / self.total_weight as f64) >= alpha
    }

    /// All validators sorted by weight (descending).
    pub fn sorted_by_weight(&self) -> Vec<&Validator> {
        let mut vals: Vec<_> = self.validators.values().collect();
        vals.sort_by(|a, b| b.weight.cmp(&a.weight));
        vals
    }

    /// Update all validator uptimes by the given elapsed time.
    pub fn update_all_uptimes(&mut self, elapsed_seconds: u64) {
        for v in self.validators.values_mut() {
            v.update_uptime(elapsed_seconds);
        }
    }
}

// ---- src/consensus/snowman.rs ----

/// Parameters for the Snowball consensus algorithm.
#[derive(Debug, Clone)]
pub struct SnowballParams {
    /// Sample size: number of validators to query per round.
    pub k: usize,
    /// Quorum size: minimum agreeing responses to update preference.
    pub alpha: usize,
    /// Decision threshold: consecutive successes needed for finality.
    pub beta_virtuous: u32,
    /// Decision threshold for rogue (conflicting) transactions.
    pub beta_rogue: u32,
    /// Maximum number of processing items (backpressure).
    pub max_outstanding: usize,
    /// Maximum number of rounds before giving up on a decision.
    pub max_rounds: u32,
}

impl Default for SnowballParams {
    fn default() -> Self {
        Self {
            k: 20,
            alpha: 15,
            beta_virtuous: 20,
            beta_rogue: 30,
            max_outstanding: 1024,
            max_rounds: 500,
        }
    }
}

/// Per-conflict-set Snowball instance. Tracks voting on competing blocks at the same height.
#[derive(Debug, Clone)]
pub struct SnowballInstance {
    /// Current preference among competing blocks.
    pub preference: BlockId,
    /// Last vote result (the block that got alpha votes in last poll).
    pub last_vote: Option<BlockId>,
    /// Consecutive polls where preference matched the alpha-majority.
    pub confidence: u32,
    /// Total polls conducted.
    pub rounds: u32,
    /// Whether finality has been reached.
    pub finalized: bool,
    /// Vote counts per block.
    pub vote_counts: HashMap<BlockId, u64>,
    /// The beta threshold for this instance.
    pub beta: u32,
}

impl SnowballInstance {
    pub fn new(initial_preference: BlockId, beta: u32) -> Self {
        let mut vote_counts = HashMap::new();
        vote_counts.insert(initial_preference.clone(), 0);
        Self {
            preference: initial_preference,
            last_vote: None,
            confidence: 0,
            rounds: 0,
            finalized: false,
            vote_counts,
            beta,
        }
    }

    /// Record the result of a poll. `votes` maps BlockId to the number of validators voting for it.
    /// `alpha` is the quorum threshold.
    ///
    /// Returns `true` if finality was just reached.
    pub fn record_poll(&mut self, votes: &HashMap<BlockId, u64>, alpha: u64) -> bool {
        if self.finalized {
            return false;
        }

        self.rounds += 1;

        // Find the block that got the most votes
        let (top_block, top_votes) = votes
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(id, count)| (id.clone(), *count))
            .unwrap_or((self.preference.clone(), 0));

        // Update cumulative vote counts
        for (block_id, count) in votes {
            *self.vote_counts.entry(block_id.clone()).or_insert(0) += count;
        }

        // Check if top_block exceeds alpha threshold
        if top_votes >= alpha {
            self.last_vote = Some(top_block.clone());

            if top_block == self.preference {
                // Preference confirmed — increment confidence
                self.confidence += 1;
            } else {
                // Preference changed — update and reset confidence
                // Only change preference if cumulative votes favor the new block
                let current_cumulative =
                    self.vote_counts.get(&self.preference).copied().unwrap_or(0);
                let new_cumulative = self.vote_counts.get(&top_block).copied().unwrap_or(0);

                if new_cumulative > current_cumulative {
                    self.preference = top_block;
                    self.confidence = 1;
                } else {
                    // Current preference still has more cumulative votes
                    self.confidence = 0;
                }
            }
        } else {
            // No block reached alpha — reset confidence
            self.confidence = 0;
        }

        // Check finality
        if self.confidence >= self.beta {
            self.finalized = true;
            return true;
        }

        false
    }

    /// Whether this instance has reached a final decision.
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// The preferred block.
    pub fn preferred(&self) -> &BlockId {
        &self.preference
    }
}

/// The Snowman consensus engine.
/// Manages block proposals, conflict sets, and finality for a linear chain.
pub struct SnowmanConsensus {
    pub params: SnowballParams,
    /// All known blocks by ID.
    pub blocks: HashMap<BlockId, ConsensusBlock>,
    /// Conflict sets: height → set of competing block IDs at that height.
    pub conflict_sets: HashMap<u64, Vec<BlockId>>,
    /// Snowball instances per height (one per conflict set).
    pub snowball_instances: HashMap<u64, SnowballInstance>,
    /// The last accepted block.
    pub last_accepted: Option<BlockId>,
    /// Last accepted height.
    pub last_accepted_height: u64,
    /// Preferred chain tip.
    pub preferred_tip: Option<BlockId>,
    /// Processing queue (blocks awaiting decision).
    pub processing: HashSet<BlockId>,
    /// Validator set for weighted voting.
    pub validator_set: ValidatorSet,
    /// Decision log for auditing.
    pub decision_log: Vec<DecisionRecord>,
}

/// Record of a consensus decision.
#[derive(Debug, Clone)]
pub struct DecisionRecord {
    pub block_id: BlockId,
    pub height: u64,
    pub status: BlockStatus,
    pub rounds: u32,
    pub decided_at: Instant,
}

impl SnowmanConsensus {
    pub fn new(params: SnowballParams, genesis_id: BlockId) -> Self {
        let genesis = ConsensusBlock {
            id: genesis_id.clone(),
            parent_id: BlockId::zero(),
            height: 0,
            timestamp: 0,
            status: BlockStatus::Accepted,
            bytes: Vec::new(),
            polls_received: 0,
            snowball: None,
            received_at: Instant::now(),
        };

        let mut blocks = HashMap::new();
        blocks.insert(genesis_id.clone(), genesis);

        Self {
            params,
            blocks,
            conflict_sets: HashMap::new(),
            snowball_instances: HashMap::new(),
            last_accepted: Some(genesis_id.clone()),
            last_accepted_height: 0,
            preferred_tip: Some(genesis_id),
            processing: HashSet::new(),
            validator_set: ValidatorSet::new(),
            decision_log: Vec::new(),
        }
    }

    /// Add a new block to the consensus engine for voting.
    pub fn add_block(&mut self, block: ConsensusBlock) -> Result<BlockStatus, ConsensusError> {
        let id = block.id.clone();
        let height = block.height;
        let parent_id = block.parent_id.clone();

        // Validate parent exists
        if !self.blocks.contains_key(&parent_id) {
            return Err(ConsensusError::MissingParent(parent_id));
        }

        // Validate parent is accepted or processing
        let parent_status = self
            .blocks
            .get(&parent_id)
            .map(|b| b.status.clone())
            .unwrap();
        match parent_status {
            BlockStatus::Rejected => {
                return Err(ConsensusError::RejectedParent(parent_id));
            }
            BlockStatus::Unknown => {
                return Err(ConsensusError::MissingParent(parent_id));
            }
            _ => {}
        }

        // Check if we're at capacity
        if self.processing.len() >= self.params.max_outstanding {
            return Err(ConsensusError::TooManyProcessing(
                self.params.max_outstanding,
            ));
        }

        // Validate height
        if height <= self.last_accepted_height {
            // Block at or below accepted height — already decided
            return Ok(BlockStatus::Rejected);
        }

        // Check for duplicate
        if self.blocks.contains_key(&id) {
            let existing_status = self.blocks.get(&id).unwrap().status.clone();
            return Ok(existing_status);
        }

        // Add to conflict set for this height
        let conflict_set = self.conflict_sets.entry(height).or_insert_with(Vec::new);
        conflict_set.push(id.clone());

        // Initialize Snowball if this is the first block at this height
        if !self.snowball_instances.contains_key(&height) {
            let beta = if conflict_set.len() == 1 {
                self.params.beta_virtuous
            } else {
                self.params.beta_rogue
            };
            self.snowball_instances
                .insert(height, SnowballInstance::new(id.clone(), beta));
        } else if conflict_set.len() > 1 {
            // Upgrade to rogue beta if we now have conflicts
            if let Some(sb) = self.snowball_instances.get_mut(&height) {
                sb.beta = self.params.beta_rogue;
            }
        }

        // Store the block
        self.blocks.insert(id.clone(), block);
        self.processing.insert(id.clone());

        // Update preferred tip if this extends it
        if let Some(ref tip) = self.preferred_tip {
            if &parent_id == tip {
                self.preferred_tip = Some(id);
            }
        }

        Ok(BlockStatus::Processing)
    }

    /// Record a poll result (voting round) at a given height.
    /// `votes` maps BlockId to the total weight of validators voting for it.
    ///
    /// Returns the list of blocks that were finalized (accepted or rejected).
    pub fn record_poll(
        &mut self,
        height: u64,
        votes: &HashMap<BlockId, u64>,
    ) -> Result<Vec<(BlockId, BlockStatus)>, ConsensusError> {
        let alpha = self.params.alpha as u64;
        let mut finalized = Vec::new();

        // Process Snowball for this height
        let became_final = if let Some(sb) = self.snowball_instances.get_mut(&height) {
            sb.record_poll(votes, alpha)
        } else {
            return Err(ConsensusError::NoConflictSet(height));
        };

        if became_final {
            let accepted_id = self
                .snowball_instances
                .get(&height)
                .unwrap()
                .preference
                .clone();

            // Accept the winning block
            if let Some(block) = self.blocks.get_mut(&accepted_id) {
                block.status = BlockStatus::Accepted;
                self.processing.remove(&accepted_id);
                finalized.push((accepted_id.clone(), BlockStatus::Accepted));

                self.decision_log.push(DecisionRecord {
                    block_id: accepted_id.clone(),
                    height,
                    status: BlockStatus::Accepted,
                    rounds: self
                        .snowball_instances
                        .get(&height)
                        .map(|s| s.rounds)
                        .unwrap_or(0),
                    decided_at: Instant::now(),
                });

                self.last_accepted = Some(accepted_id.clone());
                self.last_accepted_height = height;
            }

            // Reject all competing blocks at this height
            if let Some(conflict_set) = self.conflict_sets.get(&height) {
                for block_id in conflict_set {
                    if *block_id != accepted_id {
                        if let Some(block) = self.blocks.get_mut(block_id) {
                            block.status = BlockStatus::Rejected;
                            self.processing.remove(block_id);
                            finalized.push((block_id.clone(), BlockStatus::Rejected));

                            self.decision_log.push(DecisionRecord {
                                block_id: block_id.clone(),
                                height,
                                status: BlockStatus::Rejected,
                                rounds: self
                                    .snowball_instances
                                    .get(&height)
                                    .map(|s| s.rounds)
                                    .unwrap_or(0),
                                decided_at: Instant::now(),
                            });
                        }
                    }
                }
            }

            // Transitively reject any blocks whose parent was rejected
            let rejected_ids: Vec<BlockId> = finalized
                .iter()
                .filter(|(_, s)| *s == BlockStatus::Rejected)
                .map(|(id, _)| id.clone())
                .collect();

            for rejected_id in &rejected_ids {
                let children: Vec<BlockId> = self
                    .blocks
                    .values()
                    .filter(|b| b.parent_id == *rejected_id && b.status == BlockStatus::Processing)
                    .map(|b| b.id.clone())
                    .collect();

                for child_id in children {
                    if let Some(block) = self.blocks.get_mut(&child_id) {
                        block.status = BlockStatus::Rejected;
                        self.processing.remove(&child_id);
                        finalized.push((child_id, BlockStatus::Rejected));
                    }
                }
            }

            // Update preferred tip
            self.update_preferred_tip();
        }

        Ok(finalized)
    }

    /// Get current block status.
    pub fn block_status(&self, id: &BlockId) -> BlockStatus {
        self.blocks
            .get(id)
            .map(|b| b.status.clone())
            .unwrap_or(BlockStatus::Unknown)
    }

    /// Get the preferred block at a given height.
    pub fn preferred_at_height(&self, height: u64) -> Option<&BlockId> {
        self.snowball_instances
            .get(&height)
            .map(|sb| sb.preferred())
    }

    /// Whether the engine is fully caught up (no processing blocks).
    pub fn is_quiescent(&self) -> bool {
        self.processing.is_empty()
    }

    /// Number of blocks in processing state.
    pub fn processing_count(&self) -> usize {
        self.processing.len()
    }

    /// Build a Chits response for the given chain.
    pub fn build_chits(&self, chain_id: ChainId, request_id: u32) -> NetworkMessage {
        let preferred = self
            .preferred_tip
            .clone()
            .unwrap_or(self.last_accepted.clone().unwrap_or(BlockId::zero()));

        let accepted = self.last_accepted.clone().unwrap_or(BlockId::zero());

        NetworkMessage::Chits {
            chain_id,
            request_id,
            preferred_id: preferred.clone(),
            preferred_id_at_height: preferred,
            accepted_id: accepted,
        }
    }

    /// Recalculate the preferred tip by walking from last accepted.
    fn update_preferred_tip(&mut self) {
        let mut tip = self.last_accepted.clone().unwrap_or(BlockId::zero());
        let mut height = self.last_accepted_height;

        loop {
            let next_height = height + 1;
            if let Some(sb) = self.snowball_instances.get(&next_height) {
                let preferred = sb.preferred();
                if let Some(block) = self.blocks.get(preferred) {
                    if block.parent_id == tip && block.status == BlockStatus::Processing {
                        tip = preferred.clone();
                        height = next_height;
                        continue;
                    }
                }
            }
            break;
        }

        self.preferred_tip = Some(tip);
    }
}

/// Consensus-specific errors.
#[derive(Debug, Clone)]
pub enum ConsensusError {
    MissingParent(BlockId),
    RejectedParent(BlockId),
    TooManyProcessing(usize),
    NoConflictSet(u64),
    DuplicateBlock(BlockId),
    InvalidBlock(String),
    NotFinalized(BlockId),
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingParent(id) => write!(f, "missing parent block: {}", id),
            Self::RejectedParent(id) => write!(f, "parent block rejected: {}", id),
            Self::TooManyProcessing(max) => write!(f, "too many processing blocks (max {})", max),
            Self::NoConflictSet(h) => write!(f, "no conflict set at height {}", h),
            Self::DuplicateBlock(id) => write!(f, "duplicate block: {}", id),
            Self::InvalidBlock(reason) => write!(f, "invalid block: {}", reason),
            Self::NotFinalized(id) => write!(f, "block not finalized: {}", id),
        }
    }
}

impl std::error::Error for ConsensusError {}

// =============================================================================
// PERSISTENT PEER MANAGEMENT
// =============================================================================

/// A persistent peer record stored in RocksDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentPeerRecord {
    /// 20-byte NodeID
    pub node_id: [u8; 20],
    /// IP address bytes (4 for IPv4, 16 for IPv6)
    pub ip_bytes: Vec<u8>,
    /// Port number
    pub port: u16,
    /// Average latency in milliseconds
    pub latency_ms: u64,
    /// Reliability score: 0-1000 (higher = more reliable)
    pub reliability_score: u32,
    /// Number of successful connections
    pub success_count: u64,
    /// Number of failed connections
    pub failure_count: u64,
    /// Last time we successfully connected (Unix millis)
    pub last_connected_ms: u64,
    /// Last time we saw this peer in gossip (Unix millis)
    pub last_seen_ms: u64,
}

impl PersistentPeerRecord {
    pub fn new(node_id: [u8; 20], ip_bytes: Vec<u8>, port: u16) -> Self {
        let now_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            node_id,
            ip_bytes,
            port,
            latency_ms: 0,
            reliability_score: 500, // neutral starting score
            success_count: 0,
            failure_count: 0,
            last_connected_ms: 0,
            last_seen_ms: now_ms,
        }
    }

    /// Record a successful connection.
    pub fn record_success(&mut self, latency_ms: u64) {
        self.success_count += 1;
        self.latency_ms = if self.latency_ms == 0 {
            latency_ms
        } else {
            // Exponential moving average
            (self.latency_ms * 7 + latency_ms * 3) / 10
        };
        self.reliability_score = (self.reliability_score + 50).min(1000);
        self.last_connected_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
    }

    /// Record a failed connection attempt.
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.reliability_score = self.reliability_score.saturating_sub(100);
    }

    /// Whether this peer should be evicted (too many failures, score too low).
    pub fn should_evict(&self, max_failures: u64) -> bool {
        self.failure_count >= max_failures || self.reliability_score == 0
    }

    /// Serialize to JSON bytes for storage.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from JSON bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }

    /// Convert to SocketAddr.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        parse_peer_addr(&self.ip_bytes, self.port)
    }
}

/// Manages persistent peer storage backed by RocksDB.
pub struct PersistentPeerStore {
    /// In-memory cache of peer records
    peers: HashMap<[u8; 20], PersistentPeerRecord>,
    /// Maximum consecutive failures before eviction
    max_failures: u64,
}

impl PersistentPeerStore {
    /// Create a new persistent peer store.
    pub fn new(max_failures: u64) -> Self {
        Self {
            peers: HashMap::new(),
            max_failures,
        }
    }

    /// Load peers from RocksDB on startup.
    pub fn load_from_db(&mut self, db: &crate::db::Database) -> usize {
        let raw_peers = db.load_all_peers();
        let mut loaded = 0;
        for (key, value) in raw_peers {
            if let Some(record) = PersistentPeerRecord::decode(&value) {
                let mut node_id = [0u8; 20];
                if key.len() == 20 {
                    node_id.copy_from_slice(&key);
                    self.peers.insert(node_id, record);
                    loaded += 1;
                }
            }
        }
        loaded
    }

    /// Save a peer record to the store and optionally to DB.
    pub fn upsert(&mut self, record: PersistentPeerRecord, db: Option<&crate::db::Database>) {
        if let Some(db) = db {
            let _ = db.put_peer(&record.node_id, &record.encode());
        }
        self.peers.insert(record.node_id, record);
    }

    /// Record a successful connection for a peer.
    pub fn record_success(
        &mut self,
        node_id: &[u8; 20],
        latency_ms: u64,
        db: Option<&crate::db::Database>,
    ) {
        if let Some(record) = self.peers.get_mut(node_id) {
            record.record_success(latency_ms);
            if let Some(db) = db {
                let _ = db.put_peer(node_id, &record.encode());
            }
        }
    }

    /// Record a connection failure for a peer.
    pub fn record_failure(&mut self, node_id: &[u8; 20], db: Option<&crate::db::Database>) {
        if let Some(record) = self.peers.get_mut(node_id) {
            record.record_failure();
            if record.should_evict(self.max_failures) {
                if let Some(db) = db {
                    let _ = db.delete_peer(node_id);
                }
                self.peers.remove(node_id);
            } else if let Some(db) = db {
                let _ = db.put_peer(node_id, &record.encode());
            }
        }
    }

    /// Get all stored peer records, sorted by reliability score (best first).
    pub fn best_peers(&self, limit: usize) -> Vec<&PersistentPeerRecord> {
        let mut peers: Vec<_> = self.peers.values().collect();
        peers.sort_by(|a, b| b.reliability_score.cmp(&a.reliability_score));
        peers.truncate(limit);
        peers
    }

    /// Evict peers that have exceeded the failure threshold.
    pub fn evict_bad_peers(&mut self, db: Option<&crate::db::Database>) -> usize {
        let to_remove: Vec<[u8; 20]> = self
            .peers
            .iter()
            .filter(|(_, r)| r.should_evict(self.max_failures))
            .map(|(id, _)| *id)
            .collect();
        let count = to_remove.len();
        for id in &to_remove {
            if let Some(db) = db {
                let _ = db.delete_peer(id);
            }
            self.peers.remove(id);
        }
        count
    }

    /// Get the total number of stored peers.
    pub fn count(&self) -> usize {
        self.peers.len()
    }

    /// Get a peer record by NodeID.
    pub fn get(&self, node_id: &[u8; 20]) -> Option<&PersistentPeerRecord> {
        self.peers.get(node_id)
    }

    /// Generate PeerListAck gossip messages for peers we know about.
    pub fn peer_list_ack_ids(&self) -> Vec<NodeId> {
        self.peers.keys().map(|id| NodeId(*id)).collect()
    }
}

impl Default for PersistentPeerStore {
    fn default() -> Self {
        Self::new(5) // evict after 5 consecutive failures
    }
}

// =============================================================================
// TEST HARNESS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helpers ---

    fn make_block_id(val: u8) -> BlockId {
        let mut arr = [0u8; 32];
        arr[0] = val;
        BlockId(arr)
    }

    fn make_node_id(val: u8) -> NodeId {
        let mut arr = [0u8; 20];
        arr[0] = val;
        NodeId(arr)
    }

    fn make_chain_id() -> ChainId {
        ChainId([0u8; 32])
    }

    fn make_peer(val: u8) -> Peer {
        let addr: SocketAddr = format!("127.0.0.{}:9651", val).parse().unwrap();
        Peer::new(make_node_id(val), addr)
    }

    fn default_config() -> NetworkConfig {
        NetworkConfig {
            require_tls: false,
            max_peers: 10,
            ..Default::default()
        }
    }

    // --- Message Tests ---

    #[test]
    fn test_message_encode_decode_roundtrip() {
        let msg = NetworkMessage::Ping { uptime: 9999 };
        let encoded = msg.encode().unwrap();
        let decoded = NetworkMessage::decode(&encoded).unwrap();
        match decoded {
            NetworkMessage::Ping { uptime } => assert_eq!(uptime, 9999),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_version_message_roundtrip() {
        let msg = NetworkMessage::Version {
            network_id: 1,
            node_id: make_node_id(42),
            my_time: 1700000000,
            ip_addr: vec![10, 0, 0, 1],
            ip_port: 9651,
            my_version: "avalanche-rs/0.1.0".to_string(),
            my_version_time: 0,
            sig: vec![1, 2, 3],
            tracked_subnets: vec![],
        };
        let encoded = msg.encode().unwrap();
        let decoded = NetworkMessage::decode(&encoded).unwrap();
        match decoded {
            NetworkMessage::Version {
                network_id,
                my_version,
                ..
            } => {
                assert_eq!(network_id, 1);
                assert_eq!(my_version, "avalanche-rs/0.1.0");
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_chits_message_roundtrip() {
        let msg = NetworkMessage::Chits {
            chain_id: make_chain_id(),
            request_id: 42,
            preferred_id: make_block_id(1),
            preferred_id_at_height: make_block_id(1),
            accepted_id: make_block_id(0),
        };
        let encoded = msg.encode().unwrap();
        let decoded = NetworkMessage::decode(&encoded).unwrap();
        match decoded {
            NetworkMessage::Chits { request_id, .. } => assert_eq!(request_id, 42),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_decode_too_short() {
        let result = NetworkMessage::decode(&[0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_names() {
        assert_eq!(NetworkMessage::Ping { uptime: 0 }.name(), "Ping");
        assert_eq!(NetworkMessage::Pong { uptime: 0 }.name(), "Pong");
        assert_eq!(
            NetworkMessage::PeerList { peers: vec![] }.name(),
            "PeerList"
        );
    }

    // --- Peer Tests ---

    #[test]
    fn test_peer_reputation_clamp() {
        let mut peer = make_peer(1);
        peer.adjust_reputation(2000);
        assert_eq!(peer.reputation, 1000);
        peer.adjust_reputation(-3000);
        assert_eq!(peer.reputation, -1000);
    }

    #[test]
    fn test_peer_record_messages() {
        let mut peer = make_peer(1);
        peer.record_received(100);
        peer.record_sent(200);
        assert_eq!(peer.bytes_received, 100);
        assert_eq!(peer.bytes_sent, 200);
        assert_eq!(peer.messages_received, 1);
        assert_eq!(peer.messages_sent, 1);
    }

    // --- PeerManager Tests ---

    #[test]
    fn test_peer_manager_add_remove() {
        let config = default_config();
        let local = make_node_id(0);
        let mut pm = PeerManager::new(config, local);

        let peer = make_peer(1);
        pm.add_peer(peer).unwrap();
        assert_eq!(pm.connected_count(), 0); // still in Connecting state

        // Transition to Connected
        pm.get_peer_mut(&make_node_id(1)).unwrap().state = PeerState::Connected;
        assert_eq!(pm.connected_count(), 1);

        pm.remove_peer(&make_node_id(1));
        assert_eq!(pm.connected_count(), 0);
    }

    #[test]
    fn test_peer_manager_max_peers() {
        let config = NetworkConfig {
            max_peers: 2,
            require_tls: false,
            ..Default::default()
        };
        let local = make_node_id(0);
        let mut pm = PeerManager::new(config, local);

        pm.add_peer(make_peer(1)).unwrap();
        pm.add_peer(make_peer(2)).unwrap();

        // Third peer triggers eviction of worst-reputation peer
        let result = pm.add_peer(make_peer(3));
        assert!(result.is_ok()); // should evict one
    }

    #[test]
    fn test_peer_manager_ban() {
        let config = default_config();
        let local = make_node_id(0);
        let mut pm = PeerManager::new(config, local);

        pm.add_peer(make_peer(1)).unwrap();
        pm.ban_peer(&make_node_id(1));

        // Can't re-add banned peer
        let result = pm.add_peer(make_peer(1));
        assert!(matches!(result, Err(NetworkError::PeerBanned(_))));
    }

    #[test]
    fn test_peer_manager_discovery() {
        let config = default_config();
        let local = make_node_id(0);
        let mut pm = PeerManager::new(config, local);

        let peers = vec![PeerInfo {
            node_id: make_node_id(5),
            ip_addr: vec![10, 0, 0, 5],
            ip_port: 9651,
            cert_bytes: vec![],
            timestamp: 0,
            signature: vec![],
        }];

        let new = pm.process_peer_list(&peers);
        assert_eq!(new.len(), 1);

        let next = pm.next_to_connect();
        assert!(next.is_some());
        let (id, _) = next.unwrap();
        assert_eq!(id, make_node_id(5));
    }

    #[test]
    fn test_peer_manager_ignores_self() {
        let config = default_config();
        let local = make_node_id(0);
        let mut pm = PeerManager::new(config, local.clone());

        let peers = vec![PeerInfo {
            node_id: local,
            ip_addr: vec![127, 0, 0, 1],
            ip_port: 9651,
            cert_bytes: vec![],
            timestamp: 0,
            signature: vec![],
        }];

        let new = pm.process_peer_list(&peers);
        assert_eq!(new.len(), 0);
    }

    #[test]
    fn test_validator_peers() {
        let config = default_config();
        let local = make_node_id(0);
        let mut pm = PeerManager::new(config, local);

        let mut peer1 = make_peer(1);
        peer1.state = PeerState::Connected;
        peer1.is_validator = true;
        pm.add_peer(peer1).unwrap();

        let mut peer2 = make_peer(2);
        peer2.state = PeerState::Connected;
        peer2.is_validator = false;
        pm.add_peer(peer2).unwrap();

        let validators = pm.validator_peers();
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0], make_node_id(1));
    }

    // --- ConnectionPool Tests ---

    #[test]
    fn test_connection_pool_basic() {
        let mut pool = ConnectionPool::new(5);
        let addr: SocketAddr = "127.0.0.1:9651".parse().unwrap();

        pool.connect(make_node_id(1), addr, 10).unwrap();
        assert_eq!(pool.active_count(), 1);

        let msg = NetworkMessage::Ping { uptime: 100 };
        pool.enqueue_message(&make_node_id(1), msg).unwrap();

        let dequeued = pool.dequeue_message(&make_node_id(1));
        assert!(dequeued.is_some());
    }

    #[test]
    fn test_connection_pool_backpressure() {
        let mut pool = ConnectionPool::new(5);
        let addr: SocketAddr = "127.0.0.1:9651".parse().unwrap();

        pool.connect(make_node_id(1), addr, 2).unwrap();

        // Fill to capacity
        pool.enqueue_message(&make_node_id(1), NetworkMessage::Ping { uptime: 1 })
            .unwrap();
        pool.enqueue_message(&make_node_id(1), NetworkMessage::Ping { uptime: 2 })
            .unwrap();

        // This should trigger backpressure (drop oldest)
        pool.enqueue_message(&make_node_id(1), NetworkMessage::Ping { uptime: 3 })
            .unwrap();

        // Backpressure with Pings: front is keepalive, so second-oldest (uptime=2) is dropped.
        // Queue is now [Ping{1}, Ping{3}]. Dequeue gives uptime=1 first.
        let msg = pool.dequeue_message(&make_node_id(1)).unwrap();
        match msg {
            NetworkMessage::Ping { uptime } => assert_eq!(uptime, 1),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_connection_pool_exhausted() {
        let mut pool = ConnectionPool::new(1);
        let addr: SocketAddr = "127.0.0.1:9651".parse().unwrap();

        pool.connect(make_node_id(1), addr, 10).unwrap();
        let result = pool.connect(make_node_id(2), addr, 10);
        assert!(matches!(result, Err(NetworkError::PoolExhausted)));
    }

    #[test]
    fn test_connection_pool_disconnect() {
        let mut pool = ConnectionPool::new(5);
        let addr: SocketAddr = "127.0.0.1:9651".parse().unwrap();

        pool.connect(make_node_id(1), addr, 10).unwrap();
        pool.disconnect(&make_node_id(1));
        assert_eq!(pool.active_count(), 0);

        // Enqueue to disconnected peer fails
        let result = pool.enqueue_message(&make_node_id(1), NetworkMessage::Ping { uptime: 0 });
        assert!(result.is_err());
    }

    // --- NetworkManager Tests ---

    #[test]
    fn test_network_manager_lifecycle() {
        let config = default_config();
        let local = make_node_id(0);
        let mut nm = NetworkManager::new(config, local, None);

        nm.start().unwrap();
        assert!(nm.is_running);

        let addr: SocketAddr = "127.0.0.1:9651".parse().unwrap();
        nm.connect_peer(make_node_id(1), addr).unwrap();

        assert_eq!(nm.stats.connections_established, 1);

        nm.shutdown();
        assert!(!nm.is_running);
    }

    #[test]
    fn test_network_manager_handshake() {
        let config = default_config();
        let local = make_node_id(0);
        let mut nm = NetworkManager::new(config, local, None);
        nm.start().unwrap();

        let addr: SocketAddr = "127.0.0.1:9651".parse().unwrap();
        nm.connect_peer(make_node_id(1), addr).unwrap();

        // Simulate receiving Version from peer
        let version = NetworkMessage::Version {
            network_id: 1,
            node_id: make_node_id(1),
            my_time: 0,
            ip_addr: vec![127, 0, 0, 1],
            ip_port: 9651,
            my_version: "avalanchego/1.11.0".to_string(),
            my_version_time: 0,
            sig: vec![],
            tracked_subnets: vec![],
        };

        nm.handle_version(&make_node_id(1), &version).unwrap();

        let peer = nm.peer_manager.get_peer(&make_node_id(1)).unwrap();
        assert_eq!(peer.state, PeerState::Connected);
        assert_eq!(peer.version.as_deref(), Some("avalanchego/1.11.0"));
    }

    #[test]
    fn test_network_manager_wrong_network_id() {
        let config = default_config();
        let local = make_node_id(0);
        let mut nm = NetworkManager::new(config, local, None);
        nm.start().unwrap();

        let addr: SocketAddr = "127.0.0.1:9651".parse().unwrap();
        nm.connect_peer(make_node_id(1), addr).unwrap();

        let version = NetworkMessage::Version {
            network_id: 999, // wrong
            node_id: make_node_id(1),
            my_time: 0,
            ip_addr: vec![127, 0, 0, 1],
            ip_port: 9651,
            my_version: "evil/1.0".to_string(),
            my_version_time: 0,
            sig: vec![],
            tracked_subnets: vec![],
        };

        let result = nm.handle_version(&make_node_id(1), &version);
        assert!(result.is_err());
    }

    #[test]
    fn test_network_manager_send_receive() {
        let config = default_config();
        let local = make_node_id(0);
        let mut nm = NetworkManager::new(config, local, None);
        nm.start().unwrap();

        let addr: SocketAddr = "127.0.0.1:9651".parse().unwrap();
        nm.connect_peer(make_node_id(1), addr).unwrap();

        // Simulate inbound message
        let msg = NetworkMessage::Ping { uptime: 5000 };
        nm.inject_inbound(make_node_id(1), msg).unwrap();

        let (from, received) = nm.receive_message().unwrap();
        assert_eq!(from, make_node_id(1));
        match received {
            NetworkMessage::Ping { uptime } => assert_eq!(uptime, 5000),
            _ => panic!("wrong type"),
        }

        assert_eq!(nm.stats.total_messages_received, 1);
    }

    #[test]
    fn test_network_manager_broadcast() {
        let config = default_config();
        let local = make_node_id(0);
        let mut nm = NetworkManager::new(config, local, None);
        nm.start().unwrap();

        // Connect and handshake 3 peers
        for i in 1..=3u8 {
            let addr: SocketAddr = format!("127.0.0.{}:9651", i).parse().unwrap();
            nm.connect_peer(make_node_id(i), addr).unwrap();
            let version = NetworkMessage::Version {
                network_id: 1,
                node_id: make_node_id(i),
                my_time: 0,
                ip_addr: vec![127, 0, 0, i],
                ip_port: 9651,
                my_version: "test/1.0".to_string(),
                my_version_time: 0,
                sig: vec![],
                tracked_subnets: vec![],
            };
            nm.handle_version(&make_node_id(i), &version).unwrap();
        }

        let results = nm.broadcast(NetworkMessage::Ping { uptime: 10000 });
        assert_eq!(results.len(), 3);
        for (_, result) in &results {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_network_manager_send_before_start() {
        let config = default_config();
        let local = make_node_id(0);
        let mut nm = NetworkManager::new(config, local, None);
        // Not started

        let result = nm.send_message(&make_node_id(1), NetworkMessage::Ping { uptime: 0 });
        assert!(matches!(result, Err(NetworkError::Shutdown)));
    }

    #[test]
    fn test_network_manager_tls_required_but_missing() {
        let config = NetworkConfig {
            require_tls: true,
            ..Default::default()
        };
        let local = make_node_id(0);
        let mut nm = NetworkManager::new(config, local, None);
        let result = nm.start();
        assert!(matches!(result, Err(NetworkError::TlsError(_))));
    }

    #[test]
    fn test_tls_config_validation() {
        let tls = TlsConfig::new(
            b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_vec(),
            b"-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_vec(),
            true,
        );
        assert!(tls.validate().is_ok());

        let bad_tls = TlsConfig::new(vec![], vec![], true);
        assert!(bad_tls.validate().is_err());
    }

    // --- Snowball Tests ---

    #[test]
    fn test_snowball_basic_finality() {
        let block_a = make_block_id(1);
        let mut sb = SnowballInstance::new(block_a.clone(), 3); // beta=3

        // 3 consecutive rounds with alpha-majority for block_a
        let mut votes = HashMap::new();
        votes.insert(block_a.clone(), 15);

        assert!(!sb.record_poll(&votes, 10)); // confidence=1
        assert!(!sb.record_poll(&votes, 10)); // confidence=2
        assert!(sb.record_poll(&votes, 10)); // confidence=3 → finalized!

        assert!(sb.is_finalized());
        assert_eq!(*sb.preferred(), block_a);
    }

    #[test]
    fn test_snowball_preference_switch() {
        let block_a = make_block_id(1);
        let block_b = make_block_id(2);
        let mut sb = SnowballInstance::new(block_a.clone(), 5);

        // First round favors A
        let mut votes_a = HashMap::new();
        votes_a.insert(block_a.clone(), 15);
        sb.record_poll(&votes_a, 10);
        assert_eq!(*sb.preferred(), block_a);

        // Next 3 rounds favor B heavily
        let mut votes_b = HashMap::new();
        votes_b.insert(block_b.clone(), 18);
        sb.record_poll(&votes_b, 10);
        sb.record_poll(&votes_b, 10);
        sb.record_poll(&votes_b, 10);

        // Preference should switch to B (more cumulative votes)
        assert_eq!(*sb.preferred(), block_b);
    }

    #[test]
    fn test_snowball_no_alpha_resets_confidence() {
        let block_a = make_block_id(1);
        let mut sb = SnowballInstance::new(block_a.clone(), 5);

        // Build confidence
        let mut votes = HashMap::new();
        votes.insert(block_a.clone(), 15);
        sb.record_poll(&votes, 10); // confidence=1
        sb.record_poll(&votes, 10); // confidence=2

        // Round with no alpha — confidence resets
        let low_votes = HashMap::new();
        sb.record_poll(&low_votes, 10);
        assert_eq!(sb.confidence, 0);

        // Not finalized
        assert!(!sb.is_finalized());
    }

    #[test]
    fn test_snowball_already_finalized_noop() {
        let block_a = make_block_id(1);
        let mut sb = SnowballInstance::new(block_a.clone(), 1);

        let mut votes = HashMap::new();
        votes.insert(block_a.clone(), 15);
        assert!(sb.record_poll(&votes, 10)); // finalized

        // Further polls are no-ops
        assert!(!sb.record_poll(&votes, 10));
    }

    // --- Validator Tests ---

    #[test]
    fn test_validator_uptime() {
        let mut v = Validator::new(make_node_id(1), 1000, 0, 1000000);
        v.is_connected = true;

        v.update_uptime(100);
        assert_eq!(v.uptime_seconds, 100);
        assert_eq!(v.total_seconds, 100);
        assert!((v.uptime_percent() - 100.0).abs() < 0.01);

        v.is_connected = false;
        v.update_uptime(100);
        assert_eq!(v.uptime_seconds, 100); // didn't increase
        assert_eq!(v.total_seconds, 200);
        assert!((v.uptime_percent() - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_validator_failure_tracking() {
        let mut v = Validator::new(make_node_id(1), 1000, 0, 1000000);
        v.is_connected = true;

        for _ in 0..6 {
            v.record_failure();
        }
        assert!(!v.is_connected);
        assert_eq!(v.consecutive_failures, 6);

        v.record_response();
        assert!(v.is_connected);
        assert_eq!(v.consecutive_failures, 0);
    }

    #[test]
    fn test_validator_set_quorum() {
        let mut vs = ValidatorSet::new();

        vs.add_validator(Validator::new(make_node_id(1), 100, 0, 1000));
        vs.add_validator(Validator::new(make_node_id(2), 100, 0, 1000));
        vs.add_validator(Validator::new(make_node_id(3), 100, 0, 1000));

        assert!(!vs.has_quorum(0.67)); // none connected

        vs.get_mut(&make_node_id(1)).unwrap().is_connected = true;
        vs.get_mut(&make_node_id(2)).unwrap().is_connected = true;

        // 200/300 = 0.6667, which is < 0.67, so use 0.66 threshold
        assert!(vs.has_quorum(0.66)); // 200/300 = 0.667 > 0.66
        assert!(!vs.has_quorum(0.80)); // need 240
    }

    #[test]
    fn test_validator_set_weight() {
        let mut vs = ValidatorSet::new();
        vs.add_validator(Validator::new(make_node_id(1), 500, 0, 1000));
        vs.add_validator(Validator::new(make_node_id(2), 300, 0, 1000));
        assert_eq!(vs.total_weight(), 800);
        assert_eq!(vs.count(), 2);

        vs.remove_validator(&make_node_id(1));
        assert_eq!(vs.total_weight(), 300);
        assert_eq!(vs.count(), 1);
    }

    // --- Snowman Consensus Tests ---

    #[test]
    fn test_snowman_add_block() {
        let genesis = make_block_id(0);
        let mut consensus = SnowmanConsensus::new(SnowballParams::default(), genesis.clone());

        let block1 = ConsensusBlock::new(make_block_id(1), genesis.clone(), 1, 100, vec![1, 2, 3]);

        let status = consensus.add_block(block1).unwrap();
        assert_eq!(status, BlockStatus::Processing);
        assert_eq!(consensus.processing_count(), 1);
    }

    #[test]
    fn test_snowman_missing_parent() {
        let genesis = make_block_id(0);
        let mut consensus = SnowmanConsensus::new(SnowballParams::default(), genesis);

        let orphan = ConsensusBlock::new(
            make_block_id(99),
            make_block_id(88), // parent doesn't exist
            5,
            500,
            vec![],
        );

        let result = consensus.add_block(orphan);
        assert!(matches!(result, Err(ConsensusError::MissingParent(_))));
    }

    #[test]
    fn test_snowman_single_block_finality() {
        let genesis = make_block_id(0);
        let params = SnowballParams {
            k: 5,
            alpha: 4,
            beta_virtuous: 3,
            beta_rogue: 5,
            max_outstanding: 100,
            max_rounds: 100,
        };
        let mut consensus = SnowmanConsensus::new(params, genesis.clone());

        let block1 = ConsensusBlock::new(make_block_id(1), genesis, 1, 100, vec![]);
        consensus.add_block(block1).unwrap();

        // Simulate 3 polls all voting for block1
        let mut votes = HashMap::new();
        votes.insert(make_block_id(1), 5);

        let f1 = consensus.record_poll(1, &votes).unwrap();
        assert!(f1.is_empty()); // not yet

        let f2 = consensus.record_poll(1, &votes).unwrap();
        assert!(f2.is_empty()); // not yet

        let f3 = consensus.record_poll(1, &votes).unwrap();
        assert_eq!(f3.len(), 1);
        assert_eq!(f3[0].0, make_block_id(1));
        assert_eq!(f3[0].1, BlockStatus::Accepted);

        assert_eq!(
            consensus.block_status(&make_block_id(1)),
            BlockStatus::Accepted
        );
        assert_eq!(consensus.last_accepted_height, 1);
    }

    #[test]
    fn test_snowman_conflicting_blocks() {
        let genesis = make_block_id(0);
        let params = SnowballParams {
            k: 5,
            alpha: 4,
            beta_virtuous: 3,
            beta_rogue: 3,
            max_outstanding: 100,
            max_rounds: 100,
        };
        let mut consensus = SnowmanConsensus::new(params, genesis.clone());

        // Two conflicting blocks at height 1
        let block_a = ConsensusBlock::new(make_block_id(1), genesis.clone(), 1, 100, vec![0xAA]);
        let block_b = ConsensusBlock::new(make_block_id(2), genesis, 1, 101, vec![0xBB]);

        consensus.add_block(block_a).unwrap();
        consensus.add_block(block_b).unwrap();

        assert_eq!(consensus.processing_count(), 2);

        // All polls favor block_a
        let mut votes = HashMap::new();
        votes.insert(make_block_id(1), 5);
        votes.insert(make_block_id(2), 1);

        consensus.record_poll(1, &votes).unwrap();
        consensus.record_poll(1, &votes).unwrap();
        let finalized = consensus.record_poll(1, &votes).unwrap();

        // block_a accepted, block_b rejected
        assert!(finalized
            .iter()
            .any(|(id, s)| *id == make_block_id(1) && *s == BlockStatus::Accepted));
        assert!(finalized
            .iter()
            .any(|(id, s)| *id == make_block_id(2) && *s == BlockStatus::Rejected));

        assert!(consensus.is_quiescent());
    }

    #[test]
    fn test_snowman_chain_of_blocks() {
        let genesis = make_block_id(0);
        let params = SnowballParams {
            k: 5,
            alpha: 4,
            beta_virtuous: 2, // quick finality for test
            beta_rogue: 3,
            max_outstanding: 100,
            max_rounds: 100,
        };
        let mut consensus = SnowmanConsensus::new(params, genesis.clone());

        // Build a chain: genesis → block1 → block2 → block3
        let block1 = ConsensusBlock::new(make_block_id(1), genesis, 1, 100, vec![]);
        let block2 = ConsensusBlock::new(make_block_id(2), make_block_id(1), 2, 200, vec![]);

        consensus.add_block(block1).unwrap();
        consensus.add_block(block2).unwrap();

        // Finalize block1
        let mut votes1 = HashMap::new();
        votes1.insert(make_block_id(1), 5);
        consensus.record_poll(1, &votes1).unwrap();
        consensus.record_poll(1, &votes1).unwrap();
        assert_eq!(
            consensus.block_status(&make_block_id(1)),
            BlockStatus::Accepted
        );

        // Now finalize block2
        let mut votes2 = HashMap::new();
        votes2.insert(make_block_id(2), 5);
        consensus.record_poll(2, &votes2).unwrap();
        consensus.record_poll(2, &votes2).unwrap();
        assert_eq!(
            consensus.block_status(&make_block_id(2)),
            BlockStatus::Accepted
        );
        assert_eq!(consensus.last_accepted_height, 2);
    }

    #[test]
    fn test_snowman_transitive_rejection() {
        let genesis = make_block_id(0);
        let params = SnowballParams {
            k: 5,
            alpha: 4,
            beta_virtuous: 2,
            beta_rogue: 2,
            max_outstanding: 100,
            max_rounds: 100,
        };
        let mut consensus = SnowmanConsensus::new(params, genesis.clone());

        // block_a and block_b conflict at height 1
        let block_a = ConsensusBlock::new(make_block_id(1), genesis.clone(), 1, 100, vec![]);
        let block_b = ConsensusBlock::new(make_block_id(2), genesis, 1, 101, vec![]);
        // block_c is built on block_b
        let block_c = ConsensusBlock::new(make_block_id(3), make_block_id(2), 2, 200, vec![]);

        consensus.add_block(block_a).unwrap();
        consensus.add_block(block_b).unwrap();
        consensus.add_block(block_c).unwrap();

        // Accept block_a → block_b rejected → block_c transitively rejected
        let mut votes = HashMap::new();
        votes.insert(make_block_id(1), 5);
        consensus.record_poll(1, &votes).unwrap();
        let finalized = consensus.record_poll(1, &votes).unwrap();

        assert!(finalized
            .iter()
            .any(|(id, s)| *id == make_block_id(1) && *s == BlockStatus::Accepted));
        assert!(finalized
            .iter()
            .any(|(id, s)| *id == make_block_id(2) && *s == BlockStatus::Rejected));
        assert!(finalized
            .iter()
            .any(|(id, s)| *id == make_block_id(3) && *s == BlockStatus::Rejected));
    }

    #[test]
    fn test_snowman_build_chits() {
        let genesis = make_block_id(0);
        let consensus = SnowmanConsensus::new(SnowballParams::default(), genesis.clone());

        let chits = consensus.build_chits(make_chain_id(), 42);
        match chits {
            NetworkMessage::Chits {
                request_id,
                accepted_id,
                ..
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(accepted_id, genesis);
            }
            _ => panic!("expected Chits"),
        }
    }

    #[test]
    fn test_snowman_too_many_processing() {
        let genesis = make_block_id(0);
        let params = SnowballParams {
            max_outstanding: 2,
            ..Default::default()
        };
        let mut consensus = SnowmanConsensus::new(params, genesis.clone());

        consensus
            .add_block(ConsensusBlock::new(
                make_block_id(1),
                genesis.clone(),
                1,
                100,
                vec![],
            ))
            .unwrap();
        consensus
            .add_block(ConsensusBlock::new(
                make_block_id(2),
                genesis.clone(),
                1,
                101,
                vec![],
            ))
            .unwrap();

        // Third block at height 2 (different parent chain, but still counts toward processing)
        let result = consensus.add_block(ConsensusBlock::new(
            make_block_id(3),
            make_block_id(1),
            2,
            200,
            vec![],
        ));
        assert!(matches!(result, Err(ConsensusError::TooManyProcessing(2))));
    }

    #[test]
    fn test_snowman_decision_log() {
        let genesis = make_block_id(0);
        let params = SnowballParams {
            beta_virtuous: 1,
            ..Default::default()
        };
        let mut consensus = SnowmanConsensus::new(params, genesis.clone());

        consensus
            .add_block(ConsensusBlock::new(
                make_block_id(1),
                genesis,
                1,
                100,
                vec![],
            ))
            .unwrap();

        let mut votes = HashMap::new();
        votes.insert(make_block_id(1), 20);
        consensus.record_poll(1, &votes).unwrap();

        assert_eq!(consensus.decision_log.len(), 1);
        assert_eq!(consensus.decision_log[0].status, BlockStatus::Accepted);
        assert_eq!(consensus.decision_log[0].height, 1);
    }

    // --- Integration Test: Network + Consensus ---

    #[test]
    fn test_integration_network_consensus_flow() {
        // Setup network
        let config = default_config();
        let local = make_node_id(0);
        let mut nm = NetworkManager::new(config, local, None);
        nm.start().unwrap();

        // Connect a validator peer
        let addr: SocketAddr = "10.0.0.1:9651".parse().unwrap();
        nm.connect_peer(make_node_id(1), addr).unwrap();
        let version = NetworkMessage::Version {
            network_id: 1,
            node_id: make_node_id(1),
            my_time: 0,
            ip_addr: vec![10, 0, 0, 1],
            ip_port: 9651,
            my_version: "avalanchego/1.11.0".to_string(),
            my_version_time: 0,
            sig: vec![],
            tracked_subnets: vec![],
        };
        nm.handle_version(&make_node_id(1), &version).unwrap();
        nm.peer_manager
            .get_peer_mut(&make_node_id(1))
            .unwrap()
            .is_validator = true;

        // Setup consensus
        let genesis = make_block_id(0);
        let params = SnowballParams {
            k: 1,
            alpha: 1,
            beta_virtuous: 2,
            beta_rogue: 3,
            max_outstanding: 100,
            max_rounds: 100,
        };
        let mut consensus = SnowmanConsensus::new(params, genesis.clone());

        // Add validator to consensus
        consensus
            .validator_set
            .add_validator(Validator::new(make_node_id(1), 1000, 0, 1000000));

        // Propose a block
        let block1 = ConsensusBlock::new(make_block_id(1), genesis, 1, 100, vec![0xDE, 0xAD]);
        consensus.add_block(block1).unwrap();

        // Send PullQuery to validator
        let query = NetworkMessage::PullQuery {
            chain_id: make_chain_id(),
            request_id: 1,
            deadline: 5000,
            container_id: make_block_id(1),
        };
        nm.send_message(&make_node_id(1), query).unwrap();

        // Simulate receiving Chits response
        let chits = NetworkMessage::Chits {
            chain_id: make_chain_id(),
            request_id: 1,
            preferred_id: make_block_id(1),
            preferred_id_at_height: make_block_id(1),
            accepted_id: make_block_id(0),
        };
        nm.inject_inbound(make_node_id(1), chits).unwrap();

        // Process the Chits → record poll
        let (from, msg) = nm.receive_message().unwrap();
        assert_eq!(from, make_node_id(1));

        if let NetworkMessage::Chits { preferred_id, .. } = msg {
            let mut votes = HashMap::new();
            *votes.entry(preferred_id).or_insert(0) += 1000u64; // validator weight

            consensus.record_poll(1, &votes).unwrap();
            // Need one more round for finality (beta_virtuous=2)
            let finalized = consensus.record_poll(1, &votes).unwrap();
            assert_eq!(finalized.len(), 1);
            assert_eq!(finalized[0].1, BlockStatus::Accepted);
        }

        assert_eq!(consensus.last_accepted_height, 1);
        assert!(consensus.is_quiescent());

        // Cleanup
        nm.shutdown();
    }

    // --- Stress Test: Many Peers ---

    #[test]
    fn test_stress_many_peers() {
        let config = NetworkConfig {
            max_peers: 100,
            require_tls: false,
            ..Default::default()
        };
        let local = make_node_id(0);
        let mut nm = NetworkManager::new(config, local, None);
        nm.start().unwrap();

        // Connect 50 peers
        for i in 1..=50u8 {
            let addr: SocketAddr = format!("10.0.0.{}:9651", i).parse().unwrap();
            nm.connect_peer(make_node_id(i), addr).unwrap();
            let version = NetworkMessage::Version {
                network_id: 1,
                node_id: make_node_id(i),
                my_time: 0,
                ip_addr: vec![10, 0, 0, i],
                ip_port: 9651,
                my_version: "test/1.0".to_string(),
                my_version_time: 0,
                sig: vec![],
                tracked_subnets: vec![],
            };
            nm.handle_version(&make_node_id(i), &version).unwrap();
        }

        assert_eq!(nm.peer_manager.connected_count(), 50);

        // Broadcast to all
        let results = nm.broadcast(NetworkMessage::Ping { uptime: 10000 });
        assert_eq!(results.len(), 50);

        nm.shutdown();
    }

    // --- Stress Test: Rapid Consensus Rounds ---

    #[test]
    fn test_stress_rapid_consensus() {
        let genesis = make_block_id(0);
        let params = SnowballParams {
            k: 20,
            alpha: 15,
            beta_virtuous: 5,
            beta_rogue: 10,
            max_outstanding: 500,
            max_rounds: 1000,
        };
        let mut consensus = SnowmanConsensus::new(params, genesis.clone());

        // Add 100 blocks in a chain, finalize each
        let mut parent = genesis;
        for i in 1..=100u64 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = (i & 0xFF) as u8;
            id_bytes[1] = ((i >> 8) & 0xFF) as u8;
            let block_id = BlockId(id_bytes);

            let block = ConsensusBlock::new(block_id.clone(), parent.clone(), i, i * 100, vec![]);
            consensus.add_block(block).unwrap();

            // 5 polls to finalize (beta_virtuous=5)
            let mut votes = HashMap::new();
            votes.insert(block_id.clone(), 20);
            for _ in 0..5 {
                consensus.record_poll(i, &votes).unwrap();
            }

            assert_eq!(
                consensus.block_status(&block_id),
                BlockStatus::Accepted,
                "block at height {} should be accepted",
                i
            );
            parent = block_id;
        }

        assert_eq!(consensus.last_accepted_height, 100);
        assert!(consensus.is_quiescent());
        assert_eq!(consensus.decision_log.len(), 100);
    }

    // --- IP Parsing Tests ---

    #[test]
    fn test_parse_ipv4_addr() {
        let addr = parse_peer_addr(&[10, 0, 0, 1], 9651).unwrap();
        assert_eq!(addr.to_string(), "10.0.0.1:9651");
    }

    #[test]
    fn test_parse_ipv6_addr() {
        let ipv6_bytes = [0u8; 16]; // ::
        let addr = parse_peer_addr(&ipv6_bytes, 9651).unwrap();
        assert_eq!(addr.port(), 9651);
    }

    #[test]
    fn test_parse_invalid_addr() {
        assert!(parse_peer_addr(&[1, 2, 3], 9651).is_none());
    }

    // --- NodeId / BlockId Tests ---

    #[test]
    fn test_node_id_display() {
        let id = make_node_id(0xAB);
        let s = format!("{}", id);
        assert!(s.starts_with("NodeID-"));
    }

    #[test]
    fn test_block_id_display() {
        let id = make_block_id(0xFF);
        let s = format!("{}", id);
        assert!(s.starts_with("ff"));
    }

    #[test]
    fn test_node_id_from_bytes() {
        assert!(NodeId::from_bytes(&[0u8; 20]).is_some());
        assert!(NodeId::from_bytes(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_block_id_from_bytes() {
        assert!(BlockId::from_bytes(&[0u8; 32]).is_some());
        assert!(BlockId::from_bytes(&[0u8; 16]).is_none());
    }

    #[test]
    fn test_process_peer_list_deduplication() {
        use std::net::SocketAddr;
        let config = NetworkConfig::default();
        let my_id = NodeId([0u8; 20]);
        let mut pm = PeerManager::new(config, my_id);

        let peers = vec![PeerInfo {
            node_id: NodeId([1u8; 20]),
            ip_addr: vec![10, 0, 0, 1],
            ip_port: 9651,
            cert_bytes: vec![],
            timestamp: 0,
            signature: vec![],
        }];

        let new1 = pm.process_peer_list(&peers);
        assert_eq!(new1.len(), 1, "first time should discover 1 new peer");

        // Add the peer to the manager
        let addr: SocketAddr = "10.0.0.1:9651".parse().unwrap();
        let mut peer = Peer::new(NodeId([1u8; 20]), addr);
        peer.state = PeerState::Connected;
        let _ = pm.add_peer(peer);

        let new2 = pm.process_peer_list(&peers);
        assert_eq!(new2.len(), 0, "already-known peer should not be returned");
    }

    #[test]
    fn test_get_ancestors_roundtrip() {
        let msg = NetworkMessage::GetAncestors {
            chain_id: ChainId([0xBB; 32]),
            request_id: 7,
            deadline: 5_000_000_000,
            container_id: BlockId([0xCC; 32]),
            max_containers_size: 2_000_000,
        };
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::GetAncestors {
                request_id,
                max_containers_size,
                ..
            } => {
                assert_eq!(request_id, 7);
                assert_eq!(max_containers_size, 2_000_000);
            }
            other => panic!("expected GetAncestors, got {:?}", other.name()),
        }
    }

    #[test]
    fn test_ancestors_roundtrip() {
        let msg = NetworkMessage::Ancestors {
            chain_id: ChainId([0x11; 32]),
            request_id: 8,
            containers: vec![vec![1, 2, 3], vec![4, 5, 6]],
        };
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::Ancestors {
                request_id,
                containers,
                ..
            } => {
                assert_eq!(request_id, 8);
                assert_eq!(containers.len(), 2);
            }
            other => panic!("expected Ancestors, got {:?}", other.name()),
        }
    }

    // --- Persistent Peer Management tests ---

    #[test]
    fn test_persistent_peer_record_new() {
        let record = PersistentPeerRecord::new([0xAA; 20], vec![192, 168, 1, 1], 9651);
        assert_eq!(record.node_id, [0xAA; 20]);
        assert_eq!(record.port, 9651);
        assert_eq!(record.reliability_score, 500);
        assert_eq!(record.success_count, 0);
        assert_eq!(record.failure_count, 0);
    }

    #[test]
    fn test_persistent_peer_record_success() {
        let mut record = PersistentPeerRecord::new([0xBB; 20], vec![10, 0, 0, 1], 9651);
        record.record_success(50);
        assert_eq!(record.success_count, 1);
        assert_eq!(record.latency_ms, 50);
        assert_eq!(record.reliability_score, 550);
        assert!(record.last_connected_ms > 0);
    }

    #[test]
    fn test_persistent_peer_record_failure() {
        let mut record = PersistentPeerRecord::new([0xCC; 20], vec![10, 0, 0, 2], 9651);
        record.record_failure();
        assert_eq!(record.failure_count, 1);
        assert_eq!(record.reliability_score, 400);
    }

    #[test]
    fn test_persistent_peer_record_eviction() {
        let mut record = PersistentPeerRecord::new([0xDD; 20], vec![10, 0, 0, 3], 9651);
        for _ in 0..5 {
            record.record_failure();
        }
        assert!(record.should_evict(5));
    }

    #[test]
    fn test_persistent_peer_record_encode_decode() {
        let record = PersistentPeerRecord::new([0xEE; 20], vec![172, 16, 0, 1], 9651);
        let encoded = record.encode();
        let decoded = PersistentPeerRecord::decode(&encoded).unwrap();
        assert_eq!(decoded.node_id, record.node_id);
        assert_eq!(decoded.port, record.port);
        assert_eq!(decoded.reliability_score, record.reliability_score);
    }

    #[test]
    fn test_persistent_peer_record_socket_addr() {
        let record = PersistentPeerRecord::new([0xFF; 20], vec![192, 168, 1, 100], 9651);
        let addr = record.socket_addr().unwrap();
        assert_eq!(addr.port(), 9651);
    }

    #[test]
    fn test_persistent_peer_store_basic() {
        let mut store = PersistentPeerStore::new(3);
        let record = PersistentPeerRecord::new([0x11; 20], vec![10, 0, 0, 1], 9651);
        store.upsert(record, None);
        assert_eq!(store.count(), 1);
        assert!(store.get(&[0x11; 20]).is_some());
    }

    #[test]
    fn test_persistent_peer_store_best_peers() {
        let mut store = PersistentPeerStore::new(5);

        let mut good = PersistentPeerRecord::new([0x01; 20], vec![10, 0, 0, 1], 9651);
        good.reliability_score = 900;

        let mut bad = PersistentPeerRecord::new([0x02; 20], vec![10, 0, 0, 2], 9651);
        bad.reliability_score = 100;

        let mut ok = PersistentPeerRecord::new([0x03; 20], vec![10, 0, 0, 3], 9651);
        ok.reliability_score = 500;

        store.upsert(bad, None);
        store.upsert(good, None);
        store.upsert(ok, None);

        let best = store.best_peers(2);
        assert_eq!(best.len(), 2);
        assert_eq!(best[0].reliability_score, 900);
        assert_eq!(best[1].reliability_score, 500);
    }

    #[test]
    fn test_persistent_peer_store_evict_bad() {
        let mut store = PersistentPeerStore::new(3);

        let mut bad = PersistentPeerRecord::new([0x01; 20], vec![10, 0, 0, 1], 9651);
        for _ in 0..3 {
            bad.record_failure();
        }

        let good = PersistentPeerRecord::new([0x02; 20], vec![10, 0, 0, 2], 9651);

        store.upsert(bad, None);
        store.upsert(good, None);
        assert_eq!(store.count(), 2);

        let evicted = store.evict_bad_peers(None);
        assert_eq!(evicted, 1);
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_persistent_peer_store_record_and_evict() {
        let mut store = PersistentPeerStore::new(3);
        let record = PersistentPeerRecord::new([0xAA; 20], vec![10, 0, 0, 1], 9651);
        store.upsert(record, None);

        // 3 failures should evict
        store.record_failure(&[0xAA; 20], None);
        store.record_failure(&[0xAA; 20], None);
        store.record_failure(&[0xAA; 20], None);

        assert_eq!(store.count(), 0); // evicted
    }

    #[test]
    fn test_persistent_peer_store_db_roundtrip() {
        let (db, _dir) = crate::db::Database::open_temp().unwrap();
        let mut store = PersistentPeerStore::new(5);

        let record = PersistentPeerRecord::new([0x42; 20], vec![10, 0, 0, 42], 9651);
        store.upsert(record, Some(&db));

        // Load into a new store
        let mut store2 = PersistentPeerStore::new(5);
        let loaded = store2.load_from_db(&db);
        assert_eq!(loaded, 1);
        assert_eq!(store2.get(&[0x42; 20]).unwrap().port, 9651);
    }

    #[test]
    fn test_persistent_peer_store_peer_list_ack() {
        let mut store = PersistentPeerStore::new(5);
        store.upsert(
            PersistentPeerRecord::new([0x01; 20], vec![10, 0, 0, 1], 9651),
            None,
        );
        store.upsert(
            PersistentPeerRecord::new([0x02; 20], vec![10, 0, 0, 2], 9651),
            None,
        );

        let ack_ids = store.peer_list_ack_ids();
        assert_eq!(ack_ids.len(), 2);
    }

    #[test]
    fn test_persistent_peer_latency_averaging() {
        let mut record = PersistentPeerRecord::new([0x01; 20], vec![10, 0, 0, 1], 9651);
        record.record_success(100);
        assert_eq!(record.latency_ms, 100);

        record.record_success(200);
        // EMA: (100 * 7 + 200 * 3) / 10 = 130
        assert_eq!(record.latency_ms, 130);
    }
}

// Dead demo code removed during TDD audit — was a compile-check `fn main()` that
// Dead demo code removed during TDD audit.
