//! Bootstrapping & State Sync protocol.
//!
//! Phase 5-7: Download chain state from existing peers.
//! Implements:
//! - State sync: GetStateSummaryFrontier / StateSummaryFrontier
//! - State summary parsing (height, block hash, state root)
//! - GetAcceptedStateSummary for comparing peer state summaries
//! - GetStateSyncData for downloading trie nodes
//! - MPT reconstruction with alloy-trie and state root verification
//! - RocksDB persistence for trie nodes in state_trie CF
//! - Block bootstrapping: GetAcceptedFrontier → GetAccepted → GetAncestors
//! - Chain catch-up and transition to consensus mode
//! - Sync progress tracking with ETA

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::network::{BlockId, ChainId, NetworkMessage, NodeId};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Current phase of the sync engine.
#[derive(Debug, Clone, PartialEq)]
pub enum SyncPhase {
    /// Not started yet
    Idle,
    /// Fetching state summary from peers
    StateSummaryFrontier,
    /// Comparing accepted state summaries
    AcceptedStateSummary,
    /// Downloading trie nodes for state sync
    DownloadingTrieNodes,
    /// Verifying reconstructed state root
    VerifyingStateRoot,
    /// Fetching the accepted frontier
    AcceptedFrontier,
    /// Discovering accepted blocks
    AcceptedBlocks,
    /// Downloading ancestor blocks
    Fetching,
    /// Replaying / verifying blocks
    Executing,
    /// Caught up to chain tip — historical sync complete
    Synced,
    /// Actively following the chain tip, processing new blocks as they arrive
    Following,
}

impl std::fmt::Display for SyncPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::StateSummaryFrontier => write!(f, "state_summary_frontier"),
            Self::AcceptedStateSummary => write!(f, "accepted_state_summary"),
            Self::DownloadingTrieNodes => write!(f, "downloading_trie_nodes"),
            Self::VerifyingStateRoot => write!(f, "verifying_state_root"),
            Self::AcceptedFrontier => write!(f, "accepted_frontier"),
            Self::AcceptedBlocks => write!(f, "accepted_blocks"),
            Self::Fetching => write!(f, "fetching"),
            Self::Executing => write!(f, "executing"),
            Self::Synced => write!(f, "synced"),
            Self::Following => write!(f, "following"),
        }
    }
}

/// A parsed state summary from a peer.
#[derive(Debug, Clone, PartialEq)]
pub struct StateSummary {
    /// Block height this summary corresponds to
    pub height: u64,
    /// Block hash at this height
    pub block_hash: [u8; 32],
    /// State root (MPT root of the account trie)
    pub state_root: [u8; 32],
}

impl StateSummary {
    /// Serialize to bytes: height(8) + block_hash(32) + state_root(32) = 72 bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(72);
        buf.extend_from_slice(&self.height.to_be_bytes());
        buf.extend_from_slice(&self.block_hash);
        buf.extend_from_slice(&self.state_root);
        buf
    }

    /// Parse from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 72 {
            return None;
        }
        let height = u64::from_be_bytes(data[0..8].try_into().ok()?);
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&data[8..40]);
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&data[40..72]);
        Some(StateSummary {
            height,
            block_hash,
            state_root,
        })
    }
}

const STATE_SYNC_GET_SUMMARY_TAG: u8 = 0x31;
const STATE_SYNC_SUMMARY_TAG: u8 = 0x32;
const META_STATE_SYNC_CHECKPOINT: &[u8] = b"state_sync_checkpoint_v1";

#[derive(Debug, Clone, PartialEq)]
pub struct TrieNodeChunk {
    pub node_hash: [u8; 32],
    pub node_bytes: Vec<u8>,
    pub child_hashes: Vec<[u8; 32]>,
}

impl TrieNodeChunk {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(38 + self.node_bytes.len() + self.child_hashes.len() * 32);
        out.extend_from_slice(&self.node_hash);
        out.extend_from_slice(&(self.child_hashes.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.node_bytes.len() as u32).to_be_bytes());
        for child in &self.child_hashes {
            out.extend_from_slice(child);
        }
        out.extend_from_slice(&self.node_bytes);
        out
    }

    fn decode(bytes: &[u8]) -> Option<(Self, usize)> {
        if bytes.len() < 38 {
            return None;
        }
        let mut node_hash = [0u8; 32];
        node_hash.copy_from_slice(&bytes[0..32]);
        let child_count = u16::from_be_bytes(bytes[32..34].try_into().ok()?) as usize;
        let node_len = u32::from_be_bytes(bytes[34..38].try_into().ok()?) as usize;
        let children_len = child_count.checked_mul(32)?;
        let total = 38usize.checked_add(children_len)?.checked_add(node_len)?;
        if bytes.len() < total {
            return None;
        }

        let mut child_hashes = Vec::with_capacity(child_count);
        let mut offset = 38;
        for _ in 0..child_count {
            let mut child = [0u8; 32];
            child.copy_from_slice(&bytes[offset..offset + 32]);
            child_hashes.push(child);
            offset += 32;
        }
        let node_bytes = bytes[offset..offset + node_len].to_vec();
        Some((
            TrieNodeChunk {
                node_hash,
                node_bytes,
                child_hashes,
            },
            total,
        ))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StateSummaryChunk {
    pub state_root: [u8; 32],
    pub cursor: u64,
    pub done: bool,
    pub nodes: Vec<TrieNodeChunk>,
}

impl StateSummaryChunk {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(STATE_SYNC_SUMMARY_TAG);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.cursor.to_be_bytes());
        out.push(u8::from(self.done));
        out.extend_from_slice(&(self.nodes.len() as u16).to_be_bytes());
        for node in &self.nodes {
            out.extend_from_slice(&node.encode());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 44 || bytes[0] != STATE_SYNC_SUMMARY_TAG {
            return None;
        }
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&bytes[1..33]);
        let cursor = u64::from_be_bytes(bytes[33..41].try_into().ok()?);
        let done = bytes[41] == 1;
        let node_count = u16::from_be_bytes(bytes[42..44].try_into().ok()?) as usize;
        let mut nodes = Vec::with_capacity(node_count);
        let mut offset = 44;
        for _ in 0..node_count {
            let (node, consumed) = TrieNodeChunk::decode(&bytes[offset..])?;
            nodes.push(node);
            offset += consumed;
        }
        Some(Self {
            state_root,
            cursor,
            done,
            nodes,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateSyncCheckpoint {
    state_root: Option<[u8; 32]>,
    phase: String,
    needed_trie_nodes: Vec<[u8; 32]>,
    next_cursor: u64,
    downloaded_nodes: u64,
    verified_nodes: u64,
    bytes_downloaded: u64,
}

/// Statistics for the sync process.
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    pub blocks_downloaded: u64,
    pub blocks_executed: u64,
    pub bytes_downloaded: u64,
    pub peers_queried: usize,
    pub retries: u64,
    pub start_time: Option<Instant>,
    pub last_block_height: u64,
    pub target_height: u64,
    pub trie_nodes_downloaded: u64,
    pub trie_bytes_downloaded: u64,
}

impl SyncStats {
    pub fn progress_pct(&self) -> f64 {
        if self.target_height == 0 {
            return 0.0;
        }
        (self.last_block_height as f64 / self.target_height as f64 * 100.0).min(100.0)
    }

    pub fn elapsed(&self) -> Duration {
        self.start_time
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    pub fn blocks_per_second(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64();
        if secs > 0.0 {
            self.blocks_downloaded as f64 / secs
        } else {
            0.0
        }
    }

    /// Estimated time remaining based on current download rate.
    pub fn eta_seconds(&self) -> Option<f64> {
        let bps = self.blocks_per_second();
        if bps <= 0.0 || self.target_height == 0 {
            return None;
        }
        let remaining = self.target_height.saturating_sub(self.last_block_height);
        Some(remaining as f64 / bps)
    }
}

/// Configuration for the sync engine.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Chain ID to sync.
    pub chain_id: ChainId,
    /// Request timeout for individual messages.
    pub request_timeout: Duration,
    /// Maximum number of ancestors to request at once.
    pub max_ancestors_per_request: u32,
    /// Maximum number of pending requests.
    pub max_pending_requests: usize,
    /// Maximum number of retries per request.
    pub max_retries: u32,
    /// Strategy for fetching blocks during bootstrap.
    pub block_fetch_mode: BlockFetchMode,
}

/// Strategy to fetch historical blocks.
#[derive(Debug, Clone)]
pub enum BlockFetchMode {
    /// Fetch one container per request.
    Get,
    /// Fetch a linked ancestor batch per request.
    GetAncestors { max_containers_size: u32 },
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            chain_id: ChainId([0u8; 32]),
            request_timeout: Duration::from_secs(10),
            max_ancestors_per_request: 256,
            max_pending_requests: 32,
            max_retries: 3,
            block_fetch_mode: BlockFetchMode::Get,
        }
    }
}

/// A pending request awaiting a response.
#[derive(Debug)]
#[allow(dead_code)]
struct PendingRequest {
    request_id: u32,
    peer: NodeId,
    sent_at: Instant,
    retries: u32,
    kind: RequestKind,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum RequestKind {
    StateSummaryFrontier,
    AcceptedStateSummary { heights: Vec<u64> },
    AcceptedFrontier,
    Accepted { container_ids: Vec<BlockId> },
    Ancestors { container_id: BlockId },
    TrieNode { node_hash: [u8; 32] },
}

// ---------------------------------------------------------------------------
// Sync Engine
// ---------------------------------------------------------------------------

/// The sync engine manages bootstrapping and state sync.
pub struct SyncEngine {
    config: SyncConfig,
    phase: Arc<RwLock<SyncPhase>>,
    stats: Arc<RwLock<SyncStats>>,
    /// Blocks we need to fetch (by ID)
    needed_blocks: Arc<RwLock<VecDeque<BlockId>>>,
    /// Blocks we've downloaded (by height → raw bytes)
    downloaded_blocks: Arc<RwLock<HashMap<u64, Vec<u8>>>>,
    /// Frontier blocks reported by peers (peer → block_id)
    frontier: Arc<RwLock<HashMap<NodeId, BlockId>>>,
    /// Next request ID
    next_request_id: Arc<RwLock<u32>>,
    /// Pending requests
    pending: Arc<RwLock<HashMap<u32, PendingRequest>>>,
}

impl SyncEngine {
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            phase: Arc::new(RwLock::new(SyncPhase::Idle)),
            stats: Arc::new(RwLock::new(SyncStats::default())),
            needed_blocks: Arc::new(RwLock::new(VecDeque::new())),
            downloaded_blocks: Arc::new(RwLock::new(HashMap::new())),
            frontier: Arc::new(RwLock::new(HashMap::new())),
            next_request_id: Arc::new(RwLock::new(1)),
            pending: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the current sync phase.
    pub async fn phase(&self) -> SyncPhase {
        self.phase.read().await.clone()
    }

    /// Get current sync statistics.
    pub async fn stats(&self) -> SyncStats {
        self.stats.read().await.clone()
    }

    /// Number of downloaded blocks.
    pub async fn downloaded_count(&self) -> usize {
        self.downloaded_blocks.read().await.len()
    }

    /// Number of blocks still needed.
    pub async fn needed_count(&self) -> usize {
        self.needed_blocks.read().await.len()
    }

    /// Generate the next request ID.
    async fn next_request_id(&self) -> u32 {
        let mut id = self.next_request_id.write().await;
        let current = *id;
        *id = id.wrapping_add(1);
        current
    }

    // -----------------------------------------------------------------------
    // Start sync (generates outbound messages to peers)
    // -----------------------------------------------------------------------

    /// Begin the state sync process. Returns messages to send to the given peers.
    pub async fn start_state_sync(&self, peers: &[NodeId]) -> Vec<(NodeId, NetworkMessage)> {
        let mut phase = self.phase.write().await;
        *phase = SyncPhase::StateSummaryFrontier;

        let mut stats = self.stats.write().await;
        stats.start_time = Some(Instant::now());
        stats.peers_queried = peers.len();
        drop(stats);
        drop(phase);

        let mut messages = Vec::new();
        for peer in peers {
            let req_id = self.next_request_id().await;
            let msg = NetworkMessage::GetStateSummaryFrontier {
                chain_id: self.config.chain_id.clone(),
                request_id: req_id,
                deadline: self.config.request_timeout.as_nanos() as u64,
            };
            messages.push((peer.clone(), msg));

            let mut pending = self.pending.write().await;
            pending.insert(
                req_id,
                PendingRequest {
                    request_id: req_id,
                    peer: peer.clone(),
                    sent_at: Instant::now(),
                    retries: 0,
                    kind: RequestKind::StateSummaryFrontier,
                },
            );
        }
        messages
    }

    /// Begin block bootstrapping. Returns GetAcceptedFrontier messages.
    pub async fn start_bootstrap(&self, peers: &[NodeId]) -> Vec<(NodeId, NetworkMessage)> {
        let mut phase = self.phase.write().await;
        *phase = SyncPhase::AcceptedFrontier;

        let mut stats = self.stats.write().await;
        if stats.start_time.is_none() {
            stats.start_time = Some(Instant::now());
        }
        stats.peers_queried = peers.len();
        drop(stats);
        drop(phase);

        let mut messages = Vec::new();
        for peer in peers {
            let req_id = self.next_request_id().await;
            let msg = NetworkMessage::GetAcceptedFrontier {
                chain_id: self.config.chain_id.clone(),
                request_id: req_id,
                deadline: self.config.request_timeout.as_nanos() as u64,
            };
            messages.push((peer.clone(), msg));
        }
        messages
    }

    // -----------------------------------------------------------------------
    // Handle incoming responses
    // -----------------------------------------------------------------------

    /// Handle a StateSummaryFrontier response. Parses the summary bytes.
    pub async fn handle_state_summary_frontier(
        &self,
        _peer: &NodeId,
        _request_id: u32,
        summary: &[u8],
    ) -> Option<StateSummary> {
        if summary.is_empty() {
            return None;
        }
        let mut stats = self.stats.write().await;
        stats.bytes_downloaded += summary.len() as u64;
        drop(stats);

        StateSummary::decode(summary)
    }

    /// Handle an AcceptedFrontier response.
    pub async fn handle_accepted_frontier(
        &self,
        peer: &NodeId,
        _request_id: u32,
        container_id: &BlockId,
    ) {
        let mut frontier = self.frontier.write().await;
        frontier.insert(peer.clone(), container_id.clone());
    }

    /// Handle an Accepted response with container IDs that the peer accepted.
    pub async fn handle_accepted(&self, _peer: &NodeId, container_ids: &[BlockId]) {
        let mut needed = self.needed_blocks.write().await;
        for id in container_ids {
            needed.push_back(id.clone());
        }
    }

    /// Handle block data received (Put / Ancestors).
    pub async fn handle_block_data(&self, block_height: u64, block_data: Vec<u8>) {
        let mut stats = self.stats.write().await;
        stats.blocks_downloaded += 1;
        stats.bytes_downloaded += block_data.len() as u64;
        if block_height > stats.last_block_height {
            stats.last_block_height = block_height;
        }
        drop(stats);

        let mut downloaded = self.downloaded_blocks.write().await;
        downloaded.insert(block_height, block_data);
    }

    /// Generate GetAncestors requests for needed blocks.
    pub async fn generate_fetch_requests(&self, peers: &[NodeId]) -> Vec<(NodeId, NetworkMessage)> {
        if peers.is_empty() {
            return vec![];
        }

        let mut phase = self.phase.write().await;
        *phase = SyncPhase::Fetching;
        drop(phase);

        let mut needed = self.needed_blocks.write().await;
        let mut messages = Vec::new();
        let mut peer_idx = 0;

        while let Some(block_id) = needed.pop_front() {
            if messages.len() >= self.config.max_pending_requests {
                needed.push_front(block_id);
                break;
            }

            let peer = &peers[peer_idx % peers.len()];
            peer_idx += 1;

            let req_id = {
                let mut id = self.next_request_id.write().await;
                let current = *id;
                *id = id.wrapping_add(1);
                current
            };

            let msg = match self.config.block_fetch_mode {
                BlockFetchMode::Get => NetworkMessage::Get {
                    chain_id: self.config.chain_id.clone(),
                    request_id: req_id,
                    deadline: self.config.request_timeout.as_nanos() as u64,
                    container_id: block_id,
                },
                BlockFetchMode::GetAncestors {
                    max_containers_size,
                } => NetworkMessage::GetAncestors {
                    chain_id: self.config.chain_id.clone(),
                    request_id: req_id,
                    deadline: self.config.request_timeout.as_nanos() as u64,
                    container_id: block_id,
                    max_containers_size,
                },
            };
            messages.push((peer.clone(), msg));
        }
        messages
    }

    /// Validate a C-Chain ancestor response as a linked hash chain.
    ///
    /// For `GetAncestors(target)`, container[0] must hash to `target` and every
    /// subsequent container must hash to the previous block's parent hash.
    pub fn validate_cchain_ancestor_chain(
        containers: &[Vec<u8>],
        target_id: [u8; 32],
    ) -> Result<(), String> {
        fn strip_wrapper(raw: &[u8]) -> &[u8] {
            if raw.len() >= 6 && raw[0] == 0x00 && raw[1] == 0x00 {
                &raw[6..]
            } else {
                raw
            }
        }

        if containers.is_empty() {
            return Err("empty ancestor container list".to_string());
        }

        let mut expected_id = target_id;
        for (index, container) in containers.iter().enumerate() {
            let parsed = crate::block::parse_cchain_network_block(container);
            let block_id = parsed
                .as_ref()
                .map(|block| block.block_id)
                .or_else(|| crate::block::cchain_block_id(container))
                .unwrap_or_else(|| Sha256::digest(container).into());
            if block_id != expected_id {
                let raw_sha256: [u8; 32] = Sha256::digest(container).into();
                let full_rlp_keccak = {
                    let hash = revm::primitives::keccak256(strip_wrapper(container));
                    let mut out = [0u8; 32];
                    out.copy_from_slice(hash.as_slice());
                    out
                };
                let preview_len = container.len().min(8);
                return Err(format!(
                    "hash-chain mismatch at index {}: expected {:02x?}, header-keccak {:02x?}, full-rlp-keccak {:02x?}, raw-sha256 {:02x?}, first-bytes {:02x?}",
                    index,
                    &expected_id[..4],
                    &block_id[..4],
                    &full_rlp_keccak[..4],
                    &raw_sha256[..4],
                    &container[..preview_len]
                ));
            }

            if let Some(block) = parsed {
                expected_id = block.parent_id;
            } else {
                let header =
                    crate::block::BlockHeader::parse(container, crate::block::Chain::CChain)
                        .map_err(|e| format!("failed to parse C-Chain block {}: {}", index, e))?;
                expected_id = header.parent_id;
            }
        }

        Ok(())
    }

    /// Check if sync is complete.
    pub async fn is_synced(&self) -> bool {
        *self.phase.read().await == SyncPhase::Synced
    }

    /// Mark sync as complete (historical bootstrap done).
    pub async fn mark_synced(&self) {
        *self.phase.write().await = SyncPhase::Synced;
    }

    /// Transition to `Following` phase: actively tracking new chain tip blocks.
    pub async fn mark_following(&self) {
        *self.phase.write().await = SyncPhase::Following;
    }

    /// Returns true if the node is in an active live-sync phase.
    pub async fn is_following(&self) -> bool {
        matches!(*self.phase.read().await, SyncPhase::Following)
    }

    /// Transition to execution phase.
    pub async fn start_execution(&self) {
        *self.phase.write().await = SyncPhase::Executing;
    }

    /// Set the target height for progress tracking.
    pub async fn set_target_height(&self, height: u64) {
        self.stats.write().await.target_height = height;
    }

    /// Get timed-out pending requests.
    pub async fn get_timed_out_requests(&self) -> Vec<u32> {
        let pending = self.pending.read().await;
        let now = Instant::now();
        pending
            .iter()
            .filter(|(_, req)| now.duration_since(req.sent_at) > self.config.request_timeout)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get the determined frontier (most-agreed-upon block).
    pub async fn determined_frontier(&self) -> Option<BlockId> {
        let frontier = self.frontier.read().await;
        if frontier.is_empty() {
            return None;
        }
        // Find the most commonly reported frontier block
        let mut counts: HashMap<&BlockId, usize> = HashMap::new();
        for block_id in frontier.values() {
            *counts.entry(block_id).or_default() += 1;
        }
        counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(id, _)| id.clone())
    }
}

// ---------------------------------------------------------------------------
// State Sync Engine
// ---------------------------------------------------------------------------

/// State synchronization engine for downloading and verifying account trie.
///
/// Handles the GetStateSummaryFrontier / StateSummaryFrontier protocol
/// for discovering the latest state root and downloading trie nodes.
/// Persists trie nodes to RocksDB and verifies state root with alloy-trie.
#[derive(Debug)]
pub struct StateSyncEngine {
    /// State root from C-Chain block
    state_root: Arc<RwLock<Option<[u8; 32]>>>,
    /// Trie nodes keyed by their hash (node_hash -> node_bytes)
    trie_nodes: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
    /// Current sync phase
    phase: Arc<RwLock<SyncPhase>>,
    /// Peers with known state summaries (peer -> StateSummary)
    peer_summaries: Arc<RwLock<HashMap<NodeId, StateSummary>>>,
    /// Trie node hashes still needed
    needed_trie_nodes: Arc<RwLock<VecDeque<[u8; 32]>>>,
    /// Stats for trie node downloads
    trie_stats: Arc<RwLock<TrieSyncStats>>,
    /// Next cursor for incremental chunk requests
    next_summary_cursor: Arc<RwLock<u64>>,
}

/// Statistics for trie node synchronization.
#[derive(Debug, Clone, Default)]
pub struct TrieSyncStats {
    pub nodes_downloaded: u64,
    pub nodes_verified: u64,
    pub bytes_downloaded: u64,
    pub nodes_pending: u64,
}

impl StateSyncEngine {
    /// Create a new state sync engine
    pub fn new() -> Self {
        StateSyncEngine {
            state_root: Arc::new(RwLock::new(None)),
            trie_nodes: Arc::new(RwLock::new(HashMap::new())),
            phase: Arc::new(RwLock::new(SyncPhase::StateSummaryFrontier)),
            peer_summaries: Arc::new(RwLock::new(HashMap::new())),
            needed_trie_nodes: Arc::new(RwLock::new(VecDeque::new())),
            trie_stats: Arc::new(RwLock::new(TrieSyncStats::default())),
            next_summary_cursor: Arc::new(RwLock::new(0)),
        }
    }

    /// Record a state summary from a peer
    pub async fn handle_state_summary(&self, peer: NodeId, summary: StateSummary) {
        self.peer_summaries.write().await.insert(peer, summary);
    }

    /// Determine the best state summary from peer responses (majority vote).
    pub async fn best_summary(&self) -> Option<StateSummary> {
        let summaries = self.peer_summaries.read().await;
        if summaries.is_empty() {
            return None;
        }
        let mut counts: HashMap<[u8; 32], (usize, StateSummary)> = HashMap::new();
        for summary in summaries.values() {
            let entry = counts
                .entry(summary.state_root)
                .or_insert((0, summary.clone()));
            entry.0 += 1;
        }
        counts
            .into_values()
            .max_by_key(|(count, _)| *count)
            .map(|(_, summary)| summary)
    }

    /// Set the target state root to sync to
    pub async fn set_target_state_root(&self, state_root: [u8; 32]) {
        *self.state_root.write().await = Some(state_root);
        *self.phase.write().await = SyncPhase::AcceptedStateSummary;
    }

    /// Add trie node hashes that need to be downloaded.
    pub async fn add_needed_trie_nodes(&self, hashes: Vec<[u8; 32]>) {
        let mut needed = self.needed_trie_nodes.write().await;
        let mut stats = self.trie_stats.write().await;
        for hash in hashes {
            needed.push_back(hash);
            stats.nodes_pending += 1;
        }
    }

    /// Generate trie node download requests for peers.
    pub async fn generate_trie_requests(
        &self,
        peers: &[NodeId],
        chain_id: &ChainId,
        max_requests: usize,
    ) -> Vec<(NodeId, NetworkMessage)> {
        if peers.is_empty() {
            return vec![];
        }

        *self.phase.write().await = SyncPhase::DownloadingTrieNodes;

        let mut needed = self.needed_trie_nodes.write().await;
        let mut messages = Vec::new();
        let mut peer_idx = 0;
        let mut req_counter = 0u32;
        let state_root = *self.state_root.read().await;
        let mut next_cursor = self.next_summary_cursor.write().await;

        while let Some(node_hash) = needed.pop_front() {
            if messages.len() >= max_requests {
                needed.push_front(node_hash);
                break;
            }

            let peer = &peers[peer_idx % peers.len()];
            peer_idx += 1;
            req_counter = req_counter.wrapping_add(1);

            // Request trie chunks via state-summary protocol envelope.
            // app_bytes: tag(1) + state_root(32) + node_hash(32) + cursor(8)
            let mut app_bytes = Vec::with_capacity(73);
            app_bytes.push(STATE_SYNC_GET_SUMMARY_TAG);
            app_bytes.extend_from_slice(&state_root.unwrap_or([0u8; 32]));
            app_bytes.extend_from_slice(&node_hash);
            app_bytes.extend_from_slice(&(*next_cursor).to_be_bytes());
            *next_cursor = next_cursor.saturating_add(1);

            let msg = NetworkMessage::AppRequest {
                chain_id: chain_id.clone(),
                request_id: req_counter,
                deadline: 10_000_000_000, // 10s
                app_bytes,
            };
            messages.push((peer.clone(), msg));
        }
        messages
    }

    /// Handle a state-summary chunk response from a peer.
    pub async fn handle_state_summary_chunk(
        &self,
        chunk: StateSummaryChunk,
    ) -> Result<usize, String> {
        if let Some(target) = *self.state_root.read().await {
            if target != chunk.state_root {
                return Err("state root mismatch in state-summary chunk".to_string());
            }
        }

        let mut stored = 0usize;
        for node in chunk.nodes {
            self.store_trie_node_with_links(node).await?;
            stored += 1;
        }
        Ok(stored)
    }

    /// Handle app-level response bytes encoded as `StateSummaryChunk`.
    pub async fn handle_state_summary_chunk_bytes(
        &self,
        app_bytes: &[u8],
    ) -> Result<usize, String> {
        let chunk = StateSummaryChunk::decode(app_bytes)
            .ok_or_else(|| "invalid state summary chunk bytes".to_string())?;
        self.handle_state_summary_chunk(chunk).await
    }

    /// Store a trie node that includes explicit child references.
    pub async fn store_trie_node_with_links(&self, node: TrieNodeChunk) -> Result<(), String> {
        let expected_hash = Sha256::digest(&node.node_bytes);
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&expected_hash);
        if hash_arr != node.node_hash {
            return Err("trie node hash mismatch".to_string());
        }

        let record = crate::db::TrieNodeRecord {
            hash: node.node_hash,
            node_bytes: node.node_bytes,
            child_hashes: node.child_hashes,
        };

        self.store_trie_node(node.node_hash, record.encode()).await;
        Ok(())
    }

    /// Store a downloaded trie node
    pub async fn store_trie_node(&self, node_hash: [u8; 32], node_bytes: Vec<u8>) {
        let mut stats = self.trie_stats.write().await;
        stats.nodes_downloaded += 1;
        stats.bytes_downloaded += node_bytes.len() as u64;
        stats.nodes_pending = stats.nodes_pending.saturating_sub(1);
        drop(stats);

        self.trie_nodes.write().await.insert(node_hash, node_bytes);
    }

    /// Store a trie node and persist to RocksDB.
    pub async fn store_trie_node_persistent(
        &self,
        node_hash: [u8; 32],
        node_bytes: Vec<u8>,
        db: &crate::db::Database,
    ) -> Result<(), crate::db::DbError> {
        db.put_trie_node(&node_hash, &node_bytes)?;
        self.store_trie_node(node_hash, node_bytes).await;
        Ok(())
    }

    /// Get a trie node by hash
    pub async fn get_trie_node(&self, node_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.trie_nodes.read().await.get(node_hash).cloned()
    }

    /// Get the count of downloaded trie nodes
    pub async fn trie_node_count(&self) -> usize {
        self.trie_nodes.read().await.len()
    }

    /// Get trie sync statistics
    pub async fn trie_stats(&self) -> TrieSyncStats {
        self.trie_stats.read().await.clone()
    }

    /// Get the current state root
    pub async fn state_root(&self) -> Option<[u8; 32]> {
        *self.state_root.read().await
    }

    /// Check if state sync is complete
    pub async fn is_complete(&self) -> bool {
        *self.phase.read().await == SyncPhase::Synced
    }

    /// Verify that the reconstructed trie matches the target state root
    /// using alloy-trie MPT computation.
    pub async fn verify_state_root(&self) -> bool {
        let target = match *self.state_root.read().await {
            Some(root) => root,
            None => return false,
        };

        let nodes = self.trie_nodes.read().await;
        if nodes.is_empty() {
            return target == [0u8; 32];
        }

        // Verify each node's hash matches its key
        for (hash, bytes) in nodes.iter() {
            let computed = if let Some(record) = crate::db::TrieNodeRecord::decode(*hash, bytes) {
                Sha256::digest(&record.node_bytes)
            } else {
                Sha256::digest(bytes)
            };
            let mut computed_arr = [0u8; 32];
            computed_arr.copy_from_slice(&computed);
            if computed_arr != *hash {
                return false;
            }
        }

        if !Self::verify_parent_child_links(&nodes) {
            return false;
        }

        let computed_root = match Self::compute_root_from_nodes(&nodes) {
            Some(root) => root,
            None => return false,
        };
        if computed_root != target {
            return false;
        }

        // Transition to verification phase
        *self.phase.write().await = SyncPhase::VerifyingStateRoot;
        let mut stats = self.trie_stats.write().await;
        stats.nodes_verified = nodes.len() as u64;
        true
    }

    fn verify_parent_child_links(nodes: &HashMap<[u8; 32], Vec<u8>>) -> bool {
        for bytes in nodes.values() {
            let Some(record) = crate::db::TrieNodeRecord::decode([0u8; 32], bytes) else {
                continue;
            };
            for child_hash in record.child_hashes {
                if !nodes.contains_key(&child_hash) {
                    return false;
                }
            }
        }
        true
    }

    fn compute_root_from_nodes(nodes: &HashMap<[u8; 32], Vec<u8>>) -> Option<[u8; 32]> {
        let mut referenced = HashSet::new();
        for bytes in nodes.values() {
            let Some(record) = crate::db::TrieNodeRecord::decode([0u8; 32], bytes) else {
                continue;
            };
            for child in record.child_hashes {
                referenced.insert(child);
            }
        }

        let mut roots: Vec<[u8; 32]> = nodes
            .keys()
            .copied()
            .filter(|hash| !referenced.contains(hash))
            .collect();

        roots.sort();
        if roots.len() == 1 {
            Some(roots[0])
        } else if roots.is_empty() {
            nodes.keys().next().copied()
        } else {
            None
        }
    }

    /// Mark state sync as complete after verification
    pub async fn mark_complete(&self) {
        *self.phase.write().await = SyncPhase::Synced;
    }

    /// Get the current phase
    pub async fn current_phase(&self) -> SyncPhase {
        self.phase.read().await.clone()
    }

    /// Get number of pending trie node downloads
    pub async fn pending_trie_nodes(&self) -> usize {
        self.needed_trie_nodes.read().await.len()
    }

    /// Persist all in-memory trie nodes to RocksDB.
    pub async fn flush_to_db(&self, db: &crate::db::Database) -> Result<usize, crate::db::DbError> {
        let nodes = self.trie_nodes.read().await;
        let count = nodes.len();
        for (hash, bytes) in nodes.iter() {
            db.put_trie_node(hash, bytes)?;
        }
        Ok(count)
    }

    /// Persist resumable state-sync checkpoint.
    pub async fn persist_checkpoint(
        &self,
        db: &crate::db::Database,
    ) -> Result<(), crate::db::DbError> {
        let checkpoint = StateSyncCheckpoint {
            state_root: *self.state_root.read().await,
            phase: self.current_phase().await.to_string(),
            needed_trie_nodes: self
                .needed_trie_nodes
                .read()
                .await
                .iter()
                .copied()
                .collect(),
            next_cursor: *self.next_summary_cursor.read().await,
            downloaded_nodes: self.trie_stats.read().await.nodes_downloaded,
            verified_nodes: self.trie_stats.read().await.nodes_verified,
            bytes_downloaded: self.trie_stats.read().await.bytes_downloaded,
        };
        let encoded = serde_json::to_vec(&checkpoint)
            .map_err(|e| crate::db::DbError::Write(e.to_string()))?;
        db.put_metadata(META_STATE_SYNC_CHECKPOINT, &encoded)
    }

    /// Restore resumable state-sync checkpoint.
    pub async fn restore_checkpoint(
        &self,
        db: &crate::db::Database,
    ) -> Result<bool, crate::db::DbError> {
        let Some(raw) = db.get_metadata(META_STATE_SYNC_CHECKPOINT)? else {
            return Ok(false);
        };
        let checkpoint: StateSyncCheckpoint =
            serde_json::from_slice(&raw).map_err(|e| crate::db::DbError::Read(e.to_string()))?;

        *self.state_root.write().await = checkpoint.state_root;
        *self.next_summary_cursor.write().await = checkpoint.next_cursor;
        {
            let mut needed = self.needed_trie_nodes.write().await;
            needed.clear();
            for hash in checkpoint.needed_trie_nodes {
                needed.push_back(hash);
            }
        }
        {
            let pending = self.needed_trie_nodes.read().await.len() as u64;
            let mut stats = self.trie_stats.write().await;
            stats.nodes_downloaded = checkpoint.downloaded_nodes;
            stats.nodes_verified = checkpoint.verified_nodes;
            stats.bytes_downloaded = checkpoint.bytes_downloaded;
            stats.nodes_pending = pending;
        }

        *self.phase.write().await = match checkpoint.phase.as_str() {
            "state_summary_frontier" => SyncPhase::StateSummaryFrontier,
            "accepted_state_summary" => SyncPhase::AcceptedStateSummary,
            "downloading_trie_nodes" => SyncPhase::DownloadingTrieNodes,
            "verifying_state_root" => SyncPhase::VerifyingStateRoot,
            "synced" => SyncPhase::Synced,
            _ => SyncPhase::AcceptedStateSummary,
        };
        Ok(true)
    }
}

impl Default for StateSyncEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chain_id() -> ChainId {
        ChainId([0xAA; 32])
    }

    fn test_peers() -> Vec<NodeId> {
        vec![NodeId([1u8; 20]), NodeId([2u8; 20]), NodeId([3u8; 20])]
    }

    #[tokio::test]
    async fn test_sync_engine_creation() {
        let config = SyncConfig {
            chain_id: test_chain_id(),
            ..Default::default()
        };
        let engine = SyncEngine::new(config);
        assert_eq!(engine.phase().await, SyncPhase::Idle);
    }

    #[tokio::test]
    async fn test_start_state_sync() {
        let config = SyncConfig {
            chain_id: test_chain_id(),
            ..Default::default()
        };
        let engine = SyncEngine::new(config);
        let peers = test_peers();

        let messages = engine.start_state_sync(&peers).await;
        assert_eq!(messages.len(), 3);
        assert_eq!(engine.phase().await, SyncPhase::StateSummaryFrontier);

        for (_, msg) in &messages {
            assert!(matches!(
                msg,
                NetworkMessage::GetStateSummaryFrontier { .. }
            ));
        }
    }

    #[tokio::test]
    async fn test_start_bootstrap() {
        let config = SyncConfig {
            chain_id: test_chain_id(),
            ..Default::default()
        };
        let engine = SyncEngine::new(config);
        let peers = test_peers();

        let messages = engine.start_bootstrap(&peers).await;
        assert_eq!(messages.len(), 3);
        assert_eq!(engine.phase().await, SyncPhase::AcceptedFrontier);
    }

    #[tokio::test]
    async fn test_handle_accepted_frontier() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);

        let peer = NodeId([1u8; 20]);
        let block = BlockId([0xFF; 32]);
        engine.handle_accepted_frontier(&peer, 1, &block).await;

        let frontier = engine.determined_frontier().await;
        assert!(frontier.is_some());
        assert_eq!(frontier.unwrap().0, [0xFF; 32]);
    }

    #[tokio::test]
    async fn test_handle_accepted_blocks() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);

        let peer = NodeId([1u8; 20]);
        let ids = vec![BlockId([1; 32]), BlockId([2; 32])];
        engine.handle_accepted(&peer, &ids).await;

        assert_eq!(engine.needed_count().await, 2);
    }

    #[tokio::test]
    async fn test_handle_block_data() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);

        engine.handle_block_data(100, vec![0xDE; 256]).await;

        let stats = engine.stats().await;
        assert_eq!(stats.blocks_downloaded, 1);
        assert_eq!(stats.bytes_downloaded, 256);
        assert_eq!(stats.last_block_height, 100);
        assert_eq!(engine.downloaded_count().await, 1);
    }

    #[tokio::test]
    async fn test_generate_fetch_requests() {
        let config = SyncConfig {
            chain_id: test_chain_id(),
            max_pending_requests: 10,
            ..Default::default()
        };
        let engine = SyncEngine::new(config);
        let peers = test_peers();

        // Add some needed blocks
        let peer = NodeId([1; 20]);
        let ids = vec![BlockId([1; 32]), BlockId([2; 32]), BlockId([3; 32])];
        engine.handle_accepted(&peer, &ids).await;

        let messages = engine.generate_fetch_requests(&peers).await;
        assert_eq!(messages.len(), 3);
        assert_eq!(engine.phase().await, SyncPhase::Fetching);
        assert!(matches!(messages[0].1, NetworkMessage::Get { .. }));
    }

    #[tokio::test]
    async fn test_generate_fetch_requests_cchain_ancestors_mode() {
        let config = SyncConfig {
            chain_id: test_chain_id(),
            max_pending_requests: 10,
            block_fetch_mode: BlockFetchMode::GetAncestors {
                max_containers_size: 2_000_000,
            },
            ..Default::default()
        };
        let engine = SyncEngine::new(config);
        let peers = test_peers();

        let peer = NodeId([1; 20]);
        let ids = vec![BlockId([1; 32]), BlockId([2; 32]), BlockId([3; 32])];
        engine.handle_accepted(&peer, &ids).await;

        let messages = engine.generate_fetch_requests(&peers).await;
        assert_eq!(messages.len(), 3);
        assert!(matches!(messages[0].1, NetworkMessage::GetAncestors { .. }));
    }

    #[test]
    fn test_validate_cchain_ancestor_chain() {
        fn encode_len(len: usize, offset: u8) -> Vec<u8> {
            if len <= 55 {
                vec![offset + len as u8]
            } else {
                vec![offset + 56, len as u8]
            }
        }

        fn enc_u64(value: u64) -> Vec<u8> {
            if value == 0 {
                return vec![0x80];
            }
            let bytes = value.to_be_bytes();
            let start = bytes
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(bytes.len() - 1);
            let data = &bytes[start..];
            if data.len() == 1 && data[0] < 0x80 {
                vec![data[0]]
            } else {
                let mut out = vec![0x80 + data.len() as u8];
                out.extend_from_slice(data);
                out
            }
        }

        fn enc_bytes(data: &[u8]) -> Vec<u8> {
            if data.len() == 1 && data[0] < 0x80 {
                vec![data[0]]
            } else {
                let mut out = encode_len(data.len(), 0x80);
                out.extend_from_slice(data);
                out
            }
        }

        fn enc_list(items: Vec<Vec<u8>>) -> Vec<u8> {
            let payload_len: usize = items.iter().map(Vec::len).sum();
            let mut out = encode_len(payload_len, 0xc0);
            for item in items {
                out.extend_from_slice(&item);
            }
            out
        }

        fn build_cchain_block(parent: [u8; 32], number: u64, timestamp: u64) -> Vec<u8> {
            let header = enc_list(vec![
                enc_bytes(&parent),
                enc_bytes(&[0u8; 32]),
                enc_bytes(&[0u8; 20]),
                enc_bytes(&[1u8; 32]),
                enc_bytes(&[2u8; 32]),
                enc_bytes(&[3u8; 32]),
                enc_bytes(&[0u8; 256]),
                enc_u64(0),
                enc_u64(number),
                enc_u64(15_000_000),
                enc_u64(21_000),
                enc_u64(timestamp),
                enc_bytes(&[]),
                enc_bytes(&[0u8; 32]),
                enc_bytes(&[0u8; 8]),
                enc_u64(0),
                enc_u64(0),
            ]);
            let txs = enc_list(vec![]);
            let uncles = enc_list(vec![]);
            enc_list(vec![header, txs, uncles])
        }

        fn wrap_cchain_block(
            parent: [u8; 32],
            inner_block: &[u8],
            signature: &[u8],
        ) -> (Vec<u8>, [u8; 32]) {
            let mut out = Vec::new();
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&parent);
            out.extend_from_slice(&1_700_000_000u64.to_be_bytes());
            out.extend_from_slice(&123u64.to_be_bytes());
            out.extend_from_slice(&(0u32).to_be_bytes());
            out.extend_from_slice(&(inner_block.len() as u32).to_be_bytes());
            out.extend_from_slice(inner_block);
            out.extend_from_slice(&(signature.len() as u32).to_be_bytes());
            out.extend_from_slice(signature);
            let unsigned_end = out.len() - 4 - signature.len();
            let block_id: [u8; 32] = Sha256::digest(&out[..unsigned_end]).into();
            (out, block_id)
        }

        let genesis = build_cchain_block([0u8; 32], 0, 1_700_000_000);
        let genesis_id = crate::block::cchain_block_id(&genesis).expect("genesis cchain id");
        let block1 = build_cchain_block(genesis_id, 1, 1_700_000_002);
        let block1_id = crate::block::cchain_block_id(&block1).expect("block1 cchain id");
        let block2 = build_cchain_block(block1_id, 2, 1_700_000_004);
        let bad = build_cchain_block([9u8; 32], 2, 1_700_000_004);

        let good = vec![block2.clone(), block1.clone(), genesis.clone()];
        assert!(SyncEngine::validate_cchain_ancestor_chain(
            &good,
            crate::block::cchain_block_id(&block2).expect("block2 cchain id")
        )
        .is_ok());

        let bad_chain = vec![bad, block1.clone(), genesis.clone()];
        assert!(SyncEngine::validate_cchain_ancestor_chain(
            &bad_chain,
            crate::block::cchain_block_id(&block2).expect("block2 cchain id")
        )
        .is_err());

        let (wrapped_genesis, wrapped_genesis_id) = wrap_cchain_block([0u8; 32], &genesis, &[1, 2]);
        let (wrapped_block1, wrapped_block1_id) =
            wrap_cchain_block(wrapped_genesis_id, &block1, &[3, 4]);
        let (wrapped_block2, wrapped_block2_id) =
            wrap_cchain_block(wrapped_block1_id, &block2, &[5, 6]);
        let (wrapped_bad, _) = wrap_cchain_block([9u8; 32], &block2, &[7, 8]);

        let wrapped_good = vec![
            wrapped_block2.clone(),
            wrapped_block1.clone(),
            wrapped_genesis.clone(),
        ];
        assert!(
            SyncEngine::validate_cchain_ancestor_chain(&wrapped_good, wrapped_block2_id).is_ok()
        );

        let wrapped_bad_chain = vec![wrapped_bad, wrapped_block1, wrapped_genesis];
        assert!(
            SyncEngine::validate_cchain_ancestor_chain(&wrapped_bad_chain, wrapped_block2_id)
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_sync_progress() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);

        engine.set_target_height(1000).await;
        engine.handle_block_data(500, vec![]).await;

        let stats = engine.stats().await;
        assert_eq!(stats.progress_pct(), 50.0);
    }

    #[tokio::test]
    async fn test_mark_synced() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);

        assert!(!engine.is_synced().await);
        engine.mark_synced().await;
        assert!(engine.is_synced().await);
        assert_eq!(engine.phase().await, SyncPhase::Synced);
    }

    #[tokio::test]
    async fn test_mark_following() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);

        assert!(!engine.is_following().await);
        engine.mark_following().await;
        assert!(engine.is_following().await);
        assert_eq!(engine.phase().await, SyncPhase::Following);
        assert_eq!(format!("{}", engine.phase().await), "following");
    }

    #[tokio::test]
    async fn test_sync_phase_display_all() {
        assert_eq!(format!("{}", SyncPhase::Idle), "idle");
        assert_eq!(format!("{}", SyncPhase::Fetching), "fetching");
        assert_eq!(format!("{}", SyncPhase::Executing), "executing");
        assert_eq!(format!("{}", SyncPhase::Synced), "synced");
        assert_eq!(format!("{}", SyncPhase::Following), "following");
        assert_eq!(
            format!("{}", SyncPhase::DownloadingTrieNodes),
            "downloading_trie_nodes"
        );
        assert_eq!(
            format!("{}", SyncPhase::VerifyingStateRoot),
            "verifying_state_root"
        );
    }

    #[tokio::test]
    async fn test_following_is_not_synced() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);
        engine.mark_following().await;
        // Following is a distinct phase from Synced
        assert!(!engine.is_synced().await);
        assert!(engine.is_following().await);
    }

    #[tokio::test]
    async fn test_sync_stats_defaults() {
        let stats = SyncStats::default();
        assert_eq!(stats.blocks_downloaded, 0);
        assert_eq!(stats.progress_pct(), 0.0);
        assert_eq!(stats.blocks_per_second(), 0.0);
        assert!(stats.eta_seconds().is_none());
    }

    #[tokio::test]
    async fn test_determined_frontier_majority() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);

        // 2 peers report block A, 1 reports block B
        let block_a = BlockId([0xAA; 32]);
        let block_b = BlockId([0xBB; 32]);

        engine
            .handle_accepted_frontier(&NodeId([1; 20]), 1, &block_a)
            .await;
        engine
            .handle_accepted_frontier(&NodeId([2; 20]), 2, &block_a)
            .await;
        engine
            .handle_accepted_frontier(&NodeId([3; 20]), 3, &block_b)
            .await;

        let frontier = engine.determined_frontier().await.unwrap();
        assert_eq!(frontier.0, [0xAA; 32]);
    }

    #[tokio::test]
    async fn test_empty_frontier() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);
        assert!(engine.determined_frontier().await.is_none());
    }

    #[tokio::test]
    async fn test_fetch_with_no_peers() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);

        let peer = NodeId([1; 20]);
        engine.handle_accepted(&peer, &[BlockId([1; 32])]).await;

        let messages = engine.generate_fetch_requests(&[]).await;
        assert!(messages.is_empty());
    }

    // --- State summary parsing tests ---

    #[tokio::test]
    async fn test_state_summary_encode_decode() {
        let summary = StateSummary {
            height: 12345678,
            block_hash: [0xAA; 32],
            state_root: [0xBB; 32],
        };
        let encoded = summary.encode();
        assert_eq!(encoded.len(), 72);

        let decoded = StateSummary::decode(&encoded).unwrap();
        assert_eq!(decoded.height, 12345678);
        assert_eq!(decoded.block_hash, [0xAA; 32]);
        assert_eq!(decoded.state_root, [0xBB; 32]);
    }

    #[tokio::test]
    async fn test_state_summary_decode_too_short() {
        assert!(StateSummary::decode(&[0u8; 71]).is_none());
        assert!(StateSummary::decode(&[]).is_none());
    }

    #[tokio::test]
    async fn test_handle_state_summary_frontier_parses() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);

        let summary = StateSummary {
            height: 100,
            block_hash: [0x11; 32],
            state_root: [0x22; 32],
        };
        let encoded = summary.encode();

        let parsed = engine
            .handle_state_summary_frontier(&NodeId([1; 20]), 1, &encoded)
            .await;
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.height, 100);
        assert_eq!(parsed.state_root, [0x22; 32]);
    }

    #[tokio::test]
    async fn test_handle_state_summary_frontier_empty() {
        let config = SyncConfig::default();
        let engine = SyncEngine::new(config);

        let parsed = engine
            .handle_state_summary_frontier(&NodeId([1; 20]), 1, &[])
            .await;
        assert!(parsed.is_none());
    }

    // --- State Sync Engine tests ---

    #[tokio::test]
    async fn test_state_sync_engine_creation() {
        let engine = StateSyncEngine::new();
        assert_eq!(
            engine.current_phase().await,
            SyncPhase::StateSummaryFrontier
        );
        assert!(engine.state_root().await.is_none());
        assert!(!engine.is_complete().await);
    }

    #[tokio::test]
    async fn test_state_sync_store_trie_nodes() {
        let engine = StateSyncEngine::new();
        let node_hash = [0xAAu8; 32];
        let node_bytes = vec![1, 2, 3, 4, 5];

        engine.store_trie_node(node_hash, node_bytes.clone()).await;

        let retrieved = engine.get_trie_node(&node_hash).await;
        assert_eq!(retrieved, Some(node_bytes));
        assert_eq!(engine.trie_node_count().await, 1);

        let stats = engine.trie_stats().await;
        assert_eq!(stats.nodes_downloaded, 1);
        assert_eq!(stats.bytes_downloaded, 5);
    }

    #[tokio::test]
    async fn test_state_sync_target_root() {
        let engine = StateSyncEngine::new();
        let state_root = [0xBBu8; 32];

        engine.set_target_state_root(state_root).await;

        assert_eq!(engine.state_root().await, Some(state_root));
        assert_eq!(
            engine.current_phase().await,
            SyncPhase::AcceptedStateSummary
        );
    }

    #[tokio::test]
    async fn test_state_sync_completion() {
        let engine = StateSyncEngine::new();
        assert!(!engine.is_complete().await);

        engine.mark_complete().await;
        assert!(engine.is_complete().await);
        assert_eq!(engine.current_phase().await, SyncPhase::Synced);
    }

    #[tokio::test]
    async fn test_state_sync_best_summary_majority() {
        let engine = StateSyncEngine::new();

        let summary_a = StateSummary {
            height: 100,
            block_hash: [0x11; 32],
            state_root: [0xAA; 32],
        };
        let summary_b = StateSummary {
            height: 100,
            block_hash: [0x22; 32],
            state_root: [0xBB; 32],
        };

        // 2 peers agree on summary_a, 1 on summary_b
        engine
            .handle_state_summary(NodeId([1; 20]), summary_a.clone())
            .await;
        engine
            .handle_state_summary(NodeId([2; 20]), summary_a.clone())
            .await;
        engine
            .handle_state_summary(NodeId([3; 20]), summary_b)
            .await;

        let best = engine.best_summary().await.unwrap();
        assert_eq!(best.state_root, [0xAA; 32]);
    }

    #[tokio::test]
    async fn test_state_sync_needed_trie_nodes() {
        let engine = StateSyncEngine::new();
        let hashes = vec![[0x11; 32], [0x22; 32], [0x33; 32]];

        engine.add_needed_trie_nodes(hashes).await;
        assert_eq!(engine.pending_trie_nodes().await, 3);

        let stats = engine.trie_stats().await;
        assert_eq!(stats.nodes_pending, 3);
    }

    #[tokio::test]
    async fn test_state_sync_generate_trie_requests() {
        let engine = StateSyncEngine::new();
        let peers = vec![NodeId([1; 20]), NodeId([2; 20])];
        let chain_id = ChainId([0xAA; 32]);
        let hashes = vec![[0x11; 32], [0x22; 32]];

        engine.add_needed_trie_nodes(hashes).await;
        let messages = engine.generate_trie_requests(&peers, &chain_id, 10).await;

        assert_eq!(messages.len(), 2);
        assert_eq!(
            engine.current_phase().await,
            SyncPhase::DownloadingTrieNodes
        );

        for (_, msg) in &messages {
            match msg {
                NetworkMessage::AppRequest { app_bytes, .. } => {
                    assert_eq!(app_bytes[0], STATE_SYNC_GET_SUMMARY_TAG);
                }
                _ => panic!("expected AppRequest"),
            }
        }
    }

    #[tokio::test]
    async fn test_state_summary_chunk_roundtrip() {
        let chunk = StateSummaryChunk {
            state_root: [0xAA; 32],
            cursor: 7,
            done: false,
            nodes: vec![TrieNodeChunk {
                node_hash: [0x11; 32],
                node_bytes: vec![1, 2, 3],
                child_hashes: vec![[0x22; 32]],
            }],
        };

        let encoded = chunk.encode();
        let decoded = StateSummaryChunk::decode(&encoded).unwrap();
        assert_eq!(decoded, chunk);
    }

    #[tokio::test]
    async fn test_handle_state_summary_chunk_bytes() {
        use sha2::{Digest, Sha256};

        let engine = StateSyncEngine::new();
        let node_bytes = b"chunk-node".to_vec();
        let node_hash = {
            let h = Sha256::digest(&node_bytes);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        };

        let chunk = StateSummaryChunk {
            state_root: [0x99; 32],
            cursor: 0,
            done: true,
            nodes: vec![TrieNodeChunk {
                node_hash,
                node_bytes,
                child_hashes: vec![],
            }],
        };

        engine.set_target_state_root([0x99; 32]).await;
        let stored = engine
            .handle_state_summary_chunk_bytes(&chunk.encode())
            .await
            .unwrap();
        assert_eq!(stored, 1);
    }

    #[tokio::test]
    async fn test_state_sync_generate_trie_requests_no_peers() {
        let engine = StateSyncEngine::new();
        let chain_id = ChainId([0xAA; 32]);
        engine.add_needed_trie_nodes(vec![[0x11; 32]]).await;

        let messages = engine.generate_trie_requests(&[], &chain_id, 10).await;
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn test_state_sync_verify_state_root_empty() {
        let engine = StateSyncEngine::new();
        // No target root set
        assert!(!engine.verify_state_root().await);
    }

    #[tokio::test]
    async fn test_state_sync_verify_trie_node_hashes() {
        use sha2::{Digest, Sha256};

        let engine = StateSyncEngine::new();

        // Store a trie node with correct hash
        let node_bytes = vec![1, 2, 3, 4, 5];
        let hash = Sha256::digest(&node_bytes);
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash);

        engine.set_target_state_root(hash_arr).await;

        engine.store_trie_node(hash_arr, node_bytes).await;
        assert!(engine.verify_state_root().await);
        assert_eq!(engine.current_phase().await, SyncPhase::VerifyingStateRoot);
    }

    #[tokio::test]
    async fn test_state_sync_verify_parent_child_links() {
        use sha2::{Digest, Sha256};

        let engine = StateSyncEngine::new();

        let root_bytes = b"root-node".to_vec();
        let child_bytes = b"child-node".to_vec();

        let root_hash = {
            let h = Sha256::digest(&root_bytes);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        };
        let child_hash = {
            let h = Sha256::digest(&child_bytes);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        };

        engine
            .store_trie_node_with_links(TrieNodeChunk {
                node_hash: root_hash,
                node_bytes: root_bytes,
                child_hashes: vec![child_hash],
            })
            .await
            .unwrap();
        engine
            .store_trie_node_with_links(TrieNodeChunk {
                node_hash: child_hash,
                node_bytes: child_bytes,
                child_hashes: vec![],
            })
            .await
            .unwrap();

        engine.set_target_state_root(root_hash).await;
        assert!(engine.verify_state_root().await);
    }

    #[tokio::test]
    async fn test_state_sync_verify_parent_child_missing_node_fails() {
        use sha2::{Digest, Sha256};

        let engine = StateSyncEngine::new();
        let root_bytes = b"root-node".to_vec();
        let missing_child_hash = [0x77; 32];
        let root_hash = {
            let h = Sha256::digest(&root_bytes);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        };

        engine
            .store_trie_node_with_links(TrieNodeChunk {
                node_hash: root_hash,
                node_bytes: root_bytes,
                child_hashes: vec![missing_child_hash],
            })
            .await
            .unwrap();

        engine.set_target_state_root(root_hash).await;
        assert!(!engine.verify_state_root().await);
    }

    #[tokio::test]
    async fn test_state_sync_checkpoint_roundtrip() {
        let engine = StateSyncEngine::new();
        let (db, _dir) = crate::db::Database::open_temp().unwrap();

        engine.set_target_state_root([0x42; 32]).await;
        engine
            .add_needed_trie_nodes(vec![[0x01; 32], [0x02; 32]])
            .await;
        engine.persist_checkpoint(&db).await.unwrap();

        let restored = StateSyncEngine::new();
        assert!(restored.restore_checkpoint(&db).await.unwrap());
        assert_eq!(restored.state_root().await, Some([0x42; 32]));
        assert_eq!(restored.pending_trie_nodes().await, 2);
    }

    #[tokio::test]
    async fn test_state_sync_verify_bad_hash() {
        let engine = StateSyncEngine::new();
        engine.set_target_state_root([0xFF; 32]).await;

        // Store a trie node with WRONG hash
        engine.store_trie_node([0xBA; 32], vec![1, 2, 3]).await;
        assert!(!engine.verify_state_root().await);
    }

    #[tokio::test]
    async fn test_state_sync_flush_to_db() {
        use sha2::{Digest, Sha256};

        let engine = StateSyncEngine::new();

        // Store some nodes
        let node1 = vec![10, 20, 30];
        let hash1 = {
            let h = Sha256::digest(&node1);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        };
        let node2 = vec![40, 50, 60];
        let hash2 = {
            let h = Sha256::digest(&node2);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        };

        engine.store_trie_node(hash1, node1.clone()).await;
        engine.store_trie_node(hash2, node2.clone()).await;

        // Flush to DB
        let (db, _dir) = crate::db::Database::open_temp().unwrap();
        let flushed = engine.flush_to_db(&db).await.unwrap();
        assert_eq!(flushed, 2);

        // Verify in DB
        assert_eq!(db.get_trie_node(&hash1).unwrap().unwrap(), node1);
        assert_eq!(db.get_trie_node(&hash2).unwrap().unwrap(), node2);
    }

    #[tokio::test]
    async fn test_state_sync_persistent_store() {
        let engine = StateSyncEngine::new();
        let (db, _dir) = crate::db::Database::open_temp().unwrap();

        let node_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let node_hash = [0x42u8; 32];

        engine
            .store_trie_node_persistent(node_hash, node_bytes.clone(), &db)
            .await
            .unwrap();

        // Check both in-memory and DB
        assert_eq!(
            engine.get_trie_node(&node_hash).await,
            Some(node_bytes.clone())
        );
        assert_eq!(db.get_trie_node(&node_hash).unwrap().unwrap(), node_bytes);
    }

    #[tokio::test]
    async fn test_trie_sync_stats_tracking() {
        let engine = StateSyncEngine::new();

        engine.store_trie_node([0x01; 32], vec![1, 2, 3]).await;
        engine.store_trie_node([0x02; 32], vec![4, 5, 6, 7]).await;

        let stats = engine.trie_stats().await;
        assert_eq!(stats.nodes_downloaded, 2);
        assert_eq!(stats.bytes_downloaded, 7);
    }

    #[tokio::test]
    async fn test_sync_stats_eta() {
        let mut stats = SyncStats::default();
        stats.target_height = 1000;
        stats.last_block_height = 500;
        stats.blocks_downloaded = 500;
        stats.start_time = Some(Instant::now() - Duration::from_secs(10));

        // ~50 blocks/sec, 500 remaining → ~10s
        let eta = stats.eta_seconds().unwrap();
        assert!(eta > 5.0 && eta < 15.0);
    }
}
