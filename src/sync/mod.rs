//! Bootstrapping & State Sync protocol.
//!
//! Phase 5: Download chain state from existing peers.
//! Implements:
//! - State sync: GetStateSummaryFrontier / StateSummaryFrontier
//! - Block bootstrapping: GetAcceptedFrontier → GetAccepted → GetAncestors
//! - Chain catch-up and transition to consensus mode

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::network::{BlockId, ChainId, NetworkMessage, NodeId};

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
    /// Fetching the accepted frontier
    AcceptedFrontier,
    /// Discovering accepted blocks
    AcceptedBlocks,
    /// Downloading ancestor blocks
    Fetching,
    /// Replaying / verifying blocks
    Executing,
    /// Caught up to chain tip
    Synced,
}

impl std::fmt::Display for SyncPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::StateSummaryFrontier => write!(f, "state_summary_frontier"),
            Self::AcceptedStateSummary => write!(f, "accepted_state_summary"),
            Self::AcceptedFrontier => write!(f, "accepted_frontier"),
            Self::AcceptedBlocks => write!(f, "accepted_blocks"),
            Self::Fetching => write!(f, "fetching"),
            Self::Executing => write!(f, "executing"),
            Self::Synced => write!(f, "synced"),
        }
    }
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
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            chain_id: ChainId([0u8; 32]),
            request_timeout: Duration::from_secs(10),
            max_ancestors_per_request: 256,
            max_pending_requests: 32,
            max_retries: 3,
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
    pub async fn start_state_sync(
        &self,
        peers: &[NodeId],
    ) -> Vec<(NodeId, NetworkMessage)> {
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
    pub async fn start_bootstrap(
        &self,
        peers: &[NodeId],
    ) -> Vec<(NodeId, NetworkMessage)> {
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

    /// Handle a StateSummaryFrontier response.
    pub async fn handle_state_summary_frontier(
        &self,
        _peer: &NodeId,
        _request_id: u32,
        summary: &[u8],
    ) {
        if !summary.is_empty() {
            let mut stats = self.stats.write().await;
            stats.bytes_downloaded += summary.len() as u64;
        }
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
    pub async fn handle_block_data(
        &self,
        block_height: u64,
        block_data: Vec<u8>,
    ) {
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
    pub async fn generate_fetch_requests(
        &self,
        peers: &[NodeId],
    ) -> Vec<(NodeId, NetworkMessage)> {
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

            let msg = NetworkMessage::Get {
                chain_id: self.config.chain_id.clone(),
                request_id: req_id,
                deadline: self.config.request_timeout.as_nanos() as u64,
                container_id: block_id,
            };
            messages.push((peer.clone(), msg));
        }
        messages
    }

    /// Check if sync is complete.
    pub async fn is_synced(&self) -> bool {
        *self.phase.read().await == SyncPhase::Synced
    }

    /// Mark sync as complete.
    pub async fn mark_synced(&self) {
        *self.phase.write().await = SyncPhase::Synced;
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chain_id() -> ChainId {
        ChainId([0xAA; 32])
    }

    fn test_peers() -> Vec<NodeId> {
        vec![
            NodeId([1u8; 20]),
            NodeId([2u8; 20]),
            NodeId([3u8; 20]),
        ]
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
            assert!(matches!(msg, NetworkMessage::GetStateSummaryFrontier { .. }));
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

        engine
            .handle_block_data(100, vec![0xDE; 256])
            .await;

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
    async fn test_sync_stats_defaults() {
        let stats = SyncStats::default();
        assert_eq!(stats.blocks_downloaded, 0);
        assert_eq!(stats.progress_pct(), 0.0);
        assert_eq!(stats.blocks_per_second(), 0.0);
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
        engine
            .handle_accepted(&peer, &[BlockId([1; 32])])
            .await;

        let messages = engine.generate_fetch_requests(&[]).await;
        assert!(messages.is_empty());
    }
}
