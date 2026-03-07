//! Snap Sync Protocol (Snap/1) implementation.
//!
//! Phase 10: Download full account state in ~10x fewer round trips
//! than trie-walking. Implements GetAccountRange, AccountRange,
//! GetStorageRanges, StorageRanges, GetByteCodes, ByteCodes,
//! GetTrieNodes, TrieNodes message types.

use serde::{Deserialize, Serialize};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Snap Protocol Messages
// ---------------------------------------------------------------------------

/// Snap/1 protocol message types.
#[derive(Debug, Clone)]
pub enum SnapMessage {
    GetAccountRange(GetAccountRange),
    AccountRange(AccountRange),
    GetStorageRanges(GetStorageRanges),
    StorageRanges(StorageRanges),
    GetByteCodes(GetByteCodes),
    ByteCodes(ByteCodes),
    GetTrieNodes(GetTrieNodes),
    TrieNodes(TrieNodes),
}

impl SnapMessage {
    pub fn name(&self) -> &'static str {
        match self {
            Self::GetAccountRange(_) => "GetAccountRange",
            Self::AccountRange(_) => "AccountRange",
            Self::GetStorageRanges(_) => "GetStorageRanges",
            Self::StorageRanges(_) => "StorageRanges",
            Self::GetByteCodes(_) => "GetByteCodes",
            Self::ByteCodes(_) => "ByteCodes",
            Self::GetTrieNodes(_) => "GetTrieNodes",
            Self::TrieNodes(_) => "TrieNodes",
        }
    }
}

/// Request a range of accounts from the state trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAccountRange {
    pub request_id: u64,
    pub root_hash: [u8; 32],
    pub starting_hash: [u8; 32],
    pub limit_hash: [u8; 32],
    pub response_bytes: u64,
}

/// Response with a range of accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRange {
    pub request_id: u64,
    pub accounts: Vec<AccountData>,
    pub proof: Vec<Vec<u8>>,
}

/// Account data in snap response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountData {
    pub hash: [u8; 32],
    pub nonce: u64,
    pub balance: u128,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

/// Request storage ranges for specific accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStorageRanges {
    pub request_id: u64,
    pub root_hash: [u8; 32],
    pub account_hashes: Vec<[u8; 32]>,
    pub starting_hash: [u8; 32],
    pub limit_hash: [u8; 32],
    pub response_bytes: u64,
}

/// Response with storage ranges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRanges {
    pub request_id: u64,
    pub slots: Vec<Vec<StorageSlot>>,
    pub proof: Vec<Vec<u8>>,
}

/// A single storage slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSlot {
    pub hash: [u8; 32],
    pub data: Vec<u8>,
}

/// Request bytecodes by hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetByteCodes {
    pub request_id: u64,
    pub hashes: Vec<[u8; 32]>,
    pub response_bytes: u64,
}

/// Response with bytecodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteCodes {
    pub request_id: u64,
    pub codes: Vec<Vec<u8>>,
}

/// Request trie nodes by path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTrieNodes {
    pub request_id: u64,
    pub root_hash: [u8; 32],
    pub paths: Vec<TrieNodePath>,
    pub response_bytes: u64,
}

/// Path to a trie node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrieNodePath {
    pub account_hash: [u8; 32],
    pub slot_paths: Vec<Vec<u8>>,
}

/// Response with trie nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrieNodes {
    pub request_id: u64,
    pub nodes: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Snap Sync Engine
// ---------------------------------------------------------------------------

/// Snap sync state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapSyncPhase {
    Idle,
    DownloadingAccounts,
    DownloadingStorage,
    DownloadingByteCodes,
    HealingTrie,
    Complete,
    Failed,
}

impl std::fmt::Display for SnapSyncPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::DownloadingAccounts => write!(f, "downloading_accounts"),
            Self::DownloadingStorage => write!(f, "downloading_storage"),
            Self::DownloadingByteCodes => write!(f, "downloading_bytecodes"),
            Self::HealingTrie => write!(f, "healing_trie"),
            Self::Complete => write!(f, "complete"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Progress tracking for snap sync.
#[derive(Debug, Clone)]
pub struct SnapSyncProgress {
    pub phase: SnapSyncPhase,
    pub accounts_downloaded: u64,
    pub storage_slots_downloaded: u64,
    pub bytecodes_downloaded: u64,
    pub trie_nodes_healed: u64,
    pub bytes_downloaded: u64,
    pub start_time: Option<Instant>,
    pub accounts_per_second: f64,
    pub eta_seconds: Option<f64>,
}

impl Default for SnapSyncProgress {
    fn default() -> Self {
        Self {
            phase: SnapSyncPhase::Idle,
            accounts_downloaded: 0,
            storage_slots_downloaded: 0,
            bytecodes_downloaded: 0,
            trie_nodes_healed: 0,
            bytes_downloaded: 0,
            start_time: None,
            accounts_per_second: 0.0,
            eta_seconds: None,
        }
    }
}

impl SnapSyncProgress {
    pub fn update_rate(&mut self) {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                self.accounts_per_second = self.accounts_downloaded as f64 / elapsed;
            }
        }
    }
}

/// Snap sync engine coordinates the download of state via snap protocol.
pub struct SnapSyncEngine {
    pub progress: SnapSyncProgress,
    pub target_root: [u8; 32],
    pub fallback_to_full: bool,
}

impl SnapSyncEngine {
    pub fn new(target_root: [u8; 32]) -> Self {
        Self {
            progress: SnapSyncProgress::default(),
            target_root,
            fallback_to_full: false,
        }
    }

    /// Start the snap sync process.
    pub fn start(&mut self) {
        self.progress.phase = SnapSyncPhase::DownloadingAccounts;
        self.progress.start_time = Some(Instant::now());
    }

    /// Build a GetAccountRange request for the next batch.
    pub fn build_account_range_request(
        &self,
        request_id: u64,
        starting_hash: [u8; 32],
    ) -> GetAccountRange {
        GetAccountRange {
            request_id,
            root_hash: self.target_root,
            starting_hash,
            limit_hash: [0xFF; 32],
            response_bytes: 512 * 1024, // 512 KB
        }
    }

    /// Process an account range response.
    pub fn process_account_range(&mut self, response: &AccountRange) -> Vec<AccountData> {
        self.progress.accounts_downloaded += response.accounts.len() as u64;
        self.progress.bytes_downloaded += response.accounts.len() as u64 * 104;
        self.progress.update_rate();
        response.accounts.clone()
    }

    /// Process a storage ranges response.
    pub fn process_storage_ranges(&mut self, response: &StorageRanges) {
        for slots in &response.slots {
            self.progress.storage_slots_downloaded += slots.len() as u64;
            for slot in slots {
                self.progress.bytes_downloaded += 64 + slot.data.len() as u64;
            }
        }
        self.progress.update_rate();
    }

    /// Process bytecodes response.
    pub fn process_bytecodes(&mut self, response: &ByteCodes) {
        self.progress.bytecodes_downloaded += response.codes.len() as u64;
        for code in &response.codes {
            self.progress.bytes_downloaded += code.len() as u64;
        }
    }

    /// Start the healing phase.
    pub fn start_healing(&mut self) {
        self.progress.phase = SnapSyncPhase::HealingTrie;
    }

    /// Process trie node healing response.
    pub fn process_trie_nodes(&mut self, response: &TrieNodes) {
        self.progress.trie_nodes_healed += response.nodes.len() as u64;
        for node in &response.nodes {
            self.progress.bytes_downloaded += node.len() as u64;
        }
    }

    /// Verify the trie after healing using a simple hash check.
    pub fn verify_trie_healing(&self, computed_root: &[u8; 32]) -> bool {
        *computed_root == self.target_root
    }

    /// Mark sync as complete.
    pub fn complete(&mut self) {
        self.progress.phase = SnapSyncPhase::Complete;
    }

    /// Mark sync as failed and enable fallback.
    pub fn fail(&mut self) {
        self.progress.phase = SnapSyncPhase::Failed;
        self.fallback_to_full = true;
    }

    /// Get current progress.
    pub fn get_progress(&self) -> &SnapSyncProgress {
        &self.progress
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snap_sync_engine_creation() {
        let root = [0xAA; 32];
        let engine = SnapSyncEngine::new(root);
        assert_eq!(engine.target_root, root);
        assert_eq!(engine.progress.phase, SnapSyncPhase::Idle);
        assert!(!engine.fallback_to_full);
    }

    #[test]
    fn test_snap_sync_start() {
        let mut engine = SnapSyncEngine::new([0; 32]);
        engine.start();
        assert_eq!(engine.progress.phase, SnapSyncPhase::DownloadingAccounts);
        assert!(engine.progress.start_time.is_some());
    }

    #[test]
    fn test_account_range_request() {
        let engine = SnapSyncEngine::new([0xBB; 32]);
        let req = engine.build_account_range_request(1, [0; 32]);
        assert_eq!(req.request_id, 1);
        assert_eq!(req.root_hash, [0xBB; 32]);
        assert_eq!(req.response_bytes, 512 * 1024);
    }

    #[test]
    fn test_process_account_range() {
        let mut engine = SnapSyncEngine::new([0; 32]);
        engine.start();

        let response = AccountRange {
            request_id: 1,
            accounts: vec![
                AccountData {
                    hash: [0x01; 32],
                    nonce: 5,
                    balance: 1000,
                    storage_root: [0; 32],
                    code_hash: [0; 32],
                },
                AccountData {
                    hash: [0x02; 32],
                    nonce: 0,
                    balance: 0,
                    storage_root: [0; 32],
                    code_hash: [0; 32],
                },
            ],
            proof: vec![],
        };

        let accounts = engine.process_account_range(&response);
        assert_eq!(accounts.len(), 2);
        assert_eq!(engine.progress.accounts_downloaded, 2);
        assert!(engine.progress.bytes_downloaded > 0);
    }

    #[test]
    fn test_process_storage_ranges() {
        let mut engine = SnapSyncEngine::new([0; 32]);
        engine.start();

        let response = StorageRanges {
            request_id: 1,
            slots: vec![vec![StorageSlot {
                hash: [0x01; 32],
                data: vec![0xAA; 32],
            }]],
            proof: vec![],
        };

        engine.process_storage_ranges(&response);
        assert_eq!(engine.progress.storage_slots_downloaded, 1);
    }

    #[test]
    fn test_trie_healing_verification() {
        let root = [0xCC; 32];
        let engine = SnapSyncEngine::new(root);

        assert!(engine.verify_trie_healing(&root));
        assert!(!engine.verify_trie_healing(&[0; 32]));
    }

    #[test]
    fn test_snap_sync_failure_fallback() {
        let mut engine = SnapSyncEngine::new([0; 32]);
        engine.start();
        engine.fail();

        assert_eq!(engine.progress.phase, SnapSyncPhase::Failed);
        assert!(engine.fallback_to_full);
    }

    #[test]
    fn test_snap_sync_complete() {
        let mut engine = SnapSyncEngine::new([0; 32]);
        engine.start();
        engine.complete();
        assert_eq!(engine.progress.phase, SnapSyncPhase::Complete);
    }

    #[test]
    fn test_snap_message_names() {
        let msg = SnapMessage::GetAccountRange(GetAccountRange {
            request_id: 0,
            root_hash: [0; 32],
            starting_hash: [0; 32],
            limit_hash: [0; 32],
            response_bytes: 0,
        });
        assert_eq!(msg.name(), "GetAccountRange");

        let msg = SnapMessage::TrieNodes(TrieNodes {
            request_id: 0,
            nodes: vec![],
        });
        assert_eq!(msg.name(), "TrieNodes");
    }

    #[test]
    fn test_progress_rate_update() {
        let mut progress = SnapSyncProgress::default();
        // Use a start time slightly in the past to ensure elapsed > 0
        progress.start_time = Some(Instant::now() - std::time::Duration::from_millis(100));
        progress.accounts_downloaded = 1000;
        progress.update_rate();
        // Rate should be > 0 since we downloaded accounts over non-zero time
        assert!(progress.accounts_per_second > 0.0);
    }

    #[test]
    fn test_snap_sync_phase_display() {
        assert_eq!(SnapSyncPhase::Idle.to_string(), "idle");
        assert_eq!(
            SnapSyncPhase::DownloadingAccounts.to_string(),
            "downloading_accounts"
        );
        assert_eq!(SnapSyncPhase::HealingTrie.to_string(), "healing_trie");
        assert_eq!(SnapSyncPhase::Complete.to_string(), "complete");
    }
}
