//! Archive Node Mode — stores ALL historical state trie nodes, never prunes.
//!
//! Phase 9: When --archive is enabled, the node keeps every state root and
//! trie node ever written, allowing queries at any historical block height.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::db::{AccountState, Database, CF_STATE_ROOTS};

// ---------------------------------------------------------------------------
// Archive Store
// ---------------------------------------------------------------------------

/// Column family for historical account snapshots: key = height(8) + address(20).
pub const CF_ARCHIVE_STATE: &str = "archive_state";

/// Archive node store. Keeps per-block snapshots of modified accounts
/// so any historical block can be queried.
pub struct ArchiveStore {
    /// Whether archive mode is enabled.
    pub enabled: bool,
    /// Total bytes stored in archive CFs (approximate).
    pub disk_usage: AtomicU64,
    /// Total snapshots written.
    pub snapshots_written: AtomicU64,
}

impl ArchiveStore {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            disk_usage: AtomicU64::new(0),
            snapshots_written: AtomicU64::new(0),
        }
    }

    /// Record account state at a given block height.
    /// Key = height(8 BE) ++ address(20). Value = RLP-encoded account state.
    pub fn put_account_snapshot(
        &self,
        db: &Database,
        height: u64,
        address: &[u8; 20],
        state: &AccountState,
    ) -> Result<(), crate::db::DbError> {
        if !self.enabled {
            return Ok(());
        }

        let mut key = Vec::with_capacity(28);
        key.extend_from_slice(&height.to_be_bytes());
        key.extend_from_slice(address);

        let value = state.rlp_encode();
        let size = key.len() + value.len();

        db.put_cf(CF_ARCHIVE_STATE, &key, &value)?;

        self.disk_usage.fetch_add(size as u64, Ordering::Relaxed);
        self.snapshots_written.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Get account state at a specific historical block height.
    /// If no snapshot exists at exactly `height`, walks backward to find
    /// the most recent snapshot at or before `height`.
    pub fn get_account_at_height(
        &self,
        db: &Database,
        address: &[u8; 20],
        height: u64,
    ) -> Result<Option<AccountState>, crate::db::DbError> {
        if !self.enabled {
            return Ok(None);
        }

        // Try exact match first
        let mut key = Vec::with_capacity(28);
        key.extend_from_slice(&height.to_be_bytes());
        key.extend_from_slice(address);

        if let Some(data) = db.get_cf(CF_ARCHIVE_STATE, &key)? {
            return Ok(Some(crate::db::decode_account_state_rlp(&data)));
        }

        // Walk backward from height to find most recent snapshot
        for h in (0..height).rev() {
            let mut scan_key = Vec::with_capacity(28);
            scan_key.extend_from_slice(&h.to_be_bytes());
            scan_key.extend_from_slice(address);

            if let Some(data) = db.get_cf(CF_ARCHIVE_STATE, &scan_key)? {
                return Ok(Some(crate::db::decode_account_state_rlp(&data)));
            }

            // Don't scan more than 1000 blocks back for performance
            if height - h > 1000 {
                break;
            }
        }

        Ok(None)
    }

    /// Store state root at a given height (archive mode keeps ALL roots).
    pub fn put_state_root(
        &self,
        db: &Database,
        height: u64,
        state_root: &[u8; 32],
    ) -> Result<(), crate::db::DbError> {
        if !self.enabled {
            return Ok(());
        }
        db.put_cf(CF_STATE_ROOTS, &height.to_be_bytes(), state_root)
    }

    /// Get metrics for archive storage.
    pub fn metrics(&self) -> ArchiveMetrics {
        ArchiveMetrics {
            enabled: self.enabled,
            disk_usage_bytes: self.disk_usage.load(Ordering::Relaxed),
            snapshots_written: self.snapshots_written.load(Ordering::Relaxed),
        }
    }
}

/// Archive storage metrics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchiveMetrics {
    pub enabled: bool,
    pub disk_usage_bytes: u64,
    pub snapshots_written: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{AccountState, Database};

    #[test]
    fn test_archive_disabled_noop() {
        let store = ArchiveStore::new(false);
        let (db, _dir) = Database::open_temp().unwrap();
        let addr = [0x42u8; 20];
        let state = AccountState {
            nonce: 1,
            balance: 1000,
            storage_root: [0u8; 32],
            code_hash: [0u8; 32],
        };
        store.put_account_snapshot(&db, 100, &addr, &state).unwrap();
        let result = store.get_account_at_height(&db, &addr, 100).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_archive_put_get_exact_height() {
        let store = ArchiveStore::new(true);
        let (db, _dir) = Database::open_temp().unwrap();
        let addr = [0x42u8; 20];
        let state = AccountState {
            nonce: 5,
            balance: 1_000_000,
            storage_root: [0u8; 32],
            code_hash: [0u8; 32],
        };
        store.put_account_snapshot(&db, 100, &addr, &state).unwrap();
        let result = store.get_account_at_height(&db, &addr, 100).unwrap();
        assert!(result.is_some());
        let got = result.unwrap();
        assert_eq!(got.nonce, 5);
        assert_eq!(got.balance, 1_000_000);
    }

    #[test]
    fn test_archive_query_balance_at_different_heights() {
        let store = ArchiveStore::new(true);
        let (db, _dir) = Database::open_temp().unwrap();
        let addr = [0x11u8; 20];

        // Block 100: balance = 1000
        let state_100 = AccountState {
            nonce: 0,
            balance: 1000,
            storage_root: [0u8; 32],
            code_hash: [0u8; 32],
        };
        store
            .put_account_snapshot(&db, 100, &addr, &state_100)
            .unwrap();

        // Block 200: balance = 5000
        let state_200 = AccountState {
            nonce: 3,
            balance: 5000,
            storage_root: [0u8; 32],
            code_hash: [0u8; 32],
        };
        store
            .put_account_snapshot(&db, 200, &addr, &state_200)
            .unwrap();

        // Query at block 100 → should get balance 1000
        let at_100 = store
            .get_account_at_height(&db, &addr, 100)
            .unwrap()
            .unwrap();
        assert_eq!(at_100.balance, 1000);

        // Query at block 200 → should get balance 5000
        let at_200 = store
            .get_account_at_height(&db, &addr, 200)
            .unwrap()
            .unwrap();
        assert_eq!(at_200.balance, 5000);

        // Query at block 150 → should walk back to block 100
        let at_150 = store
            .get_account_at_height(&db, &addr, 150)
            .unwrap()
            .unwrap();
        assert_eq!(at_150.balance, 1000);
    }

    #[test]
    fn test_archive_metrics() {
        let store = ArchiveStore::new(true);
        let (db, _dir) = Database::open_temp().unwrap();
        let addr = [0xAAu8; 20];
        let state = AccountState {
            nonce: 1,
            balance: 100,
            storage_root: [0u8; 32],
            code_hash: [0u8; 32],
        };

        store.put_account_snapshot(&db, 1, &addr, &state).unwrap();
        store.put_account_snapshot(&db, 2, &addr, &state).unwrap();

        let metrics = store.metrics();
        assert!(metrics.enabled);
        assert_eq!(metrics.snapshots_written, 2);
        assert!(metrics.disk_usage_bytes > 0);
    }

    #[test]
    fn test_archive_state_root_storage() {
        let store = ArchiveStore::new(true);
        let (db, _dir) = Database::open_temp().unwrap();
        let root = [0xBBu8; 32];

        store.put_state_root(&db, 42, &root).unwrap();
        let got = db
            .get_cf(CF_STATE_ROOTS, &42u64.to_be_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(got.as_slice(), &root);
    }

    #[test]
    fn test_archive_no_snapshot_returns_none() {
        let store = ArchiveStore::new(true);
        let (db, _dir) = Database::open_temp().unwrap();
        let addr = [0xFFu8; 20];
        let result = store.get_account_at_height(&db, &addr, 100).unwrap();
        assert!(result.is_none());
    }
}
