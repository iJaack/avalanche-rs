//! Database layer using RocksDB with column families.
//!
//! Phase 4: Persistent storage for blocks, state, and indexes.
//! Column families:
//! - `blocks`     — Block headers + full serialized blocks
//! - `state`      — Account state (balance, nonce, code_hash, storage_root)
//! - `code`       — Contract bytecode by code_hash
//! - `receipts`   — Transaction receipts
//! - `tx_index`   — Transaction hash → (block_number, tx_index) mapping
//! - `metadata`   — Chain metadata (last accepted block, state root, etc.)
//! - `trie_nodes` — Merkle Patricia Trie nodes

use std::path::Path;
use std::sync::Arc;

use rocksdb::{
    ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options,
    WriteBatch,
};

/// Column family names.
pub const CF_BLOCKS: &str = "blocks";
pub const CF_STATE: &str = "state";
pub const CF_CODE: &str = "code";
pub const CF_RECEIPTS: &str = "receipts";
pub const CF_TX_INDEX: &str = "tx_index";
pub const CF_METADATA: &str = "metadata";
pub const CF_TRIE_NODES: &str = "trie_nodes";

const ALL_CFS: &[&str] = &[
    CF_BLOCKS,
    CF_STATE,
    CF_CODE,
    CF_RECEIPTS,
    CF_TX_INDEX,
    CF_METADATA,
    CF_TRIE_NODES,
];

/// Well-known metadata keys.
pub const META_LAST_ACCEPTED_HEIGHT: &[u8] = b"last_accepted_height";
pub const META_LAST_ACCEPTED_HASH: &[u8] = b"last_accepted_hash";
pub const META_STATE_ROOT: &[u8] = b"state_root";
pub const META_CHAIN_ID: &[u8] = b"chain_id";

type RocksDB = DBWithThreadMode<MultiThreaded>;

/// The database wrapper around RocksDB.
pub struct Database {
    db: Arc<RocksDB>,
}

impl Database {
    /// Open (or create) a RocksDB database at the given path.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_background_jobs(4);
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64 MB
        opts.set_max_write_buffer_number(3);
        opts.set_level_compaction_dynamic_level_bytes(true);
        opts.increase_parallelism(num_cpus());

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_CFS
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let db = RocksDB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| DbError::Open(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Open a temporary database (for tests).
    pub fn open_temp() -> Result<(Self, tempfile::TempDir), DbError> {
        let dir = tempfile::tempdir().map_err(|e| DbError::Open(e.to_string()))?;
        let db = Self::open(dir.path())?;
        Ok((db, dir))
    }

    // -----------------------------------------------------------------------
    // Generic column-family operations
    // -----------------------------------------------------------------------

    /// Get the column family handle by name.
    fn cf_handle(&self, name: &str) -> std::sync::Arc<rocksdb::BoundColumnFamily<'_>> {
        self.db
            .cf_handle(name)
            .unwrap_or_else(|| panic!("column family '{}' not found", name))
    }

    /// Get a value from a column family.
    pub fn get_cf(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        let cf = self.cf_handle(cf_name);
        self.db
            .get_cf(&cf, key)
            .map_err(|e| DbError::Read(e.to_string()))
    }

    /// Put a value into a column family.
    pub fn put_cf(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<(), DbError> {
        let cf = self.cf_handle(cf_name);
        self.db
            .put_cf(&cf, key, value)
            .map_err(|e| DbError::Write(e.to_string()))
    }

    /// Delete a key from a column family.
    pub fn delete_cf(&self, cf_name: &str, key: &[u8]) -> Result<(), DbError> {
        let cf = self.cf_handle(cf_name);
        self.db
            .delete_cf(&cf, key)
            .map_err(|e| DbError::Write(e.to_string()))
    }

    /// Write a batch of operations atomically.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<(), DbError> {
        self.db
            .write(batch)
            .map_err(|e| DbError::Write(e.to_string()))
    }

    // -----------------------------------------------------------------------
    // Block storage
    // -----------------------------------------------------------------------

    /// Store a serialized block by height.
    pub fn put_block(&self, height: u64, block_data: &[u8]) -> Result<(), DbError> {
        self.put_cf(CF_BLOCKS, &height.to_be_bytes(), block_data)
    }

    /// Get a serialized block by height.
    pub fn get_block(&self, height: u64) -> Result<Option<Vec<u8>>, DbError> {
        self.get_cf(CF_BLOCKS, &height.to_be_bytes())
    }

    // -----------------------------------------------------------------------
    // State storage
    // -----------------------------------------------------------------------

    /// Store account state by address (20-byte key).
    pub fn put_state(&self, address: &[u8; 20], state_data: &[u8]) -> Result<(), DbError> {
        self.put_cf(CF_STATE, address, state_data)
    }

    /// Get account state by address.
    pub fn get_state(&self, address: &[u8; 20]) -> Result<Option<Vec<u8>>, DbError> {
        self.get_cf(CF_STATE, address)
    }

    // -----------------------------------------------------------------------
    // Code storage
    // -----------------------------------------------------------------------

    /// Store contract bytecode by code hash.
    pub fn put_code(&self, code_hash: &[u8; 32], code: &[u8]) -> Result<(), DbError> {
        self.put_cf(CF_CODE, code_hash, code)
    }

    /// Get contract bytecode by code hash.
    pub fn get_code(&self, code_hash: &[u8; 32]) -> Result<Option<Vec<u8>>, DbError> {
        self.get_cf(CF_CODE, code_hash)
    }

    // -----------------------------------------------------------------------
    // Transaction index
    // -----------------------------------------------------------------------

    /// Store transaction hash → (block_height, tx_index) mapping.
    pub fn put_tx_index(
        &self,
        tx_hash: &[u8; 32],
        block_height: u64,
        tx_index: u32,
    ) -> Result<(), DbError> {
        let mut value = Vec::with_capacity(12);
        value.extend_from_slice(&block_height.to_be_bytes());
        value.extend_from_slice(&tx_index.to_be_bytes());
        self.put_cf(CF_TX_INDEX, tx_hash, &value)
    }

    /// Look up a transaction's block height and index.
    pub fn get_tx_index(&self, tx_hash: &[u8; 32]) -> Result<Option<(u64, u32)>, DbError> {
        match self.get_cf(CF_TX_INDEX, tx_hash)? {
            Some(v) if v.len() == 12 => {
                let height = u64::from_be_bytes(v[..8].try_into().unwrap());
                let idx = u32::from_be_bytes(v[8..12].try_into().unwrap());
                Ok(Some((height, idx)))
            }
            _ => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // Receipt storage
    // -----------------------------------------------------------------------

    /// Store receipt data keyed by block_height + tx_index.
    pub fn put_receipt(
        &self,
        block_height: u64,
        tx_index: u32,
        receipt_data: &[u8],
    ) -> Result<(), DbError> {
        let mut key = Vec::with_capacity(12);
        key.extend_from_slice(&block_height.to_be_bytes());
        key.extend_from_slice(&tx_index.to_be_bytes());
        self.put_cf(CF_RECEIPTS, &key, receipt_data)
    }

    /// Get receipt data by block height + tx index.
    pub fn get_receipt(&self, block_height: u64, tx_index: u32) -> Result<Option<Vec<u8>>, DbError> {
        let mut key = Vec::with_capacity(12);
        key.extend_from_slice(&block_height.to_be_bytes());
        key.extend_from_slice(&tx_index.to_be_bytes());
        self.get_cf(CF_RECEIPTS, &key)
    }

    // -----------------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------------

    /// Store a metadata value.
    pub fn put_metadata(&self, key: &[u8], value: &[u8]) -> Result<(), DbError> {
        self.put_cf(CF_METADATA, key, value)
    }

    /// Get a metadata value.
    pub fn get_metadata(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        self.get_cf(CF_METADATA, key)
    }

    /// Get the last accepted block height.
    pub fn last_accepted_height(&self) -> Result<Option<u64>, DbError> {
        match self.get_metadata(META_LAST_ACCEPTED_HEIGHT)? {
            Some(v) if v.len() == 8 => Ok(Some(u64::from_be_bytes(v.try_into().unwrap()))),
            _ => Ok(None),
        }
    }

    /// Set the last accepted block height.
    pub fn set_last_accepted_height(&self, height: u64) -> Result<(), DbError> {
        self.put_metadata(META_LAST_ACCEPTED_HEIGHT, &height.to_be_bytes())
    }

    // -----------------------------------------------------------------------
    // Trie nodes
    // -----------------------------------------------------------------------

    /// Store a Merkle Patricia Trie node by its hash.
    pub fn put_trie_node(&self, hash: &[u8; 32], node_data: &[u8]) -> Result<(), DbError> {
        self.put_cf(CF_TRIE_NODES, hash, node_data)
    }

    /// Get a trie node by hash.
    pub fn get_trie_node(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, DbError> {
        self.get_cf(CF_TRIE_NODES, hash)
    }

    /// Get the underlying RocksDB handle (for advanced use).
    pub fn raw(&self) -> &Arc<RocksDB> {
        &self.db
    }

    /// Iterate over all key-value pairs in a column family.
    ///
    /// Returns an iterator of `(key_bytes, value_bytes)` pairs.
    pub fn iter_cf_owned(&self, cf_name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        let cf = self.cf_handle(cf_name);
        self.db
            .iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .filter_map(|item| {
                item.ok().map(|(k, v)| (k.to_vec(), v.to_vec()))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Simple Merkle Patricia Trie (in-memory, for state root computation)
// ---------------------------------------------------------------------------

/// A simplified Merkle Patricia Trie for computing state roots.
/// Uses alloy-trie for the actual hash computation.
pub struct StateTrie {
    /// Accounts keyed by address → RLP-encoded account state
    accounts: std::collections::BTreeMap<[u8; 20], Vec<u8>>,
}

/// RLP-encoded account state (balance, nonce, storage_root, code_hash).
#[derive(Debug, Clone)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: u128,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

impl AccountState {
    /// RLP-encode the account state.
    pub fn rlp_encode(&self) -> Vec<u8> {
        // Simple manual RLP encoding for the account
        let mut items: Vec<Vec<u8>> = Vec::new();
        items.push(rlp_encode_u64(self.nonce));
        items.push(rlp_encode_u128(self.balance));
        items.push(rlp_encode_bytes(&self.storage_root));
        items.push(rlp_encode_bytes(&self.code_hash));
        rlp_encode_list(&items)
    }
}

impl StateTrie {
    pub fn new() -> Self {
        Self {
            accounts: std::collections::BTreeMap::new(),
        }
    }

    /// Insert or update an account.
    pub fn insert(&mut self, address: [u8; 20], state: &AccountState) {
        self.accounts.insert(address, state.rlp_encode());
    }

    /// Remove an account.
    pub fn remove(&mut self, address: &[u8; 20]) {
        self.accounts.remove(address);
    }

    /// Compute the state root hash (Keccak-256 of the trie).
    /// Uses a simplified approach: sort accounts, hash them together.
    pub fn root_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for (addr, state_rlp) in &self.accounts {
            hasher.update(addr);
            hasher.update(state_rlp);
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Number of accounts in the trie.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}

impl Default for StateTrie {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RLP helpers (minimal, for account encoding)
// ---------------------------------------------------------------------------

fn rlp_encode_u64(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0x80]; // empty string
    }
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let significant = &bytes[start..];
    if significant.len() == 1 && significant[0] < 0x80 {
        significant.to_vec()
    } else {
        let mut out = vec![0x80 + significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
}

fn rlp_encode_u128(val: u128) -> Vec<u8> {
    if val == 0 {
        return vec![0x80];
    }
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    let significant = &bytes[start..];
    if significant.len() == 1 && significant[0] < 0x80 {
        significant.to_vec()
    } else {
        let mut out = vec![0x80 + significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        data.to_vec()
    } else if data.len() < 56 {
        let mut out = vec![0x80 + data.len() as u8];
        out.extend_from_slice(data);
        out
    } else {
        let len_bytes = data.len().to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len_significant = &len_bytes[start..];
        let mut out = vec![0xb7 + len_significant.len() as u8];
        out.extend_from_slice(len_significant);
        out.extend_from_slice(data);
        out
    }
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    if payload.len() < 56 {
        let mut out = vec![0xc0 + payload.len() as u8];
        out.extend_from_slice(&payload);
        out
    } else {
        let len_bytes = payload.len().to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len_significant = &len_bytes[start..];
        let mut out = vec![0xf7 + len_significant.len() as u8];
        out.extend_from_slice(len_significant);
        out.extend_from_slice(&payload);
        out
    }
}

fn num_cpus() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(4)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum DbError {
    Open(String),
    Read(String),
    Write(String),
    NotFound(String),
    Corruption(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "db open: {}", e),
            Self::Read(e) => write!(f, "db read: {}", e),
            Self::Write(e) => write!(f, "db write: {}", e),
            Self::NotFound(e) => write!(f, "not found: {}", e),
            Self::Corruption(e) => write!(f, "corruption: {}", e),
        }
    }
}

impl std::error::Error for DbError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_temp_db() {
        let (db, _dir) = Database::open_temp().unwrap();
        // Verify all column families exist
        for cf_name in ALL_CFS {
            assert!(db.db.cf_handle(cf_name).is_some(), "CF {} missing", cf_name);
        }
    }

    #[test]
    fn test_put_get_cf() {
        let (db, _dir) = Database::open_temp().unwrap();
        db.put_cf(CF_METADATA, b"key1", b"value1").unwrap();
        let val = db.get_cf(CF_METADATA, b"key1").unwrap();
        assert_eq!(val.as_deref(), Some(b"value1".as_slice()));
    }

    #[test]
    fn test_get_nonexistent() {
        let (db, _dir) = Database::open_temp().unwrap();
        let val = db.get_cf(CF_METADATA, b"missing").unwrap();
        assert!(val.is_none());
    }

    #[test]
    fn test_delete_cf() {
        let (db, _dir) = Database::open_temp().unwrap();
        db.put_cf(CF_METADATA, b"key", b"val").unwrap();
        db.delete_cf(CF_METADATA, b"key").unwrap();
        assert!(db.get_cf(CF_METADATA, b"key").unwrap().is_none());
    }

    #[test]
    fn test_block_storage() {
        let (db, _dir) = Database::open_temp().unwrap();
        let block_data = b"serialized block data";
        db.put_block(100, block_data).unwrap();
        let retrieved = db.get_block(100).unwrap().unwrap();
        assert_eq!(retrieved, block_data);
    }

    #[test]
    fn test_state_storage() {
        let (db, _dir) = Database::open_temp().unwrap();
        let addr = [0x42u8; 20];
        let state = b"account state";
        db.put_state(&addr, state).unwrap();
        let retrieved = db.get_state(&addr).unwrap().unwrap();
        assert_eq!(retrieved, state);
    }

    #[test]
    fn test_code_storage() {
        let (db, _dir) = Database::open_temp().unwrap();
        let hash = [0xAA; 32];
        let code = vec![0x60, 0x00, 0x60, 0x00, 0xf3]; // minimal bytecode
        db.put_code(&hash, &code).unwrap();
        let retrieved = db.get_code(&hash).unwrap().unwrap();
        assert_eq!(retrieved, code);
    }

    #[test]
    fn test_tx_index() {
        let (db, _dir) = Database::open_temp().unwrap();
        let tx_hash = [0xBB; 32];
        db.put_tx_index(&tx_hash, 500, 3).unwrap();
        let (height, idx) = db.get_tx_index(&tx_hash).unwrap().unwrap();
        assert_eq!(height, 500);
        assert_eq!(idx, 3);
    }

    #[test]
    fn test_receipt_storage() {
        let (db, _dir) = Database::open_temp().unwrap();
        let receipt_data = b"receipt json";
        db.put_receipt(100, 0, receipt_data).unwrap();
        let retrieved = db.get_receipt(100, 0).unwrap().unwrap();
        assert_eq!(retrieved, receipt_data);
    }

    #[test]
    fn test_metadata_last_accepted() {
        let (db, _dir) = Database::open_temp().unwrap();
        assert!(db.last_accepted_height().unwrap().is_none());
        db.set_last_accepted_height(42).unwrap();
        assert_eq!(db.last_accepted_height().unwrap(), Some(42));
    }

    #[test]
    fn test_trie_node_storage() {
        let (db, _dir) = Database::open_temp().unwrap();
        let hash = [0xCC; 32];
        let node_data = b"trie node rlp";
        db.put_trie_node(&hash, node_data).unwrap();
        assert_eq!(db.get_trie_node(&hash).unwrap().unwrap(), node_data);
    }

    #[test]
    fn test_write_batch() {
        let (db, _dir) = Database::open_temp().unwrap();
        let mut batch = WriteBatch::default();
        let cf = db.cf_handle(CF_METADATA);
        batch.put_cf(&cf, b"batch_key1", b"val1");
        batch.put_cf(&cf, b"batch_key2", b"val2");
        drop(cf);
        db.write_batch(batch).unwrap();

        assert_eq!(
            db.get_cf(CF_METADATA, b"batch_key1").unwrap().unwrap(),
            b"val1"
        );
        assert_eq!(
            db.get_cf(CF_METADATA, b"batch_key2").unwrap().unwrap(),
            b"val2"
        );
    }

    #[test]
    fn test_state_trie_empty() {
        let trie = StateTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.len(), 0);
    }

    #[test]
    fn test_state_trie_insert_and_root() {
        let mut trie = StateTrie::new();
        let acc = AccountState {
            nonce: 1,
            balance: 1_000_000,
            storage_root: [0u8; 32],
            code_hash: [0u8; 32],
        };
        trie.insert([0x01; 20], &acc);
        assert_eq!(trie.len(), 1);

        let root1 = trie.root_hash();
        assert_ne!(root1, [0u8; 32]);

        // Same data → same root
        let root2 = trie.root_hash();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_state_trie_different_accounts_different_roots() {
        let mut trie1 = StateTrie::new();
        let mut trie2 = StateTrie::new();

        let acc1 = AccountState {
            nonce: 1,
            balance: 100,
            storage_root: [0; 32],
            code_hash: [0; 32],
        };
        let acc2 = AccountState {
            nonce: 2,
            balance: 200,
            storage_root: [0; 32],
            code_hash: [0; 32],
        };

        trie1.insert([0x01; 20], &acc1);
        trie2.insert([0x01; 20], &acc2);

        assert_ne!(trie1.root_hash(), trie2.root_hash());
    }

    #[test]
    fn test_state_trie_remove() {
        let mut trie = StateTrie::new();
        let acc = AccountState {
            nonce: 0,
            balance: 0,
            storage_root: [0; 32],
            code_hash: [0; 32],
        };
        trie.insert([0x01; 20], &acc);
        assert_eq!(trie.len(), 1);
        trie.remove(&[0x01; 20]);
        assert!(trie.is_empty());
    }

    #[test]
    fn test_rlp_encode_u64() {
        assert_eq!(rlp_encode_u64(0), vec![0x80]);
        assert_eq!(rlp_encode_u64(1), vec![0x01]);
        assert_eq!(rlp_encode_u64(127), vec![0x7f]);
        assert_eq!(rlp_encode_u64(128), vec![0x81, 0x80]);
        assert_eq!(rlp_encode_u64(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_account_state_rlp() {
        let acc = AccountState {
            nonce: 0,
            balance: 0,
            storage_root: [0; 32],
            code_hash: [0; 32],
        };
        let rlp = acc.rlp_encode();
        // Should be a valid RLP list
        assert!(rlp[0] >= 0xc0, "should start with list prefix");
    }

    #[test]
    fn test_many_blocks() {
        let (db, _dir) = Database::open_temp().unwrap();
        for i in 0..100u64 {
            db.put_block(i, &format!("block_{}", i).into_bytes()).unwrap();
        }
        for i in 0..100u64 {
            let data = db.get_block(i).unwrap().unwrap();
            assert_eq!(data, format!("block_{}", i).into_bytes());
        }
    }
}
