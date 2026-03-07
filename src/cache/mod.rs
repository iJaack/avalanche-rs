//! Performance caches — LRU caches for blocks, accounts, and connection pooling.
//!
//! Phase 10: Replace hot-path RwLocks with parking_lot, add LRU caches
//! for recent blocks and account state to reduce DB lookups.

use lru::LruCache;
use parking_lot::RwLock;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Block Cache
// ---------------------------------------------------------------------------

/// LRU cache for recently accessed blocks.
pub struct BlockCache {
    cache: RwLock<LruCache<u64, Vec<u8>>>,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl BlockCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            cache: RwLock::new(LruCache::new(cap)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Get a block from cache.
    pub fn get(&self, height: u64) -> Option<Vec<u8>> {
        let mut cache = self.cache.write();
        match cache.get(&height) {
            Some(data) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(data.clone())
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Put a block in cache.
    pub fn put(&self, height: u64, data: Vec<u8>) {
        let mut cache = self.cache.write();
        cache.put(height, data);
    }

    /// Get cache hit rate.
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed) as f64;
        let misses = self.misses.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        if total == 0.0 {
            0.0
        } else {
            hits / total
        }
    }

    /// Current number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.read().is_empty()
    }

    /// Clear the cache.
    pub fn clear(&self) {
        self.cache.write().clear();
    }
}

// ---------------------------------------------------------------------------
// Account State Cache
// ---------------------------------------------------------------------------

/// Cached account state for reducing trie lookups.
#[derive(Debug, Clone)]
pub struct CachedAccountState {
    pub nonce: u64,
    pub balance: u128,
    pub code_hash: [u8; 32],
}

/// LRU cache for account state.
pub struct AccountCache {
    cache: RwLock<LruCache<[u8; 20], CachedAccountState>>,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl AccountCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            cache: RwLock::new(LruCache::new(cap)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Get account state from cache.
    pub fn get(&self, address: &[u8; 20]) -> Option<CachedAccountState> {
        let mut cache = self.cache.write();
        match cache.get(address) {
            Some(state) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(state.clone())
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Put account state in cache.
    pub fn put(&self, address: [u8; 20], state: CachedAccountState) {
        let mut cache = self.cache.write();
        cache.put(address, state);
    }

    /// Invalidate a cached account.
    pub fn invalidate(&self, address: &[u8; 20]) {
        let mut cache = self.cache.write();
        cache.pop(address);
    }

    /// Hit rate.
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed) as f64;
        let misses = self.misses.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        if total == 0.0 {
            0.0
        } else {
            hits / total
        }
    }

    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.read().is_empty()
    }

    pub fn clear(&self) {
        self.cache.write().clear();
    }
}

// ---------------------------------------------------------------------------
// Connection Pool
// ---------------------------------------------------------------------------

/// A simple connection pool for peer connections.
pub struct ConnectionPool {
    /// Maximum connections
    pub max_connections: usize,
    /// Minimum connections to maintain
    pub min_connections: usize,
    /// Active connection count
    pub active: AtomicU64,
    /// Total connections created
    pub total_created: AtomicU64,
}

impl ConnectionPool {
    pub fn new(min: usize, max: usize) -> Self {
        Self {
            max_connections: max,
            min_connections: min,
            active: AtomicU64::new(0),
            total_created: AtomicU64::new(0),
        }
    }

    /// Try to acquire a connection slot.
    pub fn acquire(&self) -> Result<ConnectionHandle<'_>, CacheError> {
        let current = self.active.load(Ordering::Relaxed);
        if current as usize >= self.max_connections {
            return Err(CacheError::PoolExhausted);
        }
        self.active.fetch_add(1, Ordering::Relaxed);
        self.total_created.fetch_add(1, Ordering::Relaxed);
        Ok(ConnectionHandle { pool: self })
    }

    /// Release a connection back to the pool.
    pub fn release(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Current active connections.
    pub fn active_count(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    /// Whether we need more connections to meet minimum.
    pub fn needs_more(&self) -> bool {
        (self.active.load(Ordering::Relaxed) as usize) < self.min_connections
    }
}

/// Handle to a pooled connection. Releases on drop.
pub struct ConnectionHandle<'a> {
    pool: &'a ConnectionPool,
}

impl<'a> Drop for ConnectionHandle<'a> {
    fn drop(&mut self) {
        self.pool.release();
    }
}

// ---------------------------------------------------------------------------
// Batch Writer
// ---------------------------------------------------------------------------

/// Batch write helper for RocksDB.
pub struct BatchWriter {
    pub writes_batched: AtomicU64,
    pub bytes_batched: AtomicU64,
}

impl BatchWriter {
    pub fn new() -> Self {
        Self {
            writes_batched: AtomicU64::new(0),
            bytes_batched: AtomicU64::new(0),
        }
    }

    /// Execute a batch write. Collects all key-value pairs and writes them
    /// atomically using RocksDB WriteBatch.
    pub fn write_batch(
        &self,
        db: &crate::db::Database,
        cf_name: &str,
        entries: &[(&[u8], &[u8])],
    ) -> Result<(), crate::db::DbError> {
        use rocksdb::WriteBatch;

        let mut batch = WriteBatch::default();
        let cf = db
            .raw()
            .cf_handle(cf_name)
            .unwrap_or_else(|| panic!("CF {} not found", cf_name));

        let mut total_bytes = 0u64;
        for (key, value) in entries {
            batch.put_cf(&cf, key, value);
            total_bytes += (key.len() + value.len()) as u64;
        }

        db.write_batch(batch)?;

        self.writes_batched
            .fetch_add(entries.len() as u64, Ordering::Relaxed);
        self.bytes_batched.fetch_add(total_bytes, Ordering::Relaxed);

        Ok(())
    }

    pub fn metrics(&self) -> (u64, u64) {
        (
            self.writes_batched.load(Ordering::Relaxed),
            self.bytes_batched.load(Ordering::Relaxed),
        )
    }
}

impl Default for BatchWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum CacheError {
    PoolExhausted,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PoolExhausted => write!(f, "connection pool exhausted"),
        }
    }
}

impl std::error::Error for CacheError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    // --- Block Cache tests ---

    #[test]
    fn test_block_cache_creation() {
        let cache = BlockCache::new(100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_block_cache_put_get() {
        let cache = BlockCache::new(10);
        cache.put(100, vec![0xAA; 64]);
        let result = cache.get(100);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_block_cache_miss() {
        let cache = BlockCache::new(10);
        assert!(cache.get(999).is_none());
        assert_eq!(cache.misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_block_cache_hit_rate() {
        let cache = BlockCache::new(10);
        cache.put(1, vec![0x01]);
        cache.get(1); // hit
        cache.get(2); // miss
        let rate = cache.hit_rate();
        assert!((rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_block_cache_eviction() {
        let cache = BlockCache::new(2);
        cache.put(1, vec![0x01]);
        cache.put(2, vec![0x02]);
        cache.put(3, vec![0x03]); // should evict 1

        assert!(cache.get(1).is_none()); // evicted
        assert!(cache.get(3).is_some()); // still present
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_block_cache_clear() {
        let cache = BlockCache::new(10);
        cache.put(1, vec![0x01]);
        cache.put(2, vec![0x02]);
        cache.clear();
        assert!(cache.is_empty());
    }

    // --- Account Cache tests ---

    #[test]
    fn test_account_cache_creation() {
        let cache = AccountCache::new(100);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_account_cache_put_get() {
        let cache = AccountCache::new(10);
        let addr = [0x42u8; 20];
        let state = CachedAccountState {
            nonce: 5,
            balance: 1_000_000,
            code_hash: [0u8; 32],
        };
        cache.put(addr, state);
        let result = cache.get(&addr);
        assert!(result.is_some());
        assert_eq!(result.unwrap().nonce, 5);
    }

    #[test]
    fn test_account_cache_invalidate() {
        let cache = AccountCache::new(10);
        let addr = [0x42u8; 20];
        cache.put(
            addr,
            CachedAccountState {
                nonce: 1,
                balance: 100,
                code_hash: [0u8; 32],
            },
        );
        cache.invalidate(&addr);
        assert!(cache.get(&addr).is_none());
    }

    #[test]
    fn test_account_cache_hit_rate() {
        let cache = AccountCache::new(10);
        let addr = [0x01u8; 20];
        cache.put(
            addr,
            CachedAccountState {
                nonce: 0,
                balance: 0,
                code_hash: [0u8; 32],
            },
        );
        cache.get(&addr); // hit
        cache.get(&[0x02u8; 20]); // miss
        assert!((cache.hit_rate() - 0.5).abs() < 0.01);
    }

    // --- Connection Pool tests ---

    #[test]
    fn test_connection_pool_creation() {
        let pool = ConnectionPool::new(10, 50);
        assert_eq!(pool.min_connections, 10);
        assert_eq!(pool.max_connections, 50);
        assert_eq!(pool.active_count(), 0);
    }

    #[test]
    fn test_connection_pool_acquire_release() {
        let pool = ConnectionPool::new(5, 10);
        {
            let _handle = pool.acquire().unwrap();
            assert_eq!(pool.active_count(), 1);
        }
        // Handle dropped — should release
        assert_eq!(pool.active_count(), 0);
    }

    #[test]
    fn test_connection_pool_exhausted() {
        let pool = ConnectionPool::new(1, 2);
        let _h1 = pool.acquire().unwrap();
        let _h2 = pool.acquire().unwrap();
        let result = pool.acquire();
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_pool_needs_more() {
        let pool = ConnectionPool::new(5, 10);
        assert!(pool.needs_more()); // 0 < 5
        for _ in 0..5 {
            std::mem::forget(pool.acquire().unwrap()); // don't drop
        }
        assert!(!pool.needs_more()); // 5 >= 5
    }

    // --- Batch Writer tests ---

    #[test]
    fn test_batch_writer_creation() {
        let writer = BatchWriter::new();
        let (writes, bytes) = writer.metrics();
        assert_eq!(writes, 0);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn test_batch_writer_write() {
        let writer = BatchWriter::new();
        let (db, _dir) = Database::open_temp().unwrap();

        let entries: Vec<(&[u8], &[u8])> = vec![
            (b"key1", b"value1"),
            (b"key2", b"value2"),
            (b"key3", b"value3"),
        ];

        writer
            .write_batch(&db, crate::db::CF_METADATA, &entries)
            .unwrap();

        let (writes, bytes) = writer.metrics();
        assert_eq!(writes, 3);
        assert!(bytes > 0);

        // Verify data was written
        let v1 = db.get_cf(crate::db::CF_METADATA, b"key1").unwrap().unwrap();
        assert_eq!(v1, b"value1");
    }

    #[test]
    fn test_batch_writer_large_batch() {
        let writer = BatchWriter::new();
        let (db, _dir) = Database::open_temp().unwrap();

        let keys: Vec<Vec<u8>> = (0..100u64)
            .map(|i| format!("key_{}", i).into_bytes())
            .collect();
        let values: Vec<Vec<u8>> = (0..100u64)
            .map(|i| format!("value_{}", i).into_bytes())
            .collect();

        let entries: Vec<(&[u8], &[u8])> = keys
            .iter()
            .zip(values.iter())
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();

        writer
            .write_batch(&db, crate::db::CF_METADATA, &entries)
            .unwrap();

        let (writes, _) = writer.metrics();
        assert_eq!(writes, 100);
    }
}
