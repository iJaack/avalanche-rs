//! Transaction Pool with priority queue, nonce gap handling, and eviction.
//!
//! Phase 9: EIP-1559-aware priority ordering, per-account limits,
//! pool size limits, and RPC inspection methods.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

// ---------------------------------------------------------------------------
// Pool Transaction
// ---------------------------------------------------------------------------

/// A transaction in the pool.
#[derive(Debug, Clone)]
pub struct PoolTransaction {
    /// Transaction hash
    pub hash: [u8; 32],
    /// Sender address
    pub from: [u8; 20],
    /// Recipient
    pub to: Option<[u8; 20]>,
    /// Nonce
    pub nonce: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Gas price (legacy) or max fee per gas (EIP-1559)
    pub max_fee_per_gas: u128,
    /// Max priority fee per gas (EIP-1559 tip)
    pub max_priority_fee_per_gas: u128,
    /// Value transferred
    pub value: u128,
    /// Calldata
    pub data: Vec<u8>,
    /// Transaction size in bytes
    pub size: usize,
    /// Timestamp when added to pool
    pub timestamp: u64,
}

impl PoolTransaction {
    /// Compute the effective gas price given the current base fee.
    pub fn effective_gas_price(&self, base_fee: u128) -> u128 {
        let priority = self.max_priority_fee_per_gas;
        let max = self.max_fee_per_gas;
        // effective = min(max_fee, base_fee + priority_fee)
        max.min(base_fee + priority)
    }
}

// ---------------------------------------------------------------------------
// Transaction Pool
// ---------------------------------------------------------------------------

/// Maximum transactions per account.
const DEFAULT_MAX_PER_ACCOUNT: usize = 64;

/// Transaction pool with EIP-1559 aware priority ordering.
pub struct TransactionPool {
    /// Pool size limit
    pub max_size: usize,
    /// Max transactions per account
    pub max_per_account: usize,
    /// Current base fee for priority calculations
    pub base_fee: u128,

    /// Pending transactions (executable, correct nonce sequence)
    pending: HashMap<[u8; 20], BTreeMap<u64, PoolTransaction>>,
    /// Queued transactions (future nonce, waiting for gap to fill)
    queued: HashMap<[u8; 20], BTreeMap<u64, PoolTransaction>>,
    /// Quick lookup by hash
    by_hash: HashMap<[u8; 32], ([u8; 20], u64, bool)>, // (from, nonce, is_pending)

    /// Total transaction count
    total_count: usize,
    /// Stats
    pub adds: u64,
    pub evictions: u64,
    pub promotions: u64,
}

impl TransactionPool {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            max_per_account: DEFAULT_MAX_PER_ACCOUNT,
            base_fee: 25_000_000_000, // 25 gwei default
            pending: HashMap::new(),
            queued: HashMap::new(),
            by_hash: HashMap::new(),
            total_count: 0,
            adds: 0,
            evictions: 0,
            promotions: 0,
        }
    }

    /// Add a transaction to the pool.
    /// Returns Ok(true) if added, Ok(false) if replaced existing, Err if rejected.
    pub fn add(&mut self, tx: PoolTransaction, account_nonce: u64) -> Result<bool, PoolError> {
        // Check per-account limit
        let account_count = self.account_tx_count(&tx.from);
        if account_count >= self.max_per_account {
            return Err(PoolError::AccountLimitReached(self.max_per_account));
        }

        // Determine if pending or queued based on nonce
        let is_pending = tx.nonce == account_nonce
            || self.pending.get(&tx.from).map_or(false, |m| {
                // Check if this nonce is the next expected
                m.keys().last().map_or(false, |&last| tx.nonce == last + 1)
            });

        let from = tx.from;
        let nonce = tx.nonce;
        let hash = tx.hash;

        // Check for replacement
        let replaced = self.by_hash.contains_key(&hash);

        if is_pending {
            self.pending
                .entry(from)
                .or_insert_with(BTreeMap::new)
                .insert(nonce, tx);
            self.by_hash.insert(hash, (from, nonce, true));
        } else {
            self.queued
                .entry(from)
                .or_insert_with(BTreeMap::new)
                .insert(nonce, tx);
            self.by_hash.insert(hash, (from, nonce, false));
        }

        if !replaced {
            self.total_count += 1;
            self.adds += 1;
        }

        // Evict if over limit
        if self.total_count > self.max_size {
            self.evict_lowest_fee();
        }

        // Try to promote queued → pending
        self.promote_queued(&from, account_nonce);

        Ok(!replaced)
    }

    /// Remove a transaction by hash.
    pub fn remove(&mut self, hash: &[u8; 32]) -> Option<PoolTransaction> {
        if let Some((from, nonce, is_pending)) = self.by_hash.remove(hash) {
            self.total_count = self.total_count.saturating_sub(1);
            if is_pending {
                if let Some(map) = self.pending.get_mut(&from) {
                    return map.remove(&nonce);
                }
            } else {
                if let Some(map) = self.queued.get_mut(&from) {
                    return map.remove(&nonce);
                }
            }
        }
        None
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&PoolTransaction> {
        if let Some((from, nonce, is_pending)) = self.by_hash.get(hash) {
            if *is_pending {
                self.pending.get(from)?.get(nonce)
            } else {
                self.queued.get(from)?.get(nonce)
            }
        } else {
            None
        }
    }

    /// Get all pending transactions sorted by effective gas price (highest first).
    pub fn pending_sorted(&self) -> Vec<&PoolTransaction> {
        let mut txs: Vec<&PoolTransaction> =
            self.pending.values().flat_map(|m| m.values()).collect();
        let base = self.base_fee;
        txs.sort_by(|a, b| {
            b.effective_gas_price(base)
                .cmp(&a.effective_gas_price(base))
        });
        txs
    }

    /// Promote queued transactions to pending when nonce gap is filled.
    fn promote_queued(&mut self, from: &[u8; 20], account_nonce: u64) {
        let next_pending = self
            .pending
            .get(from)
            .and_then(|m| m.keys().last().map(|k| k + 1))
            .unwrap_or(account_nonce);

        if let Some(queued) = self.queued.get_mut(from) {
            let mut nonce = next_pending;
            loop {
                if let Some(tx) = queued.remove(&nonce) {
                    let hash = tx.hash;
                    self.pending
                        .entry(*from)
                        .or_insert_with(BTreeMap::new)
                        .insert(nonce, tx);
                    // Update lookup
                    if let Some(entry) = self.by_hash.get_mut(&hash) {
                        entry.2 = true; // mark as pending
                    }
                    self.promotions += 1;
                    nonce += 1;
                } else {
                    break;
                }
            }
        }
    }

    /// Evict the transaction with the lowest effective gas price.
    fn evict_lowest_fee(&mut self) {
        let base = self.base_fee;
        let mut worst_hash: Option<[u8; 32]> = None;
        let mut worst_price = u128::MAX;

        // Search queued first (prefer evicting queued over pending)
        for map in self.queued.values() {
            for tx in map.values() {
                let price = tx.effective_gas_price(base);
                if price < worst_price {
                    worst_price = price;
                    worst_hash = Some(tx.hash);
                }
            }
        }

        // If no queued, evict from pending
        if worst_hash.is_none() {
            for map in self.pending.values() {
                for tx in map.values() {
                    let price = tx.effective_gas_price(base);
                    if price < worst_price {
                        worst_price = price;
                        worst_hash = Some(tx.hash);
                    }
                }
            }
        }

        if let Some(hash) = worst_hash {
            self.remove(&hash);
            self.evictions += 1;
        }
    }

    /// Count transactions for a given account.
    fn account_tx_count(&self, from: &[u8; 20]) -> usize {
        let p = self.pending.get(from).map_or(0, |m| m.len());
        let q = self.queued.get(from).map_or(0, |m| m.len());
        p + q
    }

    /// Pool status.
    pub fn status(&self) -> PoolStatus {
        PoolStatus {
            pending: self.pending.values().map(|m| m.len()).sum(),
            queued: self.queued.values().map(|m| m.len()).sum(),
            total: self.total_count,
            max_size: self.max_size,
        }
    }

    /// Pool content for eth_txpool_content.
    pub fn content(&self) -> PoolContent {
        let pending_txs: Vec<PoolTxInfo> = self
            .pending
            .values()
            .flat_map(|m| m.values())
            .map(|tx| pool_tx_info(tx))
            .collect();

        let queued_txs: Vec<PoolTxInfo> = self
            .queued
            .values()
            .flat_map(|m| m.values())
            .map(|tx| pool_tx_info(tx))
            .collect();

        PoolContent {
            pending: pending_txs,
            queued: queued_txs,
        }
    }

    /// Pool inspection for eth_txpool_inspect.
    pub fn inspect(&self) -> PoolInspect {
        let pending: Vec<String> = self
            .pending
            .values()
            .flat_map(|m| m.values())
            .map(|tx| {
                format!(
                    "0x{}: {} wei + {} gas x {} wei",
                    hex::encode(tx.from),
                    tx.value,
                    tx.gas_limit,
                    tx.max_fee_per_gas,
                )
            })
            .collect();

        let queued: Vec<String> = self
            .queued
            .values()
            .flat_map(|m| m.values())
            .map(|tx| {
                format!(
                    "0x{}: {} wei + {} gas x {} wei",
                    hex::encode(tx.from),
                    tx.value,
                    tx.gas_limit,
                    tx.max_fee_per_gas,
                )
            })
            .collect();

        PoolInspect { pending, queued }
    }

    /// Total count of transactions in the pool.
    pub fn len(&self) -> usize {
        self.total_count
    }

    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Update the base fee (called when a new block is processed).
    pub fn set_base_fee(&mut self, base_fee: u128) {
        self.base_fee = base_fee;
    }
}

fn pool_tx_info(tx: &PoolTransaction) -> PoolTxInfo {
    PoolTxInfo {
        hash: format!("0x{}", hex::encode(tx.hash)),
        from: format!("0x{}", hex::encode(tx.from)),
        to: tx.to.map(|a| format!("0x{}", hex::encode(a))),
        nonce: tx.nonce,
        gas_limit: tx.gas_limit,
        max_fee_per_gas: tx.max_fee_per_gas,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        value: tx.value,
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct PoolStatus {
    pub pending: usize,
    pub queued: usize,
    pub total: usize,
    pub max_size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolContent {
    pub pending: Vec<PoolTxInfo>,
    pub queued: Vec<PoolTxInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolTxInfo {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub value: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolInspect {
    pub pending: Vec<String>,
    pub queued: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum PoolError {
    PoolFull,
    AccountLimitReached(usize),
    NonceTooLow,
    UnderpricedReplacement,
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PoolFull => write!(f, "transaction pool is full"),
            Self::AccountLimitReached(n) => write!(f, "account limit ({}) reached", n),
            Self::NonceTooLow => write!(f, "nonce too low"),
            Self::UnderpricedReplacement => write!(f, "replacement tx underpriced"),
        }
    }
}

impl std::error::Error for PoolError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tx(from: u8, nonce: u64, max_fee: u128, priority: u128) -> PoolTransaction {
        let mut hash = [0u8; 32];
        hash[0] = from;
        hash[1..9].copy_from_slice(&nonce.to_be_bytes());
        PoolTransaction {
            hash,
            from: [from; 20],
            to: Some([0xBB; 20]),
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: priority,
            value: 0,
            data: vec![],
            size: 100,
            timestamp: 0,
        }
    }

    #[test]
    fn test_pool_creation() {
        let pool = TransactionPool::new(4096);
        assert_eq!(pool.max_size, 4096);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_add_and_get() {
        let mut pool = TransactionPool::new(100);
        let tx = make_tx(0x01, 0, 100, 10);
        let hash = tx.hash;
        pool.add(tx, 0).unwrap();

        assert_eq!(pool.len(), 1);
        assert!(pool.get(&hash).is_some());
        assert_eq!(pool.get(&hash).unwrap().nonce, 0);
    }

    #[test]
    fn test_priority_ordering() {
        let mut pool = TransactionPool::new(100);
        pool.base_fee = 10;

        // Add txs with different fees
        let tx_low = make_tx(0x01, 0, 20, 5);
        let tx_high = make_tx(0x02, 0, 100, 50);
        let tx_mid = make_tx(0x03, 0, 50, 20);

        pool.add(tx_low, 0).unwrap();
        pool.add(tx_high, 0).unwrap();
        pool.add(tx_mid, 0).unwrap();

        let sorted = pool.pending_sorted();
        assert_eq!(sorted.len(), 3);
        // Highest effective price first
        assert_eq!(sorted[0].from, [0x02; 20]);
        assert_eq!(sorted[1].from, [0x03; 20]);
        assert_eq!(sorted[2].from, [0x01; 20]);
    }

    #[test]
    fn test_nonce_gap_queuing() {
        let mut pool = TransactionPool::new(100);

        // Account nonce is 0, submit nonce 2 (gap)
        let tx = make_tx(0x01, 2, 100, 10);
        pool.add(tx, 0).unwrap();

        let status = pool.status();
        assert_eq!(status.queued, 1);
        assert_eq!(status.pending, 0);
    }

    #[test]
    fn test_nonce_gap_promotion() {
        let mut pool = TransactionPool::new(100);

        // Submit nonce 1 first (gap — queued)
        let tx1 = make_tx(0x01, 1, 100, 10);
        pool.add(tx1, 0).unwrap();
        assert_eq!(pool.status().queued, 1);

        // Submit nonce 0 (fills gap — both should become pending)
        let tx0 = make_tx(0x01, 0, 100, 10);
        // Need different hash
        let mut tx0_mod = tx0;
        tx0_mod.hash[31] = 0xFF;
        pool.add(tx0_mod, 0).unwrap();

        let status = pool.status();
        assert_eq!(status.pending, 2);
        assert_eq!(status.queued, 0);
    }

    #[test]
    fn test_account_limit() {
        let mut pool = TransactionPool::new(1000);
        pool.max_per_account = 3;

        for i in 0..3u64 {
            let tx = make_tx(0x01, i, 100, 10);
            pool.add(tx, 0).unwrap();
        }

        // 4th should fail
        let tx = make_tx(0x01, 3, 100, 10);
        let result = pool.add(tx, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_pool_eviction() {
        let mut pool = TransactionPool::new(3);
        pool.base_fee = 10;

        pool.add(make_tx(0x01, 0, 100, 50), 0).unwrap(); // high fee
        pool.add(make_tx(0x02, 0, 20, 5), 0).unwrap(); // low fee
        pool.add(make_tx(0x03, 0, 50, 20), 0).unwrap(); // mid fee

        // Pool is at limit. Adding one more should evict lowest
        pool.add(make_tx(0x04, 0, 80, 30), 0).unwrap();

        assert_eq!(pool.len(), 3);
        // The lowest fee tx (0x02) should have been evicted
        let status = pool.status();
        assert_eq!(status.total, 3);
    }

    #[test]
    fn test_pool_remove() {
        let mut pool = TransactionPool::new(100);
        let tx = make_tx(0x01, 0, 100, 10);
        let hash = tx.hash;
        pool.add(tx, 0).unwrap();

        let removed = pool.remove(&hash);
        assert!(removed.is_some());
        assert!(pool.is_empty());
    }

    #[test]
    fn test_pool_status() {
        let mut pool = TransactionPool::new(100);
        pool.add(make_tx(0x01, 0, 100, 10), 0).unwrap();
        pool.add(make_tx(0x02, 0, 50, 5), 0).unwrap();

        let status = pool.status();
        assert_eq!(status.pending, 2);
        assert_eq!(status.total, 2);
        assert_eq!(status.max_size, 100);
    }

    #[test]
    fn test_pool_content() {
        let mut pool = TransactionPool::new(100);
        pool.add(make_tx(0x01, 0, 100, 10), 0).unwrap();

        let content = pool.content();
        assert_eq!(content.pending.len(), 1);
        assert_eq!(content.queued.len(), 0);
    }

    #[test]
    fn test_pool_inspect() {
        let mut pool = TransactionPool::new(100);
        pool.add(make_tx(0x01, 0, 100, 10), 0).unwrap();

        let inspect = pool.inspect();
        assert_eq!(inspect.pending.len(), 1);
        assert!(inspect.pending[0].contains("gas"));
    }

    #[test]
    fn test_effective_gas_price() {
        let tx = make_tx(0x01, 0, 100, 20);
        // base_fee=50: effective = min(100, 50+20) = 70
        assert_eq!(tx.effective_gas_price(50), 70);
        // base_fee=90: effective = min(100, 90+20) = 100 (capped at max_fee)
        assert_eq!(tx.effective_gas_price(90), 100);
    }

    #[test]
    fn test_set_base_fee() {
        let mut pool = TransactionPool::new(100);
        pool.set_base_fee(50_000_000_000);
        assert_eq!(pool.base_fee, 50_000_000_000);
    }
}
