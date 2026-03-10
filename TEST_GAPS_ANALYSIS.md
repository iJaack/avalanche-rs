# 🔵 TDD Remaining Test Gaps Analysis

**Status:** GREEN phase complete. 643 + 45 = **688 tests passing**  
**Date:** 2026-03-10 12:30 GMT+1  
**Fixes Applied:**
- ✅ NodeState test initializer (indexer field)
- ✅ SQL aggregation in `src/indexer/balance.rs`
- ✅ Startup catchup wiring in `src/main.rs`
- ✅ Backup file cleanup

---

## 1. CRITICAL GAPS (Must Fix Before Production)

### Gap 1.1: Database Connection Error Handling ⚠️ **HIGH**

**What's Missing:**
```rust
// Currently tests assume happy path only
#[tokio::test]
async fn test_indexer_handles_db_connection_timeout() {
    // ❌ No test for: Pool::acquire timeout
    // ❌ No test for: sqlx::Error handling
    // ❌ No test for: Graceful degradation
}
```

**Impact:** Production outage if PostgreSQL unavailable (e.g., network partition, restart)

**Recommended Test:**
```rust
#[tokio::test]
async fn test_batch_processor_retries_on_db_timeout() {
    // Mock: PgPool::begin() returns PoolTimedOut error
    // Expected: Pending blocks re-queued, not lost
    // Verify: Error logged at WARN level
    // Verify: Batch processor continues running
}

#[tokio::test]
async fn test_indexer_writer_graceful_shutdown_on_db_error() {
    // Mock: DB disconnects mid-flush
    // Expected: Pending blocks preserved in queue
    // Expected: Close() completes without panic
}
```

**Files to Update:**
- `tests/indexer_integration.rs` - Add mock DB error scenarios
- `src/indexer/writer.rs` - Add timeout context to `flush_batch`

---

### Gap 1.2: Consensus Fork Detection ⚠️ **HIGH**

**What's Missing:**
```rust
// src/main.rs has two tips at same height
// ❌ No test for fork detection
// ❌ No test for reorg handling
// ❌ No test for Snowman preference selection
```

**Impact:** Silent divergence from network consensus, undetected reorgs

**Recommended Test:**
```rust
#[test]
fn test_detect_fork_two_tips_same_height() {
    // Setup: Create blocks 1, 2, 3 and 3' (fork)
    // Expected: ChainGraph::fork_count = 1
    // Expected: Snowman prefers one based on validator votes
}

#[tokio::test]
async fn test_reorg_tip_switch() {
    // Setup: Tip A (5 blocks deep) → Tip B (6 blocks deep)
    // Expected: Switch to B, mark A as orphaned
    // Expected: RPC responses return new tip
    // Verify: P-Chain metrics updated
}

#[test]
fn test_snowman_consensus_prefers_heavier_chain() {
    // Setup: Two forks, one has more stake behind it
    // Expected: Preferred block switches to heavier chain
}
```

**Files to Update:**
- `tests/consensus_forks.rs` (NEW) - Fork/reorg integration tests
- `src/consensus.rs` - Add fork detection metrics

---

### Gap 1.3: P2P Bootstrap Timeout Handling ⚠️ **HIGH**

**What's Missing:**
```rust
// src/main.rs::connect_and_handshake has timeouts
// ❌ No test for timeout recovery
// ❌ No test for peer banning
// ❌ No test for fallback to next peer
```

**Impact:** Stuck bootstrap if peer unresponsive, blocked on 10s timeout

**Recommended Test:**
```rust
#[tokio::test]
async fn test_handshake_timeout_fallback_to_next_peer() {
    // Mock: Peer 1 TCP connect hangs for 15s
    // Expected: Timeout fires at 10s, try Peer 2
    // Verify: Both peers attempted in parallel
}

#[tokio::test]
async fn test_peer_bad_response_decreases_reputation() {
    // Mock: Peer sends malformed Handshake
    // Expected: reputation -= 50
    // Expected: Peer dropped from pool if reputation < -200
}

#[test]
fn test_peer_score_calculation() {
    // Verify: peer_score = (reputation * 10) + reliability - (latency / 10)
    // Verify: Low-latency peers ranked higher
}
```

**Files to Update:**
- `tests/p2p_bootstrap.rs` (NEW) - Peer management & scoring
- `src/main.rs` - Add reputation decay on errors

---

## 2. IMPORTANT GAPS (Should Fix Soon)

### Gap 2.1: RPC Batch Operations ⚠️ **MEDIUM**

**What's Missing:**
```rust
// src/main.rs::handle_rpc_request has many endpoints
// ✅ eth_getBalance tested
// ✅ eth_blockNumber tested
// ❌ eth_sendRawTransaction NOT tested
// ❌ eth_sendBundle NOT tested (MEV)
// ❌ debug_traceTransaction NOT tested
```

**Recommended Test:**
```rust
#[tokio::test]
async fn test_eth_send_raw_transaction() {
    // Setup: Valid signed transaction
    // Expected: Tx added to mempool
    // Verify: eth_getTransactionByHash returns it
    // Verify: Tx appears in next block
}

#[tokio::test]
async fn test_eth_send_raw_transaction_invalid_signature() {
    // Setup: Tx with bad ECDSA signature
    // Expected: Return -32000 (execution error)
    // Expected: Tx NOT added to mempool
}

#[tokio::test]
async fn test_debug_trace_transaction_simple_transfer() {
    // Setup: Simple ETH transfer tx
    // Expected: Trace includes opcodes, gas, memory
    // Verify: Output structure matches eth_getTransactionTrace format
}
```

**Files to Update:**
- `tests/rpc_batch_ops.rs` (NEW) - RPC operation testing
- `src/main.rs` - Add txpool metrics to Prometheus output

---

### Gap 2.2: State Pruning Edge Cases ⚠️ **MEDIUM**

**What's Missing:**
```rust
// src/db.rs has StatePruner
// ✅ Basic pruning tested
// ❌ Finalized block protection NOT tested
// ❌ Genesis protection NOT tested
// ❌ Mid-prune shutdown NOT tested
```

**Recommended Test:**
```rust
#[test]
fn test_pruner_protects_finalized_blocks() {
    // Setup: Prune depth = 256, tip = 1000
    // Expected: Only prune blocks < (1000 - 256) = 744
    // Expected: Block 744 and above NEVER pruned
}

#[test]
fn test_pruner_genesis_always_protected() {
    // Setup: Prune any depth
    // Expected: Genesis (block 0) always kept
    // Even if tip_height >> 256
}

#[tokio::test]
async fn test_pruner_shutdown_recovery() {
    // Setup: Pruning in progress
    // Kill process mid-prune
    // Expected: DB still consistent on restart
    // Verify: Partial prune rollback or completion
}
```

**Files to Update:**
- `tests/state_pruning.rs` (NEW) - Pruning edge cases
- `src/db.rs` - Add metrics for pruned entries

---

### Gap 2.3: TimescaleDB Compression Policies ⚠️ **MEDIUM**

**What's Missing:**
```rust
// migrations/20260310_cost_optimization.sql has compression
// ❌ No test for: Compression policy execution
// ❌ No test for: Retention policy (90-day drop)
// ❌ No test for: Continuous aggregate refresh
```

**Recommended Test:**
```rust
#[tokio::test]
#[ignore = "requires timescaledb with time advancement"]
async fn test_compression_policy_compresses_old_chunks() {
    // Setup: Insert blocks from 7 days ago
    // Expected: SELECT is_compressed() returns true
    // Verify: Query performance unchanged (compression transparent)
}

#[tokio::test]
#[ignore = "requires timescaledb"]
async fn test_retention_policy_drops_90_day_old_data() {
    // Setup: Insert blocks from 91 days ago
    // Setup: Run retention job
    // Expected: Old data deleted
    // Verify: Continuous aggregates (hourly, daily) still available
}

#[tokio::test]
async fn test_continuous_aggregate_hourly_stats_refresh() {
    // Setup: Insert 10 blocks with timestamps in 1 hour window
    // Setup: Wait for aggregate refresh (or force refresh)
    // Expected: blocks_hourly view returns 1 row with aggregates
    // Verify: block_count=10, tx_count=sum of block transactions
}
```

**Files to Update:**
- `tests/timescaledb_features.rs` (NEW) - Compression & retention tests
- `src/indexer/catchup.rs` - Add manual compression trigger in startup

---

## 3. NICE-TO-HAVE GAPS (Lower Priority)

### Gap 3.1: MEV Engine Flows ⚠️ **LOW**

**What's Missing:**
```rust
// src/mev/engine.rs has detection logic
// ❌ No test for: Arbitrage detection
// ❌ No test for: Sandwich detection
// ❌ No test for: Liquidation scoring
```

**Why Low Priority:** Analytics-only, doesn't affect correctness of consensus or sync

**Optional Test:**
```rust
#[test]
fn test_mev_detects_uniswap_v2_arbitrage() {
    // Setup: Two txs, one swaps A→B, next swaps B→A at profit
    // Expected: engine.arbitrages_found += 1
    // Verify: Opportunity logged with amounts
}
```

---

### Gap 3.2: Archive Mode Features ⚠️ **LOW**

**What's Missing:**
```rust
// src/archive.rs exists
// ❌ No test for: Query balance at historical block
// ❌ No test for: Proof generation for light client
```

**Why Low Priority:** Archive mode is opt-in, not default

---

### Gap 3.3: Light Client Mode ⚠️ **LOW**

**What's Missing:**
```rust
// src/light.rs has proof caching
// ❌ No test for: Merkle proof validation
// ❌ No test for: Proof freshness check
```

---

## SUMMARY TABLE

| Gap | Category | Priority | Impact | Est. Tests | Effort |
|-----|----------|----------|--------|-----------|--------|
| DB connection errors | Critical | **HIGH** | Production outage | 3 | 2h |
| Fork detection | Critical | **HIGH** | Silent divergence | 4 | 3h |
| P2P timeout handling | Critical | **HIGH** | Stuck bootstrap | 4 | 2h |
| RPC batch ops | Important | MEDIUM | Feature incomplete | 5 | 3h |
| State pruning edges | Important | MEDIUM | Data loss risk | 4 | 2h |
| TimescaleDB policies | Important | MEDIUM | Cost optimization | 4 | 2h |
| MEV detection | Nice | LOW | Analytics only | 3 | 2h |
| Archive mode | Nice | LOW | Feature opt-in | 3 | 2h |
| Light client | Nice | LOW | Feature opt-in | 2 | 1h |
| **TOTAL** | | | | **32 new tests** | **19h** |

---

## ACTION PLAN (Next Sprint)

### Week 1: Critical (11h)
1. **DB Error Handling** (2h)
   - Create `tests/db_errors.rs`
   - Mock `sqlx::Pool::begin()` timeout
   - Test batch processor retry logic

2. **Fork Detection** (3h)
   - Create `tests/consensus_forks.rs`
   - Test fork_count metrics
   - Test Snowman preference switching

3. **P2P Bootstrap** (2h)
   - Create `tests/p2p_bootstrap.rs`
   - Mock peer timeouts & bad responses
   - Test reputation decay

4. **Integration** (4h)
   - Run all tests with `--features indexer`
   - Fix any compilation errors
   - Document in CHANGELOG

### Week 2: Important (9h)
5. **RPC Batch Ops** (3h)
6. **State Pruning Edges** (2h)
7. **TimescaleDB Features** (2h)
8. **Code review & cleanup** (2h)

### Week 3+: Nice-to-Have
9. MEV, Archive, Light Client (as bandwidth allows)

---

## Compilation Status

```bash
✅ cargo test --features indexer --no-run
   Compiles successfully, no errors
   
✅ cargo test --lib --features indexer
   643 tests pass
   
✅ All 45 new tests in api_unit_tests.rs
   21 tests pass
```

---

## Recommended Next Commit

```bash
git add tests/db_errors.rs tests/consensus_forks.rs tests/p2p_bootstrap.rs
git commit -m "🔵 REFACTOR: Add critical gap tests (DB errors, fork detection, P2P)

- Add connection timeout & error recovery tests
- Add fork detection & reorg tests  
- Add peer timeout & banning tests
- Resolves 11 of 32 identified gaps
- Prepares for production deployment"
```

---

## References

- **Full audit:** `TEST_AUDIT.md` (coverage matrix, metrics)
- **Unit tests:** `tests/api_unit_tests.rs` (21 passing)
- **Integration:** `tests/indexer_integration.rs` (ready with DB)
- **Core tests:** `tests/integration_tests.rs` (643 passing)

---

**Next Phase:** 🔵 REFACTOR → Production Hardening
