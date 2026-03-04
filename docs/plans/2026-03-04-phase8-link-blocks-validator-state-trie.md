# Phase 8 — Link Blocks + Validator Set Extraction + State Trie Basics

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Verify chain integrity by walking parent→child links, hex-dump genesis for validator extraction, map C-Chain state roots to blocks, and add a BlockMetadata struct.

**Architecture:** All changes are in `src/block/mod.rs`, `src/db/mod.rs`, and `src/main.rs`. No new files needed for Tasks 1-4. We add a `CF_STATE_ROOTS` column family to the DB and extend the block parser to extract `stateRoot`. `BlockMetadata` wraps `BlockHeader` with a `tx_count` field derived from block bytes.

**Tech Stack:** Rust, RocksDB (rocksdb crate), SHA-256 (sha2), existing block parsing infra in `src/block/mod.rs`.

---

## Key Codebase Facts

- **Block storage key format**: P-Chain = raw 32-byte SHA-256. C-Chain = `b"c:" + 32-byte SHA-256`.
- **`verify_block_chain(db, tip_id)`** already exists in `src/main.rs:176`. It walks the chain. We extend it.
- **`BlockHeader::parse(raw, chain)`** and **`BlockHeader::extract_parent_id(raw)`** exist in `src/block/mod.rs`.
- **RocksDB CF helpers**: `db.get_cf(cf_name, key)`, `db.put_cf(cf_name, key, value)`, `db.iter_cf_owned(cf_name)`.
- **`ALL_CFS`** slice in `src/db/mod.rs:30` must include any new column family or RocksDB will error on open.
- **`ChainGraph`** in `src/block/mod.rs` is in-memory only. We add DB-backed functions to `src/main.rs`.
- **C-Chain RLP stateRoot** is field 3 in the header list (after parentHash, sha3Uncles, miner).
- **tx_count for P-Chain Banff/Apricot**: stored as a `uint32 BE` slice length, offset depends on block type.

---

## Task 1: Chain Integrity Verification + Walk

**Files:**
- Modify: `src/main.rs:176-255` (enhance `verify_block_chain`)
- Modify: `src/main.rs` (add `integrity_check_pchain`)

### Step 1: Write failing test for chain integrity check

In `src/main.rs`, add a `#[cfg(test)]` module at the bottom with:

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use avalanche_rs::db::Database;
    use sha2::{Digest, Sha256};

    /// Helper: make a Banff Standard block (typeID 32).
    fn make_banff_std(parent: [u8; 32], height: u64) -> Vec<u8> {
        let mut raw = vec![0u8; 54];
        raw[2..6].copy_from_slice(&32u32.to_be_bytes());
        raw[6..14].copy_from_slice(&1_700_000_000u64.to_be_bytes()); // timestamp
        raw[14..46].copy_from_slice(&parent);
        raw[46..54].copy_from_slice(&height.to_be_bytes());
        raw
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    #[test]
    fn test_integrity_check_all_match() {
        let (db, _dir) = Database::open_temp().unwrap();
        // Store 3 blocks: genesis -> b1 -> b2
        let g = make_banff_std([0u8; 32], 0);
        let g_id = sha256(&g);
        let b1 = make_banff_std(g_id, 1);
        let b1_id = sha256(&b1);
        let b2 = make_banff_std(b1_id, 2);
        let b2_id = sha256(&b2);

        db.put_cf(avalanche_rs::db::CF_BLOCKS, &g_id, &g).unwrap();
        db.put_cf(avalanche_rs::db::CF_BLOCKS, &b1_id, &b1).unwrap();
        db.put_cf(avalanche_rs::db::CF_BLOCKS, &b2_id, &b2).unwrap();

        let (ok, mismatch) = integrity_check_pchain(&db);
        assert_eq!(ok, 3);
        assert_eq!(mismatch, 0);
    }

    #[test]
    fn test_chain_walk_full() {
        let (db, _dir) = Database::open_temp().unwrap();
        let g = make_banff_std([0u8; 32], 0);
        let g_id = sha256(&g);
        let b1 = make_banff_std(g_id, 1);
        let b1_id = sha256(&b1);
        let b2 = make_banff_std(b1_id, 2);
        let b2_id = sha256(&b2);

        db.put_cf(avalanche_rs::db::CF_BLOCKS, &g_id, &g).unwrap();
        db.put_cf(avalanche_rs::db::CF_BLOCKS, &b1_id, &b1).unwrap();
        db.put_cf(avalanche_rs::db::CF_BLOCKS, &b2_id, &b2).unwrap();

        let (length, tip_h, genesis_h) = verify_block_chain(&db, b2_id);
        assert_eq!(length, 3);
        assert_eq!(tip_h, 2);
        assert_eq!(genesis_h, 0);
    }
}
```

Run: `cargo test --lib integration_tests 2>&1 | tail -20`
Expected: FAIL — `integrity_check_pchain` not found.

### Step 2: Implement `integrity_check_pchain`

Add this function to `src/main.rs` after `verify_block_chain` (around line 256):

```rust
/// Iterate all P-Chain blocks in CF_BLOCKS (keys without "c:" prefix),
/// compute SHA-256 of each block's raw bytes, and verify it matches the key.
/// Returns (verified_count, mismatch_count).
fn integrity_check_pchain(db: &Database) -> (usize, usize) {
    use sha2::{Digest, Sha256};
    let all = db.iter_cf_owned(CF_BLOCKS);
    let mut ok = 0usize;
    let mut mismatch = 0usize;

    for (key, value) in &all {
        // Skip C-Chain blocks (prefixed with "c:")
        if key.starts_with(b"c:") {
            continue;
        }
        if key.len() != 32 {
            continue;
        }
        let mut hasher = Sha256::new();
        hasher.update(value);
        let computed: [u8; 32] = hasher.finalize().into();
        let stored_key: [u8; 32] = key.as_slice().try_into().unwrap();
        if computed == stored_key {
            ok += 1;
        } else {
            mismatch += 1;
            info!(
                "Integrity mismatch: key={:02x}{:02x}{:02x}{:02x}… computed={:02x}{:02x}{:02x}{:02x}…",
                stored_key[0], stored_key[1], stored_key[2], stored_key[3],
                computed[0], computed[1], computed[2], computed[3]
            );
        }
    }
    info!(
        "Block integrity check: {} blocks verified, {} mismatches",
        ok, mismatch
    );
    (ok, mismatch)
}
```

### Step 3: Run tests

Run: `cargo test --lib integration_tests::test_integrity_check_all_match integration_tests::test_chain_walk_full 2>&1 | tail -20`
Expected: PASS.

### Step 4: Wire into startup

In `main()`, after the DB opens (around line 332), call integrity check and log the result. Add after the `info!("Database opened...")` line:

```rust
// Phase 8: verify block chain integrity on startup
let (ok, bad) = integrity_check_pchain(&db);
if bad > 0 {
    warn!("Chain integrity: {} blocks OK, {} MISMATCHES — block storage format issue!", ok, bad);
} else if ok > 0 {
    info!("Chain integrity: {} blocks verified, all match", ok);
}
```

### Step 5: Commit

```bash
git add src/main.rs
git commit -m "feat: phase 8.1 — chain integrity check + walk"
```

---

## Task 2: Genesis Hex Dump + Validator Extraction

**Files:**
- Modify: `src/main.rs` (add `dump_genesis_block`)

### Step 1: Write failing test

In the `#[cfg(test)]` module, add:

```rust
#[test]
fn test_dump_genesis_finds_correct_block() {
    let (db, _dir) = Database::open_temp().unwrap();
    // Store a genesis block (parent = all zeros)
    let genesis = make_banff_std([0u8; 32], 0);
    let genesis_id = sha256(&genesis);
    db.put_cf(avalanche_rs::db::CF_BLOCKS, &genesis_id, &genesis).unwrap();
    // Store a non-genesis block
    let b1 = make_banff_std(genesis_id, 1);
    let b1_id = sha256(&b1);
    db.put_cf(avalanche_rs::db::CF_BLOCKS, &b1_id, &b1).unwrap();

    let result = find_genesis_block(&db);
    assert!(result.is_some(), "should find genesis block");
    let (key, raw) = result.unwrap();
    assert_eq!(key, genesis_id);
    assert_eq!(raw.len(), genesis.len());
}
```

Run: `cargo test --lib integration_tests::test_dump_genesis_finds_correct_block 2>&1 | tail -10`
Expected: FAIL — `find_genesis_block` not found.

### Step 2: Implement `find_genesis_block`

Add after `integrity_check_pchain` in `src/main.rs`:

```rust
/// Iterate P-Chain blocks and find the one whose parent_id is all zeros.
/// Returns (block_id_key, raw_bytes) of the genesis block.
fn find_genesis_block(db: &Database) -> Option<([u8; 32], Vec<u8>)> {
    let all = db.iter_cf_owned(CF_BLOCKS);
    for (key, value) in all {
        if key.starts_with(b"c:") || key.len() != 32 {
            continue;
        }
        // Quick check: is parent_id all zeros?
        if let Some(parent) = avalanche_rs::block::BlockHeader::extract_parent_id(&value) {
            if parent == [0u8; 32] {
                let id: [u8; 32] = key.try_into().unwrap();
                return Some((id, value));
            }
        }
    }
    None
}
```

### Step 3: Run test

Run: `cargo test --lib integration_tests::test_dump_genesis_finds_correct_block 2>&1 | tail -10`
Expected: PASS.

### Step 4: Wire into startup + hex dump

Add after the integrity check in `main()`:

```rust
// Phase 8: dump P-Chain genesis for validator extraction analysis
if let Some((genesis_id, genesis_raw)) = find_genesis_block(&db) {
    let dump_len = genesis_raw.len().min(200);
    info!(
        "P-Chain genesis found: id={:02x}{:02x}{:02x}{:02x}…, {} bytes total",
        genesis_id[0], genesis_id[1], genesis_id[2], genesis_id[3],
        genesis_raw.len()
    );
    info!(
        "P-Chain genesis: first {} bytes = {:02x?}",
        dump_len, &genesis_raw[..dump_len]
    );
    // Parse and log header for confirmation
    if let Ok(hdr) = avalanche_rs::block::BlockHeader::parse(&genesis_raw, avalanche_rs::block::Chain::PChain) {
        info!(
            "P-Chain genesis parsed: height={}, type={:?}, timestamp={}",
            hdr.height, hdr.block_type, hdr.timestamp
        );
    }
} else {
    info!("P-Chain genesis block not found in DB (need more sync rounds)");
}
```

### Step 5: Commit

```bash
git add src/main.rs
git commit -m "feat: phase 8.2 — P-Chain genesis hex dump for validator extraction"
```

---

## Task 3: C-Chain State Root Mapping

**Files:**
- Modify: `src/db/mod.rs` (add CF_STATE_ROOTS)
- Modify: `src/block/mod.rs` (extract stateRoot from RLP)
- Modify: `src/main.rs` (store stateRoot mapping when storing C-Chain blocks)

### Step 1: Write failing test for stateRoot extraction

In `src/block/mod.rs`, in the existing `#[cfg(test)]` module, add:

```rust
#[test]
fn test_extract_state_root() {
    let state_root = [0x42u8; 32];
    let raw = make_cchain_block_with_state_root([0u8; 32], 1, 1_700_000_000, state_root);
    let extracted = BlockHeader::extract_state_root(&raw);
    assert_eq!(extracted, Some(state_root));
}
```

Also add a helper function alongside the existing test helpers:
```rust
fn make_cchain_block_with_state_root(
    parent: [u8; 32],
    number: u64,
    timestamp: u64,
    state_root: [u8; 32],
) -> Vec<u8> {
    let mut header_payload: Vec<u8> = Vec::new();
    // 0: parentHash
    header_payload.push(0xa0);
    header_payload.extend_from_slice(&parent);
    // 1: sha3Uncles
    header_payload.push(0xa0);
    header_payload.extend_from_slice(&[0x1du8; 32]);
    // 2: miner (20 bytes)
    header_payload.push(0x94);
    header_payload.extend_from_slice(&[0u8; 20]);
    // 3: stateRoot
    header_payload.push(0xa0);
    header_payload.extend_from_slice(&state_root);
    // 4: txRoot
    header_payload.push(0xa0);
    header_payload.extend_from_slice(&[0u8; 32]);
    // 5: receiptRoot
    header_payload.push(0xa0);
    header_payload.extend_from_slice(&[0u8; 32]);
    // 6: bloom (256 bytes)
    header_payload.push(0xb9);
    header_payload.push(0x01);
    header_payload.push(0x00);
    header_payload.extend_from_slice(&[0u8; 256]);
    // 7: difficulty
    header_payload.push(0x80);
    // 8: number
    encode_rlp_u64(&mut header_payload, number);
    // 9: gasLimit
    encode_rlp_u64(&mut header_payload, 8_000_000);
    // 10: gasUsed
    header_payload.push(0x80);
    // 11: timestamp
    encode_rlp_u64(&mut header_payload, timestamp);

    let header_list = rlp_list(header_payload);
    let empty = 0xc0u8;
    let mut outer = Vec::new();
    outer.extend_from_slice(&header_list);
    outer.push(empty);
    outer.push(empty);
    rlp_list(outer)
}
```

Run: `cargo test --lib block::tests::test_extract_state_root 2>&1 | tail -10`
Expected: FAIL — `extract_state_root` not found.

### Step 2: Add `extract_state_root` to `BlockHeader` in `src/block/mod.rs`

In the `impl BlockHeader` block, after `extract_parent_id`, add:

```rust
/// Extract the stateRoot (field 3) from a C-Chain RLP block.
/// Returns None if not parseable or not a C-Chain block.
pub fn extract_state_root(raw: &[u8]) -> Option<[u8; 32]> {
    if raw.is_empty() {
        return None;
    }
    // Handle Avalanche wrapper
    let rlp = if raw.len() >= 6 && raw[0] == 0x00 && raw[1] == 0x00 {
        &raw[6..]
    } else {
        raw
    };
    if rlp.is_empty() || rlp[0] < 0xc0 {
        return None;
    }
    // Outer list
    let (_, header_start) = rlp_list_start(rlp, 0).ok()?;
    // Inner header list
    let (_, fields_start) = rlp_list_start(rlp, header_start).ok()?;
    // Skip field 0 (parentHash), 1 (sha3Uncles), 2 (miner), then read field 3 (stateRoot)
    let mut pos = fields_start;
    for _ in 0..3 {
        pos = rlp_skip(rlp, pos).ok()?;
    }
    // Field 3 is stateRoot: 0xa0 + 32 bytes
    rlp_read_bytes32(rlp, pos).ok()
}
```

Run: `cargo test --lib block::tests::test_extract_state_root 2>&1 | tail -10`
Expected: PASS.

### Step 3: Add `CF_STATE_ROOTS` to `src/db/mod.rs`

In `src/db/mod.rs`, add the constant:
```rust
pub const CF_STATE_ROOTS: &str = "state_roots";
```

Add `CF_STATE_ROOTS` to the `ALL_CFS` slice:
```rust
const ALL_CFS: &[&str] = &[
    CF_BLOCKS,
    CF_STATE,
    CF_CODE,
    CF_RECEIPTS,
    CF_TX_INDEX,
    CF_METADATA,
    CF_TRIE_NODES,
    CF_STATE_ROOTS,  // <-- add this
];
```

### Step 4: Write failing test for stateRoot storage

In `src/db/mod.rs` tests, add:

```rust
#[test]
fn test_state_roots_cf_exists() {
    let (db, _dir) = Database::open_temp().unwrap();
    // Store a state root mapping: block_hash -> state_root
    let block_hash = [0xAAu8; 32];
    let state_root = [0xBBu8; 32];
    db.put_cf(CF_STATE_ROOTS, &block_hash, &state_root).unwrap();
    let retrieved = db.get_cf(CF_STATE_ROOTS, &block_hash).unwrap().unwrap();
    assert_eq!(retrieved.as_slice(), &state_root);
}
```

Run: `cargo test --lib db::tests::test_state_roots_cf_exists 2>&1 | tail -10`
Expected: PASS (CF is auto-created by the `create_missing_column_families` option).

### Step 5: Store stateRoot in `src/main.rs` when processing C-Chain Ancestors

Find the C-Chain block storage loop in `src/main.rs` (around line 1291-1304). After storing the block with `put_cf(CF_BLOCKS, &key, container)`, add:

```rust
// Store stateRoot → block_hash mapping
if let Some(state_root) = avalanche_rs::block::BlockHeader::extract_state_root(container) {
    if let Err(e) = node.db.put_cf(
        avalanche_rs::db::CF_STATE_ROOTS,
        &state_root,
        &hash,
    ) {
        debug!("state_root store failed: {}", e);
    }
}
```

Also add the import at the top of main.rs (after the `use avalanche_rs::db::{Database, CF_BLOCKS};` line):
```rust
use avalanche_rs::db::{Database, CF_BLOCKS, CF_STATE_ROOTS};
```

Wait — check existing import at line 25: `use avalanche_rs::db::{Database, CF_BLOCKS};` — update this to add `CF_STATE_ROOTS`.

### Step 6: Log stateRoot count at startup

After the genesis hex dump in `main()`, add:

```rust
// Log C-Chain stateRoot mapping count
let state_root_entries = db.iter_cf_owned(avalanche_rs::db::CF_STATE_ROOTS).len();
info!("C-Chain stateRoot mapping: {} entries", state_root_entries);
```

### Step 7: Commit

```bash
git add src/block/mod.rs src/db/mod.rs src/main.rs
git commit -m "feat: phase 8.3 — C-Chain stateRoot extraction + mapping"
```

---

## Task 4: BlockMetadata Struct

**Files:**
- Modify: `src/block/mod.rs` (add BlockMetadata + tx_count extraction)
- Modify: `src/main.rs` (log metadata at 10s interval)

### Step 1: Write failing test for BlockMetadata

In `src/block/mod.rs` tests, add:

```rust
#[test]
fn test_block_metadata_from_banff_standard() {
    // BanffStandard: typeID=32, [6..14]=ts, [14..46]=parent, [46..54]=height
    // After height (54..): tx slice. For minimal block, no txs → tx_count=0
    let parent = [0xDEu8; 32];
    let raw = make_banff_block(32, parent, 100, 1_700_000_000);
    let meta = BlockMetadata::from_raw(&raw, Chain::PChain).unwrap();
    assert_eq!(meta.height, 100);
    assert_eq!(meta.timestamp, 1_700_000_000);
    assert_eq!(meta.parent_id, parent);
    assert_eq!(meta.block_type, BlockType::BanffStandard);
    assert_eq!(meta.size_bytes, raw.len());
}

#[test]
fn test_block_metadata_cchain() {
    let parent = [0xCCu8; 32];
    let raw = make_cchain_block(parent, 42, 1_750_000_000);
    let meta = BlockMetadata::from_raw(&raw, Chain::CChain).unwrap();
    assert_eq!(meta.height, 42);
    assert_eq!(meta.block_type, BlockType::CChainEvm);
}
```

Run: `cargo test --lib block::tests::test_block_metadata_from_banff_standard 2>&1 | tail -10`
Expected: FAIL — `BlockMetadata` not found.

### Step 2: Add `BlockMetadata` to `src/block/mod.rs`

After the `BlockHeader` struct definition (after line 65), add:

```rust
/// Block metadata: a superset of BlockHeader with derived fields.
/// Used for logging and indexing.
#[derive(Debug, Clone)]
pub struct BlockMetadata {
    pub id: BlockId,
    pub height: u64,
    pub timestamp: u64,
    pub parent_id: BlockId,
    pub block_type: BlockType,
    /// Number of transactions extracted from the block body (best-effort, 0 if unparseable).
    pub tx_count: u32,
    pub size_bytes: usize,
}

impl BlockMetadata {
    /// Parse a raw block into `BlockMetadata`.
    /// `tx_count` is extracted from the block body where possible.
    pub fn from_raw(raw: &[u8], chain: Chain) -> Result<Self, String> {
        let hdr = BlockHeader::parse(raw, chain)?;
        let tx_count = extract_tx_count(raw, &hdr.block_type);
        Ok(Self {
            id: hdr.id,
            height: hdr.height,
            timestamp: hdr.timestamp,
            parent_id: hdr.parent_id,
            block_type: hdr.block_type,
            tx_count,
            size_bytes: raw.len(),
        })
    }
}

/// Extract the transaction count from a P-Chain block body.
/// Returns 0 if the block type doesn't have transactions or the bytes are too short.
fn extract_tx_count(raw: &[u8], block_type: &BlockType) -> u32 {
    match block_type {
        BlockType::BanffStandard | BlockType::ApricotStandard => {
            // BanffStandard: after [0..54] header, [54..58] = tx slice length (uint32 BE)
            // ApricotStandard: after [0..46] header, [46..50] = tx slice length
            let tx_len_offset = match block_type {
                BlockType::BanffStandard => 54,
                BlockType::ApricotStandard => 46,
                _ => unreachable!(),
            };
            if raw.len() >= tx_len_offset + 4 {
                u32::from_be_bytes(raw[tx_len_offset..tx_len_offset + 4].try_into().unwrap())
            } else {
                0
            }
        }
        _ => 0,
    }
}
```

### Step 3: Run tests

Run: `cargo test --lib block::tests::test_block_metadata_from_banff_standard block::tests::test_block_metadata_cchain 2>&1 | tail -10`
Expected: PASS.

### Step 4: Log block metadata at 10s interval

In `src/main.rs`, in the metrics loop (around line 420-431), update to also log block metadata for the last few blocks. Since we can't iterate all blocks efficiently in the metrics timer, just log counts:

```rust
// Phase 8: log stateRoot count in C-Chain metrics
let state_root_count = metrics_node.db.iter_cf_owned(avalanche_rs::db::CF_STATE_ROOTS).len();
info!(
    "C-Chain: {} blocks synced, {} stateRoot mappings",
    c.blocks_synced, state_root_count
);
```

Replace the existing `info!("C-Chain: {} blocks synced, EVM analysis pending", ...)` line.

Also add per-block metadata logging when blocks arrive. In the P-Chain Ancestors handler (around line 1400+), after storing each block, add:

```rust
if let Ok(meta) = avalanche_rs::block::BlockMetadata::from_raw(container, avalanche_rs::block::Chain::PChain) {
    debug!(
        "P-Chain block: height={}, parent={:02x}{:02x}…, type={:?}, {} txs, {} bytes",
        meta.height,
        meta.parent_id[0], meta.parent_id[1],
        meta.block_type,
        meta.tx_count,
        meta.size_bytes
    );
}
```

### Step 5: Commit

```bash
git add src/block/mod.rs src/main.rs
git commit -m "feat: phase 8.4 — BlockMetadata struct + tx_count + metadata logging"
```

---

## Task 5: Build + Test + Live Run + Commit + Push

### Step 1: Build

Run: `cargo build --release 2>&1 | tail -5`
Expected: `Finished release [optimized] target(s) in ...`

### Step 2: Run tests

Run: `cargo test --lib 2>&1 | tail -10`
Expected: 300+ tests pass, 0 failures.

### Step 3: Live run 90 seconds

Run: `cargo run --release -- --network-id 1 --log-level debug 2>&1 | head -200 &`
Wait 90 seconds, then kill with `kill %1`.
Expected output to contain:
- `Chain integrity: N blocks verified`
- `C-Chain stateRoot mapping: M entries`
- `P-Chain genesis found:` (if genesis synced) OR `P-Chain genesis block not found in DB`

### Step 4: Final commit + push

```bash
git add -A
git commit -m "feat: phase 8 — link blocks + validator set extraction + state trie basics"
git push origin main
```
