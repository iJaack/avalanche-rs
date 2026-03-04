# Phase 3: Block Storage + Recursive Fetch + C-Chain Bootstrap

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Store downloaded P-Chain blocks in RocksDB, recursively fetch ancestors until genesis, and kick off C-Chain bootstrap.

**Architecture:** Extend the bootstrap state machine in `src/main.rs` with a new `FetchingAncestors` state that tracks recursion depth. On each Ancestors response, store all containers by SHA-256 hash, then immediately request the next batch using the oldest block's ID (computed from SHA-256 of its raw bytes). Cap at 10 rounds. Add a C-Chain ID constant and send GetAcceptedFrontier for it after P-Chain bootstrap starts.

**Tech Stack:** Rust, RocksDB (`src/db/mod.rs`), sha2 crate, bs58 crate, tokio, existing `NetworkMessage` types.

---

## Key Facts

- **P-Chain ID:** `[0u8; 32]` (already in use)
- **C-Chain Fuji ID (CB58):** `yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp`
  - CB58 decode = base58 decode → strip last 4 bytes (checksum) → 32 bytes
- **Block storage key:** SHA-256 of the raw container bytes (`db.put_cf(CF_BLOCKS, &hash, &container)`)
- **Oldest block = last entry in `containers` vec** (Ancestors returns newest first)
- **Parent ID extraction:** bytes `[2..34]` of the container (after 2-byte codec version)
- **Genesis block parent:** all zeros `[0u8; 32]` — stop condition
- **DB method for hash-keyed blocks:** use `db.put_cf(avalanche_rs::db::CF_BLOCKS, &hash, data)` directly (existing `put_block` uses height, not hash)
- **Max recursion depth:** 10 rounds (~3300 blocks)
- **Bootstrap state machine** is local to `connect_and_handshake` at ~line 732 in `src/main.rs`

---

## Task 1: Extend BootstrapState + store blocks in Ancestors handler

**Files:**
- Modify: `src/main.rs:99-106` (BootstrapState enum)
- Modify: `src/main.rs:892-905` (Ancestors match arm)

**Step 1: Update BootstrapState enum**

Replace the existing enum (lines 99-106):

```rust
#[derive(Debug, PartialEq, Clone, Copy)]
enum BootstrapState {
    Idle,
    WaitingFrontier(u32),
    WaitingAccepted(u32),
    WaitingAncestors(u32),
    FetchingAncestors { req: u32, depth: u32, total_blocks: u32 },
    Done,
}
```

**Step 2: Run `cargo check` to confirm it compiles**

```bash
cargo check 2>&1 | head -20
```
Expected: errors about unhandled variant `FetchingAncestors` in match arms (expected — we fix next).

**Step 3: Add `use sha2::{Digest, Sha256}` import at top of main.rs**

Add after the existing `use` block (around line 18):
```rust
use sha2::{Digest, Sha256};
```

Also add the `CF_BLOCKS` import:
```rust
use avalanche_rs::db::CF_BLOCKS;
```

**Step 4: Rewrite the Ancestors match arm**

Replace (lines 892-905):
```rust
NetworkMessage::Ancestors { request_id, containers, .. } => {
    info!(
        "Ancestors from {} — {} containers, {} bytes total",
        addr,
        containers.len(),
        containers.iter().map(|c| c.len()).sum::<usize>()
    );
    if let BootstrapState::WaitingAncestors(req) = bootstrap_state {
        if request_id == req {
            bootstrap_state = BootstrapState::Done;
            info!("Bootstrap: complete with {}", addr);
        }
    }
}
```

With:
```rust
NetworkMessage::Ancestors { request_id, containers, chain_id } => {
    let total_bytes: usize = containers.iter().map(|c| c.len()).sum();
    info!(
        "Ancestors from {} — {} containers, {} bytes total",
        addr, containers.len(), total_bytes
    );

    let expected_req = match bootstrap_state {
        BootstrapState::WaitingAncestors(req) => Some((req, 0u32, 0u32)),
        BootstrapState::FetchingAncestors { req, depth, total_blocks } => Some((req, depth, total_blocks)),
        _ => None,
    };

    if let Some((req, depth, prev_total)) = expected_req {
        if request_id == req {
            // ── Store all containers ─────────────────────────────────────────
            let mut stored = 0u32;
            let mut oldest_container: Option<Vec<u8>> = None;

            for container in &containers {
                let mut hasher = Sha256::new();
                hasher.update(container);
                let hash: [u8; 32] = hasher.finalize().into();

                if let Err(e) = node.db.put_cf(CF_BLOCKS, &hash, container) {
                    warn!("Failed to store block {:02x?}: {}", &hash[..4], e);
                } else {
                    stored += 1;
                }
                oldest_container = Some(container.clone());
            }

            let new_total = prev_total + stored;
            info!("Bootstrap: stored {} blocks (total: {})", stored, new_total);

            // Update metadata with total stored count
            let _ = node.db.put_metadata(
                b"p_chain_blocks_downloaded",
                &new_total.to_le_bytes(),
            );

            // ── Decide: recurse or finish ────────────────────────────────────
            let should_recurse = depth < 10
                && oldest_container.as_ref().map_or(false, |c| {
                    // Extract parent ID: bytes [2..34] after 2-byte codec version
                    if c.len() >= 34 {
                        let parent: [u8; 32] = c[2..34].try_into().unwrap_or([0u8; 32]);
                        parent != [0u8; 32]
                    } else {
                        false
                    }
                });

            if should_recurse {
                let oldest = oldest_container.unwrap();
                // The "block ID" to request ancestors of = SHA-256 of the oldest container
                let mut hasher = Sha256::new();
                hasher.update(&oldest);
                let oldest_id: [u8; 32] = hasher.finalize().into();

                let new_req = req + 1;
                let new_depth = depth + 1;
                let get_ancestors = NetworkMessage::GetAncestors {
                    chain_id: ChainId([0u8; 32]),
                    request_id: new_req,
                    deadline: 5_000_000_000u64,
                    container_id: BlockId(oldest_id),
                    max_containers_size: 2_000_000,
                };
                if let Ok(encoded) = get_ancestors.encode_proto() {
                    if tls_stream.write_all(&encoded).await.is_ok() {
                        let _ = tls_stream.flush().await;
                        info!(
                            "Bootstrap: recursive GetAncestors depth={} req={} (total blocks so far: {})",
                            new_depth, new_req, new_total
                        );
                        bootstrap_state = BootstrapState::FetchingAncestors {
                            req: new_req,
                            depth: new_depth,
                            total_blocks: new_total,
                        };
                    } else {
                        warn!("Bootstrap: failed to send recursive GetAncestors, stopping");
                        bootstrap_state = BootstrapState::Done;
                    }
                }
            } else {
                if depth >= 10 {
                    info!("Bootstrap: reached max depth (10 rounds, {} blocks), stopping fetch", new_total);
                } else {
                    info!("Bootstrap: reached genesis (or short block), {} blocks total", new_total);
                }
                bootstrap_state = BootstrapState::Done;
                info!("Bootstrap P-Chain complete with {} — {} total blocks stored", addr, new_total);
            }
        }
    }
}
```

**Step 5: Run `cargo check`**

```bash
cargo check 2>&1 | grep "^error" | head -20
```
Expected: no errors (warnings OK).

**Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: store P-Chain blocks in RocksDB + recursive ancestor fetching"
```

---

## Task 2: Add C-Chain bootstrap (Fuji)

**Files:**
- Modify: `src/main.rs` — add constant + send GetAcceptedFrontier for C-Chain

**Step 1: Add the C-Chain Fuji ID constant**

Add after the `FUJI_BOOTSTRAP_IPS` constant (around line 93):

```rust
/// C-Chain ID on Fuji testnet (CB58: yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp).
/// Decoded: base58check → strip 4-byte checksum → 32 bytes.
const FUJI_CCHAIN_ID: [u8; 32] = [
    0x7f, 0xc9, 0x3d, 0x85, 0xc6, 0xd6, 0x2c, 0x5b,
    0x2a, 0xc0, 0xb5, 0x19, 0xc8, 0x7b, 0x57, 0xb4,
    0x2a, 0x5b, 0xda, 0x4f, 0xa1, 0x0d, 0x04, 0x48,
    0x20, 0xe0, 0x1d, 0x3e, 0x30, 0x37, 0x05, 0x44,
];
```

> **Note:** The actual 32-byte value must be computed by CB58-decoding `yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp`. Use this one-liner to verify:
> ```bash
> cargo run --example decode_chain_id 2>/dev/null || \
>   python3 -c "import base58; b=base58.b58decode('yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp'); print(list(b[:-4]))"
> ```
> OR compute inline in code (preferred — see Step 2).

**Step 2: Compute C-Chain ID at runtime (safer, self-documenting)**

Instead of a hardcoded byte array, compute it in `connect_and_handshake` after the bootstrap_state machine variables are set up (around line 734), by decoding CB58:

```rust
// Decode C-Chain Fuji ID from CB58
let cchain_id: [u8; 32] = {
    let cb58 = "yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp";
    let decoded = bs58::decode(cb58).into_vec().unwrap_or_default();
    // CB58 = base58(payload + checksum4), strip last 4 bytes
    if decoded.len() >= 36 {
        decoded[..32].try_into().unwrap_or([0u8; 32])
    } else {
        warn!("Failed to decode C-Chain ID from CB58");
        [0u8; 32]
    }
};
```

Also add `use bs58;` at the top of main.rs if not already present. Check with:
```bash
grep "bs58" /Users/jaack/Documents/1\ Projects/Github/avalanche-rs/src/main.rs
```
If not present, add: `use bs58;` (it's already in Cargo.toml).

**Step 3: Send GetAcceptedFrontier for C-Chain after bootstrap timer fires**

In the bootstrap timer arm (around line 766-782), after sending GetAcceptedFrontier for P-Chain, add:

```rust
// Also kick off C-Chain bootstrap
if node.config.network_id == 5 {
    let cchain_req = NetworkMessage::GetAcceptedFrontier {
        chain_id: ChainId(cchain_id),
        request_id: bootstrap_request_base + 1000,
        deadline: 5_000_000_000u64,
    };
    if let Ok(encoded) = cchain_req.encode_proto() {
        if tls_stream.write_all(&encoded).await.is_ok() {
            let _ = tls_stream.flush().await;
            info!("Bootstrap: sent GetAcceptedFrontier for C-Chain (req={})",
                bootstrap_request_base + 1000);
        }
    }
}
```

**Step 4: Handle AcceptedFrontier for C-Chain (log only)**

In the `AcceptedFrontier` match arm, add a branch that logs C-Chain responses (those with `request_id == bootstrap_request_base + 1000`):

After the existing `WaitingFrontier` check, add:
```rust
// Log C-Chain frontier if it comes back
if request_id == bootstrap_request_base + 1000 {
    info!("C-Chain AcceptedFrontier from {} — tip={}", addr, container_id);
}
```

**Step 5: `cargo check`**

```bash
cargo check 2>&1 | grep "^error" | head -20
```

**Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: add C-Chain GetAcceptedFrontier bootstrap (Fuji)"
```

---

## Task 3: Build + test + live run + final commit

**Step 1: Build release**

```bash
cargo build --release 2>&1 | tail -5
```
Expected: `Finished release [optimized] target(s) in ...`

**Step 2: Run tests**

```bash
cargo test --lib 2>&1 | tail -10
```
Expected: all tests pass (db tests, network tests).

**Step 3: Live test (90 seconds on Fuji)**

```bash
RUST_LOG=info ./target/release/avalanche-rs \
  --network-id 5 \
  --data-dir /tmp/avax-phase3-test \
  2>&1 | tee /tmp/avax-phase3.log &
PID=$!
sleep 90
kill $PID
grep -E "stored|recursive|Bootstrap|C-Chain" /tmp/avax-phase3.log | tail -30
```

Expected output pattern:
```
Bootstrap: sent GetAcceptedFrontier (req=...) to ...
Bootstrap: sent GetAcceptedFrontier for C-Chain (req=...)
Ancestors from ... — 331 containers, ...
Bootstrap: stored 331 blocks (total: 331)
Bootstrap: recursive GetAncestors depth=1 req=... (total blocks so far: 331)
Bootstrap: stored ... blocks (total: ...)
C-Chain AcceptedFrontier from ... — tip=...
```

**Step 4: Final commit + openclaw notification**

```bash
git add src/main.rs
git commit -m "feat: phase 3 — P-Chain block storage + recursive fetch + C-Chain bootstrap"
openclaw system event --text "Done: avalanche-rs phase 3 — block storage + recursive fetch" --mode now
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `cannot borrow node.db` in async closure | `let db = &node.db;` before the loop, or use `Arc<Database>` |
| `containers` moved in loop | Iterate with `&containers` for hashing, then use the last element |
| CB58 decode gives wrong length | Check if bs58 decode includes checksum — strip last 4 bytes |
| `cchain_id` not in scope in timer arm | Move the decode block before the message loop |
| `FetchingAncestors` unmatched in if-let | Change to `match bootstrap_state { ... }` as shown |
