# M6 Scope — Hardening And Archive Parity

**Date:** 2026-04-10  
**Base:** `main` after merging `codex/m5-coreth-public-rpc-parity`  
**Goal:** move the node from broad public RPC surface parity to production-grade correctness under historical queries, replacement flows, reorgs, and runtime failures.

## Why M6 exists

M5 closes most of the missing public Coreth RPC surface, but the remaining gap is not "more endpoints". The remaining work is:

1. historical/archive semantics for methods that still operate on current in-memory state only
2. runtime hardening around txpool, bootstrap, forks, and database failures
3. regression coverage for correctness under failure and restart conditions

## Non-goals

1. Re-introducing X-Chain / AVM APIs removed in M0
2. Adding a new large public API family unrelated to archive correctness or node hardening
3. Broad UI / dashboard work beyond metrics required for operating the node safely

## Success criteria

1. `eth_getProof`, `eth_call`, and balance/storage lookups behave correctly for historical block contexts that the node claims to support
2. txpool replacement, resend, mined/pending transitions, and receipt/index projections remain correct under reorg and replay scenarios
3. bootstrap and steady-state operation tolerate peer failures, reorgs, and transient DB failures without silent corruption
4. the new behavior is covered by deterministic unit and regression tests, not only ad hoc local runs

## Milestone 1 — Historical State Query Parity

### Scope

Make historical state semantics explicit and correct for the read methods users will expect to work against past blocks.

### Atomic tasks

1. Define supported historical modes for `eth_getProof`, `eth_call`, `eth_getBalance`, `eth_getStorageAt`, and `eth_getTransactionCount`.
2. Introduce a reusable historical-state snapshot/replay path so methods do not special-case block selection independently.
3. Either implement historical proofs from persisted state or fail with a documented, intentional capability boundary that is consistent across related methods.
4. Ensure block tags (`latest`, `pending`, hex heights) are normalized through one shared resolver.
5. Document which methods require archive mode and what data must be retained.

### Regression and unit tests

1. Add unit tests for block-tag resolution and historical context selection.
2. Add regression tests for `eth_getProof` at current head, past head, missing block, and archive-disabled cases.
3. Add regression tests for `eth_call` and `eth_getBalance` against historical blocks with differing account state.
4. Add replay-based tests that compare historical results before and after restart.

### Exit condition

This milestone is not complete until historical query behavior is either fully implemented or intentionally rejected with stable, documented RPC errors, and all regressions are green.

## Milestone 2 — Txpool, Receipts, And Reorg Correctness

### Scope

Harden the path from pending tx submission through mining, replacement, receipt storage, and reorg handling.

### Atomic tasks

1. Audit txpool replacement and duplicate behavior across legacy and EIP-1559 managed/raw flows.
2. Validate mined/pending transaction lookup paths against block import, replay, and replacement edge cases.
3. Add explicit reorg handling for receipt/index invalidation where required by current storage strategy.
4. Verify `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBlockReceipts`, and filter/event paths under replay and reorg scenarios.
5. Confirm `eth_resend` behavior is consistent with txpool replacement rules for both legacy and typed transactions.

### Regression and unit tests

1. Add unit tests for txpool replacement thresholds and stale-hash cleanup.
2. Add regression tests covering replacement followed by mining and receipt retrieval.
3. Add reorg tests where a previously indexed tx/receipt becomes orphaned and is replaced by a new canonical block.
4. Add filter regression tests to ensure pending/block/accepted subscriptions do not double-report after replay.

### Exit condition

This milestone is not complete until canonical vs orphaned transaction visibility is deterministic under test and no stale tx/receipt indexes remain after replay or reorg.

## Milestone 3 — Bootstrap, Fork, And DB Failure Hardening

### Scope

Close the operational gaps that can turn partial parity into production incidents.

### Atomic tasks

1. Add explicit peer timeout fallback and bad-peer handling during bootstrap.
2. Add fork/reorg detection metrics and canonical-tip validation tests.
3. Audit DB write and read failure handling in receipt/index persistence and startup recovery paths.
4. Ensure restart during catchup or mid-import resumes cleanly without double-writing or silent gaps.
5. Expose the minimum metrics needed to detect lag, reorgs, write failures, and txpool drift.

### Regression and unit tests

1. Add bootstrap timeout tests for unresponsive and malformed peers.
2. Add fork/reorg tests with two competing tips at the same height and a later canonical switch.
3. Add DB fault-injection tests for partial receipt/index persistence and restart recovery.
4. Add restart regression tests for catchup resume and idempotent block replay.

### Exit condition

This milestone is not complete until bootstrap, fork, and DB error paths are covered by deterministic tests and the node exposes enough metrics to detect these failures in operation.

## Recommended execution order

1. Milestone 2 first
2. Milestone 1 second
3. Milestone 3 third

## Reasoning for the order

1. M5 just expanded the public RPC surface, so txpool/receipt/reorg correctness is the highest immediate risk.
2. Historical parity is the next highest user-visible gap after public RPC surface completion.
3. Bootstrap and DB hardening are critical, but they are less likely to block immediate RPC validation than txpool and archive semantics.

## Deliverables

1. code changes on a new `codex/m6-*` branch
2. deterministic regression coverage for each milestone
3. operator-facing documentation updates for any intentional archive limitations
4. a short release note summarizing newly supported historical semantics and hardening guarantees
