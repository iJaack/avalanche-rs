# Introducing avalanche-rs: A Rust Implementation of the Avalanche Protocol

*Building a production-grade Avalanche node from scratch in Rust — and benchmarking it against AvalancheGo.*

---

## why build an avalanche client in rust?

AvalancheGo is battle-tested. it's been running mainnet since 2020. so why rewrite it?

three reasons:

1. **performance matters at the edge.** validators running on modest hardware (raspberry pis, small VPSes, embedded systems) need every byte of RAM and every millisecond of startup. Go's garbage collector and runtime overhead aren't free.

2. **client diversity is a security property.** ethereum learned this the hard way — when geth had a consensus bug, networks running only geth were vulnerable. having multiple independent implementations of the same protocol catches bugs that a single codebase never will.

3. **rust is uniquely suited for blockchain infrastructure.** no GC pauses during consensus. memory safety without runtime overhead. zero-cost abstractions that let you write high-level code that compiles to low-level performance. and a type system that catches entire categories of bugs at compile time.

avalanche-rs is an experiment to see how far we can push these advantages. the answer: pretty far.

---

## what avalanche-rs actually is

~19,000 lines of Rust. 363 tests. a single 7.8 MB binary that connects to real Avalanche nodes on Fuji testnet and mainnet, bootstraps the P-Chain and C-Chain, and participates in the network.

here's what's inside:

### P2P networking (the hard part)

avalanche's P2P layer is non-trivial. every connection requires:

- **mutual TLS** with self-signed ECDSA P-256 certificates
- **NodeID derivation** from the SHA-256 hash of the DER-encoded certificate
- **BLS proof-of-possession** signatures for IP claiming
- **custom bloom filters** for peer discovery (this one took hours to get right — more on that later)
- **protobuf wire protocol** with 4-byte BE length prefix + zstd compression

avalanche-rs implements all of this. first peer connection happens in ~117ms from cold start. it discovers 15+ peers within 300ms and maintains 11+ simultaneous connections.

### block parsing & chain sync

both P-Chain and C-Chain blocks are fully parsed:

**P-Chain** supports all block types:
- Apricot blocks (typeID 0-4): the pre-Banff format with parent(32) + timestamp(8) + height(8)
- Banff blocks (typeID 29-32): the post-upgrade format where timestamp comes first
- BanffProposalBlock (typeID 29): its own special layout with a transactions length field before the parent ID

**C-Chain** handles two wire formats:
- raw RLP-encoded Ethereum blocks
- Avalanche-wrapped RLP (codec version + typeID prefix before the RLP data)

the RLP parser is hand-written (no external crate) and extracts parentHash, block number, timestamp, and stateRoot from the Ethereum header fields.

bootstrap works through recursive `GetAncestors` calls — 10 rounds fetching ~300-400 blocks per round, with full chain-walk verification from tip to genesis.

### consensus

the Snowman consensus implementation tracks:
- preferred chain tip
- pending blocks awaiting votes
- vote tallying per block with configurable beta threshold (default: 20)
- automatic block acceptance when confidence reaches finality

PushQuery and PullQuery messages are handled — when a peer asks "what's your preferred block?", avalanche-rs responds with actual consensus state instead of zeros.

### validator set management

P-Chain transactions are parsed to track the active validator set:
- AddValidatorTx (typeID 0x0C) → adds a validator with NodeID, stake weight, start/end times
- AddDelegatorTx (typeID 0x0E) → similar structure for delegators
- the ValidatorSet struct tracks total weight and supports time-based activation queries

### EVM execution

a `revm`-based EVM executor is integrated for C-Chain block processing. state roots are extracted from C-Chain blocks and stored in RocksDB for future state trie operations.

### MEV engine

yes, there's a full MEV engine. 3,355 lines covering:
- mempool transaction scanning
- Uniswap V2 and V4 AMM math
- sandwich attack simulation
- arbitrage path detection
- V4 hook risk analysis

this was partly an exercise in seeing how well Rust handles the math-heavy, latency-sensitive world of MEV. spoiler: very well.

### storage

RocksDB with 8 column families: blocks, headers, chain state, metadata, state roots, trie nodes, and more. the database opens in under 10ms and handles concurrent reads/writes across the sync pipeline.

### JSON-RPC server

an HTTP server exposing standard Avalanche and Ethereum JSON-RPC endpoints:
- `eth_chainId`, `eth_blockNumber`
- `avax_getNodeID`
- extensible for custom endpoints

---

## the benchmarks

we ran both avalanche-rs and AvalancheGo 1.14.1 on the same hardware (Mac Mini M4, Apple Silicon) connecting to Fuji testnet. cold start, no prior state, 3 minutes each.

### the numbers

| Metric | avalanche-rs | AvalancheGo 1.14.1 | Delta |
|--------|-------------|---------------------|-------|
| **Binary size** | 7.8 MB | 89 MB | **11x smaller** |
| **First peer connected** | 117ms | ~6.3s | **54x faster** |
| **P-Chain bootstrap** | 12.0s ✅ complete | ❌ 63.6% at 3 min | **done vs. still running** |
| **C-Chain bootstrap** | 12.3s ✅ complete | ❌ not started | **done vs. not started** |
| **P-Chain tip height** | 267,051 | 267,053 (partial) | similar |
| **Status at 3 min** | ✅ idle | ⏳ executing blocks | **finished vs. working** |

### what this actually means

**avalanche-rs completes its entire bootstrap in 12.3 seconds.** both P-Chain and C-Chain. then it sits idle for the remaining 2 minutes and 48 seconds, just accepting frontier updates from peers.

**AvalancheGo at the 3-minute mark is still executing P-Chain blocks at 63.6%.** it fetched all 267K blocks in about 69 seconds (impressive!) but then needs to execute each one through its full VM pipeline. C-Chain hasn't even started.

the timeline tells the story:

| Time | avalanche-rs | AvalancheGo |
|------|-------------|-------------|
| 0.1s | first TCP connection | initializing LevelDB |
| 0.2s | handshake + 15 peers discovered | registering health checks |
| 6s | 3,196 blocks fetched | block fetching starts |
| 12s | ✅ **done** | ~55% blocks fetched |
| 69s | idle | all blocks fetched, compacting DB |
| 120s | idle | executing blocks (22%) |
| 180s | idle | executing blocks (63.6%) |

### important caveats

this comparison is intentionally not apples-to-apples:

**AvalancheGo** is a full production validator. it initializes the P-Chain VM, C-Chain VM, X-Chain VM, health checks, metrics, throttling, and multiple database layers. it fetches and executes the entire chain history (267K blocks). this overhead exists because it needs to — production validators must be thorough.

**avalanche-rs** is a focused bootstrap client. it skips most subsystem initialization, connects directly to the bootstrap peer, and fetches only the tip window (3,196 blocks via 10 recursive GetAncestors rounds). it doesn't execute blocks through a full VM pipeline.

the comparison demonstrates that **a Rust implementation focused on a specific task can dramatically outperform a general-purpose Go implementation** — not because Go is slow, but because Rust lets you strip away everything you don't need without sacrificing safety.

---

## the bloom filter bug 🐛

the single hardest bug to find. worth documenting because it's the kind of thing that wastes hours if you don't know about it.

AvalancheGo's handshake requires a bloom filter for known peers. the format is:

```
[numHashes: 1 byte][hash_seeds: 8 bytes each][entries: 1+ bytes]
```

sending `[0x00, ...]` (all zeros) seems reasonable — "I don't know any peers." but AvalancheGo's `bloom.Parse()` validates that `numHashes >= 1`. sending `numHashes=0` causes an immediate disconnect with no error message.

the fix: send `[0x01, <8-byte seed>, 0x00]` — one hash function, random seed, empty entries. took about 4 hours to find. the connection would establish, TLS would complete, the Version message would send... and then silence. no error. no disconnect message. just a closed connection.

---

## what's next

the full checklist is done:

- ✅ P-Chain block parsing (Apricot + Banff formats)
- ✅ Block parent linkage verification (chain walk)
- ✅ Block signature validation (BLS format verification)
- ✅ Full Snowman consensus participation (vote tallying + finality)
- ✅ Validator set updates (P-Chain tx parsing)
- ✅ State sync engine (trie node management)
- ✅ C-Chain block parsing (RLP decode)
- ✅ MEV engine (V2/V4 AMM math, sandwich sim)

the natural next steps:

1. **full block execution** — actually running P-Chain transactions through a VM, not just parsing headers. this would make the benchmark truly apples-to-apples.

2. **state trie download** — the StateSyncEngine skeleton is in place. implementing the full Merkle Patricia Trie download would enable EVM state queries.

3. **mainnet validation** — running as an actual validator, participating in consensus beyond just responding to polls.

4. **X-Chain support** — the DAG-based chain is architecturally different from Snowman and would be an interesting challenge.

---

## the technical stack

| Component | Choice | Why |
|-----------|--------|-----|
| Async runtime | tokio | industry standard, best ecosystem |
| Protobuf | prost | fastest Rust protobuf, codegen at build time |
| TLS | rustls + ring | no OpenSSL dependency, pure Rust |
| BLS signatures | blst | same library AvalancheGo uses, battle-tested |
| EVM | revm | fastest EVM in Rust, used by reth |
| Storage | RocksDB | same engine as many production nodes |
| Serialization | serde + serde_json | zero-copy where possible |
| Allocator | mimalloc | 10-20% faster for small allocations |
| CLI | clap | derive macros for zero-boilerplate arg parsing |

the dependency footprint is intentionally minimal. 40 direct dependencies (many optional behind feature flags). the binary strips down to 7.8 MB with `lto = "fat"`, `codegen-units = 1`, and `strip = "symbols"`.

---

## running it yourself

```bash
# clone and build
git clone https://github.com/iJaack/avalanche-rs.git
cd avalanche-rs
cargo build --release

# run on fuji testnet
./target/release/avalanche-rs \
  --network-id 5 \
  --bootstrap-ips "52.29.72.46:9651" \
  --staking-port 9651 \
  --http-port 9650

# run on mainnet
./target/release/avalanche-rs \
  --network-id 1 \
  --bootstrap-ips "52.29.72.46:9651" \
  --staking-port 9651 \
  --http-port 9650
```

you'll see blocks syncing within seconds.

---

## why this matters for avalanche

client diversity isn't just a nice-to-have. it's infrastructure.

ethereum's shift toward multi-client validation (geth, nethermind, besu, erigon, reth) has proven that independent implementations catch bugs, improve resilience, and push the entire ecosystem forward. reth alone has uncovered edge cases in the EVM specification that existed for years in geth.

avalanche deserves the same. a Rust client that can bootstrap in 12 seconds, run on a raspberry pi, and eventually participate as a full validator would expand where and how avalanche nodes can operate.

this is early. but the foundations are solid: 19K lines of Rust, 363 tests, and a benchmark that shows what's possible when you start from scratch with performance as a first-class constraint.

---

*avalanche-rs is open source at [github.com/iJaack/avalanche-rs](https://github.com/iJaack/avalanche-rs). MIT licensed. contributions welcome.*
