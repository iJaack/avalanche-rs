// Global allocator: mimalloc (faster small allocations)
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use avalanche_rs::types::*;
use avalanche_rs::rpc::RpcClient;
use std::time::{Instant, Duration};
use tokio::task::JoinSet;

const ENDPOINT: &str = "https://api.avax.network";

struct BenchResult {
    name: String,
    samples: Vec<Duration>,
    errors: usize,
}

impl BenchResult {
    fn new(name: &str) -> Self {
        Self { name: name.to_string(), samples: vec![], errors: 0 }
    }
    fn add(&mut self, d: Duration) { self.samples.push(d); }
    fn add_error(&mut self) { self.errors += 1; }
    fn report(&self) {
        if self.samples.is_empty() {
            println!("  {:<40} ❌ all {} requests failed", self.name, self.errors);
            return;
        }
        let mut sorted = self.samples.clone();
        sorted.sort();
        let n = sorted.len();
        let min = sorted[0];
        let max = sorted[n - 1];
        let median = sorted[n / 2];
        let p95 = sorted[(n as f64 * 0.95) as usize];
        let avg: Duration = sorted.iter().sum::<Duration>() / n as u32;
        let total: Duration = sorted.iter().sum();
        println!("  {:<40} avg {:>8.1?}  med {:>8.1?}  p95 {:>8.1?}  min {:>8.1?}  max {:>8.1?}  ok {}/{}  total {:>8.1?}",
            self.name, avg, median, p95, min, max, n, n + self.errors, total);
    }
}

async fn bench_rpc_sequential(client: &RpcClient, method: &str, params: Vec<serde_json::Value>, rounds: usize) -> BenchResult {
    let mut result = BenchResult::new(&format!("{} (seq x{})", method, rounds));
    for _ in 0..rounds {
        let start = Instant::now();
        match client.call(method, params.clone()).await {
            Ok(_) => result.add(start.elapsed()),
            Err(_) => result.add_error(),
        }
    }
    result
}

async fn bench_rpc_concurrent(endpoint: &str, method: &str, params: Vec<serde_json::Value>, concurrency: usize) -> BenchResult {
    let mut result = BenchResult::new(&format!("{} (concurrent x{})", method, concurrency));
    let mut set = JoinSet::new();
    let start = Instant::now();
    for _ in 0..concurrency {
        let ep = endpoint.to_string();
        let m = method.to_string();
        let p = params.clone();
        set.spawn(async move {
            let client = RpcClient::new(&ep).unwrap();
            let t = Instant::now();
            match client.call(&m, p).await {
                Ok(_) => Ok(t.elapsed()),
                Err(e) => Err(e),
            }
        });
    }
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(d)) => result.add(d),
            _ => result.add_error(),
        }
    }
    let wall = start.elapsed();
    println!("  {:<40} wall time: {:?} for {} requests ({:.1} req/s)",
        format!("  └─ throughput"), wall, concurrency,
        concurrency as f64 / wall.as_secs_f64());
    result
}

#[tokio::main]
async fn main() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║   avalanche-rs v0.1.0 OPTIMIZED — Full Benchmark Suite                  ║");
    println!("╠══════════════════════════════════════════════════════════════════════════╣");
    println!("║  Optimizations: SHA2-ASM, mimalloc, AHash, faster-hex, fat LTO, -O3     ║");
    println!("║  Target: {} + local ops                        ║", ENDPOINT);
    println!("╚══════════════════════════════════════════════════════════════════════════╝");
    println!();

    let c_client = RpcClient::new(format!("{}/ext/bc/C/rpc", ENDPOINT)).unwrap();
    let p_client = RpcClient::new(format!("{}/ext/bc/P", ENDPOINT)).unwrap();

    // Warmup
    print!("🔥 Warming up...");
    let _ = c_client.call("eth_blockNumber", vec![]).await;
    let _ = c_client.call("eth_blockNumber", vec![]).await;
    // Warmup local ops too
    for i in 0u32..100_000 { let _ = ID::hash(&i.to_be_bytes()); }
    println!(" done\n");

    // ── RPC LATENCY ─────────────────────────────────────
    println!("━━━ C-Chain Sequential Latency ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    bench_rpc_sequential(&c_client, "eth_blockNumber", vec![], 20).await.report();
    bench_rpc_sequential(&c_client, "eth_getBalance",
        vec![serde_json::json!("0x8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC"), serde_json::json!("latest")],
        20).await.report();
    bench_rpc_sequential(&c_client, "eth_chainId", vec![], 20).await.report();
    bench_rpc_sequential(&c_client, "eth_gasPrice", vec![], 20).await.report();

    println!();
    println!("━━━ P-Chain Sequential Latency ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    bench_rpc_sequential(&p_client, "platform.getHeight", vec![], 20).await.report();

    println!();
    println!("━━━ Concurrent Throughput ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let ep = format!("{}/ext/bc/C/rpc", ENDPOINT);
    bench_rpc_concurrent(&ep, "eth_blockNumber", vec![], 50).await.report();
    println!();
    bench_rpc_concurrent(&ep, "eth_blockNumber", vec![], 100).await.report();
    println!();
    bench_rpc_concurrent(&ep, "eth_blockNumber", vec![], 200).await.report();

    // ── LOCAL PERFORMANCE ───────────────────────────────
    println!();
    println!("━━━ Local Client Performance (OPTIMIZED) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // SHA-256 (with ASM acceleration)
    let n = 1_000_000u64;
    let start = Instant::now();
    for i in 0..n {
        let _ = ID::hash(&(i as u32).to_be_bytes());
    }
    let elapsed = start.elapsed();
    println!("  {:<40} total {:>8.1?}  per-op {:>6.0} ns  throughput {:>8.1} M/s",
        format!("SHA-256 hash (x{})", n), elapsed,
        elapsed.as_nanos() as f64 / n as f64,
        n as f64 / elapsed.as_secs_f64() / 1_000_000.0);

    // Block chain build
    let n = 100_000u64;
    let start = Instant::now();
    let mut parent = BlockID(ID::new([0u8; 32]));
    for i in 1..=n {
        let id = BlockID(ID::hash(&(i as u32).to_be_bytes()));
        let b = Block::new(id, parent, i, i * 6, vec![], ID::new([0u8; 32])).unwrap();
        parent = b.id;
    }
    let elapsed = start.elapsed();
    println!("  {:<40} total {:>8.1?}  per-op {:>6.0} ns  throughput {:>8.1} M/s",
        format!("Block chain build (x{})", n), elapsed,
        elapsed.as_nanos() as f64 / n as f64,
        n as f64 / elapsed.as_secs_f64() / 1_000_000.0);

    // JSON roundtrip (serde)
    let block = Block::new(
        BlockID(ID::hash(b"bench")),
        BlockID(ID::new([0u8; 32])),
        999, 12345, vec![], ID::new([0u8; 32]),
    ).unwrap();
    let n = 100_000u64;
    let start = Instant::now();
    for _ in 0..n {
        let json = serde_json::to_vec(&block).unwrap();
        let _: Block = serde_json::from_slice(&json).unwrap();
    }
    let elapsed = start.elapsed();
    println!("  {:<40} total {:>8.1?}  per-op {:>6.0} ns  throughput {:>8.1} M/s",
        format!("JSON roundtrip (x{})", n), elapsed,
        elapsed.as_nanos() as f64 / n as f64,
        n as f64 / elapsed.as_secs_f64() / 1_000_000.0);

    // Hex roundtrip (faster-hex)
    let id = ID::new([0xAB; 32]);
    let n = 1_000_000u64;
    let start = Instant::now();
    for _ in 0..n {
        // Use faster-hex for encoding
        let mut buf = vec![0u8; 64];
        faster_hex::hex_encode(id.as_bytes(), &mut buf).unwrap();
        let hex_str = unsafe { std::str::from_utf8_unchecked(&buf) };
        // Decode back
        let mut out = [0u8; 32];
        faster_hex::hex_decode(hex_str.as_bytes(), &mut out).unwrap();
    }
    let elapsed = start.elapsed();
    println!("  {:<40} total {:>8.1?}  per-op {:>6.0} ns  throughput {:>8.1} M/s",
        format!("Hex roundtrip/faster-hex (x{})", n), elapsed,
        elapsed.as_nanos() as f64 / n as f64,
        n as f64 / elapsed.as_secs_f64() / 1_000_000.0);

    // Also show old hex for comparison
    let start = Instant::now();
    for _ in 0..n {
        let h = hex::encode(id.as_bytes());
        let _ = hex::decode(&h).unwrap();
    }
    let elapsed = start.elapsed();
    println!("  {:<40} total {:>8.1?}  per-op {:>6.0} ns  throughput {:>8.1} M/s",
        format!("Hex roundtrip/std hex (x{})", n), elapsed,
        elapsed.as_nanos() as f64 / n as f64,
        n as f64 / elapsed.as_secs_f64() / 1_000_000.0);

    // AHash HashMap stress
    let n = 100_000u64;
    let start = Instant::now();
    let mut map: ahash::AHashMap<ID, u64> = ahash::AHashMap::with_capacity(n as usize);
    for i in 0..n {
        let id = ID::hash(&(i as u32).to_be_bytes());
        map.insert(id, i);
    }
    for i in 0..n {
        let id = ID::hash(&(i as u32).to_be_bytes());
        let _ = map.get(&id);
    }
    let elapsed = start.elapsed();
    println!("  {:<40} total {:>8.1?}  per-op {:>6.0} ns  ({} insert + {} lookup)",
        format!("AHashMap stress (x{})", n * 2), elapsed,
        elapsed.as_nanos() as f64 / (n * 2) as f64, n, n);

    // Standard HashMap for comparison
    let start = Instant::now();
    let mut map = std::collections::HashMap::with_capacity(n as usize);
    for i in 0..n {
        let id = ID::hash(&(i as u32).to_be_bytes());
        map.insert(id, i);
    }
    for i in 0..n {
        let id = ID::hash(&(i as u32).to_be_bytes());
        let _ = map.get(&id);
    }
    let elapsed = start.elapsed();
    println!("  {:<40} total {:>8.1?}  per-op {:>6.0} ns  ({} insert + {} lookup)",
        format!("StdHashMap stress (x{})", n * 2), elapsed,
        elapsed.as_nanos() as f64 / (n * 2) as f64, n, n);

    // ── EXTREME STRESS ──────────────────────────────────
    println!();
    println!("━━━ Extreme Stress Tests ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // 10M hashes
    let n = 10_000_000u64;
    let start = Instant::now();
    for i in 0..n {
        let _ = ID::hash(&(i as u32).to_be_bytes());
    }
    let elapsed = start.elapsed();
    println!("  {:<40} total {:>8.1?}  per-op {:>6.0} ns  throughput {:>8.1} M/s",
        format!("SHA-256 hash (x{})", n), elapsed,
        elapsed.as_nanos() as f64 / n as f64,
        n as f64 / elapsed.as_secs_f64() / 1_000_000.0);

    // 1M block chain
    let n = 1_000_000u64;
    let start = Instant::now();
    let mut parent = BlockID(ID::new([0u8; 32]));
    for i in 1..=n {
        let id = BlockID(ID::hash(&(i as u32).to_be_bytes()));
        let b = Block::new(id, parent, i, i * 6, vec![], ID::new([0u8; 32])).unwrap();
        parent = b.id;
    }
    let elapsed = start.elapsed();
    println!("  {:<40} total {:>8.1?}  per-op {:>6.0} ns  throughput {:>8.1} M/s",
        format!("Block chain (x{})", n), elapsed,
        elapsed.as_nanos() as f64 / n as f64,
        n as f64 / elapsed.as_secs_f64() / 1_000_000.0);

    // 1M JSON roundtrips
    let n = 1_000_000u64;
    let start = Instant::now();
    for _ in 0..n {
        let json = serde_json::to_vec(&block).unwrap();
        let _: Block = serde_json::from_slice(&json).unwrap();
    }
    let elapsed = start.elapsed();
    println!("  {:<40} total {:>8.1?}  per-op {:>6.0} ns  throughput {:>8.1} M/s",
        format!("JSON roundtrip (x{})", n), elapsed,
        elapsed.as_nanos() as f64 / n as f64,
        n as f64 / elapsed.as_secs_f64() / 1_000_000.0);

    println!();
    println!("══════════════════════════════════════════════════════════════════════════");
    println!("  ✅ OPTIMIZED benchmark complete.");
    println!("══════════════════════════════════════════════════════════════════════════");
    println!();
}
