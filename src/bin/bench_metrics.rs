use std::time::Instant;

fn current_rss_kb() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if rc != 0 {
        return 0;
    }
    let usage = unsafe { usage.assume_init() };
    usage.ru_maxrss as u64
}

fn main() {
    let start = Instant::now();

    let mut total = 0u64;
    for i in 0..50_000u64 {
        total = total.wrapping_add(i.rotate_left((i % 31) as u32));
    }

    let mut trie = avalanche_rs::db::StateTrie::new();
    for i in 0..500u64 {
        let mut addr = [0u8; 20];
        addr[12..20].copy_from_slice(&i.to_be_bytes());
        trie.insert(
            addr,
            &avalanche_rs::db::AccountState {
                nonce: i,
                balance: (i * 10) as u128,
                storage_root: [0x44; 32],
                code_hash: [0x55; 32],
            },
        );
    }
    let root = trie.root_hash();

    let elapsed_ms = start.elapsed().as_millis() as u64;
    let rss_kb = current_rss_kb();

    let out = serde_json::json!({
        "workload_elapsed_ms": elapsed_ms,
        "memory_rss_kb": rss_kb,
        "checksum": total,
        "trie_root": hex::encode(root),
    });

    println!("{}", out);
}
