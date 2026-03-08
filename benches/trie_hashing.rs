use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_state_trie_root_hash(c: &mut Criterion) {
    let mut trie = avalanche_rs::db::StateTrie::new();
    for i in 0..1000u64 {
        let mut addr = [0u8; 20];
        addr[12..20].copy_from_slice(&i.to_be_bytes());
        trie.insert(
            addr,
            &avalanche_rs::db::AccountState {
                nonce: i,
                balance: i as u128 * 1000,
                storage_root: [0x11; 32],
                code_hash: [0x22; 32],
            },
        );
    }

    c.bench_function("trie_hashing_root_1000_accounts", |b| {
        b.iter(|| {
            let root = trie.root_hash();
            black_box(root);
        })
    });
}

criterion_group!(benches, bench_state_trie_root_hash);
criterion_main!(benches);
