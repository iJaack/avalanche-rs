use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn bench_mpt_insert(c: &mut Criterion) {
    c.bench_function("mpt_insert_100", |b| {
        b.iter(|| {
            let mut trie: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(100);
            for i in 0u64..100 {
                let mut key = [0u8; 32];
                let hash = Sha256::digest(&i.to_be_bytes());
                key.copy_from_slice(&hash);
                trie.insert(key, vec![i as u8; 32]);
            }
            black_box(&trie);
        })
    });
}

fn bench_mpt_lookup(c: &mut Criterion) {
    let mut trie: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(1000);
    let mut keys = Vec::with_capacity(1000);
    for i in 0u64..1000 {
        let mut key = [0u8; 32];
        let hash = Sha256::digest(&i.to_be_bytes());
        key.copy_from_slice(&hash);
        trie.insert(key, vec![i as u8; 32]);
        keys.push(key);
    }

    c.bench_function("mpt_lookup_1000", |b| {
        b.iter(|| {
            for key in &keys {
                black_box(trie.get(black_box(key)));
            }
        })
    });
}

fn bench_mpt_proof_generation(c: &mut Criterion) {
    // Simulate proof generation: hash chain from leaf to root
    c.bench_function("mpt_proof_16_levels", |b| {
        b.iter(|| {
            let mut current = [0u8; 32];
            for level in 0u8..16 {
                let mut hasher = Sha256::new();
                hasher.update(&current);
                hasher.update(&[level]);
                current = hasher.finalize().into();
            }
            black_box(current);
        })
    });
}

criterion_group!(
    benches,
    bench_mpt_insert,
    bench_mpt_lookup,
    bench_mpt_proof_generation
);
criterion_main!(benches);
