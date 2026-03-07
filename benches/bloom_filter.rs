use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::{Digest, Sha256};

/// Simple bloom filter for benchmarking (same logic as avalanche-core)
struct BloomFilter {
    bits: Vec<u8>,
    num_bits: usize,
    num_hashes: u8,
}

impl BloomFilter {
    fn with_capacity(expected_elements: usize, _fp_rate: f64) -> Self {
        let num_bits = (expected_elements * 10).max(64);
        let byte_len = (num_bits + 7) / 8;
        Self {
            bits: vec![0u8; byte_len],
            num_bits,
            num_hashes: 7,
        }
    }

    fn insert(&mut self, data: &[u8]) {
        for i in 0..self.num_hashes {
            let mut hasher = Sha256::new();
            hasher.update(&[i]);
            hasher.update(data);
            let hash = hasher.finalize();
            let pos = u64::from_be_bytes(hash[..8].try_into().unwrap()) as usize % self.num_bits;
            self.bits[pos / 8] |= 1 << (pos % 8);
        }
    }

    fn may_contain(&self, data: &[u8]) -> bool {
        for i in 0..self.num_hashes {
            let mut hasher = Sha256::new();
            hasher.update(&[i]);
            hasher.update(data);
            let hash = hasher.finalize();
            let pos = u64::from_be_bytes(hash[..8].try_into().unwrap()) as usize % self.num_bits;
            if self.bits[pos / 8] & (1 << (pos % 8)) == 0 {
                return false;
            }
        }
        true
    }
}

fn bench_bloom_insert(c: &mut Criterion) {
    c.bench_function("bloom_insert_100", |b| {
        b.iter(|| {
            let mut bloom = BloomFilter::with_capacity(100, 0.01);
            for i in 0u32..100 {
                bloom.insert(&i.to_be_bytes());
            }
            black_box(&bloom.bits);
        })
    });
}

fn bench_bloom_lookup(c: &mut Criterion) {
    let mut bloom = BloomFilter::with_capacity(1000, 0.01);
    for i in 0u32..1000 {
        bloom.insert(&i.to_be_bytes());
    }

    c.bench_function("bloom_lookup_1000", |b| {
        b.iter(|| {
            for i in 0u32..1000 {
                black_box(bloom.may_contain(&i.to_be_bytes()));
            }
        })
    });
}

fn bench_bloom_false_positive_rate(c: &mut Criterion) {
    let mut bloom = BloomFilter::with_capacity(1000, 0.01);
    for i in 0u32..1000 {
        bloom.insert(&i.to_be_bytes());
    }

    c.bench_function("bloom_fp_check_10000", |b| {
        b.iter(|| {
            let mut false_positives = 0u32;
            for i in 1000u32..11000 {
                if bloom.may_contain(&i.to_be_bytes()) {
                    false_positives += 1;
                }
            }
            black_box(false_positives);
        })
    });
}

criterion_group!(
    benches,
    bench_bloom_insert,
    bench_bloom_lookup,
    bench_bloom_false_positive_rate
);
criterion_main!(benches);
