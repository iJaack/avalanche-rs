use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;

/// Simulates Snowball voting rounds to benchmark consensus throughput
fn bench_snowball_voting(c: &mut Criterion) {
    c.bench_function("snowball_10_rounds", |b| {
        b.iter(|| {
            let mut preference: [u8; 32] = [0; 32];
            let mut confidence: u32 = 0;
            let mut consecutive: u32 = 0;
            let alpha: u32 = 15;
            let beta: u32 = 3;

            for round in 0..10u32 {
                // Simulate votes (20 validators, 18 agree)
                let votes_for = 18u32;
                if votes_for >= alpha {
                    consecutive += 1;
                    confidence += 1;
                    preference = [round as u8; 32];
                } else {
                    consecutive = 0;
                }

                if consecutive >= beta {
                    black_box(preference);
                    break;
                }
            }
            black_box((preference, confidence, consecutive));
        })
    });
}

fn bench_block_status_tracking(c: &mut Criterion) {
    c.bench_function("track_1000_blocks", |b| {
        b.iter(|| {
            let mut statuses: HashMap<[u8; 32], u8> = HashMap::with_capacity(1000);
            for i in 0u32..1000 {
                let mut id = [0u8; 32];
                id[..4].copy_from_slice(&i.to_be_bytes());
                statuses.insert(id, 1); // 1 = Processing
            }
            // Accept all
            for (_, status) in statuses.iter_mut() {
                *status = 3; // 3 = Accepted
            }
            black_box(&statuses);
        })
    });
}

fn bench_validator_selection(c: &mut Criterion) {
    c.bench_function("select_from_100_validators", |b| {
        let validators: Vec<(u64, bool)> = (0..100)
            .map(|i| (1000 + i * 100, i % 10 != 0)) // weight, connected
            .collect();

        b.iter(|| {
            let connected: Vec<&(u64, bool)> = validators
                .iter()
                .filter(|(_, connected)| *connected)
                .collect();
            let total_weight: u64 = connected.iter().map(|(w, _)| w).sum();
            black_box((connected.len(), total_weight));
        })
    });
}

criterion_group!(
    benches,
    bench_snowball_voting,
    bench_block_status_tracking,
    bench_validator_selection
);
criterion_main!(benches);
