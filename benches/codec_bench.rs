use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_json_roundtrip(c: &mut Criterion) {
    let data = serde_json::json!({
        "id": "2XkPRcDBiNRTJFGQ8rXnbLBmwVEHrY5RaJmGBfKoVPnJaHcbfD",
        "parentID": "2XkPRcDBiNRTJFGQ8rXnbLBmwVEHrY5RaJmGBfKoVPnJaHcbfD",
        "height": 1000u64,
        "timestamp": "2026-01-01T00:00:00Z"
    });

    c.bench_function("json_serialize", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&data)).unwrap();
            black_box(s);
        })
    });

    c.bench_function("json_deserialize", |b| {
        let s = serde_json::to_string(&data).unwrap();
        b.iter(|| {
            let v: serde_json::Value = serde_json::from_str(black_box(&s)).unwrap();
            black_box(v);
        })
    });
}

fn bench_hex_encoding(c: &mut Criterion) {
    let bytes = vec![0xABu8; 32];

    c.bench_function("hex_encode_32b", |b| {
        b.iter(|| {
            let s = hex::encode(black_box(&bytes));
            black_box(s);
        })
    });

    c.bench_function("hex_decode_32b", |b| {
        let s = hex::encode(&bytes);
        b.iter(|| {
            let v = hex::decode(black_box(&s)).unwrap();
            black_box(v);
        })
    });
}

fn bench_sha256(c: &mut Criterion) {
    use sha2::{Digest, Sha256};
    let data = vec![0u8; 256];

    c.bench_function("sha256_256b", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&data));
            let result = hasher.finalize();
            black_box(result);
        })
    });
}

criterion_group!(
    benches,
    bench_json_roundtrip,
    bench_hex_encoding,
    bench_sha256
);
criterion_main!(benches);
