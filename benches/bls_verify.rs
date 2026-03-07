use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_bls_keygen(c: &mut Criterion) {
    use blst::min_pk::SecretKey;

    c.bench_function("bls_keygen", |b| {
        b.iter(|| {
            let ikm = [0x42u8; 32];
            let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
            let pk = sk.sk_to_pk();
            black_box(pk);
        })
    });
}

fn bench_bls_sign(c: &mut Criterion) {
    use blst::min_pk::SecretKey;

    let ikm = [0x42u8; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let message = b"test message for BLS signing benchmark";
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    c.bench_function("bls_sign", |b| {
        b.iter(|| {
            let sig = sk.sign(black_box(message), dst, &[]);
            black_box(sig);
        })
    });
}

fn bench_bls_verify(c: &mut Criterion) {
    use blst::min_pk::SecretKey;

    let ikm = [0x42u8; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();
    let message = b"test message for BLS verification benchmark";
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let sig = sk.sign(message, dst, &[]);

    c.bench_function("bls_verify", |b| {
        b.iter(|| {
            let result = sig.verify(true, black_box(message), dst, &[], &pk, true);
            black_box(result);
        })
    });
}

fn bench_bls_aggregate_verify(c: &mut Criterion) {
    use blst::min_pk::{AggregateSignature, SecretKey};

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let mut sigs = Vec::new();
    let mut pks = Vec::new();
    let mut msgs = Vec::new();

    for i in 0u8..10 {
        let mut ikm = [0u8; 32];
        ikm[0] = i;
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = sk.sk_to_pk();
        let msg = format!("message {}", i);
        let sig = sk.sign(msg.as_bytes(), dst, &[]);
        pks.push(pk);
        sigs.push(sig);
        msgs.push(msg);
    }

    let sig_refs: Vec<&blst::min_pk::Signature> = sigs.iter().collect();
    let agg = AggregateSignature::aggregate(&sig_refs, true).unwrap();
    let agg_sig = agg.to_signature();

    c.bench_function("bls_aggregate_verify_10", |b| {
        b.iter(|| {
            let pk_refs: Vec<&blst::min_pk::PublicKey> = pks.iter().collect();
            let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_bytes()).collect();
            let result = agg_sig.aggregate_verify(true, &msg_refs, dst, &pk_refs, true);
            black_box(result);
        })
    });
}

criterion_group!(
    benches,
    bench_bls_keygen,
    bench_bls_sign,
    bench_bls_verify,
    bench_bls_aggregate_verify
);
criterion_main!(benches);
