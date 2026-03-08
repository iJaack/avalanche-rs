use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_tls_identity_generation(c: &mut Criterion) {
    c.bench_function("tls_identity_generate", |b| {
        b.iter(|| {
            let id = avalanche_rs::identity::NodeIdentity::generate().expect("identity");
            black_box(id);
        })
    });
}

fn bench_tls_config_build(c: &mut Criterion) {
    c.bench_function("tls_config_build", |b| {
        b.iter(|| {
            let id = avalanche_rs::identity::NodeIdentity::generate().expect("identity");
            let _ = rustls::crypto::ring::default_provider().install_default();
            let server = id.tls_server_config().expect("server config");
            let client = id.tls_client_config().expect("client config");
            black_box((server, client));
        })
    });
}

criterion_group!(benches, bench_tls_identity_generation, bench_tls_config_build);
criterion_main!(benches);
