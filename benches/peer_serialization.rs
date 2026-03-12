use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_peer_message_serialize(c: &mut Criterion) {
    let message = avalanche_rs::network::NetworkMessage::Version {
        network_id: 1,
        node_id: avalanche_rs::network::NodeId([0x11; 20]),
        my_time: 1_700_000_000,
        ip_addr: vec![127, 0, 0, 1],
        ip_port: 9651,
        my_version: "avalanche-rs/0.1.0".to_string(),
        my_version_time: 1_700_000_000,
        sig: vec![0x22; 65],
        tracked_subnets: vec![avalanche_rs::network::ChainId([0x33; 32])],
        supported_acps: vec![],
        objected_acps: vec![],
    };

    c.bench_function("peer_serialization_version_proto", |b| {
        b.iter(|| {
            let encoded = message.encode_proto().expect("encode");
            black_box(encoded);
        })
    });
}

fn bench_peer_message_deserialize(c: &mut Criterion) {
    let message = avalanche_rs::network::NetworkMessage::Ping { uptime: 9_999 };
    let encoded = message.encode_proto().expect("encode");

    c.bench_function("peer_serialization_ping_decode_proto", |b| {
        b.iter(|| {
            let decoded = avalanche_rs::network::NetworkMessage::decode_proto(black_box(&encoded))
                .expect("decode");
            black_box(decoded);
        })
    });
}

criterion_group!(
    benches,
    bench_peer_message_serialize,
    bench_peer_message_deserialize
);
criterion_main!(benches);
