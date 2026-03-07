use criterion::{black_box, criterion_group, criterion_main, Criterion};
use prost::Message;

fn bench_proto_encode_ping(c: &mut Criterion) {
    use avalanche_rs::network::NetworkMessage;

    let msg = NetworkMessage::Ping { uptime: 9500 };

    c.bench_function("proto_encode_ping", |b| {
        b.iter(|| {
            let encoded = black_box(&msg).encode_proto().unwrap();
            black_box(encoded);
        })
    });
}

fn bench_proto_decode_ping(c: &mut Criterion) {
    use avalanche_rs::network::NetworkMessage;

    let msg = NetworkMessage::Ping { uptime: 9500 };
    let encoded = msg.encode_proto().unwrap();

    c.bench_function("proto_decode_ping", |b| {
        b.iter(|| {
            let decoded = NetworkMessage::decode_proto(black_box(&encoded)).unwrap();
            black_box(decoded);
        })
    });
}

fn bench_proto_encode_put(c: &mut Criterion) {
    use avalanche_rs::network::{BlockId, ChainId, NetworkMessage};

    let msg = NetworkMessage::Put {
        chain_id: ChainId([0xCC; 32]),
        request_id: 42,
        container: vec![0xDE; 4096],
    };

    c.bench_function("proto_encode_put_4kb", |b| {
        b.iter(|| {
            let encoded = black_box(&msg).encode_proto().unwrap();
            black_box(encoded);
        })
    });
}

fn bench_proto_decode_put(c: &mut Criterion) {
    use avalanche_rs::network::{BlockId, ChainId, NetworkMessage};

    let msg = NetworkMessage::Put {
        chain_id: ChainId([0xCC; 32]),
        request_id: 42,
        container: vec![0xDE; 4096],
    };
    let encoded = msg.encode_proto().unwrap();

    c.bench_function("proto_decode_put_4kb", |b| {
        b.iter(|| {
            let decoded = NetworkMessage::decode_proto(black_box(&encoded)).unwrap();
            black_box(decoded);
        })
    });
}

fn bench_proto_roundtrip_chits(c: &mut Criterion) {
    use avalanche_rs::network::{BlockId, ChainId, NetworkMessage};

    let msg = NetworkMessage::Chits {
        chain_id: ChainId([0xAA; 32]),
        request_id: 77,
        preferred_id: BlockId([1u8; 32]),
        preferred_id_at_height: BlockId([2u8; 32]),
        accepted_id: BlockId([3u8; 32]),
    };

    c.bench_function("proto_roundtrip_chits", |b| {
        b.iter(|| {
            let encoded = msg.encode_proto().unwrap();
            let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
            black_box(decoded);
        })
    });
}

criterion_group!(
    benches,
    bench_proto_encode_ping,
    bench_proto_decode_ping,
    bench_proto_encode_put,
    bench_proto_decode_put,
    bench_proto_roundtrip_chits
);
criterion_main!(benches);
