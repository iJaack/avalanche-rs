use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::{Digest, Sha256};

fn make_banff_std(parent: [u8; 32], height: u64) -> Vec<u8> {
    let mut raw = vec![0u8; 54];
    raw[2..6].copy_from_slice(&32u32.to_be_bytes()); // typeID = BanffStandard
    raw[6..14].copy_from_slice(&1_700_000_000u64.to_be_bytes()); // timestamp
    raw[14..46].copy_from_slice(&parent); // parent ID
    raw[46..54].copy_from_slice(&height.to_be_bytes()); // height
    raw
}

fn make_cchain_rlp_block(height: u64) -> Vec<u8> {
    // Minimal RLP-encoded C-Chain block header
    let mut block = Vec::with_capacity(600);
    // RLP list prefix (long)
    block.push(0xf9);
    block.push(0x02);
    block.push(0x00);
    // parent hash (32 bytes)
    block.push(0xa0);
    block.extend_from_slice(&[0u8; 32]);
    // uncle hash (32 bytes)
    block.push(0xa0);
    block.extend_from_slice(&[0u8; 32]);
    // coinbase (20 bytes)
    block.push(0x94);
    block.extend_from_slice(&[0u8; 20]);
    // state root (32 bytes)
    block.push(0xa0);
    block.extend_from_slice(&[0u8; 32]);
    // tx root (32 bytes)
    block.push(0xa0);
    block.extend_from_slice(&[0u8; 32]);
    // receipt root (32 bytes)
    block.push(0xa0);
    block.extend_from_slice(&[0u8; 32]);
    // logs bloom (256 bytes)
    block.push(0xb9);
    block.push(0x01);
    block.push(0x00);
    block.extend_from_slice(&[0u8; 256]);
    // difficulty
    block.push(0x80);
    // number (height)
    block.push(0x88);
    block.extend_from_slice(&height.to_be_bytes());
    // Pad to reach expected length
    while block.len() < 515 {
        block.push(0x80);
    }
    block
}

fn bench_pchain_block_parse(c: &mut Criterion) {
    let parent = [0u8; 32];
    let block = make_banff_std(parent, 1000);

    c.bench_function("pchain_block_parse", |b| {
        b.iter(|| {
            let header = avalanche_rs::block::BlockHeader::parse(
                black_box(&block),
                avalanche_rs::block::Chain::PChain,
            );
            black_box(header);
        })
    });
}

fn bench_cchain_block_parse(c: &mut Criterion) {
    let block = make_cchain_rlp_block(5000);

    c.bench_function("cchain_block_parse", |b| {
        b.iter(|| {
            let header = avalanche_rs::block::BlockHeader::parse(
                black_box(&block),
                avalanche_rs::block::Chain::CChain,
            );
            black_box(header);
        })
    });
}

fn bench_block_id_sha256(c: &mut Criterion) {
    let block = make_banff_std([0xAA; 32], 1000);

    c.bench_function("block_id_sha256", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&block));
            let result = hasher.finalize();
            black_box(result);
        })
    });
}

criterion_group!(
    benches,
    bench_pchain_block_parse,
    bench_cchain_block_parse,
    bench_block_id_sha256
);
criterion_main!(benches);
