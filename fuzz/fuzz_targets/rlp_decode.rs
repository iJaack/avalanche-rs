#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz RLP decoding for C-Chain blocks
    // Try to parse as a C-Chain block (RLP-encoded)
    let _ = avalanche_rs::block::BlockHeader::parse(data, avalanche_rs::block::Chain::CChain);

    // Also fuzz the C-Chain field extraction
    let _ = avalanche_rs::block::extract_cchain_block_fields(data);

    // Fuzz transaction extraction
    let _ = avalanche_rs::block::extract_cchain_transactions(data);
});
