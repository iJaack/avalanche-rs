#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz P-Chain block deserialization
    let _ = avalanche_rs::block::BlockHeader::parse(data, avalanche_rs::block::Chain::PChain);

    // Fuzz C-Chain block deserialization
    let _ = avalanche_rs::block::BlockHeader::parse(data, avalanche_rs::block::Chain::CChain);

    // Fuzz parent ID extraction
    let _ = avalanche_rs::block::BlockHeader::extract_parent_id(data);
});
