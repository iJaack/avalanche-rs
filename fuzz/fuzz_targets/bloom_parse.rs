#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz bloom filter parsing from wire format
    // Avalanche bloom filter format: [numHashes(1)][seeds(8*N)][entries...]
    if data.is_empty() {
        return;
    }

    let num_hashes = data[0] as usize;
    let seed_bytes = num_hashes * 8;

    if data.len() < 1 + seed_bytes {
        return;
    }

    // Parse seeds
    let mut seeds = Vec::with_capacity(num_hashes);
    for i in 0..num_hashes {
        let offset = 1 + i * 8;
        if offset + 8 <= data.len() {
            let seed = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
            seeds.push(seed);
        }
    }

    // Parse filter entries
    let entry_offset = 1 + seed_bytes;
    if entry_offset < data.len() {
        let entries = &data[entry_offset..];
        // Verify we can check bits without panicking
        for byte in entries {
            let _ = byte.count_ones();
        }
    }
});
