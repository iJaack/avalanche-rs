#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    // Fuzz protobuf message decoding — should never panic
    let _ = avalanche_rs::proto::pb::Message::decode(data);

    // Also try with length prefix (Avalanche wire format)
    if data.len() >= 4 {
        let _ = avalanche_rs::network::NetworkMessage::decode_proto(data);
    }

    // Try decompression path
    let _ = avalanche_rs::proto::decompress_message(data);
});
