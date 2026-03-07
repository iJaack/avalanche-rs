#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz JSON-RPC request parsing
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<serde_json::Value>(s);

        // Try to parse as a JSON-RPC request and extract method/params
        if let Ok(req) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = req["method"].as_str();
            let _ = req["params"].as_array();
            let _ = req["id"].as_u64();
        }
    }
});
