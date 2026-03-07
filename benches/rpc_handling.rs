use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_rpc_json_parse(c: &mut Criterion) {
    let request = r#"{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28","latest"],"id":1}"#;

    c.bench_function("rpc_json_parse", |b| {
        b.iter(|| {
            let req: serde_json::Value = serde_json::from_str(black_box(request)).unwrap();
            let method = req["method"].as_str().unwrap();
            black_box(method);
        })
    });
}

fn bench_rpc_method_routing(c: &mut Criterion) {
    let methods = vec![
        "eth_chainId",
        "eth_blockNumber",
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_getCode",
        "eth_call",
        "eth_estimateGas",
        "eth_gasPrice",
        "eth_getBlockByNumber",
        "eth_getLogs",
        "eth_feeHistory",
        "eth_maxPriorityFeePerGas",
        "platform.getCurrentValidators",
        "debug_traceTransaction",
        "info.getNetworkID",
    ];

    c.bench_function("rpc_method_routing_15", |b| {
        b.iter(|| {
            for method in &methods {
                // Simulate method matching (same pattern as main.rs)
                let result = match *method {
                    "eth_chainId" => "chain_id",
                    "eth_blockNumber" => "block_number",
                    "eth_getBalance" => "get_balance",
                    "eth_getTransactionCount" => "get_tx_count",
                    "eth_getCode" => "get_code",
                    "eth_call" => "call",
                    "eth_estimateGas" => "estimate_gas",
                    "eth_gasPrice" => "gas_price",
                    "eth_getBlockByNumber" => "get_block",
                    "eth_getLogs" => "get_logs",
                    "eth_feeHistory" => "fee_history",
                    "eth_maxPriorityFeePerGas" => "max_priority_fee",
                    "platform.getCurrentValidators" => "validators",
                    "debug_traceTransaction" => "trace_tx",
                    "info.getNetworkID" => "network_id",
                    _ => "unknown",
                };
                black_box(result);
            }
        })
    });
}

fn bench_rpc_response_format(c: &mut Criterion) {
    c.bench_function("rpc_response_format", |b| {
        b.iter(|| {
            let result = format!(
                "{{\"jsonrpc\":\"2.0\",\"result\":\"0x{:x}\",\"id\":{}}}",
                black_box(43114u64),
                black_box(1)
            );
            black_box(result);
        })
    });
}

fn bench_rpc_hex_parse(c: &mut Criterion) {
    let hex_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28";

    c.bench_function("rpc_hex_address_parse", |b| {
        b.iter(|| {
            let s = black_box(hex_addr).strip_prefix("0x").unwrap_or(hex_addr);
            let bytes = hex::decode(s).unwrap();
            black_box(bytes);
        })
    });
}

criterion_group!(
    benches,
    bench_rpc_json_parse,
    bench_rpc_method_routing,
    bench_rpc_response_format,
    bench_rpc_hex_parse
);
criterion_main!(benches);
