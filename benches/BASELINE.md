# Benchmark Baseline

Measured on Mac Mini M4 (Apple Silicon), 2026-03-07.

## Benchmark Suites

| Suite | Benchmarks | Description |
|-------|-----------|-------------|
| `codec_bench` | 4 | JSON roundtrip, hex encode/decode, SHA-256 |
| `consensus_bench` | 3 | Snowball voting, block tracking, validator selection |
| `block_parsing` | 3 | P-Chain/C-Chain block deserialization, block ID hashing |
| `trie_ops` | 3 | MPT insert, lookup, proof generation |
| `p2p_codec` | 5 | Protobuf encode/decode for Ping, Put (4KB), Chits |
| `rpc_handling` | 4 | JSON-RPC parsing, method routing, response formatting |
| `bls_verify` | 4 | BLS keygen, sign, verify, aggregate verify (10 sigs) |
| `bloom_filter` | 3 | Bloom insert, lookup, false positive rate |

## Running

```bash
cargo bench                          # Run all benchmarks
cargo bench --bench bls_verify       # Run specific suite
cargo bench -- "proto_encode"        # Filter by name
```

## Expected Performance Ranges

| Benchmark | Expected Range |
|-----------|---------------|
| `sha256_256b` | 200-500 ns |
| `json_serialize` | 300-800 ns |
| `proto_encode_ping` | 100-400 ns |
| `proto_decode_ping` | 100-400 ns |
| `bls_sign` | 500-2000 µs |
| `bls_verify` | 1-3 ms |
| `bloom_insert_100` | 50-200 µs |
| `rpc_json_parse` | 200-600 ns |
