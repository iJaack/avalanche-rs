// ============================================================================
// Avalanche Rust Client - Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use avalanche_rs::types::*;

    // ========================================================================
    // TYPES MODULE TESTS
    // ========================================================================

    mod types_tests {
        use super::*;

        #[test]
        fn test_id_creation() {
            let id = ID::new([0u8; 32]);
            assert_eq!(id.as_bytes(), &[0u8; 32]);
        }

        #[test]
        fn test_id_from_vec() {
            let v = vec![42u8; 32];
            let id = ID::from_vec(v).unwrap();
            assert_eq!(id.as_bytes()[0], 42);
        }

        #[test]
        fn test_id_from_vec_wrong_length() {
            let v = vec![0u8; 16];
            assert!(ID::from_vec(v).is_err());
        }

        #[test]
        fn test_id_from_str_cb58() {
            let id = ID::from_str("11111111111111111111111111111111LpoYY").unwrap();
            assert_eq!(id.as_bytes(), &[0u8; 32]);
        }

        #[test]
        fn test_id_hex_roundtrip() {
            let mut arr = [0u8; 32];
            arr[0] = 0xAB;
            arr[31] = 0xCD;
            let id = ID::new(arr);
            let hex = id.to_hex();
            let recovered = ID::from_hex(&hex).unwrap();
            assert_eq!(id, recovered);
        }

        #[test]
        fn test_id_from_bytes() {
            let bytes = [7u8; 32];
            let id = ID::from_bytes(&bytes).unwrap();
            assert_eq!(id.as_bytes(), &[7u8; 32]);
        }

        #[test]
        fn test_id_hash_deterministic() {
            let h1 = ID::hash(b"test data");
            let h2 = ID::hash(b"test data");
            assert_eq!(h1, h2);
        }

        #[test]
        fn test_id_hash_different() {
            assert_ne!(ID::hash(b"hello"), ID::hash(b"world"));
        }

        #[test]
        fn test_id_hashmap_key() {
            let id1 = ID::new([1u8; 32]);
            let id2 = ID::new([1u8; 32]);
            let id3 = ID::new([2u8; 32]);

            let mut map = HashMap::new();
            map.insert(id1, "first");
            map.insert(id2, "second");
            map.insert(id3, "third");
            assert_eq!(map.len(), 2);
        }

        #[test]
        fn test_typed_ids() {
            let node = NodeID(ID::new([1u8; 32]));
            let block = BlockID(ID::new([1u8; 32]));
            assert_eq!(node.0, block.0);
        }

        #[test]
        fn test_block_creation() {
            let block = Block::new(
                BlockID(ID::hash(b"block1")),
                BlockID(ID::new([0u8; 32])),
                1,
                1000,
                vec![],
                ID::new([0u8; 32]),
            )
            .unwrap();
            assert_eq!(block.height, 1);
            assert_eq!(block.tx_count(), 0);
        }

        #[test]
        fn test_block_json_roundtrip() {
            let block = Block::new(
                BlockID(ID::hash(b"test")),
                BlockID(ID::new([0u8; 32])),
                5,
                500,
                vec![],
                ID::new([0u8; 32]),
            )
            .unwrap();
            let json = serde_json::to_string(&block).unwrap();
            let recovered: Block = serde_json::from_str(&json).unwrap();
            assert_eq!(block, recovered);
        }

        #[test]
        fn test_transaction_x_chain() {
            let tx = Transaction::XChain {
                id: TransactionID(ID::hash(b"tx1")),
                inputs: vec![],
                outputs: vec![],
            };
            assert_eq!(tx.chain_type(), "X");
        }

        #[test]
        fn test_transaction_c_chain() {
            let tx = Transaction::CChain {
                id: TransactionID(ID::hash(b"tx2")),
                nonce: 0,
                gas_price: 25_000_000_000,
                gas_limit: 21_000,
                to: Some("0x1234".to_string()),
                value: 1_000_000_000,
                data: vec![],
            };
            assert_eq!(tx.chain_type(), "C");
        }

        #[test]
        fn test_utxo_creation() {
            let utxo = UTXO::new(
                TransactionID(ID::hash(b"utxo_tx")),
                0,
                ID::new([0u8; 32]),
                1_000_000_000,
                "X-avax1abc".to_string(),
            );
            assert_eq!(utxo.amount, 1_000_000_000);
            assert!(!utxo.locked);
        }

        #[test]
        fn test_utxo_lock() {
            let utxo = UTXO::new(
                TransactionID(ID::hash(b"lock")),
                0,
                ID::new([0u8; 32]),
                500,
                "owner".to_string(),
            )
            .lock();
            assert!(utxo.locked);
        }

        #[test]
        fn test_utxo_json_roundtrip() {
            let utxo = UTXO::new(
                TransactionID(ID::hash(b"json")),
                1,
                ID::new([0u8; 32]),
                999,
                "owner".to_string(),
            );
            let json = serde_json::to_string(&utxo).unwrap();
            let recovered: UTXO = serde_json::from_str(&json).unwrap();
            assert_eq!(utxo, recovered);
        }

        #[test]
        fn test_error_display() {
            let err = AvalancheError::InvalidHex("bad".to_string());
            assert!(format!("{}", err).contains("bad"));
        }
    }

    // ========================================================================
    // CODEC TESTS
    // ========================================================================

    mod codec_tests {
        use super::*;

        #[test]
        fn test_json_codec_roundtrip() {
            let block = Block::new(
                BlockID(ID::hash(b"codec")),
                BlockID(ID::new([0u8; 32])),
                10,
                100,
                vec![],
                ID::new([0u8; 32]),
            )
            .unwrap();
            let encoded = avalanche_rs::codec::encode(&block).unwrap();
            let decoded: Block = avalanche_rs::codec::decode(&encoded).unwrap();
            assert_eq!(block, decoded);
        }

        #[test]
        fn test_json_codec_invalid() {
            let result = avalanche_rs::codec::decode::<Block>(b"not json");
            assert!(result.is_err());
        }
    }

    // ========================================================================
    // RPC CLIENT TESTS
    // ========================================================================

    #[cfg(feature = "rpc")]
    mod rpc_tests {
        use avalanche_rs::rpc::*;

        #[test]
        fn test_rpc_client_creation() {
            assert!(RpcClient::new("http://localhost:9650").is_ok());
        }

        #[test]
        fn test_request_builder() {
            let req = RequestBuilder::new("test.method")
                .param(serde_json::json!({"key": "value"}))
                .build(1);
            assert_eq!(req.method, "test.method");
            assert_eq!(req.id, 1);
            assert_eq!(req.params.len(), 1);
        }

        #[test]
        fn test_error_display() {
            let err = RpcClientError::TimeoutError;
            assert_eq!(format!("{}", err), "Request timeout");
        }
    }

    // ========================================================================
    // CONSENSUS TESTS
    // ========================================================================

    #[cfg(feature = "p2p")]
    mod consensus_tests {
        use super::*;
        use avalanche_rs::network::*;

        #[test]
        fn test_snowball_finality() {
            let genesis = BlockId::zero();
            let block = BlockId::from_bytes(&[1u8; 32]).unwrap();
            let mut sb = SnowballInstance::new(genesis.clone(), 3);

            // Simulate 3 consecutive alpha-majority polls for `block`
            let mut votes = HashMap::new();
            votes.insert(block.clone(), 15u64); // alpha threshold met

            sb.record_poll(&votes, 15);
            assert!(!sb.is_finalized());
            sb.record_poll(&votes, 15);
            assert!(!sb.is_finalized());
            sb.record_poll(&votes, 15);
            assert!(sb.is_finalized());
        }

        #[test]
        fn test_snowman_block_lifecycle() {
            let genesis = BlockId::from_bytes(&[0u8; 32]).unwrap();
            let params = SnowballParams {
                k: 20,
                alpha: 15,
                beta_virtuous: 3,
                beta_rogue: 5,
                max_outstanding: 10,
                max_rounds: 500,
            };
            let mut engine = SnowmanConsensus::new(params, genesis.clone());

            let block1_id = BlockId::from_bytes(&[1u8; 32]).unwrap();
            let block1 = ConsensusBlock::new(block1_id.clone(), genesis.clone(), 1, 100, vec![]);

            assert!(engine.add_block(block1).is_ok());
            assert_eq!(engine.processing_count(), 1);
        }

        #[test]
        fn test_snowman_missing_parent() {
            let genesis = BlockId::from_bytes(&[0u8; 32]).unwrap();
            let params = SnowballParams::default();
            let mut engine = SnowmanConsensus::new(params, genesis.clone());

            let orphan_parent = BlockId::from_bytes(&[99u8; 32]).unwrap();
            let orphan_id = BlockId::from_bytes(&[100u8; 32]).unwrap();
            let orphan = ConsensusBlock::new(orphan_id, orphan_parent, 5, 500, vec![]);

            assert!(engine.add_block(orphan).is_err());
        }
    }

    // ========================================================================
    // PERFORMANCE TESTS
    // ========================================================================

    mod perf_tests {
        use super::*;
        use std::time::Instant;

        #[test]
        fn test_id_creation_perf() {
            let start = Instant::now();
            for i in 0u32..10_000 {
                let mut arr = [0u8; 32];
                arr[..4].copy_from_slice(&i.to_be_bytes());
                let _ = ID::new(arr);
            }
            assert!(start.elapsed().as_millis() < 50, "ID creation too slow");
        }

        #[test]
        fn test_hash_perf() {
            let start = Instant::now();
            for i in 0u32..10_000 {
                let _ = ID::hash(&i.to_be_bytes());
            }
            assert!(start.elapsed().as_millis() < 100, "Hashing too slow");
        }

        #[test]
        fn test_json_roundtrip_perf() {
            let block = Block::new(
                BlockID(ID::hash(b"perf")),
                BlockID(ID::new([0u8; 32])),
                100,
                1000,
                vec![],
                ID::new([0u8; 32]),
            )
            .unwrap();

            let start = Instant::now();
            for _ in 0..1_000 {
                let json = serde_json::to_string(&block).unwrap();
                let _: Block = serde_json::from_str(&json).unwrap();
            }
            assert!(start.elapsed().as_millis() < 200, "JSON roundtrip too slow");
        }
    }

    // ========================================================================
    // STRESS TESTS
    // ========================================================================

    mod stress_tests {
        use super::*;

        #[test]
        fn test_1000_block_chain() {
            let mut parent = BlockID(ID::new([0u8; 32]));
            let mut blocks = Vec::with_capacity(1000);

            for i in 1u64..=1000 {
                let id = BlockID(ID::hash(&i.to_be_bytes()));
                let block = Block::new(id, parent, i, i * 10, vec![], ID::new([0u8; 32])).unwrap();
                parent = block.id;
                blocks.push(block);
            }
            assert_eq!(blocks.len(), 1000);
            assert_eq!(blocks.last().unwrap().height, 1000);
        }

        #[test]
        fn test_10k_ids_in_hashmap() {
            let mut map = HashMap::with_capacity(10_000);
            for i in 0u32..10_000 {
                map.insert(ID::hash(&i.to_be_bytes()), i);
            }
            assert_eq!(map.len(), 10_000);
        }

        #[cfg(feature = "p2p")]
        #[test]
        fn test_50_peers() {
            use avalanche_rs::network::*;

            let config = NetworkConfig::default();
            let mut local_bytes = [0u8; 20]; // NodeId is 20 bytes
            local_bytes[19] = 0xFF;
            let local = NodeId::from_bytes(&local_bytes).unwrap();
            let mut pm = PeerManager::new(config, local);

            for i in 1u8..=50 {
                let mut id_bytes = [0u8; 20];
                id_bytes[0] = i;
                let node_id = NodeId::from_bytes(&id_bytes).unwrap();
                let addr = format!("127.0.0.{}:9651", i).parse().unwrap();
                let mut peer = Peer::new(node_id, addr);
                peer.state = PeerState::Connected;
                let _ = pm.add_peer(peer);
            }
            assert_eq!(pm.connected_count(), 50);
        }
    }

    // ========================================================================
    // MAINNET CONFIGURATION TESTS (Feature 5)
    // ========================================================================

    mod mainnet_tests {
        /// Mainnet C-Chain CB58 ID (2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5).
        /// Verify it decodes to a valid 32-byte array.
        #[test]
        fn test_mainnet_cchain_id_decodes() {
            let cb58 = "2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5";
            let decoded = bs58::decode(cb58).into_vec().expect("valid base58");
            // CB58 = base58(payload[32] + checksum[4])
            assert!(decoded.len() >= 36, "decoded too short: {}", decoded.len());
            let id: [u8; 32] = decoded[..32].try_into().expect("32 bytes");
            // Must be non-zero
            assert!(
                id.iter().any(|&b| b != 0),
                "C-Chain ID should not be all zeros"
            );
        }

        /// Fuji C-Chain CB58 ID (yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp).
        #[test]
        fn test_fuji_cchain_id_decodes() {
            let cb58 = "yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp";
            let decoded = bs58::decode(cb58).into_vec().expect("valid base58");
            assert!(decoded.len() >= 36);
            let id: [u8; 32] = decoded[..32].try_into().expect("32 bytes");
            assert!(id.iter().any(|&b| b != 0));
        }

        /// Mainnet and Fuji C-Chain IDs must be distinct.
        #[test]
        fn test_mainnet_and_fuji_cchain_ids_differ() {
            let mainnet_id: [u8; 32] = {
                let d = bs58::decode("2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5")
                    .into_vec()
                    .unwrap();
                d[..32].try_into().unwrap()
            };
            let fuji_id: [u8; 32] = {
                let d = bs58::decode("yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp")
                    .into_vec()
                    .unwrap();
                d[..32].try_into().unwrap()
            };
            assert_ne!(mainnet_id, fuji_id);
        }

        /// Verify the mainnet EVM executor initializes without panicking.
        #[test]
        fn test_mainnet_evm_executor_init() {
            use avalanche_rs::evm::EvmExecutor;
            let exec = EvmExecutor::new(43114);
            // Chain initializes with zero accounts
            assert_eq!(exec.account_count(), 0);
        }

        /// Verify the Fuji EVM executor initializes without panicking.
        #[test]
        fn test_fuji_evm_executor_init() {
            use avalanche_rs::evm::EvmExecutor;
            let exec = EvmExecutor::new(43113);
            assert_eq!(exec.account_count(), 0);
        }

        /// Verify that state root computation works with mainnet chain ID.
        #[test]
        fn test_mainnet_state_root_not_empty() {
            use avalanche_rs::evm::EvmExecutor;
            let mut exec = EvmExecutor::new(43114); // mainnet
            exec.set_balance([0x01u8; 20], 1_000_000_000_000_000_000u128); // 1 AVAX

            let root = exec.compute_state_root_mpt();
            // Should produce the empty-trie EMPTY_ROOT_HASH modified by the account
            let empty_trie = [
                0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
                0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
                0xe3, 0x63, 0xb4, 0x21,
            ];
            assert_ne!(
                root, empty_trie,
                "state root with accounts should differ from empty trie"
            );
        }

        /// Simulate the network_id selection logic used in main() for cchain_id.
        #[test]
        fn test_network_id_selects_correct_cchain_cb58() {
            let for_network = |network_id: u32| -> [u8; 32] {
                let cb58 = match network_id {
                    1 => "2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5",
                    _ => "yH8D7ThNJkxmtkuv2jgBa4P1Rn3Qpr4pPr7QYNfcdoS6k6HWp",
                };
                let decoded = bs58::decode(cb58).into_vec().unwrap();
                decoded[..32].try_into().unwrap()
            };

            let mainnet = for_network(1);
            let fuji = for_network(5);
            let unknown = for_network(99);

            assert_ne!(mainnet, fuji);
            assert_eq!(fuji, unknown, "unknown networks fall back to Fuji ID");
        }
    }
}
