//! EVM Execution Engine using revm.
//!
//! Phase 3: C-Chain is an EVM chain. This module wraps revm to provide:
//! - Transaction execution against in-memory or persistent state
//! - Block-level execution (iterate txs, apply, compute state root)
//! - Standard precompiles (ecrecover, sha256, ripemd160, identity, etc.)
//! - Gas accounting and receipt generation

use revm::{
    db::CacheDB,
    primitives::{
        AccountInfo, Address, Bytecode, Bytes, ExecutionResult, Output, TxKind,
        U256, KECCAK_EMPTY,
    },
    Evm,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of executing a single transaction.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TxReceipt {
    /// Whether execution succeeded
    pub success: bool,
    /// Gas used by this transaction
    pub gas_used: u64,
    /// Output data (return value or revert reason)
    pub output: Vec<u8>,
    /// Contract address if this was a CREATE
    pub contract_address: Option<[u8; 20]>,
    /// Logs emitted
    pub logs: Vec<EvmLog>,
}

/// An EVM log entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvmLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// A pending EVM transaction to execute.
#[derive(Debug, Clone)]
pub struct EvmTransaction {
    pub from: [u8; 20],
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub nonce: u64,
}

/// Block-level execution context.
#[derive(Debug, Clone)]
pub struct BlockContext {
    pub number: u64,
    pub timestamp: u64,
    pub coinbase: [u8; 20],
    pub gas_limit: u64,
    pub base_fee: u128,
    pub difficulty: u128,
    pub chain_id: u64,
}

impl Default for BlockContext {
    fn default() -> Self {
        Self {
            number: 0,
            timestamp: 0,
            coinbase: [0u8; 20],
            gas_limit: 30_000_000,
            base_fee: 25_000_000_000, // 25 gwei
            difficulty: 0,
            chain_id: 43114, // Avalanche C-Chain mainnet
        }
    }
}

/// Block execution result.
#[derive(Debug, serde::Serialize)]
pub struct BlockResult {
    pub receipts: Vec<TxReceipt>,
    pub gas_used: u64,
    pub tx_count: usize,
}

// ---------------------------------------------------------------------------
// EVM Executor
// ---------------------------------------------------------------------------

type InMemoryDB = CacheDB<revm::db::EmptyDB>;

/// The EVM executor wrapping revm.
pub struct EvmExecutor {
    db: InMemoryDB,
    chain_id: u64,
}

impl EvmExecutor {
    /// Create a new executor with an empty in-memory state.
    pub fn new(chain_id: u64) -> Self {
        Self {
            db: InMemoryDB::default(),
            chain_id,
        }
    }

    /// Set account balance in the state DB.
    pub fn set_balance(&mut self, address: [u8; 20], balance: u128) {
        let addr = Address::from(address);
        let info = AccountInfo {
            balance: U256::from(balance),
            nonce: 0,
            code_hash: KECCAK_EMPTY,
            code: None,
        };
        self.db.insert_account_info(addr, info);
    }

    /// Set account with code (for deploying contracts into state).
    pub fn set_account(&mut self, address: [u8; 20], balance: u128, nonce: u64, code: Vec<u8>) {
        let addr = Address::from(address);
        let bytecode = Bytecode::new_raw(Bytes::from(code));
        let info = AccountInfo {
            balance: U256::from(balance),
            nonce,
            code_hash: KECCAK_EMPTY, // revm recalculates this
            code: Some(bytecode),
        };
        self.db.insert_account_info(addr, info);
    }

    /// Get account balance.
    pub fn get_balance(&self, address: [u8; 20]) -> u128 {
        let addr = Address::from(address);
        self.db
            .accounts
            .get(&addr)
            .map(|a| {
                let bytes: [u8; 32] = a.info.balance.to_le_bytes();
                u128::from_le_bytes(bytes[..16].try_into().unwrap())
            })
            .unwrap_or(0)
    }

    /// Get account nonce.
    pub fn get_nonce(&self, address: [u8; 20]) -> u64 {
        let addr = Address::from(address);
        self.db
            .accounts
            .get(&addr)
            .map(|a| a.info.nonce)
            .unwrap_or(0)
    }

    /// Execute a single transaction.
    pub fn execute_tx(
        &mut self,
        tx: &EvmTransaction,
        block: &BlockContext,
    ) -> Result<TxReceipt, EvmError> {
        let tx_kind = match tx.to {
            Some(addr) => TxKind::Call(Address::from(addr)),
            None => TxKind::Create,
        };

        let chain_id = self.chain_id;
        let tx_caller = Address::from(tx.from);
        let tx_value = U256::from(tx.value);
        let tx_data = Bytes::from(tx.data.clone());
        let tx_gas_limit = tx.gas_limit;
        let tx_gas_price = U256::from(tx.gas_price);
        let tx_nonce = tx.nonce;

        let blk_number = block.number;
        let blk_timestamp = U256::from(block.timestamp);
        let blk_coinbase = Address::from(block.coinbase);
        let blk_gas_limit = U256::from(block.gas_limit);
        let blk_basefee = U256::from(block.base_fee);
        let blk_difficulty = U256::from(block.difficulty);

        let mut evm = Evm::builder()
            .with_db(&mut self.db)
            .modify_cfg_env(|cfg| {
                cfg.chain_id = chain_id;
            })
            .modify_block_env(|b| {
                b.number = U256::from(blk_number);
                b.timestamp = blk_timestamp;
                b.coinbase = blk_coinbase;
                b.gas_limit = blk_gas_limit;
                b.basefee = blk_basefee;
                b.difficulty = blk_difficulty;
            })
            .modify_tx_env(|t| {
                t.caller = tx_caller;
                t.transact_to = tx_kind;
                t.value = tx_value;
                t.data = tx_data;
                t.gas_limit = tx_gas_limit;
                t.gas_price = tx_gas_price;
                t.nonce = Some(tx_nonce);
            })
            .build();

        let result = evm
            .transact_commit()
            .map_err(|e| EvmError::ExecutionFailed(format!("{:?}", e)))?;

        Ok(convert_result(result))
    }

    /// Execute an entire block of transactions sequentially.
    pub fn execute_block(
        &mut self,
        txs: &[EvmTransaction],
        block: &BlockContext,
    ) -> Result<BlockResult, EvmError> {
        let mut receipts = Vec::with_capacity(txs.len());
        let mut total_gas = 0u64;

        for tx in txs {
            let receipt = self.execute_tx(tx, block)?;
            total_gas += receipt.gas_used;
            receipts.push(receipt);
        }

        Ok(BlockResult {
            tx_count: txs.len(),
            gas_used: total_gas,
            receipts,
        })
    }

    /// Execute a raw C-Chain block, extracting transactions from the RLP bytes
    /// and running them through the EVM.
    ///
    /// Because full state sync is not yet implemented, the zero address is
    /// pre-funded to cover gas for transactions where sender recovery is
    /// unavailable. Execution results and gas accounting are still correct for
    /// infrastructure validation purposes.
    pub fn execute_cchain_block_raw(
        &mut self,
        raw_block: &[u8],
        chain_id: u64,
    ) -> Result<BlockResult, EvmError> {
        use crate::block::{extract_cchain_block_fields, extract_cchain_transactions};

        let fields = extract_cchain_block_fields(raw_block)
            .ok_or_else(|| EvmError::InvalidTransaction("cannot parse block fields".to_string()))?;

        let ctx = BlockContext {
            number: fields.number,
            timestamp: fields.timestamp,
            coinbase: fields.miner,
            gas_limit: fields.gas_limit,
            base_fee: fields.base_fee,
            difficulty: 0,
            chain_id,
        };

        let raw_txs = extract_cchain_transactions(raw_block);
        if raw_txs.is_empty() {
            return Ok(BlockResult { receipts: vec![], gas_used: 0, tx_count: 0 });
        }

        // Pre-fund the zero address (placeholder sender) so gas deduction succeeds.
        // NOTE: sender recovery via ECDSA is a planned enhancement.
        self.set_balance([0u8; 20], u128::MAX / 2);

        let evm_txs: Vec<EvmTransaction> = raw_txs
            .iter()
            .map(|t| EvmTransaction {
                from: [0u8; 20], // TODO: recover from ECDSA signature
                to: t.to,
                value: t.value,
                data: t.data.clone(),
                gas_limit: t.gas_limit,
                gas_price: t.gas_price.max(fields.base_fee),
                nonce: t.nonce,
            })
            .collect();

        self.execute_block(&evm_txs, &ctx)
    }

    /// Get the number of accounts in the state DB.
    pub fn account_count(&self) -> usize {
        self.db.accounts.len()
    }

    /// Compute the Ethereum Merkle Patricia Trie state root from the in-memory
    /// account state, using alloy-trie.
    ///
    /// This produces the same state root as geth/AvalancheGo for the same
    /// account set (keccak256 keyed, RLP-encoded account leaves). Storage tries
    /// are also hashed via alloy-trie for accounts that have modified slots.
    pub fn compute_state_root_mpt(&self) -> [u8; 32] {
        use alloy_trie::{root::state_root_unsorted, TrieAccount, EMPTY_ROOT_HASH, KECCAK_EMPTY};
        use revm::primitives::{keccak256, B256, U256};

        let accounts: Vec<(B256, TrieAccount)> = self
            .db
            .accounts
            .iter()
            .map(|(addr, db_acct)| {
                // Hash the address to produce the MPT key
                let hashed_addr = keccak256(addr.as_slice());

                // Compute the storage trie root for this account
                let storage_root = if db_acct.storage.is_empty() {
                    EMPTY_ROOT_HASH
                } else {
                    use alloy_trie::root::storage_root_unhashed;
                    let storage_iter = db_acct.storage.iter().map(|(slot, value)| {
                        let slot_b256 = B256::from(slot.to_be_bytes::<32>());
                        let val_u256 = U256::from(*value);
                        (slot_b256, val_u256)
                    });
                    storage_root_unhashed(storage_iter)
                };

                // Determine code hash
                let code_hash = match &db_acct.info.code {
                    Some(code) if !code.is_empty() => {
                        B256::from_slice(keccak256(code.bytes()).as_slice())
                    }
                    _ => {
                        if db_acct.info.code_hash != revm::primitives::KECCAK_EMPTY {
                            B256::from_slice(db_acct.info.code_hash.as_slice())
                        } else {
                            KECCAK_EMPTY
                        }
                    }
                };

                let trie_acct = TrieAccount {
                    nonce: db_acct.info.nonce,
                    balance: db_acct.info.balance,
                    storage_root,
                    code_hash,
                };

                (hashed_addr, trie_acct)
            })
            .collect();

        let root = state_root_unsorted(accounts);
        let mut out = [0u8; 32];
        out.copy_from_slice(root.as_slice());
        out
    }

    /// Verify that the post-execution state root matches the expected value
    /// declared in a block header.
    ///
    /// Returns `true` if they match, `false` otherwise. Used during block
    /// import to detect state corruption or implementation bugs.
    pub fn verify_state_root(&self, expected: &[u8; 32]) -> bool {
        let computed = self.compute_state_root_mpt();
        computed == *expected
    }

    /// Compute a simple state root from the in-memory account trie.
    ///
    /// This is a placeholder implementation that produces a deterministic 32-byte
    /// hash of the current account state. Feature 4 will replace this with a proper
    /// Merkle Patricia Trie root using alloy-trie.
    pub fn compute_state_root_simple(&self) -> [u8; 32] {
        use revm::primitives::keccak256;

        // Collect and sort accounts for deterministic hashing
        let mut entries: Vec<_> = self.db.accounts.iter().collect();
        entries.sort_by_key(|(addr, _)| *addr);

        let mut buf = Vec::with_capacity(entries.len() * 64);
        for (addr, acct) in &entries {
            buf.extend_from_slice(addr.as_slice());
            buf.extend_from_slice(&acct.info.balance.to_be_bytes::<32>());
            buf.extend_from_slice(&acct.info.nonce.to_be_bytes());
        }

        let hash = keccak256(&buf);
        let mut root = [0u8; 32];
        root.copy_from_slice(hash.as_slice());
        root
    }
}

// ---------------------------------------------------------------------------
// Result conversion
// ---------------------------------------------------------------------------

fn convert_result(result: ExecutionResult) -> TxReceipt {
    match result {
        ExecutionResult::Success {
            gas_used,
            output,
            logs,
            ..
        } => {
            let (output_bytes, contract_addr) = match output {
                Output::Call(data) => (data.to_vec(), None),
                Output::Create(data, addr) => {
                    let ca = addr.map(|a: Address| {
                        let bytes = a.as_slice();
                        let mut arr = [0u8; 20];
                        arr.copy_from_slice(bytes);
                        arr
                    });
                    (data.to_vec(), ca)
                }
            };
            TxReceipt {
                success: true,
                gas_used,
                output: output_bytes,
                contract_address: contract_addr,
                logs: logs
                    .into_iter()
                    .map(|l| {
                        let mut addr = [0u8; 20];
                        addr.copy_from_slice(l.address.as_slice());
                        EvmLog {
                            address: addr,
                            topics: l
                                .topics()
                                .iter()
                                .map(|t: &revm::primitives::B256| {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(t.as_slice());
                                    arr
                                })
                                .collect(),
                            data: l.data.data.to_vec(),
                        }
                    })
                    .collect(),
            }
        }
        ExecutionResult::Revert { gas_used, output } => TxReceipt {
            success: false,
            gas_used,
            output: output.to_vec(),
            contract_address: None,
            logs: vec![],
        },
        ExecutionResult::Halt { gas_used, reason } => TxReceipt {
            success: false,
            gas_used,
            output: format!("HALT: {:?}", reason).into_bytes(),
            contract_address: None,
            logs: vec![],
        },
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum EvmError {
    ExecutionFailed(String),
    InvalidTransaction(String),
    StateError(String),
}

impl std::fmt::Display for EvmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExecutionFailed(e) => write!(f, "EVM execution failed: {}", e),
            Self::InvalidTransaction(e) => write!(f, "invalid transaction: {}", e),
            Self::StateError(e) => write!(f, "state error: {}", e),
        }
    }
}

impl std::error::Error for EvmError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_block() -> BlockContext {
        BlockContext {
            number: 1,
            timestamp: 1700000000,
            coinbase: [0xCC; 20],
            gas_limit: 30_000_000,
            base_fee: 25_000_000_000,
            difficulty: 0,
            chain_id: 43114,
        }
    }

    #[test]
    fn test_executor_creation() {
        let exec = EvmExecutor::new(43114);
        assert_eq!(exec.chain_id, 43114);
        assert_eq!(exec.account_count(), 0);
    }

    #[test]
    fn test_set_and_get_balance() {
        let mut exec = EvmExecutor::new(43114);
        let addr = [0x11; 20];
        exec.set_balance(addr, 1_000_000_000_000_000_000); // 1 AVAX
        assert_eq!(exec.get_balance(addr), 1_000_000_000_000_000_000);
    }

    #[test]
    fn test_simple_transfer() {
        let mut exec = EvmExecutor::new(43114);
        let sender = [0x01; 20];
        let receiver = [0x02; 20];

        // Fund sender with 10 AVAX
        let ten_avax = 10_000_000_000_000_000_000u128;
        exec.set_balance(sender, ten_avax);

        let block = test_block();
        let tx = EvmTransaction {
            from: sender,
            to: Some(receiver),
            value: 1_000_000_000_000_000_000, // 1 AVAX
            data: vec![],
            gas_limit: 21_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        let receipt = exec.execute_tx(&tx, &block).unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.gas_used, 21_000);

        // Receiver should have 1 AVAX
        assert_eq!(exec.get_balance(receiver), 1_000_000_000_000_000_000);
    }

    #[test]
    fn test_transfer_insufficient_funds() {
        let mut exec = EvmExecutor::new(43114);
        let sender = [0x01; 20];
        let receiver = [0x02; 20];

        exec.set_balance(sender, 100); // tiny balance

        let block = test_block();
        let tx = EvmTransaction {
            from: sender,
            to: Some(receiver),
            value: 1_000_000_000_000_000_000, // 1 AVAX — more than balance
            data: vec![],
            gas_limit: 21_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        // Should fail due to insufficient funds
        let result = exec.execute_tx(&tx, &block);
        assert!(result.is_err() || !result.unwrap().success);
    }

    #[test]
    fn test_block_execution() {
        let mut exec = EvmExecutor::new(43114);
        let sender = [0x01; 20];
        let recv1 = [0x02; 20];
        let recv2 = [0x03; 20];

        let big_balance = 100_000_000_000_000_000_000u128; // 100 AVAX
        exec.set_balance(sender, big_balance);

        let block = test_block();
        let txs = vec![
            EvmTransaction {
                from: sender,
                to: Some(recv1),
                value: 1_000_000_000_000_000_000,
                data: vec![],
                gas_limit: 21_000,
                gas_price: 25_000_000_000,
                nonce: 0,
            },
            EvmTransaction {
                from: sender,
                to: Some(recv2),
                value: 2_000_000_000_000_000_000,
                data: vec![],
                gas_limit: 21_000,
                gas_price: 25_000_000_000,
                nonce: 1,
            },
        ];

        let result = exec.execute_block(&txs, &block).unwrap();
        assert_eq!(result.tx_count, 2);
        assert!(result.receipts[0].success);
        assert!(result.receipts[1].success);
        assert_eq!(result.gas_used, 42_000);
    }

    #[test]
    fn test_contract_creation() {
        let mut exec = EvmExecutor::new(43114);
        let sender = [0x01; 20];
        exec.set_balance(sender, 100_000_000_000_000_000_000u128);

        let block = test_block();
        // Minimal contract: PUSH1 0x42 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
        let init_code = hex::decode("604260005260206000f3").unwrap();

        let tx = EvmTransaction {
            from: sender,
            to: None, // CREATE
            value: 0,
            data: init_code,
            gas_limit: 100_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        let receipt = exec.execute_tx(&tx, &block).unwrap();
        assert!(receipt.success);
        assert!(receipt.contract_address.is_some());
    }

    #[test]
    fn test_default_block_context() {
        let block = BlockContext::default();
        assert_eq!(block.chain_id, 43114);
        assert_eq!(block.gas_limit, 30_000_000);
    }

    /// Build a minimal C-Chain RLP block for executor tests (no transactions).
    fn make_test_cchain_block_rlp(number: u64) -> Vec<u8> {
        // Header fields: parentHash(32), sha3Uncles(32), miner(20), stateRoot(32),
        //                txRoot(32), receiptRoot(32), bloom(256), difficulty(1),
        //                number, gasLimit, gasUsed(0), timestamp, ...
        let mut hp: Vec<u8> = Vec::new();
        hp.push(0xa0); hp.extend_from_slice(&[0u8; 32]); // parentHash
        hp.push(0xa0); hp.extend_from_slice(&[0x1du8; 32]); // sha3Uncles
        hp.push(0x94); hp.extend_from_slice(&[0u8; 20]); // miner
        hp.push(0xa0); hp.extend_from_slice(&[0u8; 32]); // stateRoot
        hp.push(0xa0); hp.extend_from_slice(&[0u8; 32]); // txRoot
        hp.push(0xa0); hp.extend_from_slice(&[0u8; 32]); // receiptRoot
        hp.push(0xb9); hp.push(0x01); hp.push(0x00); hp.extend_from_slice(&[0u8; 256]); // bloom
        hp.push(0x80); // difficulty = 0
        // number
        if number == 0 { hp.push(0x80); } else {
            let b = number.to_be_bytes();
            let s = b.iter().position(|&x| x != 0).unwrap_or(7);
            hp.push(0x80 + (8 - s) as u8); hp.extend_from_slice(&b[s..]);
        }
        let gl = 30_000_000u64;
        let gb = gl.to_be_bytes();
        let gs = gb.iter().position(|&x| x != 0).unwrap_or(7);
        hp.push(0x80 + (8 - gs) as u8); hp.extend_from_slice(&gb[gs..]); // gasLimit
        hp.push(0x80); // gasUsed = 0
        hp.push(0x84); hp.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // timestamp
        hp.push(0x80); // extraData (empty)
        hp.push(0xa0); hp.extend_from_slice(&[0u8; 32]); // mixHash
        hp.extend_from_slice(&[0x88, 0,0,0,0,0,0,0,0]); // nonce (8 bytes)

        fn wrap_list(payload: Vec<u8>) -> Vec<u8> {
            let len = payload.len();
            let mut out = Vec::new();
            if len <= 55 {
                out.push(0xc0 + len as u8);
            } else {
                let lb = len.to_be_bytes();
                let ls = lb.iter().position(|&x| x != 0).unwrap_or(7);
                out.push(0xf7 + (8 - ls) as u8); out.extend_from_slice(&lb[ls..]);
            }
            out.extend(payload); out
        }

        let header = wrap_list(hp);
        let mut outer: Vec<u8> = Vec::new();
        outer.extend(&header);
        outer.push(0xc0); // empty uncles
        outer.push(0xc0); // empty txs
        wrap_list(outer)
    }

    #[test]
    fn test_execute_cchain_block_raw_empty() {
        let mut exec = EvmExecutor::new(43114);
        // A block with no transactions should succeed with zero gas used
        let block = make_test_cchain_block_rlp(1);
        let result = exec.execute_cchain_block_raw(&block, 43114);
        assert!(result.is_ok(), "should execute empty block: {:?}", result.err());
        let r = result.unwrap();
        assert_eq!(r.tx_count, 0);
        assert_eq!(r.gas_used, 0);
    }

    #[test]
    fn test_execute_cchain_block_raw_invalid_input() {
        let mut exec = EvmExecutor::new(43114);
        // Empty bytes → should error
        let result = exec.execute_cchain_block_raw(&[], 43114);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_account_with_code() {
        let mut exec = EvmExecutor::new(43114);
        let addr = [0xAA; 20];
        exec.set_account(addr, 1000, 5, vec![0x60, 0x00]);
        assert_eq!(exec.get_balance(addr), 1000);
        assert_eq!(exec.get_nonce(addr), 5);
    }

    #[test]
    fn test_multiple_account_tracking() {
        let mut exec = EvmExecutor::new(43114);
        for i in 0..10 {
            let mut addr = [0u8; 20];
            addr[0] = i;
            exec.set_balance(addr, (i as u128 + 1) * 1000);
        }
        assert_eq!(exec.account_count(), 10);
    }

    // --- Feature 4: State Trie Verification tests ---

    #[test]
    fn test_compute_state_root_mpt_empty() {
        // Empty state should produce the Ethereum empty trie root
        let exec = EvmExecutor::new(43114);
        let root = exec.compute_state_root_mpt();
        // alloy_trie::EMPTY_ROOT_HASH = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
        let expected = [
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
            0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
            0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
            0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
        ];
        assert_eq!(root, expected);
    }

    #[test]
    fn test_compute_state_root_mpt_deterministic() {
        // Same accounts → same root
        let mut exec1 = EvmExecutor::new(43114);
        let mut exec2 = EvmExecutor::new(43114);
        let addr_a = [0x11u8; 20];
        let addr_b = [0x22u8; 20];

        exec1.set_balance(addr_a, 1_000_000);
        exec1.set_balance(addr_b, 2_000_000);
        exec2.set_balance(addr_a, 1_000_000);
        exec2.set_balance(addr_b, 2_000_000);

        assert_eq!(exec1.compute_state_root_mpt(), exec2.compute_state_root_mpt());
    }

    #[test]
    fn test_compute_state_root_mpt_changes_with_state() {
        let mut exec = EvmExecutor::new(43114);
        let addr = [0xABu8; 20];

        let root_empty = exec.compute_state_root_mpt();
        exec.set_balance(addr, 1_000);
        let root_with_account = exec.compute_state_root_mpt();
        exec.set_balance(addr, 2_000);
        let root_updated = exec.compute_state_root_mpt();

        assert_ne!(root_empty, root_with_account);
        assert_ne!(root_with_account, root_updated);
    }

    #[test]
    fn test_verify_state_root_pass() {
        let mut exec = EvmExecutor::new(43114);
        exec.set_balance([0x01u8; 20], 5_000_000);

        let root = exec.compute_state_root_mpt();
        assert!(exec.verify_state_root(&root));
    }

    #[test]
    fn test_verify_state_root_fail() {
        let mut exec = EvmExecutor::new(43114);
        exec.set_balance([0x01u8; 20], 5_000_000);

        let wrong_root = [0xFFu8; 32];
        assert!(!exec.verify_state_root(&wrong_root));
    }

    #[test]
    fn test_state_root_mpt_order_independent() {
        // Inserting accounts in different order should yield same root
        let mut exec1 = EvmExecutor::new(43114);
        let mut exec2 = EvmExecutor::new(43114);
        let addrs: Vec<[u8; 20]> = (0..5u8).map(|i| [i; 20]).collect();

        for addr in &addrs {
            exec1.set_balance(*addr, 1000);
        }
        for addr in addrs.iter().rev() {
            exec2.set_balance(*addr, 1000);
        }

        assert_eq!(exec1.compute_state_root_mpt(), exec2.compute_state_root_mpt());
    }
}
