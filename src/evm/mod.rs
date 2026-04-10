//! EVM Execution Engine using revm.
//!
//! Phase 3: C-Chain is an EVM chain. This module wraps revm to provide:
//! - Transaction execution against in-memory or persistent state
//! - Block-level execution (iterate txs, apply, compute state root)
//! - Standard precompiles (ecrecover, sha256, ripemd160, identity, etc.)
//! - Gas accounting and receipt generation

use alloy_primitives::keccak256;
use revm::{
    db::CacheDB,
    inspector_handle_register,
    primitives::{
        AccessListItem, AccountInfo, Address, Bytecode, Bytes, ExecutionResult, Output, TxKind,
        B256, KECCAK_EMPTY, U256,
    },
    Database, Evm, EvmContext, Inspector, JournalEntry,
};
use std::collections::{BTreeMap, BTreeSet};

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
    pub state_root: [u8; 32],
}

/// Result of `eth_createAccessList` style access list generation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccessListResult {
    #[serde(rename = "accessList")]
    pub access_list: Vec<crate::tx::AccessListEntry>,
    #[serde(rename = "gasUsed")]
    pub gas_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of `eth_getProof` for a single storage slot.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StorageProofResult {
    pub key: String,
    pub value: String,
    pub proof: Vec<String>,
}

/// Result of `eth_getProof` for an account and optional storage keys.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountProofResult {
    pub address: String,
    #[serde(rename = "accountProof")]
    pub account_proof: Vec<String>,
    pub balance: String,
    #[serde(rename = "codeHash")]
    pub code_hash: String,
    pub nonce: String,
    #[serde(rename = "storageHash")]
    pub storage_hash: String,
    #[serde(rename = "storageProof")]
    pub storage_proof: Vec<StorageProofResult>,
}

#[derive(Debug, Default, Clone)]
struct AccessListInspector {
    accesses: BTreeMap<[u8; 20], BTreeSet<[u8; 32]>>,
}

impl AccessListInspector {
    fn record_account(&mut self, address: Address) {
        let mut raw = [0u8; 20];
        raw.copy_from_slice(address.as_slice());
        self.accesses.entry(raw).or_default();
    }

    fn record_storage(&mut self, address: Address, key: U256) {
        let mut raw = [0u8; 20];
        raw.copy_from_slice(address.as_slice());
        self.accesses
            .entry(raw)
            .or_default()
            .insert(key.to_be_bytes::<32>());
    }

    fn collect<DB: Database>(&mut self, context: &EvmContext<DB>) {
        for journal in &context.journaled_state.journal {
            for entry in journal {
                match entry {
                    JournalEntry::AccountWarmed { address } => self.record_account(*address),
                    JournalEntry::StorageWarmed { address, key } => {
                        self.record_storage(*address, *key)
                    }
                    _ => {}
                }
            }
        }
    }

    fn into_access_list(self) -> Vec<crate::tx::AccessListEntry> {
        self.accesses
            .into_iter()
            .map(|(address, storage_keys)| crate::tx::AccessListEntry {
                address,
                storage_keys: storage_keys.into_iter().collect(),
            })
            .collect()
    }
}

impl<DB: Database> Inspector<DB> for AccessListInspector {
    fn step_end(
        &mut self,
        _interp: &mut revm::interpreter::Interpreter,
        context: &mut EvmContext<DB>,
    ) {
        self.collect(context);
    }

    fn log(
        &mut self,
        _interp: &mut revm::interpreter::Interpreter,
        context: &mut EvmContext<DB>,
        _log: &revm::primitives::Log,
    ) {
        self.collect(context);
    }

    fn call_end(
        &mut self,
        context: &mut EvmContext<DB>,
        _inputs: &revm::interpreter::CallInputs,
        outcome: revm::interpreter::CallOutcome,
    ) -> revm::interpreter::CallOutcome {
        self.collect(context);
        outcome
    }

    fn create_end(
        &mut self,
        context: &mut EvmContext<DB>,
        _inputs: &revm::interpreter::CreateInputs,
        outcome: revm::interpreter::CreateOutcome,
    ) -> revm::interpreter::CreateOutcome {
        self.collect(context);
        outcome
    }

    fn eofcreate_end(
        &mut self,
        context: &mut EvmContext<DB>,
        _inputs: &revm::interpreter::EOFCreateInputs,
        outcome: revm::interpreter::CreateOutcome,
    ) -> revm::interpreter::CreateOutcome {
        self.collect(context);
        outcome
    }
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

pub struct ArchivedAccountDiff {
    pub address: [u8; 20],
    pub state: crate::db::AccountState,
    pub code: Option<Vec<u8>>,
    pub storage: Vec<([u8; 32], [u8; 32])>,
}

impl EvmExecutor {
    fn account_snapshot_from_db_account(
        account: &revm::db::DbAccount,
    ) -> (crate::db::AccountState, Option<Vec<u8>>) {
        use alloy_trie::{root::storage_root_unhashed, EMPTY_ROOT_HASH};

        let storage_root = if account.storage.is_empty() {
            *EMPTY_ROOT_HASH.as_ref()
        } else {
            let storage_iter = account
                .storage
                .iter()
                .map(|(slot, value)| (B256::from(slot.to_be_bytes::<32>()), *value));
            let root = storage_root_unhashed(storage_iter);
            let mut out = [0u8; 32];
            out.copy_from_slice(root.as_slice());
            out
        };

        let code_hash = match &account.info.code {
            Some(code) if !code.is_empty() => {
                let mut out = [0u8; 32];
                out.copy_from_slice(keccak256(code.bytes()).as_slice());
                out
            }
            _ if account.info.code_hash != KECCAK_EMPTY => {
                let mut out = [0u8; 32];
                out.copy_from_slice(account.info.code_hash.as_slice());
                out
            }
            _ => {
                let mut out = [0u8; 32];
                out.copy_from_slice(KECCAK_EMPTY.as_slice());
                out
            }
        };

        let balance_bytes = account.info.balance.to_le_bytes::<32>();
        (
            crate::db::AccountState {
                nonce: account.info.nonce,
                balance: u128::from_le_bytes(balance_bytes[..16].try_into().unwrap()),
                storage_root,
                code_hash,
            },
            account.info.code.as_ref().map(|code| code.bytes().to_vec()),
        )
    }

    /// Create a new executor with an empty in-memory state.
    pub fn new(chain_id: u64) -> Self {
        Self {
            db: InMemoryDB::default(),
            chain_id,
        }
    }

    /// Clone the executor state for read-only simulations such as tracing.
    pub fn snapshot(&self) -> Self {
        Self {
            db: self.db.clone(),
            chain_id: self.chain_id,
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

    /// Set a storage slot in the state DB.
    pub fn set_storage(&mut self, address: [u8; 20], slot: [u8; 32], value: [u8; 32]) {
        let addr = Address::from(address);
        let account = self.db.accounts.entry(addr).or_default();
        account
            .storage
            .insert(U256::from_be_bytes(slot), U256::from_be_bytes(value));
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

    /// Get account code bytes.
    pub fn get_code(&self, address: [u8; 20]) -> Vec<u8> {
        let addr = Address::from(address);
        self.db
            .accounts
            .get(&addr)
            .and_then(|a| a.info.code.as_ref())
            .map(|c| c.bytes().to_vec())
            .unwrap_or_default()
    }

    /// Get storage value at a slot for an account.
    pub fn get_storage_at(&self, address: [u8; 20], slot: [u8; 32]) -> [u8; 32] {
        let addr = Address::from(address);
        let slot_u256 = U256::from_be_bytes(slot);
        self.db
            .accounts
            .get(&addr)
            .and_then(|a| a.storage.get(&slot_u256))
            .map(|v| v.to_be_bytes())
            .unwrap_or([0u8; 32])
    }

    /// Export the current account state map in a portable form.
    pub fn archived_account_states(&self) -> BTreeMap<[u8; 20], crate::db::AccountState> {
        self.db
            .accounts
            .iter()
            .map(|(addr, account)| {
                let mut raw = [0u8; 20];
                raw.copy_from_slice(addr.as_slice());
                (raw, Self::account_snapshot_from_db_account(account).0)
            })
            .collect()
    }

    /// Return changed account snapshots, including code bytes and changed storage slots.
    pub fn changed_account_archive_diffs_since(&self, previous: &Self) -> Vec<ArchivedAccountDiff> {
        let current = self
            .db
            .accounts
            .iter()
            .map(|(addr, account)| {
                let mut raw = [0u8; 20];
                raw.copy_from_slice(addr.as_slice());
                let (state, code) = Self::account_snapshot_from_db_account(account);
                (
                    raw,
                    (
                        state,
                        code,
                        account
                            .storage
                            .iter()
                            .map(|(slot, value)| (slot.to_be_bytes::<32>(), value.to_be_bytes()))
                            .collect::<BTreeMap<_, _>>(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let previous_states = previous.archived_account_states();
        let addresses = current
            .keys()
            .chain(previous_states.keys())
            .copied()
            .collect::<BTreeSet<_>>();

        addresses
            .into_iter()
            .filter_map(|address| {
                let (current_state, code, current_storage) = current
                    .get(&address)
                    .cloned()
                    .unwrap_or((crate::db::AccountState::default(), None, BTreeMap::new()));
                if previous_states.get(&address) == Some(&current_state) {
                    None
                } else {
                    let previous_storage = previous
                        .db
                        .accounts
                        .get(&Address::from(address))
                        .map(|account| {
                            account
                                .storage
                                .iter()
                                .map(|(slot, value)| {
                                    (slot.to_be_bytes::<32>(), value.to_be_bytes())
                                })
                                .collect::<BTreeMap<_, _>>()
                        })
                        .unwrap_or_default();
                    let changed_slots = current_storage
                        .keys()
                        .chain(previous_storage.keys())
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .filter_map(|slot| {
                            let current_value =
                                current_storage.get(&slot).copied().unwrap_or([0u8; 32]);
                            if previous_storage.get(&slot).copied() == Some(current_value) {
                                None
                            } else {
                                Some((slot, current_value))
                            }
                        })
                        .collect::<Vec<_>>();
                    Some(ArchivedAccountDiff {
                        address,
                        state: current_state,
                        code,
                        storage: changed_slots,
                    })
                }
            })
            .collect()
    }

    /// Execute a call without committing state changes (eth_call).
    pub fn execute_call(
        &self,
        tx: &EvmTransaction,
        block: &BlockContext,
    ) -> Result<Vec<u8>, EvmError> {
        let mut db_clone = self.db.clone();
        let tx_kind = match tx.to {
            Some(addr) => TxKind::Call(Address::from(addr)),
            None => TxKind::Create,
        };

        let chain_id = if block.chain_id == 0 {
            self.chain_id
        } else {
            block.chain_id
        };
        let mut evm = Evm::builder()
            .with_db(&mut db_clone)
            .modify_cfg_env(|cfg| {
                cfg.chain_id = chain_id;
            })
            .modify_block_env(|b| {
                b.number = U256::from(block.number);
                b.timestamp = U256::from(block.timestamp);
                b.coinbase = Address::from(block.coinbase);
                b.gas_limit = U256::from(block.gas_limit);
                b.basefee = U256::from(block.base_fee);
            })
            .modify_tx_env(|t| {
                t.caller = Address::from(tx.from);
                t.transact_to = tx_kind;
                t.value = U256::from(tx.value);
                t.data = Bytes::from(tx.data.clone());
                t.gas_limit = tx.gas_limit;
                t.gas_price = U256::from(tx.gas_price);
                t.nonce = Some(tx.nonce);
            })
            .build();

        let result = evm
            .transact_commit()
            .map_err(|e| EvmError::ExecutionFailed(format!("{:?}", e)))?;

        match result {
            ExecutionResult::Success { output, .. } => match output {
                Output::Call(data) => Ok(data.to_vec()),
                Output::Create(data, _) => Ok(data.to_vec()),
            },
            ExecutionResult::Revert { output, .. } => Err(EvmError::ExecutionFailed(format!(
                "revert: 0x{}",
                hex::encode(&output)
            ))),
            ExecutionResult::Halt { reason, .. } => {
                Err(EvmError::ExecutionFailed(format!("halt: {:?}", reason)))
            }
        }
    }

    /// Estimate gas for a transaction (eth_estimateGas).
    pub fn estimate_gas(&self, tx: &EvmTransaction, block: &BlockContext) -> Result<u64, EvmError> {
        let mut db_clone = self.db.clone();
        let tx_kind = match tx.to {
            Some(addr) => TxKind::Call(Address::from(addr)),
            None => TxKind::Create,
        };

        let chain_id = if block.chain_id == 0 {
            self.chain_id
        } else {
            block.chain_id
        };
        let mut evm = Evm::builder()
            .with_db(&mut db_clone)
            .modify_cfg_env(|cfg| {
                cfg.chain_id = chain_id;
            })
            .modify_block_env(|b| {
                b.number = U256::from(block.number);
                b.timestamp = U256::from(block.timestamp);
                b.coinbase = Address::from(block.coinbase);
                b.gas_limit = U256::from(block.gas_limit);
                b.basefee = U256::from(block.base_fee);
            })
            .modify_tx_env(|t| {
                t.caller = Address::from(tx.from);
                t.transact_to = tx_kind;
                t.value = U256::from(tx.value);
                t.data = Bytes::from(tx.data.clone());
                t.gas_limit = block.gas_limit; // use block gas limit for estimation
                t.gas_price = U256::from(tx.gas_price);
                t.nonce = Some(tx.nonce);
            })
            .build();

        let result = evm
            .transact_commit()
            .map_err(|e| EvmError::ExecutionFailed(format!("{:?}", e)))?;

        match result {
            ExecutionResult::Success { gas_used, .. } => Ok(gas_used),
            ExecutionResult::Revert { gas_used, .. } => Ok(gas_used),
            ExecutionResult::Halt { gas_used, .. } => Ok(gas_used),
        }
    }

    /// Generate an EIP-2930 access list for a transaction by tracing warmed
    /// accounts and storage slots during execution.
    pub fn create_access_list(
        &self,
        tx: &EvmTransaction,
        block: &BlockContext,
        initial_access_list: &[crate::tx::AccessListEntry],
    ) -> Result<AccessListResult, EvmError> {
        let mut db_clone = self.db.clone();
        let tx_kind = match tx.to {
            Some(addr) => TxKind::Call(Address::from(addr)),
            None => TxKind::Create,
        };

        let chain_id = if block.chain_id == 0 {
            self.chain_id
        } else {
            block.chain_id
        };
        let initial_revm_access_list = initial_access_list
            .iter()
            .map(|entry| AccessListItem {
                address: Address::from(entry.address),
                storage_keys: entry
                    .storage_keys
                    .iter()
                    .map(|key| B256::from_slice(key))
                    .collect(),
            })
            .collect::<Vec<_>>();

        let mut evm = Evm::builder()
            .with_db(&mut db_clone)
            .with_external_context(AccessListInspector::default())
            .append_handler_register(inspector_handle_register)
            .modify_cfg_env(|cfg| {
                cfg.chain_id = chain_id;
            })
            .modify_block_env(|b| {
                b.number = U256::from(block.number);
                b.timestamp = U256::from(block.timestamp);
                b.coinbase = Address::from(block.coinbase);
                b.gas_limit = U256::from(block.gas_limit);
                b.basefee = U256::from(block.base_fee);
            })
            .modify_tx_env(|t| {
                t.caller = Address::from(tx.from);
                t.transact_to = tx_kind;
                t.value = U256::from(tx.value);
                t.data = Bytes::from(tx.data.clone());
                t.gas_limit = tx.gas_limit;
                t.gas_price = U256::from(tx.gas_price);
                t.nonce = Some(tx.nonce);
                t.access_list = initial_revm_access_list;
            })
            .build();

        let result = evm
            .transact_commit()
            .map_err(|e| EvmError::ExecutionFailed(format!("{:?}", e)))?;

        let (gas_used, error) = match result {
            ExecutionResult::Success { gas_used, .. } => (gas_used, None),
            ExecutionResult::Revert { gas_used, .. } => {
                (gas_used, Some("execution reverted".to_string()))
            }
            ExecutionResult::Halt { gas_used, reason } => (gas_used, Some(format!("{:?}", reason))),
        };

        let inspector = evm.into_context().external;
        let mut merged = BTreeMap::<[u8; 20], BTreeSet<[u8; 32]>>::new();
        for entry in initial_access_list {
            merged
                .entry(entry.address)
                .or_default()
                .extend(entry.storage_keys.iter().copied());
        }
        for entry in inspector.into_access_list() {
            merged
                .entry(entry.address)
                .or_default()
                .extend(entry.storage_keys);
        }
        let explicit_addresses = initial_access_list
            .iter()
            .map(|entry| entry.address)
            .collect::<BTreeSet<_>>();
        let mut always_warm = BTreeSet::new();
        always_warm.insert(tx.from);
        always_warm.insert(block.coinbase);
        if let Some(to) = tx.to {
            always_warm.insert(to);
        }
        for precompile in 1u8..=9 {
            let mut address = [0u8; 20];
            address[19] = precompile;
            always_warm.insert(address);
        }

        Ok(AccessListResult {
            access_list: merged
                .into_iter()
                .filter_map(|(address, storage_keys)| {
                    if storage_keys.is_empty()
                        && always_warm.contains(&address)
                        && !explicit_addresses.contains(&address)
                    {
                        return None;
                    }
                    Some(crate::tx::AccessListEntry {
                        address,
                        storage_keys: storage_keys.into_iter().collect(),
                    })
                })
                .collect(),
            gas_used,
            error,
        })
    }

    /// Execute a transaction with a custom revm inspector attached.
    pub fn inspect_tx<INSP>(
        &mut self,
        tx: &EvmTransaction,
        block: &BlockContext,
        inspector: INSP,
    ) -> Result<(TxReceipt, INSP), EvmError>
    where
        INSP: for<'a> Inspector<&'a mut InMemoryDB>,
    {
        let tx_kind = match tx.to {
            Some(addr) => TxKind::Call(Address::from(addr)),
            None => TxKind::Create,
        };

        let chain_id = if block.chain_id == 0 {
            self.chain_id
        } else {
            block.chain_id
        };
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
            .with_external_context(inspector)
            .append_handler_register(inspector_handle_register)
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
        let receipt = convert_result(result);
        let inspector = evm.into_context().external;
        Ok((receipt, inspector))
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

        let chain_id = if block.chain_id == 0 {
            self.chain_id
        } else {
            block.chain_id
        };
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
            total_gas = total_gas
                .checked_add(receipt.gas_used)
                .ok_or_else(|| EvmError::StateError("block gas overflow".to_string()))?;
            if total_gas > block.gas_limit {
                return Err(EvmError::InvalidTransaction(format!(
                    "block gas limit exceeded: used={}, limit={}",
                    total_gas, block.gas_limit
                )));
            }
            receipts.push(receipt);
        }

        let state_root = self.compute_state_root_mpt();

        Ok(BlockResult {
            tx_count: txs.len(),
            gas_used: total_gas,
            receipts,
            state_root,
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
        use crate::block::{extract_cchain_block_fields, extract_cchain_transactions, BlockHeader};

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
            let state_root = self.compute_state_root_mpt();
            if let Some(expected_state_root) = BlockHeader::extract_state_root(raw_block) {
                if state_root != expected_state_root {
                    return Err(EvmError::StateError(format!(
                        "state root mismatch: expected=0x{}, computed=0x{}",
                        hex::encode(expected_state_root),
                        hex::encode(state_root)
                    )));
                }
            }

            return Ok(BlockResult {
                receipts: vec![],
                gas_used: 0,
                tx_count: 0,
                state_root,
            });
        }

        // Recover sender addresses from ECDSA signatures. Fall back to zero address
        // if recovery fails (e.g., missing signature data).
        let evm_txs: Vec<EvmTransaction> = raw_txs
            .iter()
            .map(|t| {
                let from = t.recover_sender().unwrap_or([0u8; 20]);
                // Pre-fund recovered sender so gas deduction succeeds
                // (full state sync is not yet implemented)
                self.set_balance(from, u128::MAX / 2);
                EvmTransaction {
                    from,
                    to: t.to,
                    value: t.value,
                    data: t.data.clone(),
                    gas_limit: t.gas_limit,
                    gas_price: t.gas_price.max(fields.base_fee),
                    nonce: t.nonce,
                }
            })
            .collect();

        let result = self.execute_block(&evm_txs, &ctx)?;

        if let Some(expected_state_root) = BlockHeader::extract_state_root(raw_block) {
            if result.state_root != expected_state_root {
                return Err(EvmError::StateError(format!(
                    "state root mismatch: expected=0x{}, computed=0x{}",
                    hex::encode(expected_state_root),
                    hex::encode(result.state_root)
                )));
            }
        }

        Ok(result)
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

    /// Build an account/storage proof for the latest in-memory state.
    pub fn get_proof(
        &self,
        address: [u8; 20],
        storage_keys: &[([u8; 32], String)],
    ) -> AccountProofResult {
        use alloy_primitives::{keccak256, B256};
        use alloy_rlp::{encode, encode_fixed_size};
        use alloy_trie::{
            proof::ProofRetainer, HashBuilder, Nibbles, TrieAccount, EMPTY_ROOT_HASH, KECCAK_EMPTY,
        };

        let account_code_hash = |account: &revm::db::DbAccount| match &account.info.code {
            Some(code) if !code.is_empty() => B256::from_slice(keccak256(code.bytes()).as_slice()),
            _ if account.info.code_hash != revm::primitives::KECCAK_EMPTY => {
                B256::from_slice(account.info.code_hash.as_slice())
            }
            _ => KECCAK_EMPTY,
        };

        let storage_root_for_account = |account: &revm::db::DbAccount| {
            if account.storage.is_empty() {
                EMPTY_ROOT_HASH
            } else {
                use alloy_trie::root::storage_root_unhashed;
                let storage_iter = account
                    .storage
                    .iter()
                    .map(|(slot, value)| (B256::from(slot.to_be_bytes::<32>()), *value));
                storage_root_unhashed(storage_iter)
            }
        };

        let db_account = self.db.accounts.get(&Address::from(address));
        let (storage_hash, storage_proof) = if let Some(account) = db_account {
            if account.storage.is_empty() {
                (
                    EMPTY_ROOT_HASH,
                    storage_keys
                        .iter()
                        .map(|(_, display_key)| StorageProofResult {
                            key: display_key.clone(),
                            value: "0x0".to_string(),
                            proof: vec![],
                        })
                        .collect::<Vec<_>>(),
                )
            } else {
                let mut sorted_storage = account
                    .storage
                    .iter()
                    .map(|(slot, value)| (keccak256(slot.to_be_bytes::<32>()), *value))
                    .collect::<Vec<_>>();
                sorted_storage.sort_unstable_by_key(|(slot, _)| *slot);

                let mut storage_builder =
                    HashBuilder::default().with_proof_retainer(ProofRetainer::new(
                        storage_keys
                            .iter()
                            .map(|(slot, _)| Nibbles::unpack(keccak256(*slot)))
                            .collect(),
                    ));
                for (hashed_slot, value) in &sorted_storage {
                    storage_builder.add_leaf(
                        Nibbles::unpack(*hashed_slot),
                        encode_fixed_size(value).as_ref(),
                    );
                }
                let root = storage_builder.root();
                let proof_nodes = storage_builder.take_proof_nodes();
                let proofs = storage_keys
                    .iter()
                    .map(|(slot, display_key)| {
                        let target = Nibbles::unpack(keccak256(*slot));
                        let value = account
                            .storage
                            .get(&U256::from_be_bytes(*slot))
                            .copied()
                            .unwrap_or_default();
                        StorageProofResult {
                            key: display_key.clone(),
                            value: format!("0x{:x}", value),
                            proof: proof_nodes
                                .matching_nodes_sorted(&target)
                                .into_iter()
                                .map(|(_, node)| format!("0x{}", hex::encode(node)))
                                .collect(),
                        }
                    })
                    .collect::<Vec<_>>();
                (root, proofs)
            }
        } else {
            (
                EMPTY_ROOT_HASH,
                storage_keys
                    .iter()
                    .map(|(_, display_key)| StorageProofResult {
                        key: display_key.clone(),
                        value: "0x0".to_string(),
                        proof: vec![],
                    })
                    .collect::<Vec<_>>(),
            )
        };

        let mut sorted_accounts = self.db.accounts.iter().collect::<Vec<_>>();
        sorted_accounts.sort_unstable_by_key(|(addr, _)| keccak256(addr.as_slice()));

        let target_nibbles = Nibbles::unpack(keccak256(address));
        let mut account_builder = HashBuilder::default()
            .with_proof_retainer(ProofRetainer::from_iter([target_nibbles.clone()]));
        for (addr, account) in sorted_accounts {
            let trie_account = TrieAccount {
                nonce: account.info.nonce,
                balance: account.info.balance,
                storage_root: if addr.as_slice() == address {
                    storage_hash
                } else {
                    storage_root_for_account(account)
                },
                code_hash: account_code_hash(account),
            };
            account_builder.add_leaf(
                Nibbles::unpack(keccak256(addr.as_slice())),
                encode(trie_account).as_ref(),
            );
        }
        let _ = account_builder.root();
        let account_proof = account_builder
            .take_proof_nodes()
            .matching_nodes_sorted(&target_nibbles)
            .into_iter()
            .map(|(_, node)| format!("0x{}", hex::encode(node)))
            .collect::<Vec<_>>();

        let (balance, nonce, code_hash) = if let Some(account) = db_account {
            (
                format!("0x{:x}", account.info.balance),
                format!("0x{:x}", account.info.nonce),
                format!("0x{}", hex::encode(account_code_hash(account))),
            )
        } else {
            (
                "0x0".to_string(),
                "0x0".to_string(),
                format!("0x{}", hex::encode(KECCAK_EMPTY)),
            )
        };

        AccountProofResult {
            address: format!("0x{}", hex::encode(address)),
            account_proof,
            balance,
            code_hash,
            nonce,
            storage_hash: format!("0x{}", hex::encode(storage_hash)),
            storage_proof,
        }
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
        assert_eq!(result.state_root, exec.compute_state_root_mpt());
    }

    #[test]
    fn test_block_gas_limit_enforced() {
        let mut exec = EvmExecutor::new(43114);
        let sender = [0x01; 20];
        exec.set_balance(sender, 100_000_000_000_000_000_000u128);

        let block = BlockContext {
            gas_limit: 21_000,
            ..test_block()
        };
        let txs = vec![
            EvmTransaction {
                from: sender,
                to: Some([0x02; 20]),
                value: 1,
                data: vec![],
                gas_limit: 21_000,
                gas_price: 25_000_000_000,
                nonce: 0,
            },
            EvmTransaction {
                from: sender,
                to: Some([0x03; 20]),
                value: 1,
                data: vec![],
                gas_limit: 21_000,
                gas_price: 25_000_000_000,
                nonce: 1,
            },
        ];

        let err = exec.execute_block(&txs, &block).unwrap_err();
        assert!(
            err.to_string().contains("block gas limit exceeded"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_receipt_generation_for_transfer() {
        let mut exec = EvmExecutor::new(43114);
        let sender = [0x01; 20];
        let receiver = [0x02; 20];
        exec.set_balance(sender, 10_000_000_000_000_000_000u128);

        let tx = EvmTransaction {
            from: sender,
            to: Some(receiver),
            value: 1_000_000_000_000,
            data: vec![],
            gas_limit: 21_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        let receipt = exec.execute_tx(&tx, &test_block()).unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.gas_used, 21_000);
        assert!(receipt.logs.is_empty());
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
        hp.push(0xa0);
        hp.extend_from_slice(&[0u8; 32]); // parentHash
        hp.push(0xa0);
        hp.extend_from_slice(&[0x1du8; 32]); // sha3Uncles
        hp.push(0x94);
        hp.extend_from_slice(&[0u8; 20]); // miner
        hp.push(0xa0);
        hp.extend_from_slice(&[
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
            0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
            0xe3, 0x63, 0xb4, 0x21,
        ]); // stateRoot = empty trie
        hp.push(0xa0);
        hp.extend_from_slice(&[0u8; 32]); // txRoot
        hp.push(0xa0);
        hp.extend_from_slice(&[0u8; 32]); // receiptRoot
        hp.push(0xb9);
        hp.push(0x01);
        hp.push(0x00);
        hp.extend_from_slice(&[0u8; 256]); // bloom
        hp.push(0x80); // difficulty = 0
                       // number
        if number == 0 {
            hp.push(0x80);
        } else {
            let b = number.to_be_bytes();
            let s = b.iter().position(|&x| x != 0).unwrap_or(7);
            hp.push(0x80 + (8 - s) as u8);
            hp.extend_from_slice(&b[s..]);
        }
        let gl = 30_000_000u64;
        let gb = gl.to_be_bytes();
        let gs = gb.iter().position(|&x| x != 0).unwrap_or(7);
        hp.push(0x80 + (8 - gs) as u8);
        hp.extend_from_slice(&gb[gs..]); // gasLimit
        hp.push(0x80); // gasUsed = 0
        hp.push(0x84);
        hp.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // timestamp
        hp.push(0x80); // extraData (empty)
        hp.push(0xa0);
        hp.extend_from_slice(&[0u8; 32]); // mixHash
        hp.extend_from_slice(&[0x88, 0, 0, 0, 0, 0, 0, 0, 0]); // nonce (8 bytes)

        fn wrap_list(payload: Vec<u8>) -> Vec<u8> {
            let len = payload.len();
            let mut out = Vec::new();
            if len <= 55 {
                out.push(0xc0 + len as u8);
            } else {
                let lb = len.to_be_bytes();
                let ls = lb.iter().position(|&x| x != 0).unwrap_or(7);
                out.push(0xf7 + (8 - ls) as u8);
                out.extend_from_slice(&lb[ls..]);
            }
            out.extend(payload);
            out
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
        assert!(
            result.is_ok(),
            "should execute empty block: {:?}",
            result.err()
        );
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
    fn test_execute_cchain_block_raw_state_root_mismatch() {
        let mut exec = EvmExecutor::new(43114);
        let mut block = make_test_cchain_block_rlp(1);

        // Corrupt a byte in the state root field to force mismatch.
        let idx = block
            .windows(2)
            .position(|w| w == [0xa0, 0x56])
            .map(|p| p + 1)
            .expect("state root prefix present");
        block[idx] ^= 0x01;

        let result = exec.execute_cchain_block_raw(&block, 43114);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("state root mismatch"));
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
    fn test_get_code() {
        let mut exec = EvmExecutor::new(43114);
        let addr = [0xBB; 20];
        let code = vec![0x60, 0x42, 0x60, 0x00, 0x52];
        exec.set_account(addr, 0, 0, code.clone());
        assert_eq!(exec.get_code(addr), code);
    }

    #[test]
    fn test_get_code_empty() {
        let exec = EvmExecutor::new(43114);
        assert!(exec.get_code([0xFF; 20]).is_empty());
    }

    #[test]
    fn test_get_storage_at_empty() {
        let exec = EvmExecutor::new(43114);
        assert_eq!(exec.get_storage_at([0x01; 20], [0u8; 32]), [0u8; 32]);
    }

    #[test]
    fn test_execute_call_simple_transfer() {
        let mut exec = EvmExecutor::new(43114);
        let sender = [0x01; 20];
        exec.set_balance(sender, 10_000_000_000_000_000_000u128);
        let block = test_block();
        let tx = EvmTransaction {
            from: sender,
            to: Some([0x02; 20]),
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };
        let result = exec.execute_call(&tx, &block);
        assert!(result.is_ok());
    }

    #[test]
    fn test_estimate_gas_transfer() {
        let mut exec = EvmExecutor::new(43114);
        let sender = [0x01; 20];
        exec.set_balance(sender, 10_000_000_000_000_000_000u128);
        let block = test_block();
        let tx = EvmTransaction {
            from: sender,
            to: Some([0x02; 20]),
            value: 1_000_000_000,
            data: vec![],
            gas_limit: 21_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };
        let gas = exec.estimate_gas(&tx, &block).unwrap();
        assert_eq!(gas, 21_000);
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
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
            0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
            0xe3, 0x63, 0xb4, 0x21,
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

        assert_eq!(
            exec1.compute_state_root_mpt(),
            exec2.compute_state_root_mpt()
        );
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

        assert_eq!(
            exec1.compute_state_root_mpt(),
            exec2.compute_state_root_mpt()
        );
    }
}
