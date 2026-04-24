//! Debug & Trace APIs for EVM execution tracing.
//!
//! Phase 10: debug_traceTransaction, debug_traceBlockByNumber,
//! structLogs format with configurable tracers.

use crate::evm::{BlockContext, EvmExecutor, EvmTransaction};
use revm::{
    inspectors::GasInspector,
    interpreter::{
        CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, EOFCreateInputs,
        InstructionResult, Interpreter, OpCode,
    },
    primitives::{db::Database, Address, CreateScheme, U256},
    EvmContext, Inspector,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Trace Types
// ---------------------------------------------------------------------------

/// A single step in the EVM execution trace.
#[derive(Debug, Clone, Serialize)]
pub struct StructLog {
    /// Program counter
    pub pc: u64,
    /// Opcode name
    pub op: String,
    /// Remaining gas
    pub gas: u64,
    /// Gas cost of this operation
    #[serde(rename = "gasCost")]
    pub gas_cost: u64,
    /// Call depth
    pub depth: u32,
    /// Stack contents (top of stack first)
    pub stack: Vec<String>,
    /// Memory contents (hex encoded, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<Vec<String>>,
    /// Storage changes (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<std::collections::HashMap<String, String>>,
    /// Error message if this step failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Full transaction trace result.
#[derive(Debug, Clone, Serialize)]
pub struct TransactionTrace {
    /// Gas used by the transaction
    pub gas: u64,
    /// Whether the transaction failed
    pub failed: bool,
    /// Return value (hex encoded)
    #[serde(rename = "returnValue")]
    pub return_value: String,
    /// Execution steps
    #[serde(rename = "structLogs")]
    pub struct_logs: Vec<StructLog>,
    /// Call trace representation used by `callTracer`.
    #[serde(skip_serializing)]
    pub call_trace: Option<CallTrace>,
}

/// Call trace format (callTracer).
#[derive(Debug, Clone, Serialize)]
pub struct CallTrace {
    /// Call type: CALL, STATICCALL, DELEGATECALL, CREATE, CREATE2
    #[serde(rename = "type")]
    pub call_type: String,
    /// Sender
    pub from: String,
    /// Recipient
    pub to: String,
    /// Value transferred
    pub value: String,
    /// Gas provided
    pub gas: String,
    /// Gas used
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
    /// Input data
    pub input: String,
    /// Output data
    pub output: String,
    /// Error if call failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Sub-calls
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<CallTrace>,
}

/// Tracer configuration.
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// Tracer to use: "structLogger" (default) or "callTracer"
    pub tracer: TracerType,
    /// Whether to include memory in structLogs
    pub enable_memory: bool,
    /// Whether to include storage in structLogs
    pub enable_storage: bool,
    /// Maximum number of struct logs to collect (0 = unlimited)
    pub limit: usize,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            tracer: TracerType::StructLogger,
            enable_memory: false,
            enable_storage: false,
            limit: 0,
        }
    }
}

impl TraceConfig {
    pub fn from_input(opts: TraceConfigInput) -> Self {
        let tracer = match opts.tracer.as_deref() {
            Some("callTracer") => TracerType::CallTracer,
            _ => TracerType::StructLogger,
        };

        Self {
            tracer,
            enable_memory: opts.enable_memory.unwrap_or(false),
            enable_storage: opts.enable_storage.unwrap_or(false),
            limit: opts.limit.unwrap_or(0) as usize,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct TraceConfigInput {
    #[serde(default)]
    tracer: Option<String>,
    #[serde(default, rename = "enableMemory")]
    enable_memory: Option<bool>,
    #[serde(default, rename = "enableStorage")]
    enable_storage: Option<bool>,
    #[serde(default)]
    limit: Option<u64>,
}

/// Tracer type selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracerType {
    StructLogger,
    CallTracer,
}

// ---------------------------------------------------------------------------
// EVM Tracer
// ---------------------------------------------------------------------------

/// EVM execution tracer that produces structLogs or callTracer output.
pub struct EvmTracer;

#[derive(Debug, Clone)]
struct PendingStep {
    pc: usize,
    opcode: u8,
    gas: u64,
    depth: u32,
    stack: Vec<U256>,
    memory: Option<Vec<String>>,
}

#[derive(Debug)]
struct TraceInspector {
    config: TraceConfig,
    gas_inspector: GasInspector,
    pending_step: Option<PendingStep>,
    struct_logs: Vec<StructLog>,
    storage_by_account: HashMap<[u8; 20], HashMap<String, String>>,
    root_call: CallTrace,
    call_stack: Vec<CallTrace>,
}

impl TraceInspector {
    fn new(tx: &EvmTransaction, config: &TraceConfig) -> Self {
        Self {
            config: config.clone(),
            gas_inspector: GasInspector::default(),
            pending_step: None,
            struct_logs: Vec::new(),
            storage_by_account: HashMap::new(),
            root_call: EvmTracer::call_trace(tx, 0, true, &[]),
            call_stack: Vec::new(),
        }
    }

    fn collect_struct_logs(&self) -> bool {
        self.config.tracer == TracerType::StructLogger
    }

    fn attach_child(&mut self, child: CallTrace) {
        if let Some(parent) = self.call_stack.last_mut() {
            parent.calls.push(child);
        } else {
            self.root_call.calls.push(child);
        }
    }

    fn finalize_root(
        mut self,
        tx: &EvmTransaction,
        gas_used: u64,
        success: bool,
        output: &[u8],
    ) -> Self {
        self.root_call.gas_used = format!("0x{:x}", gas_used);
        self.root_call.output = format!("0x{}", hex::encode(output));
        self.root_call.error = if success {
            None
        } else {
            Some("execution reverted".to_string())
        };
        if tx.to.is_none() && self.root_call.to == "0x" {
            self.root_call.to = "0x".to_string();
        }
        self
    }

    fn finish(mut self) -> (Vec<StructLog>, CallTrace) {
        while let Some(child) = self.call_stack.pop() {
            self.attach_child(child);
        }
        (self.struct_logs, self.root_call)
    }

    fn record_storage<DB: Database>(
        &mut self,
        interp: &Interpreter,
        context: &EvmContext<DB>,
        opcode: u8,
        stack: &[U256],
    ) -> Option<HashMap<String, String>> {
        if !self.config.enable_storage || !matches!(opcode, 0x54 | 0x55) {
            return None;
        }

        let slot = *stack.last()?;
        let address = interp.contract.target_address;
        let account = context.journaled_state.state.get(&address)?;
        let value = account
            .storage
            .get(&slot)
            .map(|entry| entry.present_value())
            .unwrap_or(U256::ZERO);

        let mut addr = [0u8; 20];
        addr.copy_from_slice(address.as_slice());
        let snapshot = self.storage_by_account.entry(addr).or_default();
        snapshot.insert(EvmTracer::hex_u256(slot), EvmTracer::hex_u256(value));
        Some(snapshot.clone())
    }

    fn finalize_child(
        mut frame: CallTrace,
        gas_used: u64,
        result: InstructionResult,
        output: &[u8],
        to: Option<Address>,
    ) -> CallTrace {
        frame.gas_used = format!("0x{:x}", gas_used);
        frame.output = format!("0x{}", hex::encode(output));
        if let Some(to) = to {
            frame.to = EvmTracer::hex_address(to);
        }
        frame.error = EvmTracer::instruction_error(result);
        frame
    }

    fn call_trace_from_inputs(inputs: &CallInputs) -> CallTrace {
        CallTrace {
            call_type: match inputs.scheme {
                CallScheme::Call | CallScheme::ExtCall => "CALL".to_string(),
                CallScheme::CallCode => "CALLCODE".to_string(),
                CallScheme::DelegateCall | CallScheme::ExtDelegateCall => {
                    "DELEGATECALL".to_string()
                }
                CallScheme::StaticCall | CallScheme::ExtStaticCall => "STATICCALL".to_string(),
            },
            from: EvmTracer::hex_address(inputs.caller),
            to: EvmTracer::hex_address(inputs.target_address),
            value: EvmTracer::hex_u256(inputs.call_value()),
            gas: format!("0x{:x}", inputs.gas_limit),
            gas_used: "0x0".to_string(),
            input: format!("0x{}", hex::encode(&inputs.input)),
            output: "0x".to_string(),
            error: None,
            calls: vec![],
        }
    }

    fn call_trace_from_create(inputs: &CreateInputs) -> CallTrace {
        CallTrace {
            call_type: match inputs.scheme {
                CreateScheme::Create => "CREATE".to_string(),
                CreateScheme::Create2 { .. } => "CREATE2".to_string(),
            },
            from: EvmTracer::hex_address(inputs.caller),
            to: "0x".to_string(),
            value: EvmTracer::hex_u256(inputs.value),
            gas: format!("0x{:x}", inputs.gas_limit),
            gas_used: "0x0".to_string(),
            input: format!("0x{}", hex::encode(&inputs.init_code)),
            output: "0x".to_string(),
            error: None,
            calls: vec![],
        }
    }
}

impl<DB: Database> Inspector<DB> for TraceInspector {
    fn initialize_interp(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        self.gas_inspector.initialize_interp(interp, context);
    }

    fn step(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        self.gas_inspector.step(interp, context);
        if !self.collect_struct_logs()
            || (self.config.limit > 0 && self.struct_logs.len() >= self.config.limit)
        {
            return;
        }

        self.pending_step = Some(PendingStep {
            pc: interp.program_counter(),
            opcode: interp.current_opcode(),
            gas: interp.gas.remaining(),
            depth: context.journaled_state.depth() as u32 + 1,
            stack: interp.stack.data().clone(),
            memory: if self.config.enable_memory {
                Some(EvmTracer::memory_words(
                    interp.shared_memory.context_memory(),
                ))
            } else {
                None
            },
        });
    }

    fn step_end(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        self.gas_inspector.step_end(interp, context);
        let Some(step) = self.pending_step.take() else {
            return;
        };
        if self.config.limit > 0 && self.struct_logs.len() >= self.config.limit {
            return;
        }

        let storage = self.record_storage(interp, context, step.opcode, &step.stack);
        self.struct_logs.push(StructLog {
            pc: step.pc as u64,
            op: OpCode::new(step.opcode)
                .map(|op| op.as_str().to_string())
                .unwrap_or_else(|| format!("0x{:02x}", step.opcode)),
            gas: step.gas,
            gas_cost: self.gas_inspector.last_gas_cost(),
            depth: step.depth,
            stack: step
                .stack
                .iter()
                .rev()
                .map(|value| EvmTracer::hex_u256(*value))
                .collect(),
            memory: step.memory,
            storage,
            error: if interp.instruction_result.is_error() || interp.instruction_result.is_revert()
            {
                EvmTracer::instruction_error(interp.instruction_result)
            } else {
                None
            },
        });
    }

    fn call(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        self.call_stack.push(Self::call_trace_from_inputs(inputs));
        None
    }

    fn call_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        _inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        if let Some(frame) = self.call_stack.pop() {
            self.attach_child(Self::finalize_child(
                frame,
                outcome.gas().spent(),
                *outcome.instruction_result(),
                outcome.output(),
                None,
            ));
        }
        outcome
    }

    fn create(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        self.call_stack.push(Self::call_trace_from_create(inputs));
        None
    }

    fn create_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        _inputs: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        if let Some(frame) = self.call_stack.pop() {
            self.attach_child(Self::finalize_child(
                frame,
                outcome.gas().spent(),
                *outcome.instruction_result(),
                outcome.output(),
                outcome.address,
            ));
        }
        outcome
    }

    fn eofcreate(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut EOFCreateInputs,
    ) -> Option<CreateOutcome> {
        let input = match &inputs.kind {
            revm::interpreter::EOFCreateKind::Tx { initdata } => initdata.as_ref(),
            revm::interpreter::EOFCreateKind::Opcode { input, .. } => input.as_ref(),
        };
        self.call_stack.push(CallTrace {
            call_type: "CREATE".to_string(),
            from: EvmTracer::hex_address(inputs.caller),
            to: "0x".to_string(),
            value: EvmTracer::hex_u256(inputs.value),
            gas: format!("0x{:x}", inputs.gas_limit),
            gas_used: "0x0".to_string(),
            input: format!("0x{}", hex::encode(input)),
            output: "0x".to_string(),
            error: None,
            calls: vec![],
        });
        None
    }

    fn eofcreate_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        _inputs: &EOFCreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        if let Some(frame) = self.call_stack.pop() {
            self.attach_child(Self::finalize_child(
                frame,
                outcome.gas().spent(),
                *outcome.instruction_result(),
                outcome.output(),
                outcome.address,
            ));
        }
        outcome
    }
}

impl EvmTracer {
    fn hex_address(address: Address) -> String {
        format!("0x{}", hex::encode(address.as_slice()))
    }

    fn hex_u256(value: U256) -> String {
        format!("0x{:x}", value)
    }

    fn memory_words(memory: &[u8]) -> Vec<String> {
        memory
            .chunks(32)
            .map(|chunk| format!("0x{}", hex::encode(chunk)))
            .collect()
    }

    fn instruction_error(result: InstructionResult) -> Option<String> {
        if result.is_ok() {
            None
        } else if result.is_revert() {
            Some("execution reverted".to_string())
        } else {
            Some(format!("{:?}", result))
        }
    }

    /// Trace a single transaction.
    /// Executes the transaction and collects execution trace information.
    pub fn trace_transaction(
        executor: &mut EvmExecutor,
        tx: &EvmTransaction,
        block: &BlockContext,
        config: &TraceConfig,
    ) -> TransactionTrace {
        match executor.inspect_tx(tx, block, TraceInspector::new(tx, config)) {
            Ok((receipt, inspector)) => {
                let inspector =
                    inspector.finalize_root(tx, receipt.gas_used, receipt.success, &receipt.output);
                let (struct_logs, call_trace) = inspector.finish();
                TransactionTrace {
                    gas: receipt.gas_used,
                    failed: !receipt.success,
                    return_value: hex::encode(&receipt.output),
                    struct_logs,
                    call_trace: Some(call_trace),
                }
            }
            Err(e) => TransactionTrace {
                gas: 0,
                failed: true,
                return_value: String::new(),
                struct_logs: vec![StructLog {
                    pc: 0,
                    op: "INVALID".to_string(),
                    gas: 0,
                    gas_cost: 0,
                    depth: 1,
                    stack: vec![],
                    memory: None,
                    storage: None,
                    error: Some(e.to_string()),
                }],
                call_trace: Some(CallTrace {
                    call_type: if tx.to.is_some() {
                        "CALL".to_string()
                    } else {
                        "CREATE".to_string()
                    },
                    from: format!("0x{}", hex::encode(tx.from)),
                    to: tx
                        .to
                        .map(|a| format!("0x{}", hex::encode(a)))
                        .unwrap_or_else(|| "0x".to_string()),
                    value: format!("0x{:x}", tx.value),
                    gas: format!("0x{:x}", tx.gas_limit),
                    gas_used: "0x0".to_string(),
                    input: format!("0x{}", hex::encode(&tx.data)),
                    output: "0x".to_string(),
                    error: Some(e.to_string()),
                    calls: vec![],
                }),
            },
        }
    }

    /// Trace all transactions in a block.
    pub fn trace_block(
        executor: &mut EvmExecutor,
        txs: &[EvmTransaction],
        block: &BlockContext,
        config: &TraceConfig,
    ) -> Vec<TransactionTrace> {
        txs.iter()
            .map(|tx| Self::trace_transaction(executor, tx, block, config))
            .collect()
    }

    /// Build a call trace from a transaction execution.
    pub fn call_trace(
        tx: &EvmTransaction,
        gas_used: u64,
        success: bool,
        output: &[u8],
    ) -> CallTrace {
        CallTrace {
            call_type: if tx.to.is_some() {
                "CALL".to_string()
            } else {
                "CREATE".to_string()
            },
            from: format!("0x{}", hex::encode(tx.from)),
            to: tx
                .to
                .map(|a| format!("0x{}", hex::encode(a)))
                .unwrap_or_else(|| "0x".to_string()),
            value: format!("0x{:x}", tx.value),
            gas: format!("0x{:x}", tx.gas_limit),
            gas_used: format!("0x{:x}", gas_used),
            input: format!("0x{}", hex::encode(&tx.data)),
            output: format!("0x{}", hex::encode(output)),
            error: if !success {
                Some("execution reverted".to_string())
            } else {
                None
            },
            calls: vec![],
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn trace_test_code() -> Vec<u8> {
        // PUSH1 0x00; CALLDATALOAD; PUSH1 0x00; MSTORE; STOP
        vec![0x60, 0x00, 0x35, 0x60, 0x00, 0x52, 0x00]
    }

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
    fn test_trace_simple_transfer() {
        let mut executor = EvmExecutor::new(43114);
        let sender = [0x01; 20];
        let receiver = [0x02; 20];
        executor.set_balance(sender, 10_000_000_000_000_000_000u128);
        executor.set_account(receiver, 0, 1, trace_test_code());

        let tx = EvmTransaction {
            from: sender,
            to: Some(receiver),
            value: 1_000_000_000,
            data: vec![0xAA, 0xBB, 0xCC, 0xDD],
            gas_limit: 50_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        let trace = EvmTracer::trace_transaction(
            &mut executor,
            &tx,
            &test_block(),
            &TraceConfig::default(),
        );

        assert!(!trace.failed);
        assert!(trace.gas > 21_000);
        assert!(!trace.struct_logs.is_empty());
        assert_eq!(trace.struct_logs[0].op, "PUSH1");
        assert_eq!(trace.struct_logs[1].op, "CALLDATALOAD");
    }

    #[test]
    fn test_trace_with_memory_enabled() {
        let mut executor = EvmExecutor::new(43114);
        executor.set_balance([0x01; 20], 10_000_000_000_000_000_000u128);
        executor.set_account([0x02; 20], 0, 1, trace_test_code());

        let tx = EvmTransaction {
            from: [0x01; 20],
            to: Some([0x02; 20]),
            value: 0,
            data: vec![0x11; 32],
            gas_limit: 50_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        let config = TraceConfig {
            enable_memory: true,
            ..Default::default()
        };

        let trace = EvmTracer::trace_transaction(&mut executor, &tx, &test_block(), &config);
        assert!(trace.struct_logs.iter().all(|log| log.memory.is_some()));
        assert!(trace
            .struct_logs
            .last()
            .and_then(|log| log.memory.as_ref())
            .is_some_and(|memory| !memory.is_empty()));
    }

    #[test]
    fn test_trace_block() {
        let mut executor = EvmExecutor::new(43114);
        executor.set_balance([0x01; 20], 100_000_000_000_000_000_000u128);

        let txs = vec![
            EvmTransaction {
                from: [0x01; 20],
                to: Some([0x02; 20]),
                value: 1_000,
                data: vec![],
                gas_limit: 21_000,
                gas_price: 25_000_000_000,
                nonce: 0,
            },
            EvmTransaction {
                from: [0x01; 20],
                to: Some([0x03; 20]),
                value: 2_000,
                data: vec![],
                gas_limit: 21_000,
                gas_price: 25_000_000_000,
                nonce: 1,
            },
        ];

        let traces =
            EvmTracer::trace_block(&mut executor, &txs, &test_block(), &TraceConfig::default());

        assert_eq!(traces.len(), 2);
        assert!(!traces[0].failed);
        assert!(!traces[1].failed);
    }

    #[test]
    fn test_trace_config_from_json() {
        let opts = serde_json::json!({
            "tracer": "callTracer",
            "enableMemory": true,
            "enableStorage": true,
            "limit": 100
        });

        let config = TraceConfig::from_input(serde_json::from_value(opts).unwrap());
        assert_eq!(config.tracer, TracerType::CallTracer);
        assert!(config.enable_memory);
        assert!(config.enable_storage);
        assert_eq!(config.limit, 100);
    }

    #[test]
    fn test_trace_config_default() {
        let config = TraceConfig::default();
        assert_eq!(config.tracer, TracerType::StructLogger);
        assert!(!config.enable_memory);
        assert!(!config.enable_storage);
        assert_eq!(config.limit, 0);
    }

    #[test]
    fn test_call_trace_format() {
        let tx = EvmTransaction {
            from: [0x01; 20],
            to: Some([0x02; 20]),
            value: 1000,
            data: vec![0xAA, 0xBB],
            gas_limit: 21000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        let trace = EvmTracer::call_trace(&tx, 21000, true, &[]);
        assert_eq!(trace.call_type, "CALL");
        assert!(trace.error.is_none());
        assert!(trace.calls.is_empty());
    }

    #[test]
    fn test_call_trace_create() {
        let tx = EvmTransaction {
            from: [0x01; 20],
            to: None, // CREATE
            value: 0,
            data: vec![0x60, 0x00],
            gas_limit: 100_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        let trace = EvmTracer::call_trace(&tx, 50000, true, &[0x60]);
        assert_eq!(trace.call_type, "CREATE");
    }

    #[test]
    fn test_trace_with_limit() {
        let mut executor = EvmExecutor::new(43114);
        executor.set_balance([0x01; 20], 10_000_000_000_000_000_000u128);
        executor.set_account([0x02; 20], 0, 1, trace_test_code());

        let tx = EvmTransaction {
            from: [0x01; 20],
            to: Some([0x02; 20]),
            value: 0,
            data: vec![0xAA; 100],
            gas_limit: 50_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        let config = TraceConfig {
            limit: 1,
            ..Default::default()
        };

        let trace = EvmTracer::trace_transaction(&mut executor, &tx, &test_block(), &config);
        assert!(trace.struct_logs.len() <= 1);
    }

    #[test]
    fn test_struct_log_serialization() {
        let log = StructLog {
            pc: 0,
            op: "PUSH1".to_string(),
            gas: 100000,
            gas_cost: 3,
            depth: 1,
            stack: vec!["0x42".to_string()],
            memory: None,
            storage: None,
            error: None,
        };

        let json = serde_json::to_string(&log).unwrap();
        assert!(json.contains("PUSH1"));
        assert!(json.contains("\"pc\":0"));
        // memory and storage should not be present (skip_serializing_if)
        assert!(!json.contains("memory"));
        assert!(!json.contains("storage"));
    }

    #[test]
    fn test_trace_failed_transaction() {
        let mut executor = EvmExecutor::new(43114);
        // Don't fund sender — should fail
        let tx = EvmTransaction {
            from: [0x01; 20],
            to: Some([0x02; 20]),
            value: 1_000_000_000_000_000_000,
            data: vec![],
            gas_limit: 21_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        let trace = EvmTracer::trace_transaction(
            &mut executor,
            &tx,
            &test_block(),
            &TraceConfig::default(),
        );

        assert!(trace.failed);
    }
}
