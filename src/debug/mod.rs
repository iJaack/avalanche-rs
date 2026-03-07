//! Debug & Trace APIs for EVM execution tracing.
//!
//! Phase 10: debug_traceTransaction, debug_traceBlockByNumber,
//! structLogs format with configurable tracers.

use crate::evm::{BlockContext, EvmExecutor, EvmTransaction};
use serde::Serialize;

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
    /// Parse from JSON-RPC options.
    pub fn from_json(opts: &serde_json::Value) -> Self {
        let mut config = Self::default();

        if let Some(tracer) = opts.get("tracer").and_then(|v| v.as_str()) {
            config.tracer = match tracer {
                "callTracer" => TracerType::CallTracer,
                _ => TracerType::StructLogger,
            };
        }

        if let Some(mem) = opts.get("enableMemory").and_then(|v| v.as_bool()) {
            config.enable_memory = mem;
        }
        if let Some(storage) = opts.get("enableStorage").and_then(|v| v.as_bool()) {
            config.enable_storage = storage;
        }
        if let Some(limit) = opts.get("limit").and_then(|v| v.as_u64()) {
            config.limit = limit as usize;
        }

        config
    }
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

impl EvmTracer {
    /// Trace a single transaction.
    /// Executes the transaction and collects execution trace information.
    pub fn trace_transaction(
        executor: &mut EvmExecutor,
        tx: &EvmTransaction,
        block: &BlockContext,
        config: &TraceConfig,
    ) -> TransactionTrace {
        // Execute the transaction to get the result
        let receipt = executor.execute_tx(tx, block);

        match receipt {
            Ok(receipt) => {
                // Generate struct logs based on the execution
                let mut struct_logs = Vec::new();

                // Simulate trace output from the transaction
                // In a full implementation, this would use revm's step inspector
                // For now, we produce a trace with the key execution milestones

                // Entry point
                struct_logs.push(StructLog {
                    pc: 0,
                    op: if tx.to.is_some() {
                        "CALL".to_string()
                    } else {
                        "CREATE".to_string()
                    },
                    gas: tx.gas_limit,
                    gas_cost: 21000,
                    depth: 1,
                    stack: vec![],
                    memory: if config.enable_memory {
                        Some(vec![])
                    } else {
                        None
                    },
                    storage: if config.enable_storage {
                        Some(std::collections::HashMap::new())
                    } else {
                        None
                    },
                    error: None,
                });

                // If there's calldata, simulate processing it
                if !tx.data.is_empty() {
                    struct_logs.push(StructLog {
                        pc: 1,
                        op: "CALLDATALOAD".to_string(),
                        gas: tx.gas_limit.saturating_sub(21000),
                        gas_cost: 3,
                        depth: 1,
                        stack: vec![format!(
                            "0x{}",
                            hex::encode(&tx.data[..tx.data.len().min(32)])
                        )],
                        memory: None,
                        storage: None,
                        error: None,
                    });
                }

                // Final step
                struct_logs.push(StructLog {
                    pc: if tx.data.is_empty() { 1 } else { 2 },
                    op: if receipt.success {
                        "STOP".to_string()
                    } else {
                        "REVERT".to_string()
                    },
                    gas: tx.gas_limit.saturating_sub(receipt.gas_used),
                    gas_cost: 0,
                    depth: 1,
                    stack: vec![],
                    memory: None,
                    storage: None,
                    error: if !receipt.success {
                        Some(String::from_utf8_lossy(&receipt.output).to_string())
                    } else {
                        None
                    },
                });

                // Apply limit
                if config.limit > 0 && struct_logs.len() > config.limit {
                    struct_logs.truncate(config.limit);
                }

                TransactionTrace {
                    gas: receipt.gas_used,
                    failed: !receipt.success,
                    return_value: hex::encode(&receipt.output),
                    struct_logs,
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

        let tx = EvmTransaction {
            from: sender,
            to: Some(receiver),
            value: 1_000_000_000,
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

        assert!(!trace.failed);
        assert_eq!(trace.gas, 21_000);
        assert!(!trace.struct_logs.is_empty());
        assert_eq!(trace.struct_logs[0].op, "CALL");
    }

    #[test]
    fn test_trace_with_memory_enabled() {
        let mut executor = EvmExecutor::new(43114);
        executor.set_balance([0x01; 20], 10_000_000_000_000_000_000u128);

        let tx = EvmTransaction {
            from: [0x01; 20],
            to: Some([0x02; 20]),
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            gas_price: 25_000_000_000,
            nonce: 0,
        };

        let config = TraceConfig {
            enable_memory: true,
            ..Default::default()
        };

        let trace = EvmTracer::trace_transaction(&mut executor, &tx, &test_block(), &config);
        // Memory should be present in first log
        assert!(trace.struct_logs[0].memory.is_some());
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

        let config = TraceConfig::from_json(&opts);
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

        let tx = EvmTransaction {
            from: [0x01; 20],
            to: Some([0x02; 20]),
            value: 0,
            data: vec![0xAA; 100],
            gas_limit: 21_000,
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
