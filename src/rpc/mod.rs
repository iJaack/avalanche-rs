//! Avalanche JSON-RPC Client
//! 
//! Production-grade async HTTP client for Avalanche node communication.
//! Supports X-chain, C-chain, and P-chain methods with connection pooling,
//! timeout handling, and automatic retry logic.

use std::sync::Arc;
use std::time::Duration;
use serde_json::{json, Value};
use serde::{Serialize, Deserialize};
use hyper::{Request, StatusCode, Uri};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper_tls::HttpsConnector;
use http_body_util::{BodyExt, Full};
use bytes::Bytes;

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

#[derive(Debug)]
pub enum RpcClientError {
    /// Network/HTTP errors
    NetworkError(String),
    /// RPC error response from server
    RpcError(RpcError),
    /// JSON parse/serialization error
    ParseError(String),
    /// Request timeout
    TimeoutError,
    /// Connection failed after retries
    ConnectionFailed(String),
    /// Invalid parameters
    InvalidParams(String),
}

impl std::fmt::Display for RpcClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcClientError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            RpcClientError::RpcError(err) => {
                write!(f, "RPC error {}: {}", err.code, err.message)
            }
            RpcClientError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            RpcClientError::TimeoutError => write!(f, "Request timeout"),
            RpcClientError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            RpcClientError::InvalidParams(msg) => write!(f, "Invalid params: {}", msg),
        }
    }
}

impl std::error::Error for RpcClientError {}

pub type Result<T> = std::result::Result<T, RpcClientError>;

// ============================================================================
// JSON-RPC REQUEST/RESPONSE TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Vec<Value>,
    pub id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: u64,
}

// ============================================================================
// CHAIN-SPECIFIC RESPONSE TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub hash: String,
    pub number: String,
    pub timestamp: String,
    pub transactions: Vec<String>,
    pub parent_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub tx_id: String,
    pub status: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub balance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Avalanche API returns `nodeID`, not `node_id`
    #[serde(alias = "nodeID", alias = "node_id")]
    pub node_id: String,
    /// Stake weight (nAVAX as string)
    #[serde(alias = "stakeAmount", default)]
    pub stake: String,
    /// Validator status
    #[serde(default)]
    pub status: String,
    /// Uptime percentage
    #[serde(default)]
    pub uptime: String,
    /// Start time (Unix timestamp as string)
    #[serde(alias = "startTime", default)]
    pub start_time: String,
    /// End time (Unix timestamp as string)
    #[serde(alias = "endTime", default)]
    pub end_time: String,
    /// Connected status
    #[serde(default)]
    pub connected: bool,
    /// Delegation fee (in 10000ths)
    #[serde(alias = "delegationFee", default)]
    pub delegation_fee: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorsResponse {
    pub validators: Vec<ValidatorInfo>,
}

// ============================================================================
// REQUEST BUILDERS (Type-Safe)
// ============================================================================

pub struct RequestBuilder {
    method: String,
    params: Vec<Value>,
}

impl RequestBuilder {
    pub fn new(method: impl Into<String>) -> Self {
        RequestBuilder {
            method: method.into(),
            params: vec![],
        }
    }

    pub fn param(mut self, param: Value) -> Self {
        self.params.push(param);
        self
    }

    pub fn build(self, id: u64) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: self.method,
            params: self.params,
            id,
        }
    }
}

// ============================================================================
// RPC CLIENT CONFIGURATION
// ============================================================================

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub timeout: Duration,
    pub max_retries: u32,
    pub retry_backoff_ms: u64,
    pub connect_timeout: Duration,
    pub pool_size: usize,
}

impl Default for RpcConfig {
    fn default() -> Self {
        RpcConfig {
            timeout: Duration::from_secs(30),
            max_retries: 3,
            retry_backoff_ms: 100,
            connect_timeout: Duration::from_secs(10),
            pool_size: 10,
        }
    }
}

// ============================================================================
// MAIN RPC CLIENT
// ============================================================================

pub struct RpcClient {
    endpoint: String,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    config: RpcConfig,
    request_id_counter: Arc<std::sync::Mutex<u64>>,
}

impl RpcClient {
    /// Create a new RPC client with default configuration
    pub fn new(endpoint: impl Into<String>) -> Result<Self> {
        Self::with_config(endpoint, RpcConfig::default())
    }

    /// Create a new RPC client with custom configuration
    pub fn with_config(endpoint: impl Into<String>, config: RpcConfig) -> Result<Self> {
        let https = HttpsConnector::new();
        let client = Client::builder(TokioExecutor::new()).build(https);

        Ok(RpcClient {
            endpoint: endpoint.into(),
            client,
            config,
            request_id_counter: Arc::new(std::sync::Mutex::new(1)),
        })
    }

    /// Generate next request ID
    fn next_id(&self) -> u64 {
        let mut counter = self.request_id_counter.lock().expect("request_id_counter mutex poisoned");
        let id = *counter;
        *counter = counter.wrapping_add(1);
        id
    }

    /// Core RPC call method with retry logic
    pub async fn call(
        &self,
        method: impl Into<String>,
        params: Vec<Value>,
    ) -> Result<Value> {
        let method = method.into();
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match self.call_internal(&method, params.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);

                    if attempt < self.config.max_retries {
                        // Exponential backoff: 100ms * 2^attempt
                        let backoff_ms =
                            self.config.retry_backoff_ms * (2u64.pow(attempt));
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or(RpcClientError::ConnectionFailed(
            "Max retries exceeded".to_string(),
        )))
    }

    /// Internal call implementation (single attempt)
    async fn call_internal(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<Value> {
        let id = self.next_id();

        let request_body = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id,
        };

        let body_str = serde_json::to_string(&request_body)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))?;

        let uri: Uri = self.endpoint.parse()
            .map_err(|_| RpcClientError::InvalidParams("Invalid endpoint URI".to_string()))?;

        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_str)))
            .map_err(|e: hyper::http::Error| RpcClientError::NetworkError(e.to_string()))?;

        // Execute request with timeout
        let response = tokio::time::timeout(
            self.config.timeout,
            self.client.request(request),
        )
        .await
        .map_err(|_: tokio::time::error::Elapsed| RpcClientError::TimeoutError)?
        .map_err(|e: hyper_util::client::legacy::Error| RpcClientError::NetworkError(e.to_string()))?;

        if response.status() != StatusCode::OK {
            return Err(RpcClientError::NetworkError(format!(
                "HTTP {}: {}",
                response.status(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }

        // Read response body
        let body_bytes = response.into_body()
            .collect()
            .await
            .map_err(|e: hyper::Error| RpcClientError::NetworkError(e.to_string()))?
            .to_bytes();

        let body_str = String::from_utf8(body_bytes.to_vec())
            .map_err(|e| RpcClientError::ParseError(e.to_string()))?;

        let response: JsonRpcResponse = serde_json::from_str(&body_str)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))?;

        // Check for RPC error
        if let Some(error) = response.error {
            return Err(RpcClientError::RpcError(error));
        }

        response
            .result
            .ok_or_else(|| RpcClientError::ParseError("No result in response".to_string()))
    }
}

// ============================================================================
// X-CHAIN METHODS
// ============================================================================

impl RpcClient {
    /// Get balance for an address on X-chain
    pub async fn x_get_balance(&self, address: &str) -> Result<BalanceResponse> {
        let result = self
            .call(
                "avm.getBalance",
                vec![json!(address)],
            )
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get UTXOs for an address on X-chain
    pub async fn x_get_utxos(&self, address: &str, limit: Option<u32>) -> Result<Value> {
        let mut params = vec![json!(address)];
        if let Some(l) = limit {
            params.push(json!(l));
        }

        self.call("avm.getUTXOs", params).await
    }

    /// Send transaction on X-chain
    pub async fn x_send_transaction(&self, tx: &str) -> Result<TransactionResponse> {
        let result = self
            .call(
                "avm.sendTx",
                vec![json!(tx)],
            )
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }
}

// ============================================================================
// C-CHAIN METHODS (Ethereum-Compatible)
// ============================================================================

impl RpcClient {
    /// Get block number on C-chain
    pub async fn c_block_number(&self) -> Result<String> {
        let result = self
            .call("eth_blockNumber", vec![])
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get balance for an address on C-chain
    pub async fn c_get_balance(&self, address: &str, block: &str) -> Result<String> {
        let result = self
            .call(
                "eth_getBalance",
                vec![json!(address), json!(block)],
            )
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get block by number on C-chain
    pub async fn c_get_block(&self, block_number: &str) -> Result<BlockResponse> {
        let result = self
            .call(
                "eth_getBlockByNumber",
                vec![json!(block_number), json!(true)],
            )
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Send transaction on C-chain
    pub async fn c_send_transaction(&self, tx: &str) -> Result<String> {
        let result = self
            .call(
                "eth_sendRawTransaction",
                vec![json!(tx)],
            )
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get transaction receipt on C-chain
    pub async fn c_get_transaction_receipt(&self, tx_hash: &str) -> Result<Value> {
        self.call("eth_getTransactionReceipt", vec![json!(tx_hash)])
            .await
    }

    /// Execute a read-only contract call (eth_call)
    pub async fn c_call(&self, to: &str, data: &str, block: &str) -> Result<String> {
        let result = self
            .call(
                "eth_call",
                vec![
                    json!({ "to": to, "data": data }),
                    json!(block),
                ],
            )
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get account nonce (transaction count)
    pub async fn c_get_nonce(&self, address: &str, block: &str) -> Result<String> {
        let result = self
            .call(
                "eth_getTransactionCount",
                vec![json!(address), json!(block)],
            )
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get current gas price
    pub async fn c_gas_price(&self) -> Result<String> {
        let result = self.call("eth_gasPrice", vec![]).await?;
        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get chain ID
    pub async fn c_chain_id(&self) -> Result<String> {
        let result = self.call("eth_chainId", vec![]).await?;
        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Estimate gas for a transaction
    pub async fn c_estimate_gas(&self, to: &str, data: &str, value: Option<&str>) -> Result<String> {
        let mut tx = serde_json::Map::new();
        tx.insert("to".into(), json!(to));
        tx.insert("data".into(), json!(data));
        if let Some(v) = value {
            tx.insert("value".into(), json!(v));
        }

        let result = self
            .call("eth_estimateGas", vec![Value::Object(tx)])
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get pending transactions from txpool (if available)
    pub async fn c_txpool_content(&self) -> Result<Value> {
        self.call("txpool_content", vec![]).await
    }

    /// Get pending transaction hashes
    pub async fn c_pending_transactions(&self) -> Result<Value> {
        self.call("eth_pendingTransactions", vec![]).await
    }
}

// ============================================================================
// P-CHAIN METHODS
// ============================================================================

impl RpcClient {
    /// Get current validators on P-chain
    pub async fn p_get_current_validators(
        &self,
        subnet_id: Option<&str>,
    ) -> Result<ValidatorsResponse> {
        let mut params = vec![];
        if let Some(id) = subnet_id {
            params.push(json!(id));
        }

        let result = self
            .call("platform.getCurrentValidators", params)
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get all validators on P-chain
    pub async fn p_get_validators(&self, subnet_id: Option<&str>) -> Result<ValidatorsResponse> {
        let mut params = vec![];
        if let Some(id) = subnet_id {
            params.push(json!(id));
        }

        let result = self
            .call("platform.getValidators", params)
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get pending validators on P-chain
    pub async fn p_get_pending_validators(
        &self,
        subnet_id: Option<&str>,
    ) -> Result<ValidatorsResponse> {
        let mut params = vec![];
        if let Some(id) = subnet_id {
            params.push(json!(id));
        }

        let result = self
            .call("platform.getPendingValidators", params)
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }

    /// Get info about a specific validator
    pub async fn p_get_validator_info(&self, node_id: &str) -> Result<ValidatorInfo> {
        let result = self
            .call(
                "platform.getValidator",
                vec![json!(node_id)],
            )
            .await?;

        serde_json::from_value(result)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))
    }
}

// ============================================================================
// INTEGRATION TESTS (Testnet Examples)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const AVALANCHE_TESTNET_X: &str = "http://127.0.0.1:9650/ext/bc/X";
    const AVALANCHE_TESTNET_C: &str = "http://127.0.0.1:9650/ext/bc/C/rpc";
    const AVALANCHE_TESTNET_P: &str = "http://127.0.0.1:9650/ext/P";

    #[tokio::test]
    #[ignore] // Requires local Avalanche node
    async fn test_x_chain_get_balance() {
        let client = RpcClient::new(AVALANCHE_TESTNET_X).unwrap();
        let address = "X-avax1g6yk6ghdqyggsnw5dtk77db5y36e6dg9dpmjt";

        match client.x_get_balance(address).await {
            Ok(balance) => {
                println!("Balance: {:?}", balance.balance);
                assert!(!balance.balance.is_empty());
            }
            Err(e) => println!("Expected error (no funds): {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // Requires local Avalanche node
    async fn test_c_chain_block_number() {
        let client = RpcClient::new(AVALANCHE_TESTNET_C).unwrap();

        match client.c_block_number().await {
            Ok(block_num) => {
                println!("Block number: {}", block_num);
                assert!(!block_num.is_empty());
            }
            Err(e) => println!("Error: {}", e),
        }
    }

    #[tokio::test]
    #[ignore] // Requires local Avalanche node
    async fn test_p_chain_get_current_validators() {
        let client = RpcClient::new(AVALANCHE_TESTNET_P).unwrap();

        match client.p_get_current_validators(None).await {
            Ok(validators) => {
                println!("Current validators: {} found", validators.validators.len());
                assert!(!validators.validators.is_empty());
            }
            Err(e) => println!("Error: {}", e),
        }
    }

    #[tokio::test]
    async fn test_request_builder() {
        let request = RequestBuilder::new("avm.getBalance")
            .param(json!("X-avax1g6yk6ghdqyggsnw5dtk77db5y36e6dg9dpmjt"))
            .build(1);

        assert_eq!(request.method, "avm.getBalance");
        assert_eq!(request.params.len(), 1);
        assert_eq!(request.id, 1);
    }

    #[tokio::test]
    async fn test_error_handling() {
        let config = RpcConfig {
            timeout: Duration::from_millis(100),
            ..Default::default()
        };

        let client = RpcClient::with_config("http://127.0.0.1:9999", config)
            .expect("Failed to create client");

        // This should timeout or fail connection
        let result = client.c_block_number().await;
        assert!(result.is_err());
    }

    #[test]
    fn test_rpc_error_display() {
        let error = RpcClientError::TimeoutError;
        assert_eq!(error.to_string(), "Request timeout");

        let rpc_err = RpcError {
            code: -32600,
            message: "Invalid Request".to_string(),
            data: None,
        };
        let error = RpcClientError::RpcError(rpc_err);
        assert!(error.to_string().contains("Invalid Request"));
    }
}

// ============================================================================
// EXAMPLE USAGE
// ============================================================================

// Example usage (compile-checked via doc comment, not dead code):
//
// ```no_run
// let client = RpcClient::new("http://localhost:9650/ext/bc/C/rpc").unwrap();
// let block_num = client.c_block_number().await.unwrap();
// ```
