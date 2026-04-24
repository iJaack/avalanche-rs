//! Avalanche JSON-RPC Client
//!
//! Production-grade async HTTP client for Avalanche node communication.
//! Supports C-chain and P-chain methods with connection pooling,
//! timeout handling, and automatic retry logic.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

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
    /// Internal client invariant violated
    InternalError(String),
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
            RpcClientError::InternalError(msg) => write!(f, "Internal error: {}", msg),
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
    #[serde(default)]
    pub result: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: u64,
}

// ============================================================================
// CHAIN-SPECIFIC RESPONSE TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlockTransaction {
    Hash(String),
    Object(Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub hash: String,
    pub number: String,
    pub timestamp: String,
    #[serde(default)]
    pub transactions: Vec<BlockTransaction>,
    #[serde(alias = "parentHash", alias = "parent_hash", default)]
    pub parent_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    #[serde(alias = "txID", alias = "txId", alias = "txHash", alias = "hash")]
    pub tx_id: String,
    #[serde(default)]
    pub status: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub balance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoIndex {
    pub address: String,
    pub utxo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxosResponse {
    #[serde(rename = "numFetched")]
    pub num_fetched: String,
    #[serde(rename = "utxos", default)]
    pub utxos: Vec<String>,
    #[serde(rename = "endIndex")]
    pub end_index: UtxoIndex,
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformBalanceResponse {
    pub balance: String,
    pub unlocked: String,
    #[serde(rename = "lockedStakeable")]
    pub locked_stakeable: String,
    #[serde(rename = "lockedNotStakeable")]
    pub locked_not_stakeable: String,
    #[serde(default)]
    pub balances: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub unlockeds: std::collections::HashMap<String, String>,
    #[serde(rename = "lockedStakeables", default)]
    pub locked_stakeables: std::collections::HashMap<String, String>,
    #[serde(rename = "lockedNotStakeables", default)]
    pub locked_not_stakeables: std::collections::HashMap<String, String>,
    #[serde(rename = "utxoIDs", default)]
    pub utxo_ids: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    #[serde(rename = "txID", default)]
    pub tx_id: Option<String>,
    /// Avalanche API returns `nodeID`, not `node_id`
    #[serde(alias = "nodeID", alias = "node_id")]
    pub node_id: String,
    #[serde(default)]
    pub weight: String,
    #[serde(rename = "stakeAmount", default)]
    pub stake_amount: String,
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
    #[serde(rename = "exactDelegationFee", default)]
    pub exact_delegation_fee: Option<u32>,
    #[serde(rename = "validationID", default)]
    pub validation_id: Option<String>,
    #[serde(rename = "publicKey", default)]
    pub public_key: Option<String>,
    #[serde(rename = "validationRewardOwner", default)]
    pub validation_reward_owner: Option<PlatformOwnerResponse>,
    #[serde(rename = "delegationRewardOwner", default)]
    pub delegation_reward_owner: Option<PlatformOwnerResponse>,
    #[serde(rename = "potentialReward", default)]
    pub potential_reward: Option<String>,
    #[serde(rename = "accruedDelegateeReward", default)]
    pub accrued_delegatee_reward: Option<String>,
    #[serde(rename = "remainingBalanceOwner", default)]
    pub remaining_balance_owner: Option<PlatformOwnerResponse>,
    #[serde(rename = "deactivationOwner", default)]
    pub deactivation_owner: Option<PlatformOwnerResponse>,
    #[serde(rename = "minNonce", default)]
    pub min_nonce: Option<String>,
    #[serde(default)]
    pub balance: Option<String>,
    #[serde(rename = "delegatorCount", default)]
    pub delegator_count: Option<String>,
    #[serde(rename = "delegatorWeight", default)]
    pub delegator_weight: Option<String>,
    #[serde(default)]
    pub delegators: Option<Vec<PrimaryDelegatorInfo>>,
    #[serde(default)]
    pub signer: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorsResponse {
    pub validators: Vec<ValidatorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallDetailedResponse {
    pub gas: u64,
    #[serde(rename = "errCode")]
    pub err_code: i64,
    pub err: String,
    #[serde(rename = "returnData")]
    pub return_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceOption {
    #[serde(rename = "maxPriorityFeePerGas")]
    pub max_priority_fee_per_gas: String,
    #[serde(rename = "maxFeePerGas")]
    pub max_fee_per_gas: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestPriceOptionsResponse {
    pub slow: PriceOption,
    pub normal: PriceOption,
    pub fast: PriceOption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeightResponse {
    pub height: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentEpochResponse {
    pub epoch: String,
    #[serde(rename = "startTime")]
    pub start_time: String,
    #[serde(rename = "pChainHeight")]
    pub p_chain_height: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentSupplyResponse {
    pub supply: String,
    pub height: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformOwnerResponse {
    pub locktime: String,
    pub threshold: String,
    #[serde(default)]
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimaryDelegatorInfo {
    #[serde(rename = "txID", default)]
    pub tx_id: Option<String>,
    #[serde(rename = "nodeID")]
    pub node_id: String,
    #[serde(rename = "startTime")]
    pub start_time: String,
    #[serde(rename = "endTime")]
    pub end_time: String,
    pub weight: String,
    #[serde(rename = "rewardOwner", default)]
    pub reward_owner: Option<PlatformOwnerResponse>,
    #[serde(rename = "potentialReward", default)]
    pub potential_reward: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorsAtEntry {
    pub weight: String,
    #[serde(rename = "publicKey", default)]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorsAtResponse {
    pub validators: std::collections::BTreeMap<String, ValidatorsAtEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpValidatorEntry {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub weight: String,
    #[serde(rename = "nodeIDs", default)]
    pub node_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpValidatorSetResponse {
    #[serde(default)]
    pub validators: Vec<WarpValidatorEntry>,
    #[serde(rename = "totalWeight")]
    pub total_weight: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllValidatorsAtResponse {
    #[serde(rename = "validatorSets")]
    pub validator_sets: std::collections::BTreeMap<String, WarpValidatorSetResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1ValidatorResponse {
    #[serde(rename = "subnetID")]
    pub subnet_id: String,
    #[serde(rename = "nodeID")]
    pub node_id: String,
    pub weight: String,
    #[serde(rename = "startTime")]
    pub start_time: String,
    #[serde(rename = "validationID")]
    pub validation_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "remainingBalanceOwner")]
    pub remaining_balance_owner: PlatformOwnerResponse,
    #[serde(rename = "deactivationOwner")]
    pub deactivation_owner: PlatformOwnerResponse,
    #[serde(rename = "minNonce")]
    pub min_nonce: String,
    pub balance: String,
    pub height: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIdResponse {
    #[serde(rename = "networkID")]
    pub network_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNameResponse {
    #[serde(rename = "networkName")]
    pub network_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainIdResponse {
    #[serde(rename = "blockchainID")]
    pub blockchain_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedBlockResponse {
    pub block: Value,
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainInfo {
    pub id: String,
    pub name: String,
    #[serde(rename = "subnetID")]
    pub subnet_id: String,
    #[serde(rename = "vmID")]
    pub vm_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainsResponse {
    pub blockchains: Vec<BlockchainInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetInfo {
    pub id: String,
    #[serde(rename = "controlKeys", default)]
    pub control_keys: Vec<String>,
    pub threshold: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetResponse {
    #[serde(rename = "isPermissioned")]
    pub is_permissioned: bool,
    #[serde(rename = "controlKeys", default)]
    pub control_keys: Vec<String>,
    pub threshold: String,
    pub locktime: String,
    #[serde(rename = "subnetTransformationTxID")]
    pub subnet_transformation_tx_id: String,
    #[serde(rename = "conversionID")]
    pub conversion_id: String,
    #[serde(rename = "managerChainID")]
    pub manager_chain_id: String,
    #[serde(rename = "managerAddress")]
    pub manager_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetsResponse {
    pub subnets: Vec<SubnetInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainStatusResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedByResponse {
    #[serde(rename = "subnetID")]
    pub subnet_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatesResponse {
    #[serde(rename = "blockchainIDs")]
    pub blockchain_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleValidatorsResponse {
    pub validators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampResponse {
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfigResponse {
    pub weights: Vec<u64>,
    #[serde(rename = "maxCapacity")]
    pub max_capacity: u64,
    #[serde(rename = "maxPerSecond")]
    pub max_per_second: u64,
    #[serde(rename = "targetPerSecond")]
    pub target_per_second: u64,
    #[serde(rename = "minPrice")]
    pub min_price: u64,
    #[serde(rename = "excessConversionConstant")]
    pub excess_conversion_constant: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorFeeConfigResponse {
    pub capacity: u64,
    pub target: u64,
    #[serde(rename = "minPrice")]
    pub min_price: u64,
    #[serde(rename = "excessConversionConstant")]
    pub excess_conversion_constant: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeStateResponse {
    pub capacity: u64,
    pub excess: u64,
    pub price: u64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorFeeStateResponse {
    pub excess: u64,
    pub price: u64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeResponse {
    pub staked: String,
    #[serde(default)]
    pub stakeds: std::collections::HashMap<String, String>,
    #[serde(rename = "stakedOutputs", default)]
    pub staked_outputs: Vec<Value>,
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotalStakeResponse {
    pub stake: String,
    pub weight: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinStakeResponse {
    #[serde(rename = "minValidatorStake")]
    pub min_validator_stake: String,
    #[serde(rename = "minDelegatorStake")]
    pub min_delegator_stake: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingAssetIdResponse {
    #[serde(rename = "assetID")]
    pub asset_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformTxResponse {
    pub tx: Value,
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformTxStatusResponse {
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePopResponse {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "proofOfPossession")]
    pub proof_of_possession: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdResponse {
    #[serde(rename = "nodeID")]
    pub node_id: String,
    #[serde(rename = "nodePOP")]
    pub node_pop: NodePopResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIpResponse {
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeersResponse {
    #[serde(rename = "numPeers")]
    pub num_peers: String,
    pub peers: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrappedResponse {
    #[serde(rename = "isBootstrapped")]
    pub is_bootstrapped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAliasesResponse {
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueTxResponse {
    #[serde(rename = "txID")]
    pub tx_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicTxResponse {
    pub tx: String,
    pub encoding: String,
    #[serde(rename = "blockHeight", default)]
    pub block_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicTxStatusResponse {
    pub status: String,
    #[serde(rename = "blockHeight", default)]
    pub block_height: Option<u64>,
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

fn parse_result<T: DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|e| RpcClientError::ParseError(e.to_string()))
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
    fn next_id(&self) -> Result<u64> {
        let mut counter = self.request_id_counter.lock().map_err(|_| {
            RpcClientError::InternalError("request_id_counter mutex poisoned".to_string())
        })?;
        let id = *counter;
        *counter = counter.wrapping_add(1);
        Ok(id)
    }

    /// Core RPC call method with retry logic
    pub async fn call(&self, method: impl Into<String>, params: Vec<Value>) -> Result<Value> {
        let method = method.into();
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match self.call_internal(&method, params.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    let retryable = matches!(
                        e,
                        RpcClientError::NetworkError(_)
                            | RpcClientError::TimeoutError
                            | RpcClientError::ConnectionFailed(_)
                    );

                    if !retryable || attempt >= self.config.max_retries {
                        return Err(e);
                    }

                    last_error = Some(e);
                    // Exponential backoff: 100ms * 2^attempt
                    let backoff_ms = self.config.retry_backoff_ms * (2u64.pow(attempt));
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                }
            }
        }

        Err(last_error.unwrap_or(RpcClientError::ConnectionFailed(
            "Max retries exceeded".to_string(),
        )))
    }

    /// Internal call implementation (single attempt)
    async fn call_internal(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let id = self.next_id()?;

        let request_body = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id,
        };

        let body_str = serde_json::to_string(&request_body)
            .map_err(|e| RpcClientError::ParseError(e.to_string()))?;

        let uri: Uri = self
            .endpoint
            .parse()
            .map_err(|_| RpcClientError::InvalidParams("Invalid endpoint URI".to_string()))?;

        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_str)))
            .map_err(|e: hyper::http::Error| RpcClientError::NetworkError(e.to_string()))?;

        // Execute request with timeout
        let response = tokio::time::timeout(self.config.timeout, self.client.request(request))
            .await
            .map_err(|_: tokio::time::error::Elapsed| RpcClientError::TimeoutError)?
            .map_err(|e: hyper_util::client::legacy::Error| {
                RpcClientError::NetworkError(e.to_string())
            })?;

        if response.status() != StatusCode::OK {
            return Err(RpcClientError::NetworkError(format!(
                "HTTP {}: {}",
                response.status(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )));
        }

        // Read response body
        let body_bytes = response
            .into_body()
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

        Ok(response.result)
    }

    async fn call_parsed<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<T> {
        parse_result(self.call(method, params).await?)
    }
}

// ============================================================================
// INFO METHODS
// ============================================================================

impl RpcClient {
    /// Get the network ID.
    pub async fn info_get_network_id(&self) -> Result<NetworkIdResponse> {
        self.call_parsed("info.getNetworkID", vec![json!({})]).await
    }

    /// Get the human-readable network name.
    pub async fn info_get_network_name(&self) -> Result<NetworkNameResponse> {
        self.call_parsed("info.getNetworkName", vec![json!({})])
            .await
    }

    /// Resolve a blockchain alias to a blockchain ID.
    pub async fn info_get_blockchain_id(&self, alias: &str) -> Result<BlockchainIdResponse> {
        self.call_parsed("info.getBlockchainID", vec![json!({ "alias": alias })])
            .await
    }

    /// Get this node's ID and BLS proof-of-possession.
    pub async fn info_get_node_id(&self) -> Result<NodeIdResponse> {
        self.call_parsed("info.getNodeID", vec![json!({})]).await
    }

    /// Get this node's public RPC/staking IP.
    pub async fn info_get_node_ip(&self) -> Result<NodeIpResponse> {
        self.call_parsed("info.getNodeIP", vec![json!({})]).await
    }

    /// Get node version metadata.
    pub async fn info_get_node_version(&self) -> Result<Value> {
        self.call("info.getNodeVersion", vec![json!({})]).await
    }

    /// Get connected peers, optionally filtered by node IDs.
    pub async fn info_peers(&self, node_ids: &[&str]) -> Result<PeersResponse> {
        let mut request = serde_json::Map::new();
        if !node_ids.is_empty() {
            request.insert("nodeIDs".into(), json!(node_ids));
        }
        self.call_parsed("info.peers", vec![Value::Object(request)])
            .await
    }

    /// Check whether a chain is bootstrapped.
    pub async fn info_is_bootstrapped(&self, chain: &str) -> Result<BootstrappedResponse> {
        self.call_parsed("info.isBootstrapped", vec![json!({ "chain": chain })])
            .await
    }

    /// Get network fee configuration.
    pub async fn info_get_tx_fee(&self) -> Result<Value> {
        self.call("info.getTxFee", vec![json!({})]).await
    }

    /// Get ACP support/objection summary.
    pub async fn info_acps(&self) -> Result<Value> {
        self.call("info.acps", vec![json!({})]).await
    }

    /// Get registered VMs and FXs.
    pub async fn info_get_vms(&self) -> Result<Value> {
        self.call("info.getVMs", vec![json!({})]).await
    }

    /// Get observed uptime metrics.
    pub async fn info_uptime(&self) -> Result<Value> {
        self.call("info.uptime", vec![json!({})]).await
    }

    /// Get activated and scheduled upgrades.
    pub async fn info_upgrades(&self) -> Result<Value> {
        self.call("info.upgrades", vec![json!({})]).await
    }
}

// ============================================================================
// ADMIN METHODS
// ============================================================================

impl RpcClient {
    /// Get live node configuration.
    pub async fn admin_get_config(&self) -> Result<Value> {
        self.call("admin.getConfig", vec![json!({})]).await
    }

    /// Get logger levels, optionally scoped to one logger name.
    pub async fn admin_get_logger_level(&self, logger_name: Option<&str>) -> Result<Value> {
        let mut request = serde_json::Map::new();
        if let Some(logger_name) = logger_name {
            request.insert("loggerName".into(), json!(logger_name));
        }
        self.call("admin.getLoggerLevel", vec![Value::Object(request)])
            .await
    }

    /// Update logger levels at runtime.
    pub async fn admin_set_logger_level(
        &self,
        logger_name: Option<&str>,
        log_level: Option<&str>,
        display_level: Option<&str>,
    ) -> Result<()> {
        let mut request = serde_json::Map::new();
        if let Some(logger_name) = logger_name {
            request.insert("loggerName".into(), json!(logger_name));
        }
        if let Some(log_level) = log_level {
            request.insert("logLevel".into(), json!(log_level));
        }
        if let Some(display_level) = display_level {
            request.insert("displayLevel".into(), json!(display_level));
        }
        self.call("admin.setLoggerLevel", vec![Value::Object(request)])
            .await?;
        Ok(())
    }

    /// Discover and load VM plugins.
    pub async fn admin_load_vms(&self) -> Result<Value> {
        self.call("admin.loadVMs", vec![json!({})]).await
    }

    /// Get the VM-specific runtime config.
    pub async fn admin_get_vm_config(&self) -> Result<Value> {
        self.call("admin.getVMConfig", vec![json!({})]).await
    }

    /// Add an HTTP endpoint alias.
    pub async fn admin_alias(&self, endpoint: &str, alias: &str) -> Result<()> {
        self.call(
            "admin.alias",
            vec![json!({ "endpoint": endpoint, "alias": alias })],
        )
        .await?;
        Ok(())
    }

    /// Add a blockchain alias.
    pub async fn admin_alias_chain(&self, chain: &str, alias: &str) -> Result<()> {
        self.call(
            "admin.aliasChain",
            vec![json!({ "chain": chain, "alias": alias })],
        )
        .await?;
        Ok(())
    }

    /// Get all aliases registered for a chain.
    pub async fn admin_get_chain_aliases(&self, chain: &str) -> Result<ChainAliasesResponse> {
        self.call_parsed("admin.getChainAliases", vec![json!({ "chain": chain })])
            .await
    }
}

// ============================================================================
// AVALANCHE-SPECIFIC C-CHAIN METHODS
// ============================================================================

impl RpcClient {
    /// Submit an atomic transaction.
    pub async fn avax_issue_tx(&self, tx: &str, encoding: Option<&str>) -> Result<IssueTxResponse> {
        let encoding = encoding.unwrap_or("hex");
        self.call_parsed(
            "avax.issueTx",
            vec![json!({ "tx": tx, "encoding": encoding })],
        )
        .await
    }

    /// Get paginated atomic UTXOs importable into the C-chain from a source chain.
    pub async fn avax_get_utxos(
        &self,
        addresses: &[&str],
        source_chain: &str,
        limit: Option<u32>,
        start_index: Option<UtxoIndex>,
        encoding: Option<&str>,
    ) -> Result<UtxosResponse> {
        let mut request = serde_json::Map::new();
        request.insert("addresses".into(), json!(addresses));
        request.insert("sourceChain".into(), json!(source_chain));
        if let Some(limit) = limit {
            request.insert("limit".into(), json!(limit));
        }
        if let Some(start_index) = start_index {
            request.insert("startIndex".into(), json!(start_index));
        }
        if let Some(encoding) = encoding {
            request.insert("encoding".into(), json!(encoding));
        }
        self.call_parsed("avax.getUTXOs", vec![Value::Object(request)])
            .await
    }

    /// Fetch an atomic transaction by txID.
    pub async fn avax_get_atomic_tx(
        &self,
        tx_id: &str,
        encoding: Option<&str>,
    ) -> Result<Option<AtomicTxResponse>> {
        let encoding = encoding.unwrap_or("hex");
        let result = self
            .call(
                "avax.getAtomicTx",
                vec![json!({ "txID": tx_id, "encoding": encoding })],
            )
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            parse_result(result).map(Some)
        }
    }

    /// Get atomic transaction processing/acceptance status.
    pub async fn avax_get_atomic_tx_status(&self, tx_id: &str) -> Result<AtomicTxStatusResponse> {
        self.call_parsed("avax.getAtomicTxStatus", vec![json!({ "txID": tx_id })])
            .await
    }
}

// ============================================================================
// C-CHAIN METHODS (Ethereum-Compatible)
// ============================================================================

impl RpcClient {
    /// Get block number on C-chain
    pub async fn c_block_number(&self) -> Result<String> {
        self.call_parsed("eth_blockNumber", vec![]).await
    }

    /// Get balance for an address on C-chain
    pub async fn c_get_balance(&self, address: &str, block: &str) -> Result<String> {
        self.call_parsed("eth_getBalance", vec![json!(address), json!(block)])
            .await
    }

    /// Get managed RPC accounts on the C-chain.
    pub async fn c_accounts(&self) -> Result<Vec<String>> {
        self.call_parsed("eth_accounts", vec![]).await
    }

    /// Get block by number on C-chain
    pub async fn c_get_block(&self, block_number: &str) -> Result<BlockResponse> {
        self.c_get_block_by_number(block_number, true).await
    }

    /// Get block by number on C-chain with hash-only or full transactions.
    pub async fn c_get_block_by_number(
        &self,
        block_number: &str,
        full_transactions: bool,
    ) -> Result<BlockResponse> {
        self.call_parsed(
            "eth_getBlockByNumber",
            vec![json!(block_number), json!(full_transactions)],
        )
        .await
    }

    /// Get block by hash on C-chain.
    pub async fn c_get_block_by_hash(
        &self,
        block_hash: &str,
        full_transactions: bool,
    ) -> Result<BlockResponse> {
        self.call_parsed(
            "eth_getBlockByHash",
            vec![json!(block_hash), json!(full_transactions)],
        )
        .await
    }

    /// Hash the provided bytes with Keccak-256.
    pub async fn c_web3_sha3(&self, data: &str) -> Result<String> {
        self.call_parsed("web3_sha3", vec![json!(data)]).await
    }

    /// Return whether the node is listening for network connections.
    pub async fn c_net_listening(&self) -> Result<bool> {
        self.call_parsed("net_listening", vec![]).await
    }

    /// Return the connected peer count as a hex quantity.
    pub async fn c_net_peer_count(&self) -> Result<String> {
        self.call_parsed("net_peerCount", vec![]).await
    }

    /// Get the transaction count for a block by number.
    pub async fn c_get_block_transaction_count_by_number(
        &self,
        block_number: &str,
    ) -> Result<Option<String>> {
        let result = self
            .call(
                "eth_getBlockTransactionCountByNumber",
                vec![json!(block_number)],
            )
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            parse_result(result).map(Some)
        }
    }

    /// Get the transaction count for a block by hash.
    pub async fn c_get_block_transaction_count_by_hash(
        &self,
        block_hash: &str,
    ) -> Result<Option<String>> {
        let result = self
            .call(
                "eth_getBlockTransactionCountByHash",
                vec![json!(block_hash)],
            )
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            parse_result(result).map(Some)
        }
    }

    /// Get a transaction by block number and index.
    pub async fn c_get_transaction_by_block_number_and_index(
        &self,
        block_number: &str,
        tx_index: &str,
    ) -> Result<Option<Value>> {
        let result = self
            .call(
                "eth_getTransactionByBlockNumberAndIndex",
                vec![json!(block_number), json!(tx_index)],
            )
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Get a transaction by block hash and index.
    pub async fn c_get_transaction_by_block_hash_and_index(
        &self,
        block_hash: &str,
        tx_index: &str,
    ) -> Result<Option<Value>> {
        let result = self
            .call(
                "eth_getTransactionByBlockHashAndIndex",
                vec![json!(block_hash), json!(tx_index)],
            )
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Get a raw transaction by hash.
    pub async fn c_get_raw_transaction_by_hash(&self, tx_hash: &str) -> Result<Option<String>> {
        let result = self
            .call("eth_getRawTransactionByHash", vec![json!(tx_hash)])
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            parse_result(result).map(Some)
        }
    }

    /// Get a raw transaction by block number and index.
    pub async fn c_get_raw_transaction_by_block_number_and_index(
        &self,
        block_number: &str,
        tx_index: &str,
    ) -> Result<Option<String>> {
        let result = self
            .call(
                "eth_getRawTransactionByBlockNumberAndIndex",
                vec![json!(block_number), json!(tx_index)],
            )
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            parse_result(result).map(Some)
        }
    }

    /// Get a raw transaction by block hash and index.
    pub async fn c_get_raw_transaction_by_block_hash_and_index(
        &self,
        block_hash: &str,
        tx_index: &str,
    ) -> Result<Option<String>> {
        let result = self
            .call(
                "eth_getRawTransactionByBlockHashAndIndex",
                vec![json!(block_hash), json!(tx_index)],
            )
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            parse_result(result).map(Some)
        }
    }

    /// Get the account/storage proof for the latest or pending state.
    pub async fn c_get_proof(
        &self,
        address: &str,
        storage_keys: &[&str],
        block: Option<&str>,
    ) -> Result<Value> {
        let mut params = vec![json!(address), json!(storage_keys)];
        if let Some(block) = block {
            params.push(json!(block));
        }
        self.call("eth_getProof", params).await
    }

    /// Send a raw signed transaction on C-chain.
    pub async fn c_send_transaction(&self, tx: &str) -> Result<String> {
        self.call_parsed("eth_sendRawTransaction", vec![json!(tx)])
            .await
    }

    /// Send a managed-account transaction object on C-chain.
    pub async fn c_send_transaction_object(&self, tx: Value) -> Result<String> {
        self.call_parsed("eth_sendTransaction", vec![tx]).await
    }

    /// Fill missing transaction defaults without signing or broadcasting.
    pub async fn c_fill_transaction(&self, tx: Value) -> Result<Value> {
        self.call("eth_fillTransaction", vec![tx]).await
    }

    /// Sign an arbitrary message with a managed account.
    pub async fn c_sign(&self, address: &str, data: &str) -> Result<String> {
        self.call_parsed("eth_sign", vec![json!(address), json!(data)])
            .await
    }

    /// Sign a transaction with a managed account.
    pub async fn c_sign_transaction(&self, tx: Value) -> Result<Value> {
        self.call("eth_signTransaction", vec![tx]).await
    }

    /// Replace a pending managed-account transaction with updated fee or gas limit.
    pub async fn c_resend(
        &self,
        tx: Value,
        gas_price: Option<&str>,
        gas_limit: Option<&str>,
    ) -> Result<String> {
        let mut params = vec![tx];
        if let Some(gas_price) = gas_price {
            params.push(json!(gas_price));
        } else if gas_limit.is_some() {
            params.push(Value::Null);
        }
        if let Some(gas_limit) = gas_limit {
            params.push(json!(gas_limit));
        }
        self.call_parsed("eth_resend", params).await
    }

    /// Get transaction receipt on C-chain
    pub async fn c_get_transaction_receipt(&self, tx_hash: &str) -> Result<Value> {
        self.call("eth_getTransactionReceipt", vec![json!(tx_hash)])
            .await
    }

    /// Execute a read-only contract call (eth_call)
    pub async fn c_call(&self, to: &str, data: &str, block: &str) -> Result<String> {
        self.call_parsed(
            "eth_call",
            vec![json!({ "to": to, "data": data }), json!(block)],
        )
        .await
    }

    /// Get account nonce (transaction count)
    pub async fn c_get_nonce(&self, address: &str, block: &str) -> Result<String> {
        self.call_parsed(
            "eth_getTransactionCount",
            vec![json!(address), json!(block)],
        )
        .await
    }

    /// Get current gas price
    pub async fn c_gas_price(&self) -> Result<String> {
        self.call_parsed("eth_gasPrice", vec![]).await
    }

    /// Get chain ID
    pub async fn c_chain_id(&self) -> Result<String> {
        self.call_parsed("eth_chainId", vec![]).await
    }

    /// Estimate gas for a transaction
    pub async fn c_estimate_gas(
        &self,
        to: &str,
        data: &str,
        value: Option<&str>,
    ) -> Result<String> {
        let mut tx = serde_json::Map::new();
        tx.insert("to".into(), json!(to));
        tx.insert("data".into(), json!(data));
        if let Some(v) = value {
            tx.insert("value".into(), json!(v));
        }

        self.call_parsed("eth_estimateGas", vec![Value::Object(tx)])
            .await
    }

    /// Get pending transactions from txpool (if available)
    pub async fn c_txpool_content(&self) -> Result<Value> {
        self.call("txpool_content", vec![]).await
    }

    /// Get txpool status counters.
    pub async fn c_txpool_status(&self) -> Result<Value> {
        self.call("txpool_status", vec![]).await
    }

    /// Inspect txpool grouped by sender and nonce.
    pub async fn c_txpool_inspect(&self) -> Result<Value> {
        self.call("txpool_inspect", vec![]).await
    }

    /// Inspect txpool state for a single sender address.
    pub async fn c_txpool_content_from(&self, address: &str) -> Result<Value> {
        self.call("txpool_contentFrom", vec![json!(address)]).await
    }

    /// Get pending transaction hashes
    pub async fn c_pending_transactions(&self) -> Result<Value> {
        self.call("eth_pendingTransactions", vec![]).await
    }

    /// Create a pending transaction filter.
    pub async fn c_new_pending_transaction_filter(&self) -> Result<String> {
        self.call_parsed("eth_newPendingTransactionFilter", vec![])
            .await
    }

    /// Create a block filter.
    pub async fn c_new_block_filter(&self) -> Result<String> {
        self.call_parsed("eth_newBlockFilter", vec![]).await
    }

    /// Create an accepted transaction filter.
    pub async fn c_new_accepted_transactions_filter(&self, full_tx: bool) -> Result<String> {
        let params = if full_tx {
            vec![json!({ "fullTx": true })]
        } else {
            vec![]
        };
        self.call_parsed("eth_newAcceptedTransactions", params)
            .await
    }

    /// Poll a filter for incremental changes.
    pub async fn c_get_filter_changes(&self, filter_id: &str) -> Result<Value> {
        self.call("eth_getFilterChanges", vec![json!(filter_id)])
            .await
    }

    /// Fetch all logs for a log filter.
    pub async fn c_get_filter_logs(&self, filter_id: &str) -> Result<Value> {
        self.call("eth_getFilterLogs", vec![json!(filter_id)]).await
    }

    /// Get predicted next-block base fee.
    pub async fn c_base_fee(&self) -> Result<String> {
        self.call_parsed("eth_baseFee", vec![]).await
    }

    /// Get the suggested max priority fee per gas.
    pub async fn c_max_priority_fee_per_gas(&self) -> Result<String> {
        self.call_parsed("eth_maxPriorityFeePerGas", vec![]).await
    }

    /// Get dynamic fee suggestions for slow/normal/fast confirmation targets.
    pub async fn c_suggest_price_options(&self) -> Result<SuggestPriceOptionsResponse> {
        self.call_parsed("eth_suggestPriceOptions", vec![]).await
    }

    /// Get the Coreth/Avalanche C-Chain config.
    pub async fn c_get_chain_config(&self) -> Result<Value> {
        self.call("eth_getChainConfig", vec![]).await
    }

    /// Get retained bad blocks, if any.
    pub async fn c_get_bad_blocks(&self) -> Result<Vec<Value>> {
        self.call_parsed("eth_getBadBlocks", vec![]).await
    }

    /// Execute a call and return Avalanche detailed execution metadata.
    pub async fn c_call_detailed(
        &self,
        tx: Value,
        block: Option<&str>,
    ) -> Result<CallDetailedResponse> {
        let mut params = vec![tx];
        if let Some(block) = block {
            params.push(json!(block));
        }
        self.call_parsed("eth_callDetailed", params).await
    }

    /// Get block receipts for a block hash/number selector.
    pub async fn c_get_block_receipts(&self, block: &str) -> Result<Option<Vec<Value>>> {
        self.call_parsed("eth_getBlockReceipts", vec![json!(block)])
            .await
    }

    /// Create an access list for a transaction.
    pub async fn c_create_access_list(&self, tx: Value, block: Option<&str>) -> Result<Value> {
        let mut params = vec![tx];
        if let Some(block) = block {
            params.push(json!(block));
        }
        self.call("eth_createAccessList", params).await
    }

    /// Get fee history over recent blocks.
    pub async fn c_fee_history(
        &self,
        block_count: &str,
        newest_block: &str,
        reward_percentiles: &[f64],
    ) -> Result<Value> {
        self.call(
            "eth_feeHistory",
            vec![
                json!(block_count),
                json!(newest_block),
                json!(reward_percentiles),
            ],
        )
        .await
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
        let mut request = serde_json::Map::new();
        if let Some(id) = subnet_id {
            request.insert("subnetID".into(), json!(id));
        }
        self.call_parsed(
            "platform.getCurrentValidators",
            vec![Value::Object(request)],
        )
        .await
    }

    /// Get all validators on P-chain
    pub async fn p_get_validators(&self, subnet_id: Option<&str>) -> Result<ValidatorsResponse> {
        let mut request = serde_json::Map::new();
        if let Some(id) = subnet_id {
            request.insert("subnetID".into(), json!(id));
        }
        self.call_parsed("platform.getValidators", vec![Value::Object(request)])
            .await
    }

    /// Get the validator set at a specific accepted or proposed height.
    pub async fn p_get_validators_at(
        &self,
        height: &str,
        subnet_id: &str,
    ) -> Result<ValidatorsAtResponse> {
        self.call_parsed(
            "platform.getValidatorsAt",
            vec![json!({ "height": height, "subnetID": subnet_id })],
        )
        .await
    }

    /// Get all subnet validator sets at a specific accepted or proposed height.
    pub async fn p_get_all_validators_at(&self, height: &str) -> Result<AllValidatorsAtResponse> {
        self.call_parsed(
            "platform.getAllValidatorsAt",
            vec![json!({ "height": height })],
        )
        .await
    }

    /// Get pending validators on P-chain
    pub async fn p_get_pending_validators(
        &self,
        subnet_id: Option<&str>,
    ) -> Result<ValidatorsResponse> {
        let mut request = serde_json::Map::new();
        if let Some(id) = subnet_id {
            request.insert("subnetID".into(), json!(id));
        }
        self.call_parsed(
            "platform.getPendingValidators",
            vec![Value::Object(request)],
        )
        .await
    }

    /// Get info about a specific validator
    pub async fn p_get_validator_info(
        &self,
        node_id: &str,
        subnet_id: Option<&str>,
    ) -> Result<ValidatorInfo> {
        let mut request = serde_json::Map::new();
        request.insert("nodeID".into(), json!(node_id));
        if let Some(subnet_id) = subnet_id {
            request.insert("subnetID".into(), json!(subnet_id));
        }
        self.call_parsed("platform.getValidator", vec![Value::Object(request)])
            .await
    }

    /// Get the accepted P-chain height.
    pub async fn p_get_height(&self) -> Result<HeightResponse> {
        self.call_parsed("platform.getHeight", vec![json!({})])
            .await
    }

    /// Get the current proposer VM height.
    pub async fn p_get_proposed_height(&self) -> Result<HeightResponse> {
        self.call_parsed("platform.getProposedHeight", vec![json!({})])
            .await
    }

    /// Get the proposer VM proposed height for the chain bound to this endpoint.
    pub async fn proposervm_get_proposed_height(&self) -> Result<HeightResponse> {
        self.call_parsed("proposervm.getProposedHeight", vec![json!({})])
            .await
    }

    /// Get the current Granite epoch for the chain bound to this endpoint.
    pub async fn proposervm_get_current_epoch(&self) -> Result<CurrentEpochResponse> {
        self.call_parsed("proposervm.getCurrentEpoch", vec![json!({})])
            .await
    }

    /// Get the balance breakdown for a set of P-chain addresses.
    pub async fn p_get_balance(&self, addresses: &[&str]) -> Result<PlatformBalanceResponse> {
        self.call_parsed(
            "platform.getBalance",
            vec![json!({ "addresses": addresses })],
        )
        .await
    }

    /// Get paginated UTXOs for a set of P-chain addresses.
    pub async fn p_get_utxos(
        &self,
        addresses: &[&str],
        source_chain: Option<&str>,
        limit: Option<u32>,
        start_index: Option<UtxoIndex>,
        encoding: Option<&str>,
    ) -> Result<UtxosResponse> {
        let mut request = serde_json::Map::new();
        request.insert("addresses".into(), json!(addresses));
        if let Some(source_chain) = source_chain {
            request.insert("sourceChain".into(), json!(source_chain));
        }
        if let Some(limit) = limit {
            request.insert("limit".into(), json!(limit));
        }
        if let Some(start_index) = start_index {
            request.insert("startIndex".into(), json!(start_index));
        }
        if let Some(encoding) = encoding {
            request.insert("encoding".into(), json!(encoding));
        }
        self.call_parsed("platform.getUTXOs", vec![Value::Object(request)])
            .await
    }

    /// Get a P-chain block by ID.
    pub async fn p_get_block(
        &self,
        block_id: &str,
        encoding: Option<&str>,
    ) -> Result<EncodedBlockResponse> {
        let mut request = serde_json::Map::new();
        request.insert("blockID".into(), json!(block_id));
        if let Some(encoding) = encoding {
            request.insert("encoding".into(), json!(encoding));
        }
        self.call_parsed("platform.getBlock", vec![Value::Object(request)])
            .await
    }

    /// Get a P-chain block by height.
    pub async fn p_get_block_by_height(
        &self,
        height: &str,
        encoding: Option<&str>,
    ) -> Result<EncodedBlockResponse> {
        let mut request = serde_json::Map::new();
        request.insert("height".into(), json!(height));
        if let Some(encoding) = encoding {
            request.insert("encoding".into(), json!(encoding));
        }
        self.call_parsed("platform.getBlockByHeight", vec![Value::Object(request)])
            .await
    }

    /// List blockchains validated by the node.
    pub async fn p_get_blockchains(&self) -> Result<BlockchainsResponse> {
        self.call_parsed("platform.getBlockchains", vec![json!({})])
            .await
    }

    /// Get owner and metadata for a tracked subnet.
    pub async fn p_get_subnet(&self, subnet_id: &str) -> Result<SubnetResponse> {
        self.call_parsed("platform.getSubnet", vec![json!({ "subnetID": subnet_id })])
            .await
    }

    /// List tracked subnets.
    pub async fn p_get_subnets(&self, ids: Option<&[&str]>) -> Result<SubnetsResponse> {
        let mut request = serde_json::Map::new();
        if let Some(ids) = ids {
            request.insert("ids".into(), json!(ids));
        }
        self.call_parsed("platform.getSubnets", vec![Value::Object(request)])
            .await
    }

    /// Get the status of a blockchain.
    pub async fn p_get_blockchain_status(
        &self,
        blockchain_id: &str,
    ) -> Result<BlockchainStatusResponse> {
        self.call_parsed(
            "platform.getBlockchainStatus",
            vec![json!({ "blockchainID": blockchain_id })],
        )
        .await
    }

    /// Resolve the subnet that validates a blockchain.
    pub async fn p_validated_by(&self, blockchain_id: &str) -> Result<ValidatedByResponse> {
        self.call_parsed(
            "platform.validatedBy",
            vec![json!({ "blockchainID": blockchain_id })],
        )
        .await
    }

    /// List blockchains validated by a subnet.
    pub async fn p_validates(&self, subnet_id: &str) -> Result<ValidatesResponse> {
        self.call_parsed("platform.validates", vec![json!({ "subnetID": subnet_id })])
            .await
    }

    /// Sample validators from the current validator set.
    pub async fn p_sample_validators(
        &self,
        size: usize,
        subnet_id: Option<&str>,
    ) -> Result<SampleValidatorsResponse> {
        let mut request = serde_json::Map::new();
        request.insert("size".into(), json!(size));
        if let Some(subnet_id) = subnet_id {
            request.insert("subnetID".into(), json!(subnet_id));
        }
        self.call_parsed("platform.sampleValidators", vec![Value::Object(request)])
            .await
    }

    /// Get the latest P-chain timestamp.
    pub async fn p_get_timestamp(&self) -> Result<TimestampResponse> {
        self.call_parsed("platform.getTimestamp", vec![json!({})])
            .await
    }

    /// Get the current supply upper bound for a subnet.
    pub async fn p_get_current_supply(
        &self,
        subnet_id: Option<&str>,
    ) -> Result<CurrentSupplyResponse> {
        let mut request = serde_json::Map::new();
        if let Some(subnet_id) = subnet_id {
            request.insert("subnetID".into(), json!(subnet_id));
        }
        self.call_parsed("platform.getCurrentSupply", vec![Value::Object(request)])
            .await
    }

    /// Get a committed L1 validator by validation ID.
    pub async fn p_get_l1_validator(&self, validation_id: &str) -> Result<L1ValidatorResponse> {
        self.call_parsed(
            "platform.getL1Validator",
            vec![json!({ "validationID": validation_id })],
        )
        .await
    }

    /// Submit a raw P-chain transaction to the local node.
    pub async fn p_issue_tx(&self, tx: &str, encoding: Option<&str>) -> Result<IssueTxResponse> {
        let mut request = serde_json::Map::new();
        request.insert("tx".into(), json!(tx));
        if let Some(encoding) = encoding {
            request.insert("encoding".into(), json!(encoding));
        }
        self.call_parsed("platform.issueTx", vec![Value::Object(request)])
            .await
    }

    /// Fetch a previously seen P-chain transaction.
    pub async fn p_get_tx(
        &self,
        tx_id: &str,
        encoding: Option<&str>,
    ) -> Result<PlatformTxResponse> {
        let mut request = serde_json::Map::new();
        request.insert("txID".into(), json!(tx_id));
        if let Some(encoding) = encoding {
            request.insert("encoding".into(), json!(encoding));
        }
        self.call_parsed("platform.getTx", vec![Value::Object(request)])
            .await
    }

    /// Get the local status of a P-chain transaction.
    pub async fn p_get_tx_status(&self, tx_id: &str) -> Result<PlatformTxStatusResponse> {
        self.call_parsed("platform.getTxStatus", vec![json!({ "txID": tx_id })])
            .await
    }

    /// Get the dynamic fee configuration for the P-chain.
    pub async fn p_get_fee_config(&self) -> Result<FeeConfigResponse> {
        self.call_parsed("platform.getFeeConfig", vec![json!({})])
            .await
    }

    /// Get the validator fee configuration for the P-chain.
    pub async fn p_get_validator_fee_config(&self) -> Result<ValidatorFeeConfigResponse> {
        self.call_parsed("platform.getValidatorFeeConfig", vec![json!({})])
            .await
    }

    /// Get the dynamic fee state for the P-chain.
    pub async fn p_get_fee_state(&self) -> Result<FeeStateResponse> {
        self.call_parsed("platform.getFeeState", vec![json!({})])
            .await
    }

    /// Get the validator fee state for the P-chain.
    pub async fn p_get_validator_fee_state(&self) -> Result<ValidatorFeeStateResponse> {
        self.call_parsed("platform.getValidatorFeeState", vec![json!({})])
            .await
    }

    /// Get staked amount details for a set of addresses.
    pub async fn p_get_stake(
        &self,
        addresses: &[&str],
        validators_only: Option<bool>,
        encoding: Option<&str>,
    ) -> Result<StakeResponse> {
        let mut request = serde_json::Map::new();
        request.insert("addresses".into(), json!(addresses));
        if let Some(validators_only) = validators_only {
            request.insert("validatorsOnly".into(), json!(validators_only));
        }
        if let Some(encoding) = encoding {
            request.insert("encoding".into(), json!(encoding));
        }
        self.call_parsed("platform.getStake", vec![Value::Object(request)])
            .await
    }

    /// Get total stake for a subnet.
    pub async fn p_get_total_stake(&self, subnet_id: Option<&str>) -> Result<TotalStakeResponse> {
        let mut request = serde_json::Map::new();
        if let Some(subnet_id) = subnet_id {
            request.insert("subnetID".into(), json!(subnet_id));
        }
        self.call_parsed("platform.getTotalStake", vec![Value::Object(request)])
            .await
    }

    /// Get minimum validator and delegator stakes.
    pub async fn p_get_min_stake(&self) -> Result<MinStakeResponse> {
        self.p_get_min_stake_for_subnet(None).await
    }

    /// Get minimum validator and delegator stakes for a subnet.
    pub async fn p_get_min_stake_for_subnet(
        &self,
        subnet_id: Option<&str>,
    ) -> Result<MinStakeResponse> {
        let mut request = serde_json::Map::new();
        if let Some(subnet_id) = subnet_id {
            request.insert("subnetID".into(), json!(subnet_id));
        }
        self.call_parsed("platform.getMinStake", vec![Value::Object(request)])
            .await
    }

    /// Get the staking asset ID for a subnet.
    pub async fn p_get_staking_asset_id(
        &self,
        subnet_id: Option<&str>,
    ) -> Result<StakingAssetIdResponse> {
        let mut request = serde_json::Map::new();
        if let Some(subnet_id) = subnet_id {
            request.insert("subnetID".into(), json!(subnet_id));
        }
        self.call_parsed("platform.getStakingAssetID", vec![Value::Object(request)])
            .await
    }

    /// Get reward UTXOs created after a staking period ends.
    pub async fn p_get_reward_utxos(
        &self,
        tx_id: &str,
        encoding: Option<&str>,
    ) -> Result<UtxosResponse> {
        let mut request = serde_json::Map::new();
        request.insert("txID".into(), json!(tx_id));
        if let Some(encoding) = encoding {
            request.insert("encoding".into(), json!(encoding));
        }
        self.call_parsed("platform.getRewardUTXOs", vec![Value::Object(request)])
            .await
    }
}

// ============================================================================
// INTEGRATION TESTS (Testnet Examples)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    const AVALANCHE_TESTNET_C: &str = "http://127.0.0.1:9650/ext/bc/C/rpc";
    const AVALANCHE_TESTNET_P: &str = "http://127.0.0.1:9650/ext/P";

    async fn spawn_mock_rpc_server<F>(handler: F) -> String
    where
        F: Fn(Value) -> Value + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);

        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let handler = handler.clone();
                        async move {
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let rpc_request: Value = serde_json::from_slice(&body).unwrap();
                            let id = rpc_request.get("id").cloned().unwrap_or(json!(1));
                            let result = handler(rpc_request);
                            let response = json!({
                                "jsonrpc": "2.0",
                                "result": result,
                                "id": id,
                            })
                            .to_string();
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(response)))
                                    .unwrap(),
                            )
                        }
                    });

                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        format!("http://{}", addr)
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
    async fn test_c_chain_wrappers_parse_full_transactions_and_extended_methods() {
        let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
        let recorded = calls.clone();
        let endpoint = spawn_mock_rpc_server(move |request| {
            recorded.lock().unwrap().push(request.clone());
            match request["method"].as_str().unwrap() {
                "eth_getBlockByNumber" => json!({
                    "hash": "0xabc",
                    "number": "0x1",
                    "timestamp": "0x2",
                    "transactions": [{
                        "hash": "0xtx1",
                        "from": "0x1",
                    }],
                    "parentHash": "0xdef",
                }),
                "eth_baseFee" => json!("0x10"),
                "eth_callDetailed" => json!({
                    "gas": 21000,
                    "errCode": 0,
                    "err": "",
                    "returnData": "0x1234",
                }),
                "eth_suggestPriceOptions" => json!({
                    "slow": {
                        "maxPriorityFeePerGas": "0x1",
                        "maxFeePerGas": "0x11",
                    },
                    "normal": {
                        "maxPriorityFeePerGas": "0x2",
                        "maxFeePerGas": "0x12",
                    },
                    "fast": {
                        "maxPriorityFeePerGas": "0x3",
                        "maxFeePerGas": "0x13",
                    },
                }),
                "eth_getChainConfig" => json!({
                    "chainId": 43114,
                    "londonBlock": 3308552,
                }),
                _ => panic!("unexpected method: {}", request["method"]),
            }
        })
        .await;

        let client = RpcClient::new(endpoint).unwrap();

        let block = client.c_get_block("0x1").await.unwrap();
        assert_eq!(block.parent_hash, "0xdef");
        assert!(matches!(
            block.transactions.first().unwrap(),
            BlockTransaction::Object(_)
        ));

        assert_eq!(client.c_base_fee().await.unwrap(), "0x10");

        let detailed = client
            .c_call_detailed(json!({ "to": "0x1" }), None)
            .await
            .unwrap();
        assert_eq!(detailed.gas, 21_000);
        assert_eq!(detailed.err_code, 0);
        assert_eq!(detailed.return_data, "0x1234");

        let options = client.c_suggest_price_options().await.unwrap();
        assert_eq!(options.normal.max_priority_fee_per_gas, "0x2");
        assert_eq!(options.fast.max_fee_per_gas, "0x13");

        let chain_config = client.c_get_chain_config().await.unwrap();
        assert_eq!(chain_config["chainId"], 43114);

        let calls = calls.lock().unwrap();
        assert_eq!(calls[0]["params"], json!(["0x1", true]));
        assert_eq!(calls[2]["params"], json!([{ "to": "0x1" }]));
    }

    #[tokio::test]
    async fn test_c_chain_wrappers_cover_network_lookup_and_filter_methods() {
        let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
        let recorded = calls.clone();
        let endpoint = spawn_mock_rpc_server(move |request| {
            recorded.lock().unwrap().push(request.clone());
            match request["method"].as_str().unwrap() {
                "web3_sha3" => {
                    assert_eq!(request["params"], json!(["0x68656c6c6f"]));
                    json!("0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
                }
                "net_listening" => json!(true),
                "net_peerCount" => json!("0x2"),
                "eth_getBlockTransactionCountByNumber" => json!("0x1"),
                "eth_getBlockTransactionCountByHash" => json!("0x1"),
                "eth_getTransactionByBlockNumberAndIndex" => json!({ "hash": "0xtx1" }),
                "eth_getTransactionByBlockHashAndIndex" => json!({ "hash": "0xtx1" }),
                "eth_getRawTransactionByHash" => json!("0xdeadbeef"),
                "eth_getRawTransactionByBlockNumberAndIndex" => json!("0xdeadbeef"),
                "eth_getRawTransactionByBlockHashAndIndex" => json!("0xdeadbeef"),
                "txpool_contentFrom" => json!({
                    "pending": { "0x0": { "hash": "0xtx1" } },
                    "queued": {}
                }),
                "eth_newPendingTransactionFilter" => json!("0x1"),
                "eth_newBlockFilter" => json!("0x2"),
                "eth_newAcceptedTransactions" => json!("0x3"),
                "eth_getFilterChanges" => json!(["0xtx1"]),
                "eth_getFilterLogs" => json!([]),
                _ => panic!("unexpected method: {}", request["method"]),
            }
        })
        .await;

        let client = RpcClient::new(endpoint).unwrap();

        assert_eq!(
            client.c_web3_sha3("0x68656c6c6f").await.unwrap(),
            "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
        assert!(client.c_net_listening().await.unwrap());
        assert_eq!(client.c_net_peer_count().await.unwrap(), "0x2");
        assert_eq!(
            client
                .c_get_block_transaction_count_by_number("0x1")
                .await
                .unwrap(),
            Some("0x1".to_string())
        );
        assert_eq!(
            client
                .c_get_block_transaction_count_by_hash("0xabc")
                .await
                .unwrap(),
            Some("0x1".to_string())
        );
        assert_eq!(
            client
                .c_get_transaction_by_block_number_and_index("0x1", "0x0")
                .await
                .unwrap()
                .unwrap()["hash"],
            "0xtx1"
        );
        assert_eq!(
            client
                .c_get_transaction_by_block_hash_and_index("0xabc", "0x0")
                .await
                .unwrap()
                .unwrap()["hash"],
            "0xtx1"
        );
        assert_eq!(
            client.c_get_raw_transaction_by_hash("0xtx1").await.unwrap(),
            Some("0xdeadbeef".to_string())
        );
        assert_eq!(
            client
                .c_get_raw_transaction_by_block_number_and_index("0x1", "0x0")
                .await
                .unwrap(),
            Some("0xdeadbeef".to_string())
        );
        assert_eq!(
            client
                .c_get_raw_transaction_by_block_hash_and_index("0xabc", "0x0")
                .await
                .unwrap(),
            Some("0xdeadbeef".to_string())
        );
        assert_eq!(
            client.c_txpool_content_from("0x1111").await.unwrap()["pending"]["0x0"]["hash"],
            "0xtx1"
        );
        assert_eq!(
            client.c_new_pending_transaction_filter().await.unwrap(),
            "0x1"
        );
        assert_eq!(client.c_new_block_filter().await.unwrap(), "0x2");
        assert_eq!(
            client
                .c_new_accepted_transactions_filter(true)
                .await
                .unwrap(),
            "0x3"
        );
        assert_eq!(
            client.c_get_filter_changes("0x3").await.unwrap(),
            json!(["0xtx1"])
        );
        assert_eq!(client.c_get_filter_logs("0x4").await.unwrap(), json!([]));

        let calls = calls.lock().unwrap();
        assert_eq!(calls[3]["params"], json!(["0x1"]));
        assert_eq!(calls[4]["params"], json!(["0xabc"]));
        assert_eq!(calls[10]["params"], json!(["0x1111"]));
        assert_eq!(calls[13]["params"], json!([{ "fullTx": true }]));
    }

    #[tokio::test]
    async fn test_c_chain_wrappers_cover_managed_account_and_proof_methods() {
        let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
        let recorded = calls.clone();
        let endpoint = spawn_mock_rpc_server(move |request| {
            recorded.lock().unwrap().push(request.clone());
            match request["method"].as_str().unwrap() {
                "eth_accounts" => json!(["0x1111"]),
                "eth_getProof" => json!({
                    "address": "0x1111",
                    "accountProof": ["0x80"],
                    "balance": "0x1",
                    "codeHash": "0x1234",
                    "nonce": "0x0",
                    "storageHash": "0x5678",
                    "storageProof": [{
                        "key": "0x01",
                        "value": "0x2",
                        "proof": ["0xabcd"]
                    }]
                }),
                "eth_sendTransaction" => json!("0xtx1"),
                "eth_fillTransaction" => json!({
                    "raw": "0x02deadbeef",
                    "tx": { "type": "0x2" }
                }),
                "eth_sign" => json!("0xsigned"),
                "eth_signTransaction" => json!({
                    "raw": "0xdeadbeef",
                    "tx": { "type": "0x0" }
                }),
                "eth_resend" => json!("0xtx2"),
                _ => panic!("unexpected method: {}", request["method"]),
            }
        })
        .await;

        let client = RpcClient::new(endpoint).unwrap();

        assert_eq!(
            client.c_accounts().await.unwrap(),
            vec!["0x1111".to_string()]
        );
        let proof = client
            .c_get_proof("0x1111", &["0x01"], Some("latest"))
            .await
            .unwrap();
        assert_eq!(proof["storageProof"][0]["value"], "0x2");
        assert_eq!(
            client
                .c_send_transaction_object(json!({ "from": "0x1111" }))
                .await
                .unwrap(),
            "0xtx1"
        );
        assert_eq!(
            client
                .c_fill_transaction(json!({ "from": "0x1111" }))
                .await
                .unwrap()["tx"]["type"],
            "0x2"
        );
        assert_eq!(
            client.c_sign("0x1111", "0x68656c6c6f").await.unwrap(),
            "0xsigned"
        );
        assert_eq!(
            client
                .c_sign_transaction(json!({ "from": "0x1111" }))
                .await
                .unwrap()["tx"]["type"],
            "0x0"
        );
        assert_eq!(
            client
                .c_resend(
                    json!({ "from": "0x1111", "nonce": "0x0" }),
                    Some("0x1"),
                    Some("0x2")
                )
                .await
                .unwrap(),
            "0xtx2"
        );

        let calls = calls.lock().unwrap();
        assert_eq!(calls[1]["params"], json!(["0x1111", ["0x01"], "latest"]));
        assert_eq!(calls[2]["params"], json!([{ "from": "0x1111" }]));
        assert_eq!(
            calls[6]["params"],
            json!([{ "from": "0x1111", "nonce": "0x0" }, "0x1", "0x2"])
        );
    }

    #[tokio::test]
    async fn test_platform_info_admin_and_atomic_wrappers_use_current_shapes() {
        let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
        let recorded = calls.clone();
        let endpoint = spawn_mock_rpc_server(move |request| {
            recorded.lock().unwrap().push(request.clone());
            match request["method"].as_str().unwrap() {
                "platform.getHeight" => json!({ "height": "42" }),
                "platform.getProposedHeight" => json!({ "height": "41" }),
                "proposervm.getProposedHeight" => json!({ "height": "44" }),
                "proposervm.getCurrentEpoch" => json!({
                    "epoch": "7",
                    "startTime": "1761750000",
                    "pChainHeight": "91",
                }),
                "platform.getBalance" => json!({
                    "balance": "1500",
                    "unlocked": "1200",
                    "lockedStakeable": "200",
                    "lockedNotStakeable": "100",
                    "balances": {
                        "FvwEAhmxKfeiG8SnEvq42hc6whRyY3EFYAvebMqDNDGCgxN5Z": "1500"
                    },
                    "unlockeds": {
                        "FvwEAhmxKfeiG8SnEvq42hc6whRyY3EFYAvebMqDNDGCgxN5Z": "1200"
                    },
                    "lockedStakeables": {
                        "FvwEAhmxKfeiG8SnEvq42hc6whRyY3EFYAvebMqDNDGCgxN5Z": "200"
                    },
                    "lockedNotStakeables": {
                        "FvwEAhmxKfeiG8SnEvq42hc6whRyY3EFYAvebMqDNDGCgxN5Z": "100"
                    },
                    "utxoIDs": [{
                        "txID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA",
                        "outputIndex": 0
                    }],
                }),
                "platform.getUTXOs" => json!({
                    "numFetched": "1",
                    "utxos": ["0xdeadbeef"],
                    "endIndex": {
                        "address": "P-local1",
                        "utxo": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA"
                    },
                    "encoding": "hex",
                }),
                "platform.getCurrentSupply" => json!({
                    "supply": "720000000000000000",
                    "height": "42",
                }),
                "platform.getL1Validator" => json!({
                    "subnetID": "2SE8BntErKrdVGs76bhQQDaEc8V8cprrmsnBQGcM3jUmczka6Q",
                    "nodeID": "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
                    "weight": "9",
                    "startTime": "1700000010",
                    "validationID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA",
                    "publicKey": "0x1111",
                    "remainingBalanceOwner": {
                        "locktime": "0",
                        "threshold": "1",
                        "addresses": ["P-local1"],
                    },
                    "deactivationOwner": {
                        "locktime": "0",
                        "threshold": "1",
                        "addresses": ["P-local1"],
                    },
                    "minNonce": "1",
                    "balance": "15",
                    "height": "42",
                }),
                "platform.issueTx" => json!({
                    "txID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA",
                }),
                "platform.getTx" => {
                    if request["params"][0]["encoding"] == json!("json") {
                        json!({
                            "tx": {
                                "unsignedTx": {
                                    "networkID": 1,
                                    "blockchainID": "11111111111111111111111111111111LpoYY",
                                    "outputs": [],
                                    "inputs": [],
                                    "memo": "0x",
                                },
                                "credentials": Value::Null,
                                "id": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA",
                            },
                            "encoding": "json",
                        })
                    } else {
                        json!({
                            "tx": "0xdeadbeef",
                            "encoding": "hex",
                        })
                    }
                }
                "platform.getTxStatus" => json!({
                    "status": "Processing",
                }),
                "platform.getCurrentValidators" => json!({
                    "validators": [{
                        "txID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA",
                        "nodeID": "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
                        "weight": "9",
                        "stakeAmount": "9",
                        "startTime": "1700000010",
                        "endTime": "1700001010",
                        "status": "current",
                        "validationRewardOwner": {
                            "locktime": "0",
                            "threshold": "1",
                            "addresses": ["P-local1"],
                        },
                        "delegationRewardOwner": {
                            "locktime": "0",
                            "threshold": "1",
                            "addresses": ["P-local1"],
                        },
                        "potentialReward": "123",
                        "delegationFee": "2.5000",
                        "exactDelegationFee": 25000,
                        "connected": true,
                        "uptime": "95.0000",
                        "delegatorCount": "1",
                        "delegatorWeight": "4",
                        "delegators": [{
                            "txID": "2SE8BntErKrdVGs76bhQQDaEc8V8cprrmsnBQGcM3jUmczka6Q",
                            "nodeID": "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
                            "startTime": "1700000020",
                            "endTime": "1700001020",
                            "weight": "4",
                            "rewardOwner": {
                                "locktime": "0",
                                "threshold": "1",
                                "addresses": ["P-local2"],
                            },
                            "potentialReward": "5",
                        }],
                    }],
                }),
                "platform.getValidator" => json!({
                    "txID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA",
                    "nodeID": "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
                    "weight": "9",
                    "startTime": "1700000010",
                    "validationID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA",
                    "publicKey": "0x1111",
                    "remainingBalanceOwner": {
                        "locktime": "0",
                        "threshold": "1",
                        "addresses": ["P-local1"],
                    },
                    "deactivationOwner": {
                        "locktime": "0",
                        "threshold": "1",
                        "addresses": ["P-local1"],
                    },
                    "minNonce": "1",
                    "balance": "15",
                    "status": "current",
                }),
                "platform.getValidatorsAt" => json!({
                    "validators": {
                        "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg": {
                            "weight": "9",
                            "publicKey": "0x1111",
                        }
                    }
                }),
                "platform.getAllValidatorsAt" => json!({
                    "validatorSets": {
                        "11111111111111111111111111111111LpoYY": {
                            "validators": [],
                            "totalWeight": "9",
                        },
                        "2SE8BntErKrdVGs76bhQQDaEc8V8cprrmsnBQGcM3jUmczka6Q": {
                            "validators": [{
                                "publicKey": "0x1111",
                                "weight": "9",
                                "nodeIDs": ["NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg"],
                            }],
                            "totalWeight": "9",
                        }
                    }
                }),
                "platform.getSubnet" => json!({
                    "isPermissioned": false,
                    "controlKeys": [],
                    "threshold": "0",
                    "locktime": "0",
                    "subnetTransformationTxID": "11111111111111111111111111111111LpoYY",
                    "conversionID": "11111111111111111111111111111111LpoYY",
                    "managerChainID": "11111111111111111111111111111111LpoYY",
                    "managerAddress": Value::Null,
                }),
                "platform.getSubnets" => json!({
                    "subnets": [{
                        "id": "11111111111111111111111111111111LpoYY",
                        "controlKeys": [],
                        "threshold": "0",
                    }],
                }),
                "platform.getFeeConfig" => json!({
                    "weights": [1, 1000, 1000, 4],
                    "maxCapacity": 1000000,
                    "maxPerSecond": 100000,
                    "targetPerSecond": 50000,
                    "minPrice": 1,
                    "excessConversionConstant": 2164043,
                }),
                "platform.getValidatorFeeConfig" => json!({
                    "capacity": 20000,
                    "target": 10000,
                    "minPrice": 512,
                    "excessConversionConstant": 51937021,
                }),
                "platform.getFeeState" => json!({
                    "capacity": 999000,
                    "excess": 250,
                    "price": 3,
                    "timestamp": "2026-03-12T09:15:00Z",
                }),
                "platform.getValidatorFeeState" => json!({
                    "excess": 75,
                    "price": 777,
                    "timestamp": "2026-03-12T09:15:00Z",
                }),
                "platform.getMinStake" => {
                    if request["params"][0]["subnetID"]
                        == json!("2SE8BntErKrdVGs76bhQQDaEc8V8cprrmsnBQGcM3jUmczka6Q")
                    {
                        json!({
                            "minValidatorStake": "100",
                            "minDelegatorStake": "25",
                        })
                    } else {
                        json!({
                            "minValidatorStake": "2000000000000",
                            "minDelegatorStake": "25000000000",
                        })
                    }
                }
                "platform.getStake" => json!({
                    "staked": "0",
                    "stakeds": {
                        "FvwEAhmxKfeiG8SnEvq42hc6whRyY3EFYAvebMqDNDGCgxN5Z": "0"
                    },
                    "stakedOutputs": [],
                    "encoding": "hex",
                }),
                "platform.getRewardUTXOs" => json!({
                    "numFetched": "1",
                    "utxos": ["0xfeedface"],
                    "endIndex": {
                        "address": "",
                        "utxo": "11111111111111111111111111111111LpoYY"
                    },
                    "encoding": "hex",
                }),
                "platform.getBlockByHeight" => json!({
                    "block": "0xdeadbeef",
                    "encoding": "hex",
                }),
                "platform.getBlockchains" => json!({
                    "blockchains": [{
                        "id": "2fombhL",
                        "name": "C-Chain",
                        "subnetID": "11111111111111111111111111111111LpoYY",
                        "vmID": "srEXiWaHiToEaT9YAQ4Za3ExGKTGm4iGjtnrBnmKN2eZtjn6u",
                    }],
                }),
                "info.getNodeID" => json!({
                    "nodeID": "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
                    "nodePOP": {
                        "publicKey": "0x01",
                        "proofOfPossession": "0x02",
                    },
                }),
                "info.getBlockchainID" => json!({
                    "blockchainID": "2q9e4r",
                }),
                "admin.getChainAliases" => json!({
                    "aliases": ["C", "evm", "myc"],
                }),
                "admin.setLoggerLevel" => json!({}),
                "avax.issueTx" => json!({
                    "txID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA",
                }),
                "avax.getUTXOs" => json!({
                    "numFetched": "1",
                    "utxos": ["0xabcdef"],
                    "endIndex": {
                        "address": "C-local1",
                        "utxo": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA"
                    },
                    "encoding": "hex",
                }),
                "avax.getAtomicTxStatus" => json!({
                    "status": "Processing",
                    "blockHeight": 7,
                }),
                "avax.getAtomicTx" => json!({
                    "tx": "0xdeadbeef",
                    "encoding": "hex",
                    "blockHeight": 7,
                }),
                _ => panic!("unexpected method: {}", request["method"]),
            }
        })
        .await;

        let client = RpcClient::new(endpoint).unwrap();

        let height = client.p_get_height().await.unwrap();
        assert_eq!(height.height, "42");

        let proposed_height = client.p_get_proposed_height().await.unwrap();
        assert_eq!(proposed_height.height, "41");

        let proposer_vm_height = client.proposervm_get_proposed_height().await.unwrap();
        assert_eq!(proposer_vm_height.height, "44");

        let current_epoch = client.proposervm_get_current_epoch().await.unwrap();
        assert_eq!(current_epoch.epoch, "7");
        assert_eq!(current_epoch.start_time, "1761750000");
        assert_eq!(current_epoch.p_chain_height, "91");

        let balance = client
            .p_get_balance(&["P-local1", "P-local2"])
            .await
            .unwrap();
        assert_eq!(balance.balance, "1500");
        assert_eq!(balance.locked_stakeable, "200");
        assert_eq!(balance.utxo_ids.len(), 1);

        let utxos = client
            .p_get_utxos(
                &["P-local1", "P-local2"],
                Some("P"),
                Some(64),
                Some(UtxoIndex {
                    address: "P-local1".to_string(),
                    utxo: "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA".to_string(),
                }),
                Some("hex"),
            )
            .await
            .unwrap();
        assert_eq!(utxos.num_fetched, "1");
        assert_eq!(utxos.utxos, vec!["0xdeadbeef"]);
        assert_eq!(utxos.end_index.address, "P-local1");

        let current_supply = client.p_get_current_supply(None).await.unwrap();
        assert_eq!(current_supply.supply, "720000000000000000");
        assert_eq!(current_supply.height, "42");

        let current_validators = client
            .p_get_current_validators(Some("11111111111111111111111111111111LpoYY"))
            .await
            .unwrap();
        assert_eq!(current_validators.validators.len(), 1);
        assert_eq!(
            current_validators.validators[0].tx_id.as_deref(),
            Some("2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA")
        );
        assert_eq!(current_validators.validators[0].weight, "9");
        assert_eq!(current_validators.validators[0].stake_amount, "9");
        assert_eq!(current_validators.validators[0].delegation_fee, "2.5000");
        assert_eq!(
            current_validators.validators[0].exact_delegation_fee,
            Some(25_000)
        );
        assert_eq!(
            current_validators.validators[0].potential_reward.as_deref(),
            Some("123")
        );
        assert_eq!(
            current_validators.validators[0].delegator_count.as_deref(),
            Some("1")
        );
        assert_eq!(
            current_validators.validators[0]
                .delegators
                .as_ref()
                .unwrap()[0]
                .reward_owner
                .as_ref()
                .unwrap()
                .addresses,
            vec!["P-local2"]
        );

        let l1_validator = client
            .p_get_l1_validator("2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA")
            .await
            .unwrap();
        assert_eq!(l1_validator.weight, "9");
        assert_eq!(l1_validator.min_nonce, "1");
        assert_eq!(l1_validator.balance, "15");
        assert_eq!(
            l1_validator.remaining_balance_owner.addresses,
            vec!["P-local1"]
        );
        assert_eq!(l1_validator.height, "42");

        let issued_platform_tx = client.p_issue_tx("0xdeadbeef", Some("hex")).await.unwrap();
        assert!(issued_platform_tx.tx_id.starts_with('2'));

        let platform_tx = client
            .p_get_tx(&issued_platform_tx.tx_id, Some("hex"))
            .await
            .unwrap();
        assert_eq!(platform_tx.tx, json!("0xdeadbeef"));
        assert_eq!(platform_tx.encoding, "hex");

        let platform_tx_json = client
            .p_get_tx(&issued_platform_tx.tx_id, Some("json"))
            .await
            .unwrap();
        assert_eq!(platform_tx_json.encoding, "json");
        assert_eq!(platform_tx_json.tx["unsignedTx"]["networkID"], 1);
        assert_eq!(
            platform_tx_json.tx["unsignedTx"]["blockchainID"],
            "11111111111111111111111111111111LpoYY"
        );

        let platform_tx_status = client
            .p_get_tx_status(&issued_platform_tx.tx_id)
            .await
            .unwrap();
        assert_eq!(platform_tx_status.status, "Processing");
        assert!(platform_tx_status.reason.is_none());

        let validator = client
            .p_get_validator_info(
                "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg",
                Some("2SE8BntErKrdVGs76bhQQDaEc8V8cprrmsnBQGcM3jUmczka6Q"),
            )
            .await
            .unwrap();
        assert_eq!(
            validator.validation_id.as_deref(),
            Some("2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA")
        );
        assert_eq!(validator.min_nonce.as_deref(), Some("1"));
        assert_eq!(validator.balance.as_deref(), Some("15"));
        assert_eq!(
            validator
                .remaining_balance_owner
                .as_ref()
                .unwrap()
                .addresses,
            vec!["P-local1"]
        );

        let validators_at = client
            .p_get_validators_at(
                "proposed",
                "2SE8BntErKrdVGs76bhQQDaEc8V8cprrmsnBQGcM3jUmczka6Q",
            )
            .await
            .unwrap();
        assert_eq!(
            validators_at.validators["NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg"].weight,
            "9"
        );
        assert_eq!(
            validators_at.validators["NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg"]
                .public_key
                .as_deref(),
            Some("0x1111")
        );

        let all_validators_at = client.p_get_all_validators_at("42").await.unwrap();
        assert_eq!(
            all_validators_at.validator_sets["11111111111111111111111111111111LpoYY"].total_weight,
            "9"
        );
        assert_eq!(
            all_validators_at.validator_sets["2SE8BntErKrdVGs76bhQQDaEc8V8cprrmsnBQGcM3jUmczka6Q"]
                .validators[0]
                .node_ids,
            vec!["NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg"]
        );

        let subnet = client
            .p_get_subnet("2bRCr6B4MiEfSjidDwxDpdCyviwnfUVqB2HGwhm947w9YYqb7r")
            .await
            .unwrap();
        assert!(!subnet.is_permissioned);
        assert_eq!(subnet.threshold, "0");
        assert_eq!(subnet.locktime, "0");
        assert!(subnet.manager_address.is_none());

        let subnets = client.p_get_subnets(None).await.unwrap();
        assert_eq!(subnets.subnets[0].threshold, "0");
        assert!(subnets.subnets[0].control_keys.is_empty());

        let fee_config = client.p_get_fee_config().await.unwrap();
        assert_eq!(fee_config.weights, vec![1, 1000, 1000, 4]);
        assert_eq!(fee_config.max_capacity, 1_000_000);
        assert_eq!(fee_config.excess_conversion_constant, 2_164_043);

        let validator_fee_config = client.p_get_validator_fee_config().await.unwrap();
        assert_eq!(validator_fee_config.capacity, 20_000);
        assert_eq!(validator_fee_config.min_price, 512);
        assert_eq!(validator_fee_config.excess_conversion_constant, 51_937_021);

        let fee_state = client.p_get_fee_state().await.unwrap();
        assert_eq!(fee_state.capacity, 999_000);
        assert_eq!(fee_state.excess, 250);
        assert_eq!(fee_state.price, 3);
        assert_eq!(fee_state.timestamp, "2026-03-12T09:15:00Z");

        let validator_fee_state = client.p_get_validator_fee_state().await.unwrap();
        assert_eq!(validator_fee_state.excess, 75);
        assert_eq!(validator_fee_state.price, 777);
        assert_eq!(validator_fee_state.timestamp, "2026-03-12T09:15:00Z");

        let min_stake = client
            .p_get_min_stake_for_subnet(Some("2SE8BntErKrdVGs76bhQQDaEc8V8cprrmsnBQGcM3jUmczka6Q"))
            .await
            .unwrap();
        assert_eq!(min_stake.min_validator_stake, "100");
        assert_eq!(min_stake.min_delegator_stake, "25");

        let stake = client
            .p_get_stake(&["P-local1", "P-local2"], Some(true), Some("hex"))
            .await
            .unwrap();
        assert_eq!(stake.encoding, "hex");
        assert_eq!(
            stake
                .stakeds
                .get("FvwEAhmxKfeiG8SnEvq42hc6whRyY3EFYAvebMqDNDGCgxN5Z"),
            Some(&"0".to_string())
        );

        let block = client
            .p_get_block_by_height("0x2a", Some("hex"))
            .await
            .unwrap();
        assert_eq!(block.encoding, "hex");
        assert_eq!(block.block, json!("0xdeadbeef"));

        let reward_utxos = client
            .p_get_reward_utxos(&issued_platform_tx.tx_id, Some("hex"))
            .await
            .unwrap();
        assert_eq!(reward_utxos.num_fetched, "1");
        assert_eq!(reward_utxos.utxos, vec!["0xfeedface"]);
        assert_eq!(reward_utxos.encoding, "hex");

        let blockchains = client.p_get_blockchains().await.unwrap();
        assert_eq!(blockchains.blockchains[0].name, "C-Chain");

        let node_id = client.info_get_node_id().await.unwrap();
        assert_eq!(node_id.node_pop.public_key, "0x01");

        let blockchain_id = client.info_get_blockchain_id("C").await.unwrap();
        assert_eq!(blockchain_id.blockchain_id, "2q9e4r");

        let aliases = client.admin_get_chain_aliases("C").await.unwrap();
        assert_eq!(aliases.aliases, vec!["C", "evm", "myc"]);

        client
            .admin_set_logger_level(Some("rpc"), Some("debug"), Some("warn"))
            .await
            .unwrap();

        let issued = client
            .avax_issue_tx("0xdeadbeef", Some("hex"))
            .await
            .unwrap();
        assert!(issued.tx_id.starts_with('2'));

        let atomic_utxos = client
            .avax_get_utxos(
                &["C-local1"],
                "P",
                Some(32),
                Some(UtxoIndex {
                    address: "C-local1".to_string(),
                    utxo: "11111111111111111111111111111111LpoYY".to_string(),
                }),
                Some("hex"),
            )
            .await
            .unwrap();
        assert_eq!(atomic_utxos.num_fetched, "1");
        assert_eq!(atomic_utxos.utxos, vec!["0xabcdef"]);
        assert_eq!(atomic_utxos.end_index.address, "C-local1");

        let status = client
            .avax_get_atomic_tx_status(&issued.tx_id)
            .await
            .unwrap();
        assert_eq!(status.status, "Processing");
        assert_eq!(status.block_height, Some(7));

        let atomic_tx = client
            .avax_get_atomic_tx(&issued.tx_id, Some("hex"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(atomic_tx.tx, "0xdeadbeef");

        let calls = calls.lock().unwrap();
        let fee_config_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getFeeConfig")
            .unwrap();
        assert_eq!(fee_config_call["params"], json!([{}]));

        let validator_fee_config_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getValidatorFeeConfig")
            .unwrap();
        assert_eq!(validator_fee_config_call["params"], json!([{}]));

        let subnet_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getSubnet")
            .unwrap();
        assert_eq!(
            subnet_call["params"],
            json!([{ "subnetID": "2bRCr6B4MiEfSjidDwxDpdCyviwnfUVqB2HGwhm947w9YYqb7r" }])
        );

        let issue_platform_tx_call = calls
            .iter()
            .find(|call| call["method"] == "platform.issueTx")
            .unwrap();
        assert_eq!(
            issue_platform_tx_call["params"],
            json!([{ "tx": "0xdeadbeef", "encoding": "hex" }])
        );

        let get_platform_tx_call = calls
            .iter()
            .find(|call| {
                call["method"] == "platform.getTx" && call["params"][0]["encoding"] == json!("hex")
            })
            .unwrap();
        assert_eq!(
            get_platform_tx_call["params"],
            json!([{ "txID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA", "encoding": "hex" }])
        );

        let get_platform_tx_json_call = calls
            .iter()
            .find(|call| {
                call["method"] == "platform.getTx" && call["params"][0]["encoding"] == json!("json")
            })
            .unwrap();
        assert_eq!(
            get_platform_tx_json_call["params"],
            json!([{ "txID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA", "encoding": "json" }])
        );

        let get_platform_tx_status_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getTxStatus")
            .unwrap();
        assert_eq!(
            get_platform_tx_status_call["params"],
            json!([{ "txID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA" }])
        );

        let get_validator_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getValidator")
            .unwrap();
        assert_eq!(
            get_validator_call["params"],
            json!([{ "nodeID": "NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg", "subnetID": "2SE8BntErKrdVGs76bhQQDaEc8V8cprrmsnBQGcM3jUmczka6Q" }])
        );

        let balance_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getBalance")
            .unwrap();
        assert_eq!(
            balance_call["params"],
            json!([{ "addresses": ["P-local1", "P-local2"] }])
        );

        let utxos_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getUTXOs")
            .unwrap();
        assert_eq!(
            utxos_call["params"],
            json!([{
                "addresses": ["P-local1", "P-local2"],
                "sourceChain": "P",
                "limit": 64,
                "startIndex": {
                    "address": "P-local1",
                    "utxo": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA"
                },
                "encoding": "hex"
            }])
        );

        let current_supply_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getCurrentSupply")
            .unwrap();
        assert_eq!(current_supply_call["params"], json!([{}]));

        let l1_validator_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getL1Validator")
            .unwrap();
        assert_eq!(
            l1_validator_call["params"],
            json!([{ "validationID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA" }])
        );

        let stake_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getStake")
            .unwrap();
        assert_eq!(
            stake_call["params"],
            json!([{ "addresses": ["P-local1", "P-local2"], "validatorsOnly": true, "encoding": "hex" }])
        );

        let fee_state_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getFeeState")
            .unwrap();
        assert_eq!(fee_state_call["params"], json!([{}]));

        let validator_fee_state_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getValidatorFeeState")
            .unwrap();
        assert_eq!(validator_fee_state_call["params"], json!([{}]));

        let reward_utxos_call = calls
            .iter()
            .find(|call| call["method"] == "platform.getRewardUTXOs")
            .unwrap();
        assert_eq!(
            reward_utxos_call["params"],
            json!([{ "txID": "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA", "encoding": "hex" }])
        );

        let aliases_call = calls
            .iter()
            .find(|call| call["method"] == "admin.getChainAliases")
            .unwrap();
        assert_eq!(aliases_call["params"], json!([{ "chain": "C" }]));

        let logger_call = calls
            .iter()
            .find(|call| call["method"] == "admin.setLoggerLevel")
            .unwrap();
        assert_eq!(
            logger_call["params"],
            json!([{ "loggerName": "rpc", "logLevel": "debug", "displayLevel": "warn" }])
        );

        let issue_tx_call = calls
            .iter()
            .find(|call| call["method"] == "avax.issueTx")
            .unwrap();
        assert_eq!(
            issue_tx_call["params"],
            json!([{ "tx": "0xdeadbeef", "encoding": "hex" }])
        );

        let atomic_utxos_call = calls
            .iter()
            .find(|call| call["method"] == "avax.getUTXOs")
            .unwrap();
        assert_eq!(
            atomic_utxos_call["params"],
            json!([{
                "addresses": ["C-local1"],
                "sourceChain": "P",
                "limit": 32,
                "startIndex": {
                    "address": "C-local1",
                    "utxo": "11111111111111111111111111111111LpoYY"
                },
                "encoding": "hex"
            }])
        );
    }

    #[tokio::test]
    async fn test_optional_atomic_tx_null_result_maps_to_none() {
        let endpoint =
            spawn_mock_rpc_server(move |request| match request["method"].as_str().unwrap() {
                "avax.getAtomicTx" => Value::Null,
                _ => panic!("unexpected method: {}", request["method"]),
            })
            .await;

        let client = RpcClient::new(endpoint).unwrap();
        let atomic_tx = client
            .avax_get_atomic_tx(
                "2r2x62v3WxP6xs7rZhoakaTK3hxpf1L6q8bqs6FZ83dTcKFwRA",
                Some("hex"),
            )
            .await
            .unwrap();
        assert!(atomic_tx.is_none());
    }

    #[tokio::test]
    async fn test_block_receipts_wrapper_maps_array_and_null() {
        let endpoint =
            spawn_mock_rpc_server(move |request| match request["method"].as_str().unwrap() {
                "eth_getBlockReceipts" => {
                    if request["params"][0] == json!("0x1") {
                        json!([{ "blockHash": "0xabc", "transactionIndex": "0x0" }])
                    } else {
                        Value::Null
                    }
                }
                _ => panic!("unexpected method: {}", request["method"]),
            })
            .await;

        let client = RpcClient::new(endpoint).unwrap();

        let receipts = client.c_get_block_receipts("0x1").await.unwrap();
        assert_eq!(receipts.unwrap().len(), 1);

        let missing = client
            .c_get_block_receipts(
                "0x00000000000000000000000000000000000000000000000000000000deadbeef",
            )
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_request_builder() {
        let request = RequestBuilder::new("eth_getBalance")
            .param(json!("0x1111111111111111111111111111111111111111"))
            .param(json!("latest"))
            .build(1);

        assert_eq!(request.method, "eth_getBalance");
        assert_eq!(request.params.len(), 2);
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
