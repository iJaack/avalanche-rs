//! Transaction signing and construction for Avalanche C-Chain (EVM)
//!
//! Uses k256 (secp256k1) for ECDSA signing. Supports EIP-1559 (type 2)
//! and legacy transactions. Designed for MEV bundle construction.

use k256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// WALLET
// ============================================================================

/// Lightweight wallet for transaction signing
#[derive(Clone)]
pub struct Wallet {
    signing_key: SigningKey,
    address: [u8; 20],
    chain_id: u64,
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wallet({})", self.address_hex())
    }
}

impl Wallet {
    /// Create wallet from raw 32-byte private key
    pub fn from_bytes(key: &[u8; 32], chain_id: u64) -> Result<Self, TxError> {
        let signing_key =
            SigningKey::from_bytes(key.into()).map_err(|e| TxError::InvalidKey(e.to_string()))?;

        let address = Self::derive_address(&signing_key);
        Ok(Self {
            signing_key,
            address,
            chain_id,
        })
    }

    /// Create wallet from hex private key (with or without 0x prefix)
    pub fn from_hex(hex_key: &str, chain_id: u64) -> Result<Self, TxError> {
        let clean = hex_key.trim_start_matches("0x");
        if clean.len() != 64 {
            return Err(TxError::InvalidKey(format!(
                "Expected 64 hex chars, got {}",
                clean.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        faster_hex::hex_decode(clean.as_bytes(), &mut key_bytes)
            .map_err(|e| TxError::InvalidKey(e.to_string()))?;

        Self::from_bytes(&key_bytes, chain_id)
    }

    /// Generate a random wallet (for testing)
    pub fn random(chain_id: u64) -> Self {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let address = Self::derive_address(&signing_key);
        Self {
            signing_key,
            address,
            chain_id,
        }
    }

    /// Get the address as 0x-prefixed hex string
    pub fn address_hex(&self) -> String {
        format!("0x{}", faster_hex::hex_string(&self.address))
    }

    /// Get the raw 20-byte address
    pub fn address(&self) -> &[u8; 20] {
        &self.address
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Get the public key (compressed, 33 bytes)
    pub fn public_key(&self) -> Vec<u8> {
        let verifying = VerifyingKey::from(&self.signing_key);
        verifying.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Derive Ethereum address from signing key
    /// address = keccak256(uncompressed_pubkey[1..])[12..]
    fn derive_address(key: &SigningKey) -> [u8; 20] {
        let verifying = VerifyingKey::from(key);
        let point = verifying.to_encoded_point(false);
        let pubkey_bytes = &point.as_bytes()[1..]; // strip 0x04 prefix

        // Use keccak256 for Ethereum address derivation
        let hash = keccak256(pubkey_bytes);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        addr
    }

    /// Sign a raw message hash (32 bytes)
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<EcdsaSignature, TxError> {
        let (sig, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(hash)
            .map_err(|e| TxError::SigningFailed(e.to_string()))?;

        let sig_bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..]);

        Ok(EcdsaSignature {
            r,
            s,
            v: recovery_id.to_byte(),
        })
    }

    /// Sign an EIP-1559 (type 2) transaction
    pub fn sign_eip1559(&self, tx: &Eip1559Tx) -> Result<SignedTransaction, TxError> {
        let encoded = tx.rlp_encode(self.chain_id);
        let mut prefixed = vec![0x02]; // EIP-1559 type prefix
        prefixed.extend_from_slice(&encoded);

        let hash = keccak256(&prefixed);
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash);

        let sig = self.sign_hash(&hash_arr)?;

        // Build signed tx: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s])
        let signed_rlp = tx.rlp_encode_signed(self.chain_id, &sig);
        let mut signed = vec![0x02];
        signed.extend_from_slice(&signed_rlp);

        Ok(SignedTransaction {
            raw: signed,
            hash: hash_arr,
            from: self.address,
            nonce: tx.nonce,
        })
    }

    /// Sign a legacy transaction
    pub fn sign_legacy(&self, tx: &LegacyTx) -> Result<SignedTransaction, TxError> {
        let encoded = tx.rlp_encode_for_signing(self.chain_id);
        let hash = keccak256(&encoded);
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash);

        let sig = self.sign_hash(&hash_arr)?;

        // EIP-155: v = recovery_id + chain_id * 2 + 35
        let v_eip155 = sig.v as u64 + self.chain_id * 2 + 35;

        let signed_rlp = tx.rlp_encode_signed(v_eip155, &sig);

        Ok(SignedTransaction {
            raw: signed_rlp,
            hash: hash_arr,
            from: self.address,
            nonce: tx.nonce,
        })
    }
}

// ============================================================================
// TRANSACTIONS
// ============================================================================

/// EIP-1559 (type 2) transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip1559Tx {
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListEntry>,
}

/// Access list entry for EIP-2930/1559
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListEntry {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

/// Legacy (type 0) transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyTx {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
}

/// ECDSA signature components
#[derive(Debug, Clone)]
pub struct EcdsaSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

/// Signed transaction ready for broadcast
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// Raw signed transaction bytes
    pub raw: Vec<u8>,
    /// Transaction hash
    pub hash: [u8; 32],
    /// Sender address
    pub from: [u8; 20],
    /// Nonce used
    pub nonce: u64,
}

impl SignedTransaction {
    /// Get the raw transaction as 0x-prefixed hex
    pub fn raw_hex(&self) -> String {
        format!("0x{}", faster_hex::hex_string(&self.raw))
    }

    /// Get the transaction hash as 0x-prefixed hex
    pub fn hash_hex(&self) -> String {
        format!("0x{}", faster_hex::hex_string(&self.hash))
    }

    /// Get the sender as 0x-prefixed hex
    pub fn from_hex(&self) -> String {
        format!("0x{}", faster_hex::hex_string(&self.from))
    }
}

// ============================================================================
// RLP ENCODING (minimal, no external dep)
// ============================================================================

/// Minimal RLP encoder for transaction serialization
struct Rlp {
    buf: Vec<u8>,
}

impl Rlp {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    fn encode_u64(&mut self, v: u64) {
        self.encode_uint(&v.to_be_bytes());
    }

    fn encode_u128(&mut self, v: u128) {
        self.encode_uint(&v.to_be_bytes());
    }

    fn encode_uint(&mut self, bytes: &[u8]) {
        // Strip leading zeros
        let stripped = match bytes.iter().position(|&b| b != 0) {
            Some(pos) => &bytes[pos..],
            None => &[0u8; 0], // zero value = empty bytes
        };

        if stripped.is_empty() {
            self.buf.push(0x80); // empty string
        } else if stripped.len() == 1 && stripped[0] < 0x80 {
            self.buf.push(stripped[0]); // single byte
        } else {
            self.buf.push(0x80 + stripped.len() as u8);
            self.buf.extend_from_slice(stripped);
        }
    }

    fn encode_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            self.buf.push(0x80);
        } else if data.len() == 1 && data[0] < 0x80 {
            self.buf.push(data[0]);
        } else if data.len() < 56 {
            self.buf.push(0x80 + data.len() as u8);
            self.buf.extend_from_slice(data);
        } else {
            let len_bytes = Self::encode_length_bytes(data.len());
            self.buf.push(0xb7 + len_bytes.len() as u8);
            self.buf.extend_from_slice(&len_bytes);
            self.buf.extend_from_slice(data);
        }
    }

    fn encode_fixed(&mut self, data: &[u8]) {
        self.encode_bytes(data);
    }

    /// Start a list, returns position to patch length later
    fn start_list(&mut self) -> usize {
        let pos = self.buf.len();
        // Reserve space — we'll patch in finalize_list
        self.buf.push(0); // placeholder
        pos
    }

    /// Finalize a list by patching the length at the start position
    fn finalize_list(&mut self, start: usize) {
        let content_len = self.buf.len() - start - 1;
        if content_len < 56 {
            self.buf[start] = 0xc0 + content_len as u8;
        } else {
            let len_bytes = Self::encode_length_bytes(content_len);
            // Need to insert length bytes — shift content right
            let header = vec![0xf7 + len_bytes.len() as u8];
            self.buf.splice(
                start..start + 1,
                header.into_iter().chain(len_bytes.into_iter()),
            );
        }
    }

    fn encode_length_bytes(len: usize) -> Vec<u8> {
        if len < 256 {
            vec![len as u8]
        } else if len < 65536 {
            vec![(len >> 8) as u8, len as u8]
        } else {
            vec![(len >> 16) as u8, (len >> 8) as u8, len as u8]
        }
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

impl Eip1559Tx {
    /// RLP encode for signing (without signature)
    fn rlp_encode(&self, chain_id: u64) -> Vec<u8> {
        let mut rlp = Rlp::new();
        let list_start = rlp.start_list();

        rlp.encode_u64(chain_id);
        rlp.encode_u64(self.nonce);
        rlp.encode_u128(self.max_priority_fee_per_gas);
        rlp.encode_u128(self.max_fee_per_gas);
        rlp.encode_u64(self.gas_limit);
        rlp.encode_fixed(&self.to);
        rlp.encode_u128(self.value);
        rlp.encode_bytes(&self.data);

        // Access list (empty list for now)
        let al_start = rlp.start_list();
        for entry in &self.access_list {
            let entry_start = rlp.start_list();
            rlp.encode_fixed(&entry.address);
            let keys_start = rlp.start_list();
            for key in &entry.storage_keys {
                rlp.encode_fixed(key);
            }
            rlp.finalize_list(keys_start);
            rlp.finalize_list(entry_start);
        }
        rlp.finalize_list(al_start);

        rlp.finalize_list(list_start);
        rlp.finish()
    }

    /// RLP encode with signature (for broadcast)
    fn rlp_encode_signed(&self, chain_id: u64, sig: &EcdsaSignature) -> Vec<u8> {
        let mut rlp = Rlp::new();
        let list_start = rlp.start_list();

        rlp.encode_u64(chain_id);
        rlp.encode_u64(self.nonce);
        rlp.encode_u128(self.max_priority_fee_per_gas);
        rlp.encode_u128(self.max_fee_per_gas);
        rlp.encode_u64(self.gas_limit);
        rlp.encode_fixed(&self.to);
        rlp.encode_u128(self.value);
        rlp.encode_bytes(&self.data);

        // Access list
        let al_start = rlp.start_list();
        for entry in &self.access_list {
            let entry_start = rlp.start_list();
            rlp.encode_fixed(&entry.address);
            let keys_start = rlp.start_list();
            for key in &entry.storage_keys {
                rlp.encode_fixed(key);
            }
            rlp.finalize_list(keys_start);
            rlp.finalize_list(entry_start);
        }
        rlp.finalize_list(al_start);

        // Signature: v (0 or 1 for EIP-1559), r, s
        rlp.encode_u64(sig.v as u64);
        rlp.encode_fixed(&sig.r);
        rlp.encode_fixed(&sig.s);

        rlp.finalize_list(list_start);
        rlp.finish()
    }
}

impl LegacyTx {
    /// RLP encode for signing (EIP-155: includes chain_id, 0, 0)
    fn rlp_encode_for_signing(&self, chain_id: u64) -> Vec<u8> {
        let mut rlp = Rlp::new();
        let list_start = rlp.start_list();

        rlp.encode_u64(self.nonce);
        rlp.encode_u128(self.gas_price);
        rlp.encode_u64(self.gas_limit);
        rlp.encode_fixed(&self.to);
        rlp.encode_u128(self.value);
        rlp.encode_bytes(&self.data);

        // EIP-155: append chain_id, 0, 0
        rlp.encode_u64(chain_id);
        rlp.encode_u64(0);
        rlp.encode_u64(0);

        rlp.finalize_list(list_start);
        rlp.finish()
    }

    /// RLP encode with signature
    fn rlp_encode_signed(&self, v: u64, sig: &EcdsaSignature) -> Vec<u8> {
        let mut rlp = Rlp::new();
        let list_start = rlp.start_list();

        rlp.encode_u64(self.nonce);
        rlp.encode_u128(self.gas_price);
        rlp.encode_u64(self.gas_limit);
        rlp.encode_fixed(&self.to);
        rlp.encode_u128(self.value);
        rlp.encode_bytes(&self.data);

        rlp.encode_u64(v);
        rlp.encode_fixed(&sig.r);
        rlp.encode_fixed(&sig.s);

        rlp.finalize_list(list_start);
        rlp.finish()
    }
}

// ============================================================================
// POOL RESERVES (UniswapV2 getReserves)
// ============================================================================

/// UniswapV2 pair getReserves() selector: 0x0902f1ac
pub const GET_RESERVES_SELECTOR: &str = "0x0902f1ac";

/// Decoded pool reserves
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolReserves {
    pub reserve0: u128,
    pub reserve1: u128,
    pub block_timestamp_last: u32,
}

impl PoolReserves {
    /// Decode getReserves() return data (3 x uint256, but we use uint112 + uint32)
    pub fn decode(data: &str) -> Result<Self, TxError> {
        let clean = data.trim_start_matches("0x");
        if clean.len() < 192 {
            // 3 * 64 hex chars
            return Err(TxError::DecodeFailed(
                "getReserves response too short".into(),
            ));
        }

        let reserve0 = u128::from_str_radix(&clean[0..64].trim_start_matches('0').max("0"), 16)
            .map_err(|e| TxError::DecodeFailed(e.to_string()))?;
        let reserve1 = u128::from_str_radix(&clean[64..128].trim_start_matches('0').max("0"), 16)
            .map_err(|e| TxError::DecodeFailed(e.to_string()))?;
        let ts = u32::from_str_radix(&clean[128..192].trim_start_matches('0').max("0"), 16)
            .map_err(|e| TxError::DecodeFailed(e.to_string()))?;

        Ok(Self {
            reserve0,
            reserve1,
            block_timestamp_last: ts,
        })
    }
}

// ============================================================================
// KECCAK-256 (minimal, no external dep)
// ============================================================================

/// Keccak-256 hash (Ethereum's hash function, NOT SHA3-256)
fn keccak256(data: &[u8]) -> [u8; 32] {
    // Keccak-256 implementation (pre-NIST padding)
    let mut state = [0u64; 25];
    let rate = 136; // (1600 - 256*2) / 8 = 136 bytes
    let mut offset = 0;

    // Absorb
    while offset + rate <= data.len() {
        for i in 0..rate / 8 {
            state[i] ^= u64::from_le_bytes([
                data[offset + i * 8],
                data[offset + i * 8 + 1],
                data[offset + i * 8 + 2],
                data[offset + i * 8 + 3],
                data[offset + i * 8 + 4],
                data[offset + i * 8 + 5],
                data[offset + i * 8 + 6],
                data[offset + i * 8 + 7],
            ]);
        }
        keccak_f1600(&mut state);
        offset += rate;
    }

    // Pad and absorb final block
    let mut last_block = vec![0u8; rate];
    let remaining = data.len() - offset;
    last_block[..remaining].copy_from_slice(&data[offset..]);
    last_block[remaining] = 0x01; // Keccak padding (NOT SHA3's 0x06)
    last_block[rate - 1] |= 0x80;

    for i in 0..rate / 8 {
        state[i] ^= u64::from_le_bytes([
            last_block[i * 8],
            last_block[i * 8 + 1],
            last_block[i * 8 + 2],
            last_block[i * 8 + 3],
            last_block[i * 8 + 4],
            last_block[i * 8 + 5],
            last_block[i * 8 + 6],
            last_block[i * 8 + 7],
        ]);
    }
    keccak_f1600(&mut state);

    // Squeeze
    let mut output = [0u8; 32];
    for i in 0..4 {
        let bytes = state[i].to_le_bytes();
        output[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    output
}

/// Keccak-f[1600] permutation (24 rounds)
fn keccak_f1600(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];

    for rc in &RC {
        // θ step
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ and π steps
        let mut b = [0u64; 25];
        const ROTATIONS: [u32; 25] = [
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61,
            56, 14,
        ];
        const PI: [usize; 25] = [
            0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19,
            4,
        ];
        for i in 0..25 {
            b[PI[i]] = state[i].rotate_left(ROTATIONS[i]);
        }

        // χ step
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ι step
        state[0] ^= rc;
    }
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Debug, Clone)]
pub enum TxError {
    InvalidKey(String),
    SigningFailed(String),
    EncodingFailed(String),
    DecodeFailed(String),
    InvalidNonce,
    InsufficientFunds,
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxError::InvalidKey(s) => write!(f, "Invalid key: {}", s),
            TxError::SigningFailed(s) => write!(f, "Signing failed: {}", s),
            TxError::EncodingFailed(s) => write!(f, "Encoding failed: {}", s),
            TxError::DecodeFailed(s) => write!(f, "Decode failed: {}", s),
            TxError::InvalidNonce => write!(f, "Invalid nonce"),
            TxError::InsufficientFunds => write!(f, "Insufficient funds"),
        }
    }
}

impl std::error::Error for TxError {}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Keccak-256 ---

    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(&[]);
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        assert_eq!(
            faster_hex::hex_string(&hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_keccak256_hello() {
        // keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
        let hash = keccak256(b"hello");
        assert_eq!(
            faster_hex::hex_string(&hash),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_keccak256_transfer_selector() {
        // keccak256("transfer(address,uint256)") = a9059cbb...
        let hash = keccak256(b"transfer(address,uint256)");
        assert_eq!(hash[0], 0xa9);
        assert_eq!(hash[1], 0x05);
        assert_eq!(hash[2], 0x9c);
        assert_eq!(hash[3], 0xbb);
    }

    // --- Wallet ---

    #[test]
    fn test_wallet_random() {
        let w = Wallet::random(43114); // Avalanche C-Chain
        assert_eq!(w.chain_id(), 43114);
        assert!(w.address_hex().starts_with("0x"));
        assert_eq!(w.address_hex().len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn test_wallet_from_hex() {
        // Known test key (DO NOT use in production)
        let key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let w = Wallet::from_hex(key, 43114).unwrap();
        assert!(w.address_hex().starts_with("0x"));
        assert_eq!(w.address_hex().len(), 42);
    }

    #[test]
    fn test_wallet_deterministic() {
        let key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let w1 = Wallet::from_hex(key, 43114).unwrap();
        let w2 = Wallet::from_hex(key, 43114).unwrap();
        assert_eq!(w1.address_hex(), w2.address_hex());
    }

    #[test]
    fn test_wallet_invalid_key() {
        assert!(Wallet::from_hex("not_hex", 1).is_err());
        assert!(Wallet::from_hex("0x1234", 1).is_err()); // too short
    }

    #[test]
    fn test_wallet_public_key() {
        let w = Wallet::random(1);
        let pk = w.public_key();
        assert_eq!(pk.len(), 33); // compressed
        assert!(pk[0] == 0x02 || pk[0] == 0x03); // compressed prefix
    }

    // --- Signing ---

    #[test]
    fn test_sign_hash() {
        let w = Wallet::random(43114);
        let hash = [0xABu8; 32];
        let sig = w.sign_hash(&hash).unwrap();

        assert_eq!(sig.r.len(), 32);
        assert_eq!(sig.s.len(), 32);
        assert!(sig.v == 0 || sig.v == 1);
    }

    #[test]
    fn test_sign_eip1559() {
        let w = Wallet::random(43114);
        let tx = Eip1559Tx {
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000, // 1 gwei
            max_fee_per_gas: 30_000_000_000,         // 30 gwei
            gas_limit: 21_000,
            to: [0u8; 20],
            value: 1_000_000_000_000_000_000, // 1 AVAX
            data: vec![],
            access_list: vec![],
        };

        let signed = w.sign_eip1559(&tx).unwrap();
        assert!(!signed.raw.is_empty());
        assert_eq!(signed.raw[0], 0x02); // EIP-1559 type prefix
        assert!(signed.raw_hex().starts_with("0x02"));
        assert_eq!(signed.nonce, 0);
        assert_eq!(signed.from, *w.address());
    }

    #[test]
    fn test_sign_legacy() {
        let w = Wallet::random(43114);
        let tx = LegacyTx {
            nonce: 5,
            gas_price: 25_000_000_000, // 25 gwei
            gas_limit: 21_000,
            to: [0xAA; 20],
            value: 0,
            data: vec![0xa9, 0x05, 0x9c, 0xbb], // transfer selector
        };

        let signed = w.sign_legacy(&tx).unwrap();
        assert!(!signed.raw.is_empty());
        assert_eq!(signed.nonce, 5);
        assert!(signed.hash_hex().starts_with("0x"));
    }

    #[test]
    fn test_sign_with_access_list() {
        let w = Wallet::random(43114);
        let tx = Eip1559Tx {
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 100_000,
            to: [0xBB; 20],
            value: 0,
            data: vec![0x38, 0xed, 0x17, 0x39], // swapExactTokensForTokens
            access_list: vec![AccessListEntry {
                address: [0xCC; 20],
                storage_keys: vec![[0xDD; 32]],
            }],
        };

        let signed = w.sign_eip1559(&tx).unwrap();
        assert!(!signed.raw.is_empty());
        assert_eq!(signed.raw[0], 0x02);
    }

    // --- RLP encoding ---

    #[test]
    fn test_rlp_encode_zero() {
        let mut rlp = Rlp::new();
        rlp.encode_u64(0);
        assert_eq!(rlp.finish(), vec![0x80]); // empty string = 0
    }

    #[test]
    fn test_rlp_encode_small() {
        let mut rlp = Rlp::new();
        rlp.encode_u64(1);
        assert_eq!(rlp.finish(), vec![0x01]); // single byte < 0x80
    }

    #[test]
    fn test_rlp_encode_medium() {
        let mut rlp = Rlp::new();
        rlp.encode_u64(128);
        assert_eq!(rlp.finish(), vec![0x81, 0x80]); // 0x80 needs length prefix
    }

    #[test]
    fn test_rlp_encode_empty_bytes() {
        let mut rlp = Rlp::new();
        rlp.encode_bytes(&[]);
        assert_eq!(rlp.finish(), vec![0x80]);
    }

    #[test]
    fn test_rlp_encode_list() {
        let mut rlp = Rlp::new();
        let start = rlp.start_list();
        rlp.encode_u64(1);
        rlp.encode_u64(2);
        rlp.finalize_list(start);
        assert_eq!(rlp.finish(), vec![0xc2, 0x01, 0x02]); // list of [1, 2]
    }

    // --- Pool reserves ---

    #[test]
    fn test_decode_reserves() {
        // Simulated getReserves response: reserve0=1000000, reserve1=2000000, ts=12345
        let data = format!(
            "0x{:064x}{:064x}{:064x}",
            1_000_000u128, 2_000_000u128, 12345u32
        );
        let reserves = PoolReserves::decode(&data).unwrap();
        assert_eq!(reserves.reserve0, 1_000_000);
        assert_eq!(reserves.reserve1, 2_000_000);
        assert_eq!(reserves.block_timestamp_last, 12345);
    }

    #[test]
    fn test_decode_reserves_too_short() {
        assert!(PoolReserves::decode("0x1234").is_err());
    }

    #[test]
    fn test_decode_reserves_real_world() {
        // Real-world reserves: ~100K WAVAX, ~2M USDC
        let r0 = 100_000u128 * 10u128.pow(18); // 100K WAVAX (18 decimals)
        let r1 = 2_000_000u128 * 10u128.pow(6); // 2M USDC (6 decimals)
        let ts = 1709500000u32;
        let data = format!("0x{:064x}{:064x}{:064x}", r0, r1, ts);
        let reserves = PoolReserves::decode(&data).unwrap();

        let wavax = reserves.reserve0 as f64 / 1e18;
        let usdc = reserves.reserve1 as f64 / 1e6;
        assert!((wavax - 100_000.0).abs() < 1.0);
        assert!((usdc - 2_000_000.0).abs() < 1.0);
    }

    // --- Keccak stress ---

    #[test]
    fn test_keccak_stress() {
        let start = std::time::Instant::now();
        for i in 0u32..100_000 {
            let _ = keccak256(&i.to_be_bytes());
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 5000,
            "100K keccak256 hashes should take <5s in debug mode, took {:?}",
            elapsed
        );
    }

    // --- Signing stress ---

    #[test]
    fn test_signing_stress() {
        let w = Wallet::random(43114);
        let start = std::time::Instant::now();
        for i in 0u64..1_000 {
            let tx = Eip1559Tx {
                nonce: i,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 30_000_000_000,
                gas_limit: 21_000,
                to: [0u8; 20],
                value: 0,
                data: vec![],
                access_list: vec![],
            };
            let _ = w.sign_eip1559(&tx).unwrap();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 5_000,
            "1K EIP-1559 signings should take <5s, took {:?}",
            elapsed
        );
    }

    // --- Different chain IDs ---

    #[test]
    fn test_different_chain_ids() {
        let w1 = Wallet::random(43114); // Avalanche mainnet
        let w2 = Wallet::random(43113); // Fuji testnet
        let w3 = Wallet::random(1); // Ethereum mainnet

        let tx = Eip1559Tx {
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 21_000,
            to: [0u8; 20],
            value: 0,
            data: vec![],
            access_list: vec![],
        };

        let s1 = w1.sign_eip1559(&tx).unwrap();
        let s2 = w2.sign_eip1559(&tx).unwrap();
        let s3 = w3.sign_eip1559(&tx).unwrap();

        // All should produce different raw transactions (different chain_id in encoding)
        assert_ne!(s1.raw, s2.raw);
        assert_ne!(s1.raw, s3.raw);
        assert_ne!(s2.raw, s3.raw);
    }
}
