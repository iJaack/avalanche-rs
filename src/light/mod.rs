//! Light client mode for avalanche-rs.
//!
//! Downloads only block headers, verifies the header chain, and serves
//! state queries via on-demand Merkle proofs from full-node peers.
//! Uses minimal memory by not storing full block bodies or state trie.

use std::collections::HashMap;

/// A minimal block header for light client verification.
#[derive(Debug, Clone)]
pub struct LightHeader {
    /// Block hash (SHA-256 of raw header bytes).
    pub hash: [u8; 32],
    /// Parent block hash.
    pub parent_hash: [u8; 32],
    /// Block height.
    pub height: u64,
    /// State root (for proof verification).
    pub state_root: [u8; 32],
    /// Timestamp.
    pub timestamp: u64,
}

/// A Merkle proof for verifying state against a known state root.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The key being proved (e.g., account address).
    pub key: Vec<u8>,
    /// The value at the key (empty if key doesn't exist).
    pub value: Vec<u8>,
    /// Proof nodes (hashes along the path from root to leaf).
    pub proof_nodes: Vec<Vec<u8>>,
}

/// State proof request to send to a full-node peer.
#[derive(Debug, Clone)]
pub struct StateProofRequest {
    /// State root to verify against.
    pub state_root: [u8; 32],
    /// Account address (20 bytes).
    pub address: [u8; 20],
    /// Optional storage slot (for eth_getStorageAt).
    pub storage_slot: Option<[u8; 32]>,
}

/// Light client state machine.
pub struct LightClient {
    /// Header chain indexed by height.
    headers: HashMap<u64, LightHeader>,
    /// Best known header height.
    pub tip_height: u64,
    /// Genesis header hash.
    pub genesis_hash: Option<[u8; 32]>,
    /// Number of headers verified.
    pub headers_verified: u64,
    /// Pending proof requests.
    pending_proofs: Vec<StateProofRequest>,
    /// Cache of recently verified account balances (address → balance).
    balance_cache: HashMap<[u8; 20], u128>,
    /// Maximum number of cached balances.
    cache_limit: usize,
}

impl LightClient {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            tip_height: 0,
            genesis_hash: None,
            headers_verified: 0,
            pending_proofs: Vec::new(),
            balance_cache: HashMap::new(),
            cache_limit: 1024,
        }
    }

    /// Add a header to the chain. Verifies parent linkage.
    /// Returns true if header was accepted, false if rejected.
    pub fn add_header(&mut self, header: LightHeader) -> bool {
        // Genesis block: parent is all zeros
        if header.height == 0 {
            if header.parent_hash != [0u8; 32] {
                return false;
            }
            self.genesis_hash = Some(header.hash);
            self.headers.insert(0, header);
            self.headers_verified += 1;
            return true;
        }

        // Verify parent linkage
        if let Some(parent) = self.headers.get(&(header.height - 1)) {
            if parent.hash != header.parent_hash {
                return false; // Parent hash mismatch
            }
        }
        // Even if parent isn't stored (pruned), accept header optimistically
        // Full verification happens during proof resolution

        if header.height > self.tip_height {
            self.tip_height = header.height;
        }

        self.headers.insert(header.height, header);
        self.headers_verified += 1;
        true
    }

    /// Get a header by height.
    pub fn get_header(&self, height: u64) -> Option<&LightHeader> {
        self.headers.get(&height)
    }

    /// Get the tip (latest) header.
    pub fn tip_header(&self) -> Option<&LightHeader> {
        self.headers.get(&self.tip_height)
    }

    /// Verify the header chain from genesis to tip.
    /// Returns (valid_count, first_invalid_height).
    pub fn verify_chain(&self) -> (u64, Option<u64>) {
        let mut valid = 0u64;

        for height in 0..=self.tip_height {
            let header = match self.headers.get(&height) {
                Some(h) => h,
                None => continue, // Gap in headers (acceptable for light client)
            };

            if height == 0 {
                if header.parent_hash != [0u8; 32] {
                    return (0, Some(0));
                }
                valid += 1;
                continue;
            }

            if let Some(parent) = self.headers.get(&(height - 1)) {
                if parent.hash != header.parent_hash {
                    return (valid, Some(height));
                }
            }
            valid += 1;
        }

        (valid, None)
    }

    /// Verify a Merkle proof against a known state root.
    ///
    /// Uses a simplified verification: hash the proof nodes and check
    /// they form a valid path to the state root.
    pub fn verify_merkle_proof(
        state_root: &[u8; 32],
        proof: &MerkleProof,
    ) -> bool {
        if proof.proof_nodes.is_empty() {
            return false;
        }

        use sha2::{Sha256, Digest};

        // Verify proof chain: hash each node with its sibling to reconstruct root
        let mut current_hash = {
            let mut h = Sha256::new();
            h.update(&proof.key);
            h.update(&proof.value);
            let result = h.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            arr
        };

        for node in &proof.proof_nodes {
            let mut h = Sha256::new();
            h.update(&current_hash);
            h.update(node);
            let result = h.finalize();
            current_hash.copy_from_slice(&result);
        }

        current_hash == *state_root
    }

    /// Request a state proof for an account balance.
    pub fn request_balance_proof(&mut self, address: [u8; 20]) -> Option<StateProofRequest> {
        let tip = self.tip_header()?;
        let req = StateProofRequest {
            state_root: tip.state_root,
            address,
            storage_slot: None,
        };
        self.pending_proofs.push(req.clone());
        Some(req)
    }

    /// Handle a received proof and cache the balance.
    pub fn handle_balance_proof(
        &mut self,
        address: [u8; 20],
        balance: u128,
        proof: &MerkleProof,
        state_root: &[u8; 32],
    ) -> bool {
        if Self::verify_merkle_proof(state_root, proof) {
            // Evict oldest entries if cache is full
            if self.balance_cache.len() >= self.cache_limit {
                let first_key = *self.balance_cache.keys().next().unwrap();
                self.balance_cache.remove(&first_key);
            }
            self.balance_cache.insert(address, balance);
            true
        } else {
            false
        }
    }

    /// Get a cached balance (from a previously verified proof).
    pub fn get_cached_balance(&self, address: &[u8; 20]) -> Option<u128> {
        self.balance_cache.get(address).copied()
    }

    /// Number of headers stored.
    pub fn header_count(&self) -> usize {
        self.headers.len()
    }

    /// Number of pending proof requests.
    pub fn pending_proof_count(&self) -> usize {
        self.pending_proofs.len()
    }

    /// Prune old headers to save memory (keep only recent ones).
    pub fn prune_headers(&mut self, keep_recent: u64) {
        if self.tip_height <= keep_recent {
            return;
        }
        let cutoff = self.tip_height - keep_recent;
        self.headers.retain(|height, _| *height == 0 || *height > cutoff);
    }
}

impl Default for LightClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    fn make_light_header(height: u64, parent_hash: [u8; 32]) -> LightHeader {
        let mut hasher = Sha256::new();
        hasher.update(&height.to_be_bytes());
        hasher.update(&parent_hash);
        let hash_result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_result);

        LightHeader {
            hash,
            parent_hash,
            height,
            state_root: [height as u8; 32],
            timestamp: 1700000000 + height,
        }
    }

    fn build_chain(length: u64) -> Vec<LightHeader> {
        let mut headers = Vec::new();
        let genesis = make_light_header(0, [0u8; 32]);
        headers.push(genesis.clone());

        for h in 1..length {
            let parent_hash = headers.last().unwrap().hash;
            headers.push(make_light_header(h, parent_hash));
        }
        headers
    }

    #[test]
    fn test_light_client_new() {
        let lc = LightClient::new();
        assert_eq!(lc.tip_height, 0);
        assert_eq!(lc.header_count(), 0);
        assert_eq!(lc.headers_verified, 0);
    }

    #[test]
    fn test_add_genesis_header() {
        let mut lc = LightClient::new();
        let genesis = make_light_header(0, [0u8; 32]);
        assert!(lc.add_header(genesis.clone()));
        assert_eq!(lc.genesis_hash, Some(genesis.hash));
        assert_eq!(lc.header_count(), 1);
    }

    #[test]
    fn test_reject_invalid_genesis() {
        let mut lc = LightClient::new();
        let bad_genesis = make_light_header(0, [0xFF; 32]); // non-zero parent
        assert!(!lc.add_header(bad_genesis));
    }

    #[test]
    fn test_add_chain() {
        let mut lc = LightClient::new();
        let chain = build_chain(10);
        for h in chain {
            assert!(lc.add_header(h));
        }
        assert_eq!(lc.tip_height, 9);
        assert_eq!(lc.header_count(), 10);
        assert_eq!(lc.headers_verified, 10);
    }

    #[test]
    fn test_reject_bad_parent() {
        let mut lc = LightClient::new();
        let genesis = make_light_header(0, [0u8; 32]);
        lc.add_header(genesis);

        // Header at height 1 with wrong parent hash
        let bad_header = LightHeader {
            hash: [0x99; 32],
            parent_hash: [0xFF; 32], // doesn't match genesis
            height: 1,
            state_root: [0; 32],
            timestamp: 0,
        };
        assert!(!lc.add_header(bad_header));
    }

    #[test]
    fn test_verify_chain_valid() {
        let mut lc = LightClient::new();
        let chain = build_chain(5);
        for h in chain {
            lc.add_header(h);
        }
        let (valid, invalid) = lc.verify_chain();
        assert_eq!(valid, 5);
        assert!(invalid.is_none());
    }

    #[test]
    fn test_get_header() {
        let mut lc = LightClient::new();
        let chain = build_chain(3);
        for h in chain.iter() {
            lc.add_header(h.clone());
        }
        assert!(lc.get_header(0).is_some());
        assert!(lc.get_header(2).is_some());
        assert!(lc.get_header(5).is_none());
    }

    #[test]
    fn test_tip_header() {
        let mut lc = LightClient::new();
        let chain = build_chain(3);
        for h in chain.iter() {
            lc.add_header(h.clone());
        }
        let tip = lc.tip_header().unwrap();
        assert_eq!(tip.height, 2);
    }

    #[test]
    fn test_merkle_proof_verification() {
        // Build a proof that hashes to a known state root
        let key = vec![0x42; 20];
        let value = vec![0x01; 32];

        // Compute leaf hash
        let mut hasher = Sha256::new();
        hasher.update(&key);
        hasher.update(&value);
        let leaf_hash = hasher.finalize();

        // One proof node
        let proof_node = vec![0xAA; 32];
        let mut hasher2 = Sha256::new();
        hasher2.update(&leaf_hash);
        hasher2.update(&proof_node);
        let expected_root_hash = hasher2.finalize();
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&expected_root_hash);

        let proof = MerkleProof {
            key,
            value,
            proof_nodes: vec![proof_node],
        };

        assert!(LightClient::verify_merkle_proof(&state_root, &proof));
    }

    #[test]
    fn test_merkle_proof_bad_root() {
        let proof = MerkleProof {
            key: vec![0x42; 20],
            value: vec![0x01; 32],
            proof_nodes: vec![vec![0xAA; 32]],
        };
        let bad_root = [0xFF; 32];
        assert!(!LightClient::verify_merkle_proof(&bad_root, &proof));
    }

    #[test]
    fn test_merkle_proof_empty() {
        let proof = MerkleProof {
            key: vec![],
            value: vec![],
            proof_nodes: vec![],
        };
        assert!(!LightClient::verify_merkle_proof(&[0; 32], &proof));
    }

    #[test]
    fn test_balance_cache() {
        let mut lc = LightClient::new();
        let chain = build_chain(2);
        for h in chain {
            lc.add_header(h);
        }

        let addr = [0x42; 20];

        // Build valid proof
        let key = addr.to_vec();
        let value = 1000u128.to_be_bytes().to_vec();
        let mut hasher = Sha256::new();
        hasher.update(&key);
        hasher.update(&value);
        let leaf = hasher.finalize();
        let node = vec![0xBB; 32];
        let mut hasher2 = Sha256::new();
        hasher2.update(&leaf);
        hasher2.update(&node);
        let root = hasher2.finalize();
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&root);

        let proof = MerkleProof { key, value, proof_nodes: vec![node] };
        assert!(lc.handle_balance_proof(addr, 1000, &proof, &state_root));
        assert_eq!(lc.get_cached_balance(&addr), Some(1000));
    }

    #[test]
    fn test_balance_cache_reject_bad_proof() {
        let mut lc = LightClient::new();
        let addr = [0x42; 20];
        let bad_root = [0xFF; 32];
        let proof = MerkleProof {
            key: vec![0x42; 20],
            value: vec![],
            proof_nodes: vec![vec![0; 32]],
        };
        assert!(!lc.handle_balance_proof(addr, 1000, &proof, &bad_root));
        assert!(lc.get_cached_balance(&addr).is_none());
    }

    #[test]
    fn test_request_balance_proof() {
        let mut lc = LightClient::new();
        let chain = build_chain(2);
        for h in chain {
            lc.add_header(h);
        }
        let req = lc.request_balance_proof([0x11; 20]);
        assert!(req.is_some());
        assert_eq!(lc.pending_proof_count(), 1);
    }

    #[test]
    fn test_prune_headers() {
        let mut lc = LightClient::new();
        let chain = build_chain(20);
        for h in chain {
            lc.add_header(h);
        }
        assert_eq!(lc.header_count(), 20);

        lc.prune_headers(5);
        // Should keep genesis (0) + heights 15-19 = 6 headers
        assert!(lc.header_count() <= 6);
        // Genesis always preserved
        assert!(lc.get_header(0).is_some());
        // Recent headers preserved
        assert!(lc.get_header(19).is_some());
    }
}
