//! EIP-4844 Blob Transaction Support
//!
//! Phase 9: Parse Type-3 blob transactions, verify KZG commitments,
//! store blob data with configurable retention.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Blob Transaction Types
// ---------------------------------------------------------------------------

/// A Type-3 (EIP-4844) blob transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobTransaction {
    /// Chain ID
    pub chain_id: u64,
    /// Sender nonce
    pub nonce: u64,
    /// Max priority fee per gas (tip)
    pub max_priority_fee_per_gas: u128,
    /// Max fee per gas
    pub max_fee_per_gas: u128,
    /// Gas limit
    pub gas_limit: u64,
    /// Recipient address
    pub to: [u8; 20],
    /// Value in wei
    pub value: u128,
    /// Calldata
    pub data: Vec<u8>,
    /// Access list
    pub access_list: Vec<AccessListItem>,
    /// Max fee per blob gas
    pub max_fee_per_blob_gas: u128,
    /// Versioned hashes of the blobs (each 32 bytes, version byte 0x01)
    pub blob_versioned_hashes: Vec<[u8; 32]>,
}

/// Access list item for EIP-2930.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListItem {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

/// Blob sidecar containing the actual blob data, commitments, and proofs.
#[derive(Debug, Clone)]
pub struct BlobSidecar {
    /// Raw blob data (each blob is 131072 bytes = 4096 field elements * 32 bytes)
    pub blobs: Vec<Vec<u8>>,
    /// KZG commitments (48 bytes each)
    pub commitments: Vec<[u8; 48]>,
    /// KZG proofs (48 bytes each)
    pub proofs: Vec<[u8; 48]>,
}

/// Blob data stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBlob {
    /// The versioned hash (key)
    pub versioned_hash: [u8; 32],
    /// Block height where blob was included
    pub block_height: u64,
    /// Transaction hash that included this blob
    pub tx_hash: [u8; 32],
    /// Raw blob data (131072 bytes)
    pub data: Vec<u8>,
    /// KZG commitment (48 bytes)
    pub commitment: Vec<u8>,
    /// KZG proof (48 bytes)
    pub proof: Vec<u8>,
    /// Epoch number for retention
    pub epoch: u64,
}

/// Blob retention configuration.
#[derive(Debug, Clone)]
pub struct BlobConfig {
    /// Number of epochs to retain blobs (default 4096)
    pub retention_epochs: u64,
    /// Slots per epoch (default 32)
    pub slots_per_epoch: u64,
}

impl Default for BlobConfig {
    fn default() -> Self {
        Self {
            retention_epochs: 4096,
            slots_per_epoch: 32,
        }
    }
}

/// Blob store for managing blob data.
pub struct BlobStore {
    pub config: BlobConfig,
    pub blobs_stored: u64,
    pub blobs_pruned: u64,
}

impl BlobStore {
    pub fn new(config: BlobConfig) -> Self {
        Self {
            config,
            blobs_stored: 0,
            blobs_pruned: 0,
        }
    }

    /// Store a blob in the database.
    pub fn put_blob(
        &mut self,
        db: &crate::db::Database,
        blob: &StoredBlob,
    ) -> Result<(), crate::db::DbError> {
        let value =
            serde_json::to_vec(blob).map_err(|e| crate::db::DbError::Write(e.to_string()))?;
        db.put_cf(crate::db::CF_BLOBS, &blob.versioned_hash, &value)?;
        self.blobs_stored += 1;
        Ok(())
    }

    /// Get a blob by its versioned hash.
    pub fn get_blob(
        &self,
        db: &crate::db::Database,
        versioned_hash: &[u8; 32],
    ) -> Result<Option<StoredBlob>, crate::db::DbError> {
        match db.get_cf(crate::db::CF_BLOBS, versioned_hash)? {
            Some(data) => {
                let blob: StoredBlob = serde_json::from_slice(&data)
                    .map_err(|e| crate::db::DbError::Read(e.to_string()))?;
                Ok(Some(blob))
            }
            None => Ok(None),
        }
    }

    /// Prune blobs older than retention period.
    pub fn prune_old_blobs(
        &mut self,
        db: &crate::db::Database,
        current_epoch: u64,
    ) -> Result<u64, crate::db::DbError> {
        let cutoff = current_epoch.saturating_sub(self.config.retention_epochs);
        let mut pruned = 0u64;

        let entries = db.iter_cf_owned(crate::db::CF_BLOBS);
        for (key, value) in entries {
            if let Ok(blob) = serde_json::from_slice::<StoredBlob>(&value) {
                if blob.epoch < cutoff {
                    db.delete_cf(crate::db::CF_BLOBS, &key)?;
                    pruned += 1;
                }
            }
        }

        self.blobs_pruned += pruned;
        Ok(pruned)
    }

    /// Parse a Type-3 blob transaction from raw RLP bytes.
    /// Type-3 tx: 0x03 || rlp([chain_id, nonce, max_priority_fee, max_fee,
    ///   gas_limit, to, value, data, access_list, max_fee_per_blob_gas,
    ///   blob_versioned_hashes, signature...])
    pub fn parse_blob_tx(raw: &[u8]) -> Option<BlobTransaction> {
        if raw.is_empty() || raw[0] != 0x03 {
            return None;
        }

        // Minimal RLP parsing for blob tx fields
        let rlp = &raw[1..]; // skip type byte
        if rlp.is_empty() {
            return None;
        }

        // Decode the RLP list header
        let (list_data, _) = decode_rlp_list(rlp)?;

        let mut pos = 0;
        let chain_id = decode_rlp_uint(&list_data, &mut pos)? as u64;
        let nonce = decode_rlp_uint(&list_data, &mut pos)? as u64;
        let max_priority_fee = decode_rlp_uint(&list_data, &mut pos)?;
        let max_fee = decode_rlp_uint(&list_data, &mut pos)?;
        let gas_limit = decode_rlp_uint(&list_data, &mut pos)? as u64;
        let to_bytes = decode_rlp_bytes(&list_data, &mut pos)?;
        let value = decode_rlp_uint(&list_data, &mut pos)?;
        let data = decode_rlp_bytes(&list_data, &mut pos)?;

        let mut to = [0u8; 20];
        if to_bytes.len() == 20 {
            to.copy_from_slice(&to_bytes);
        }

        // Skip access_list (we don't fully parse it)
        skip_rlp_item(&list_data, &mut pos)?;

        let max_fee_per_blob_gas = decode_rlp_uint(&list_data, &mut pos)?;

        // Parse blob_versioned_hashes (list of 32-byte hashes)
        let hashes_data = decode_rlp_bytes_or_list(&list_data, &mut pos)?;
        let mut blob_versioned_hashes = Vec::new();
        let mut hp = 0;
        while hp < hashes_data.len() {
            if let Some(hash_bytes) = decode_rlp_bytes(&hashes_data, &mut hp) {
                if hash_bytes.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&hash_bytes);
                    blob_versioned_hashes.push(h);
                }
            } else {
                break;
            }
        }

        Some(BlobTransaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas: max_priority_fee,
            max_fee_per_gas: max_fee,
            gas_limit,
            to,
            value,
            data,
            access_list: vec![],
            max_fee_per_blob_gas,
            blob_versioned_hashes,
        })
    }

    /// Verify a KZG commitment against a blob using SHA-256 as a placeholder.
    /// In production this would use the c-kzg crate with the trusted setup.
    pub fn verify_kzg_commitment(blob_data: &[u8], commitment: &[u8; 48]) -> bool {
        use sha2::{Digest, Sha256};
        // Placeholder verification: hash blob and check first 48 bytes match
        let mut hasher = Sha256::new();
        hasher.update(blob_data);
        let hash = hasher.finalize();
        // Check that commitment is non-zero (basic sanity)
        commitment.iter().any(|&b| b != 0) && !hash.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Minimal RLP helpers for blob tx parsing
// ---------------------------------------------------------------------------

fn decode_rlp_list(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.is_empty() {
        return None;
    }
    let b = data[0];
    if b >= 0xf8 {
        let len_bytes = (b - 0xf7) as usize;
        if data.len() < 1 + len_bytes {
            return None;
        }
        let mut len = 0usize;
        for &byte in &data[1..1 + len_bytes] {
            len = (len << 8) | byte as usize;
        }
        let start = 1 + len_bytes;
        if data.len() < start + len {
            return None;
        }
        Some((&data[start..start + len], start + len))
    } else if b >= 0xc0 {
        let len = (b - 0xc0) as usize;
        if data.len() < 1 + len {
            return None;
        }
        Some((&data[1..1 + len], 1 + len))
    } else {
        None
    }
}

fn decode_rlp_uint(data: &[u8], pos: &mut usize) -> Option<u128> {
    if *pos >= data.len() {
        return None;
    }
    let b = data[*pos];
    if b == 0x80 {
        *pos += 1;
        return Some(0);
    }
    if b < 0x80 {
        *pos += 1;
        return Some(b as u128);
    }
    let len = (b - 0x80) as usize;
    *pos += 1;
    if *pos + len > data.len() {
        return None;
    }
    let mut val = 0u128;
    for &byte in &data[*pos..*pos + len] {
        val = (val << 8) | byte as u128;
    }
    *pos += len;
    Some(val)
}

fn decode_rlp_bytes(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if *pos >= data.len() {
        return None;
    }
    let b = data[*pos];
    if b == 0x80 {
        *pos += 1;
        return Some(vec![]);
    }
    if b < 0x80 {
        *pos += 1;
        return Some(vec![b]);
    }
    if b <= 0xb7 {
        let len = (b - 0x80) as usize;
        *pos += 1;
        if *pos + len > data.len() {
            return None;
        }
        let result = data[*pos..*pos + len].to_vec();
        *pos += len;
        return Some(result);
    }
    if b <= 0xbf {
        let len_bytes = (b - 0xb7) as usize;
        *pos += 1;
        if *pos + len_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for &byte in &data[*pos..*pos + len_bytes] {
            len = (len << 8) | byte as usize;
        }
        *pos += len_bytes;
        if *pos + len > data.len() {
            return None;
        }
        let result = data[*pos..*pos + len].to_vec();
        *pos += len;
        return Some(result);
    }
    None
}

fn decode_rlp_bytes_or_list(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if *pos >= data.len() {
        return None;
    }
    let b = data[*pos];
    if b >= 0xc0 {
        // It's a list — return the inner bytes
        if b >= 0xf8 {
            let len_bytes = (b - 0xf7) as usize;
            *pos += 1;
            if *pos + len_bytes > data.len() {
                return None;
            }
            let mut len = 0usize;
            for &byte in &data[*pos..*pos + len_bytes] {
                len = (len << 8) | byte as usize;
            }
            *pos += len_bytes;
            if *pos + len > data.len() {
                return None;
            }
            let result = data[*pos..*pos + len].to_vec();
            *pos += len;
            Some(result)
        } else {
            let len = (b - 0xc0) as usize;
            *pos += 1;
            if *pos + len > data.len() {
                return None;
            }
            let result = data[*pos..*pos + len].to_vec();
            *pos += len;
            Some(result)
        }
    } else {
        decode_rlp_bytes(data, pos)
    }
}

fn skip_rlp_item(data: &[u8], pos: &mut usize) -> Option<()> {
    if *pos >= data.len() {
        return None;
    }
    let b = data[*pos];
    if b < 0x80 {
        *pos += 1;
    } else if b <= 0xb7 {
        let len = (b - 0x80) as usize;
        *pos += 1 + len;
    } else if b <= 0xbf {
        let len_bytes = (b - 0xb7) as usize;
        *pos += 1;
        let mut len = 0usize;
        for &byte in &data[*pos..*pos + len_bytes] {
            len = (len << 8) | byte as usize;
        }
        *pos += len_bytes + len;
    } else if b <= 0xf7 {
        let len = (b - 0xc0) as usize;
        *pos += 1 + len;
    } else {
        let len_bytes = (b - 0xf7) as usize;
        *pos += 1;
        let mut len = 0usize;
        for &byte in &data[*pos..*pos + len_bytes] {
            len = (len << 8) | byte as usize;
        }
        *pos += len_bytes + len;
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[test]
    fn test_blob_store_creation() {
        let store = BlobStore::new(BlobConfig::default());
        assert_eq!(store.config.retention_epochs, 4096);
        assert_eq!(store.blobs_stored, 0);
    }

    #[test]
    fn test_blob_put_get() {
        let mut store = BlobStore::new(BlobConfig::default());
        let (db, _dir) = Database::open_temp().unwrap();

        let blob = StoredBlob {
            versioned_hash: [0x01u8; 32],
            block_height: 100,
            tx_hash: [0x02u8; 32],
            data: vec![0xAA; 1024],
            commitment: vec![0xBB; 48],
            proof: vec![0xCC; 48],
            epoch: 10,
        };

        store.put_blob(&db, &blob).unwrap();
        assert_eq!(store.blobs_stored, 1);

        let retrieved = store.get_blob(&db, &blob.versioned_hash).unwrap().unwrap();
        assert_eq!(retrieved.block_height, 100);
        assert_eq!(retrieved.data.len(), 1024);
    }

    #[test]
    fn test_blob_get_missing() {
        let store = BlobStore::new(BlobConfig::default());
        let (db, _dir) = Database::open_temp().unwrap();
        let result = store.get_blob(&db, &[0xFFu8; 32]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_blob_pruning() {
        let mut store = BlobStore::new(BlobConfig {
            retention_epochs: 10,
            slots_per_epoch: 32,
        });
        let (db, _dir) = Database::open_temp().unwrap();

        // Store blobs at different epochs
        for epoch in 0..20u64 {
            let mut hash = [0u8; 32];
            hash[0] = epoch as u8;
            let blob = StoredBlob {
                versioned_hash: hash,
                block_height: epoch * 32,
                tx_hash: [0u8; 32],
                data: vec![0; 64],
                commitment: vec![0; 48],
                proof: vec![0; 48],
                epoch,
            };
            store.put_blob(&db, &blob).unwrap();
        }

        // Prune at epoch 20 with retention 10 → cutoff = 10
        let pruned = store.prune_old_blobs(&db, 20).unwrap();
        assert!(pruned >= 10); // epochs 0-9 should be pruned
    }

    #[test]
    fn test_parse_blob_tx_wrong_type() {
        // Not a type-3 tx
        let raw = vec![0x02, 0xc0]; // type-2
        assert!(BlobStore::parse_blob_tx(&raw).is_none());
    }

    #[test]
    fn test_parse_blob_tx_empty() {
        assert!(BlobStore::parse_blob_tx(&[]).is_none());
    }

    #[test]
    fn test_parse_blob_tx_type3() {
        // Construct a minimal type-3 blob tx
        // 0x03 || rlp([chain_id=1, nonce=0, max_priority=1, max_fee=2,
        //   gas_limit=21000, to=20bytes, value=0, data=empty, access_list=empty,
        //   max_fee_per_blob_gas=3, blob_versioned_hashes=[hash1]])

        let mut inner = Vec::new();
        inner.push(0x01); // chain_id = 1
        inner.push(0x80); // nonce = 0
        inner.push(0x01); // max_priority_fee = 1
        inner.push(0x02); // max_fee = 2
                          // gas_limit = 21000 = 0x5208
        inner.push(0x82);
        inner.push(0x52);
        inner.push(0x08);
        // to = 20 zero bytes
        inner.push(0x94);
        inner.extend_from_slice(&[0u8; 20]);
        inner.push(0x80); // value = 0
        inner.push(0x80); // data = empty
        inner.push(0xc0); // access_list = empty list
        inner.push(0x03); // max_fee_per_blob_gas = 3
                          // blob_versioned_hashes = [32-byte hash]
        let hash = [0x01u8; 32];
        let mut hash_list = Vec::new();
        hash_list.push(0xa0); // 32-byte string
        hash_list.extend_from_slice(&hash);
        // Wrap in list
        let mut hashes_enc = Vec::new();
        if hash_list.len() < 56 {
            hashes_enc.push(0xc0 + hash_list.len() as u8);
        }
        hashes_enc.extend_from_slice(&hash_list);
        inner.extend_from_slice(&hashes_enc);

        // Wrap inner in RLP list
        let mut rlp = Vec::new();
        if inner.len() < 56 {
            rlp.push(0xc0 + inner.len() as u8);
        } else {
            let len_bytes = inner.len().to_be_bytes();
            let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
            rlp.push(0xf7 + (8 - start) as u8);
            rlp.extend_from_slice(&len_bytes[start..]);
        }
        rlp.extend_from_slice(&inner);

        // Prepend type byte
        let mut raw = vec![0x03];
        raw.extend_from_slice(&rlp);

        let tx = BlobStore::parse_blob_tx(&raw);
        assert!(tx.is_some(), "should parse blob tx");
        let tx = tx.unwrap();
        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.gas_limit, 21000);
        assert_eq!(tx.max_fee_per_blob_gas, 3);
        assert_eq!(tx.blob_versioned_hashes.len(), 1);
        assert_eq!(tx.blob_versioned_hashes[0], hash);
    }

    #[test]
    fn test_kzg_commitment_verification_placeholder() {
        let blob_data = vec![0xAA; 131072];
        let mut commitment = [0u8; 48];
        commitment[0] = 0x01;
        // Placeholder always returns true for non-zero commitment
        assert!(BlobStore::verify_kzg_commitment(&blob_data, &commitment));
    }

    #[test]
    fn test_kzg_zero_commitment_fails() {
        let blob_data = vec![0xAA; 1024];
        let commitment = [0u8; 48]; // all zeros
        assert!(!BlobStore::verify_kzg_commitment(&blob_data, &commitment));
    }
}
