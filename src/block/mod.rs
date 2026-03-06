//! Block parsing and chain graph construction.
//!
//! Supports parsing both P-Chain (Avalanche codec) and C-Chain (RLP/Ethereum) blocks.

use sha2::{Digest, Sha256};

/// Raw 32-byte block identifier (SHA-256 of block bytes).
pub type BlockId = [u8; 32];

/// Block type derived from the Avalanche codec typeID (P-Chain) or RLP structure (C-Chain).
///
/// Type ID registration order (block/codec.go linearcodec):
///   0: ApricotProposalBlock   1: ApricotAbortBlock    2: ApricotCommitBlock
///   3: ApricotStandardBlock   4: ApricotAtomicBlock   (5-28: tx types)
///  29: BanffProposalBlock    30: BanffAbortBlock      31: BanffCommitBlock
///  32: BanffStandardBlock
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    /// typeID = 0 (Apricot)
    ApricotProposal,
    /// typeID = 1 (Apricot)
    ApricotAbort,
    /// typeID = 2 (Apricot)
    ApricotCommit,
    /// typeID = 3 (Apricot)
    ApricotStandard,
    /// typeID = 4 (Apricot)
    ApricotAtomic,
    /// typeID = 29 (Banff)
    BanffProposal,
    /// typeID = 30 (Banff)
    BanffAbort,
    /// typeID = 31 (Banff)
    BanffCommit,
    /// typeID = 32 (Banff)
    BanffStandard,
    /// Coreth EVM block (C-Chain)
    CChainEvm,
    /// Unknown typeID
    Unknown(u32),
}

/// Which chain a block belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    PChain,
    CChain,
}

/// Parsed block header with chain graph metadata.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    /// SHA-256 of raw block bytes — the block's ID in the chain graph.
    pub id: BlockId,
    /// Parent block ID extracted from the block body.
    pub parent_id: BlockId,
    /// Block height (for P-Chain: from block body; for C-Chain: Ethereum block number).
    pub height: u64,
    /// Unix seconds timestamp.
    pub timestamp: u64,
    /// Block type.
    pub block_type: BlockType,
    /// Size of the raw block bytes.
    pub raw_size: usize,
    /// Raw block bytes (for signature verification).
    pub raw_bytes: Vec<u8>,
}

impl BlockHeader {
    /// Parse a raw block into a `BlockHeader`.
    ///
    /// **P-Chain Apricot block layout (typeID 0-4):**
    /// - Bytes `[0..2]`: codec version (uint16 BE, usually 0)
    /// - Bytes `[2..6]`: typeID (uint32 BE)
    /// - Bytes `[6..38]`: parentID (32 bytes)
    /// - Bytes `[38..46]`: height (uint64 BE)
    /// - Bytes `[46..]`: transactions (no explicit timestamp field)
    ///
    /// **P-Chain Banff block layout (typeID 29-32, except BanffProposal):**
    /// - Bytes `[0..2]`: codec version
    /// - Bytes `[2..6]`: typeID (uint32 BE)
    /// - Bytes `[6..14]`: timestamp/Time (uint64 BE) — comes FIRST in Banff blocks
    /// - Bytes `[14..46]`: parentID (32 bytes)
    /// - Bytes `[46..54]`: height (uint64 BE)
    ///
    /// **P-Chain BanffProposalBlock layout (typeID 29):**
    /// - Bytes `[0..2]`: codec version
    /// - Bytes `[2..6]`: typeID (uint32 BE = 29)
    /// - Bytes `[6..14]`: timestamp/Time (uint64 BE)
    /// - Bytes `[14..18]`: Transactions slice length (uint32 BE, usually 0)
    /// - Bytes `[18..50]`: parentID (32 bytes)
    /// - Bytes `[50..58]`: height (uint64 BE)
    ///
    /// **C-Chain block layout:** RLP-encoded Ethereum block (possibly with Avalanche wrapper).
    pub fn parse(raw: &[u8], chain: Chain) -> Result<Self, String> {
        let id = sha256(raw);
        match chain {
            Chain::PChain => parse_pchain_block(raw, id),
            Chain::CChain => parse_cchain_block(raw, id),
        }
    }

    /// Returns true if this is the genesis block (parent_id == all zeros).
    pub fn is_genesis(&self) -> bool {
        self.parent_id == [0u8; 32]
    }

    /// Extract the stateRoot (field 3) from a C-Chain RLP block.
    /// Returns None if not parseable or not a C-Chain block.
    pub fn extract_state_root(raw: &[u8]) -> Option<[u8; 32]> {
        if raw.is_empty() {
            return None;
        }
        // Handle Avalanche wrapper
        let rlp = if raw.len() >= 6 && raw[0] == 0x00 && raw[1] == 0x00 {
            &raw[6..]
        } else {
            raw
        };
        if rlp.is_empty() || rlp[0] < 0xc0 {
            return None;
        }
        // Outer list
        let (_, header_start) = rlp_list_start(rlp, 0).ok()?;
        // Inner header list
        let (_, fields_start) = rlp_list_start(rlp, header_start).ok()?;
        // Skip field 0 (parentHash), 1 (sha3Uncles), 2 (miner), then read field 3 (stateRoot)
        let mut pos = fields_start;
        for _ in 0..3 {
            pos = rlp_skip(rlp, pos).ok()?;
        }
        // Field 3 is stateRoot: 0xa0 + 32 bytes
        rlp_read_bytes32(rlp, pos).ok()
    }

    /// Verify the BLS signature of this block using the provided public key.
    ///
    /// Post-Banff blocks include a BLS signature over the block hash. The signature
    /// is typically the last 96 bytes of the raw block data (BLS G2 compressed format).
    ///
    /// Returns `Ok(())` if signature is valid, `Err` if invalid or missing.
    /// Currently validates format only (signature must be 96 bytes, key must be 48 bytes).
    /// Full cryptographic verification is deferred to consensus layer.
    pub fn verify_signature(&self, pub_key_bytes: &[u8]) -> Result<(), String> {
        // Extract signature: last 96 bytes (BLS G2 compressed)
        if self.raw_bytes.len() < 96 {
            return Err("block too small to contain BLS signature".to_string());
        }

        let sig_bytes = &self.raw_bytes[self.raw_bytes.len() - 96..];

        // Validate public key format (BLS pubkey is 48 bytes compressed)
        if pub_key_bytes.len() != 48 {
            return Err(format!("invalid public key size: {} (expected 48)", pub_key_bytes.len()));
        }

        // Validate signature format (BLS G2 compressed is 96 bytes)
        if sig_bytes.len() != 96 {
            return Err(format!("invalid signature size: {} (expected 96)", sig_bytes.len()));
        }

        // Try to parse as BLS objects to validate structure
        use blst::min_pk::{PublicKey, Signature};
        PublicKey::from_bytes(pub_key_bytes)
            .map_err(|e| format!("invalid public key format: {:?}", e))?;
        Signature::from_bytes(sig_bytes)
            .map_err(|e| format!("invalid signature format: {:?}", e))?;

        // Format validation passed; full cryptographic verification deferred
        Ok(())
    }

    /// Returns the parent ID extracted from a raw block byte slice, accounting for
    /// the block type at the correct offset. Used for chain-walk without full parse.
    pub fn extract_parent_id(raw: &[u8]) -> Option<[u8; 32]> {
        if raw.len() < 6 {
            return None;
        }
        let type_id = u32::from_be_bytes(raw[2..6].try_into().ok()?);
        match type_id {
            29 => {
                // BanffProposal: ts(8) + txs_len(4) + parent(32) @ [18..50]
                if raw.len() >= 50 {
                    raw[18..50].try_into().ok()
                } else {
                    None
                }
            }
            30 | 31 | 32 => {
                // BanffAbort/Commit/Standard: ts(8) + parent(32) @ [14..46]
                if raw.len() >= 46 {
                    raw[14..46].try_into().ok()
                } else {
                    None
                }
            }
            _ => {
                // Apricot: parent(32) @ [6..38]
                if raw.len() >= 38 {
                    raw[6..38].try_into().ok()
                } else {
                    None
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BlockMetadata
// ---------------------------------------------------------------------------

/// Block metadata: a superset of BlockHeader with derived fields.
#[derive(Debug, Clone)]
pub struct BlockMetadata {
    pub id: BlockId,
    pub height: u64,
    pub timestamp: u64,
    pub parent_id: BlockId,
    pub block_type: BlockType,
    /// Number of transactions extracted from the block body (best-effort, 0 if unparseable).
    pub tx_count: u32,
    pub size_bytes: usize,
}

impl BlockMetadata {
    /// Parse a raw block into `BlockMetadata`.
    pub fn from_raw(raw: &[u8], chain: Chain) -> Result<Self, String> {
        let hdr = BlockHeader::parse(raw, chain)?;
        let tx_count = extract_tx_count(raw, &hdr.block_type);
        Ok(Self {
            id: hdr.id,
            height: hdr.height,
            timestamp: hdr.timestamp,
            parent_id: hdr.parent_id,
            block_type: hdr.block_type,
            tx_count,
            size_bytes: raw.len(),
        })
    }
}

/// Extract the transaction count from a P-Chain block body.
fn extract_tx_count(raw: &[u8], block_type: &BlockType) -> u32 {
    match block_type {
        BlockType::BanffStandard | BlockType::ApricotStandard => {
            let tx_len_offset = match block_type {
                BlockType::BanffStandard => 54,
                BlockType::ApricotStandard => 46,
                _ => unreachable!(),
            };
            if raw.len() >= tx_len_offset + 4 {
                u32::from_be_bytes(raw[tx_len_offset..tx_len_offset + 4].try_into().unwrap())
            } else {
                0
            }
        }
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// P-Chain parser
// ---------------------------------------------------------------------------

fn parse_pchain_block(raw: &[u8], id: BlockId) -> Result<BlockHeader, String> {
    if raw.len() < 6 {
        return Err(format!(
            "P-Chain block too short: {} bytes (need ≥6 for typeID)",
            raw.len()
        ));
    }

    let type_id = u32::from_be_bytes(raw[2..6].try_into().unwrap());

    let (parent_id, height, timestamp) = match type_id {
        29 => {
            // BanffProposalBlock: [6..14]=Time, [14..18]=Txs_len, [18..50]=PrntID, [50..58]=Hght
            if raw.len() < 58 {
                return Err(format!(
                    "BanffProposalBlock too short: {} bytes (need ≥58)",
                    raw.len()
                ));
            }
            let ts = u64::from_be_bytes(raw[6..14].try_into().unwrap());
            let mut pid = [0u8; 32];
            pid.copy_from_slice(&raw[18..50]);
            let h = u64::from_be_bytes(raw[50..58].try_into().unwrap());
            (pid, h, ts)
        }
        30 | 31 | 32 => {
            // BanffAbortBlock / BanffCommitBlock / BanffStandardBlock:
            // [6..14]=Time, [14..46]=PrntID, [46..54]=Hght
            if raw.len() < 54 {
                return Err(format!(
                    "Banff block (typeID={}) too short: {} bytes (need ≥54)",
                    type_id,
                    raw.len()
                ));
            }
            let ts = u64::from_be_bytes(raw[6..14].try_into().unwrap());
            let mut pid = [0u8; 32];
            pid.copy_from_slice(&raw[14..46]);
            let h = u64::from_be_bytes(raw[46..54].try_into().unwrap());
            (pid, h, ts)
        }
        _ => {
            // All P-Chain blocks from Ancestors use the same wire format:
            // [6..38]=PrntID(32), [38..46]=Timestamp(u64), [46..54]=Height(u64)
            // This applies even to blocks with Apricot type IDs (0-4).
            if raw.len() < 46 {
                return Err(format!(
                    "P-Chain block too short: {} bytes (need ≥46)",
                    raw.len()
                ));
            }
            let mut pid = [0u8; 32];
            pid.copy_from_slice(&raw[6..38]);
            if raw.len() >= 54 {
                let ts = u64::from_be_bytes(raw[38..46].try_into().unwrap());
                let h = u64::from_be_bytes(raw[46..54].try_into().unwrap());
                (pid, h, ts)
            } else {
                // Short block: just parent + height, no timestamp
                let h = u64::from_be_bytes(raw[38..46].try_into().unwrap());
                (pid, h, 0)
            }
        }
    };

    let block_type = match type_id {
        0 => BlockType::ApricotProposal,
        1 => BlockType::ApricotAbort,
        2 => BlockType::ApricotCommit,
        3 => BlockType::ApricotStandard,
        4 => BlockType::ApricotAtomic,
        29 => BlockType::BanffProposal,
        30 => BlockType::BanffAbort,
        31 => BlockType::BanffCommit,
        32 => BlockType::BanffStandard,
        t => BlockType::Unknown(t),
    };

    Ok(BlockHeader {
        id,
        parent_id,
        height,
        timestamp,
        block_type,
        raw_size: raw.len(),
        raw_bytes: raw.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// C-Chain / Ethereum RLP parser
// ---------------------------------------------------------------------------

/// Parse a C-Chain block from the Ancestors protocol response.
///
/// Handles two formats:
/// 1. Raw RLP: starts with 0xf8/0xf9 (RLP long list prefix)
/// 2. Avalanche-wrapped RLP: starts with 0x00 0x00 (codec version), followed by
///    4-byte typeID, then raw RLP bytes
fn parse_cchain_block(raw: &[u8], id: BlockId) -> Result<BlockHeader, String> {
    if raw.is_empty() {
        return Err("empty C-Chain block".to_string());
    }

    // Detect Avalanche codec wrapper: version bytes 0x00 0x00 followed by typeID
    let rlp_data = if raw.len() >= 6 && raw[0] == 0x00 && raw[1] == 0x00 {
        // Skip 2-byte codec version + 4-byte typeID
        &raw[6..]
    } else {
        raw
    };

    if rlp_data.is_empty() {
        return Err("C-Chain block empty after header strip".to_string());
    }

    // Verify it looks like an RLP list
    if rlp_data[0] < 0xc0 {
        return Err(format!(
            "C-Chain block: expected RLP list (0xc0+) at start, got 0x{:02x} (first raw bytes: {:02x?})",
            rlp_data[0],
            &raw[..raw.len().min(8)]
        ));
    }

    parse_cchain_rlp(rlp_data, id)
}

/// Parse an RLP-encoded Ethereum block.
///
/// Structure: `[header_list, uncles_list, txs_list]` (outer list, 3 items)
/// Header fields (in order):
///   parentHash(0) sha3Uncles(1) miner(2) stateRoot(3) txRoot(4) receiptRoot(5)
///   bloom(6) difficulty(7) number(8) gasLimit(9) gasUsed(10) timestamp(11) …
fn parse_cchain_rlp(raw: &[u8], id: BlockId) -> Result<BlockHeader, String> {
    // Outer list: [header, uncles, txs]
    let (_, header_start) =
        rlp_list_start(raw, 0).map_err(|e| format!("outer list: {}", e))?;

    // Inner header list
    let (_, fields_start) =
        rlp_list_start(raw, header_start).map_err(|e| format!("header list: {}", e))?;

    // Field 0: parentHash (32-byte string, 0xa0 prefix)
    let parent_id =
        rlp_read_bytes32(raw, fields_start).map_err(|e| format!("parentHash: {}", e))?;

    // Skip to field 8 (block number): fields 0-7 are before number
    let mut pos = fields_start;
    for i in 0..8 {
        pos = rlp_skip(raw, pos).map_err(|e| format!("skip field {}: {}", i, e))?;
    }
    let number = rlp_read_u64(raw, pos).unwrap_or(0);

    // Skip field 8 (number), 9 (gasLimit), 10 (gasUsed) to reach field 11 (timestamp)
    pos = rlp_skip(raw, pos).map_err(|e| format!("skip number: {}", e))?;
    pos = rlp_skip(raw, pos).map_err(|e| format!("skip gasLimit: {}", e))?;
    pos = rlp_skip(raw, pos).map_err(|e| format!("skip gasUsed: {}", e))?;
    let timestamp = rlp_read_u64(raw, pos).unwrap_or(0);

    Ok(BlockHeader {
        id,
        parent_id,
        height: number,
        timestamp,
        block_type: BlockType::CChainEvm,
        raw_size: raw.len(),
        raw_bytes: raw.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// RLP helpers
// ---------------------------------------------------------------------------

/// Returns `(payload_len, offset_of_first_item)` for an RLP list starting at `pos`.
fn rlp_list_start(data: &[u8], pos: usize) -> Result<(usize, usize), String> {
    if pos >= data.len() {
        return Err(format!("pos {} out of bounds (len={})", pos, data.len()));
    }
    let first = data[pos];
    if first < 0xc0 {
        return Err(format!(
            "expected list at pos {}, got 0x{:02x}",
            pos, first
        ));
    }
    if first <= 0xf7 {
        let payload_len = (first - 0xc0) as usize;
        Ok((payload_len, pos + 1))
    } else {
        let len_bytes = (first - 0xf7) as usize;
        if pos + 1 + len_bytes > data.len() {
            return Err("list length bytes out of bounds".to_string());
        }
        let mut len = 0usize;
        for i in 0..len_bytes {
            len = (len << 8) | (data[pos + 1 + i] as usize);
        }
        Ok((len, pos + 1 + len_bytes))
    }
}

/// Read a 32-byte RLP string at `pos` (expects `0xa0` prefix).
fn rlp_read_bytes32(data: &[u8], pos: usize) -> Result<[u8; 32], String> {
    if pos >= data.len() {
        return Err(format!("pos {} out of bounds", pos));
    }
    // 0xa0 = 0x80 + 32 — string of length 32
    if data[pos] != 0xa0 {
        return Err(format!(
            "expected 0xa0 at pos {}, got 0x{:02x}",
            pos, data[pos]
        ));
    }
    if pos + 33 > data.len() {
        return Err("not enough bytes for 32-byte string".to_string());
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&data[pos + 1..pos + 33]);
    Ok(result)
}

/// Read an RLP-encoded big-endian integer as `u64` at `pos`.
fn rlp_read_u64(data: &[u8], pos: usize) -> Result<u64, String> {
    if pos >= data.len() {
        return Err(format!("pos {} out of bounds", pos));
    }
    let first = data[pos];
    if first == 0x80 {
        return Ok(0); // empty string = 0
    }
    if first <= 0x7f {
        return Ok(first as u64); // single-byte value
    }
    if first <= 0xb7 {
        let len = (first - 0x80) as usize;
        if len > 8 {
            return Err(format!("u64 too long: {} bytes", len));
        }
        if pos + 1 + len > data.len() {
            return Err("not enough bytes for u64 string".to_string());
        }
        let mut value = 0u64;
        for i in 0..len {
            value = (value << 8) | (data[pos + 1 + i] as u64);
        }
        return Ok(value);
    }
    Err(format!(
        "unexpected RLP prefix 0x{:02x} for u64 at pos {}",
        first, pos
    ))
}

/// Skip one RLP item at `pos`, returning the position of the next item.
fn rlp_skip(data: &[u8], pos: usize) -> Result<usize, String> {
    if pos >= data.len() {
        return Err(format!("pos {} out of bounds (len={})", pos, data.len()));
    }
    let first = data[pos];
    if first <= 0x7f {
        // Single byte
        Ok(pos + 1)
    } else if first <= 0xb7 {
        // Short string
        let len = (first - 0x80) as usize;
        Ok(pos + 1 + len)
    } else if first <= 0xbf {
        // Long string
        let len_bytes = (first - 0xb7) as usize;
        if pos + 1 + len_bytes > data.len() {
            return Err("long string len bytes out of bounds".to_string());
        }
        let mut len = 0usize;
        for i in 0..len_bytes {
            len = (len << 8) | (data[pos + 1 + i] as usize);
        }
        Ok(pos + 1 + len_bytes + len)
    } else if first <= 0xf7 {
        // Short list
        let len = (first - 0xc0) as usize;
        Ok(pos + 1 + len)
    } else {
        // Long list
        let len_bytes = (first - 0xf7) as usize;
        if pos + 1 + len_bytes > data.len() {
            return Err("long list len bytes out of bounds".to_string());
        }
        let mut len = 0usize;
        for i in 0..len_bytes {
            len = (len << 8) | (data[pos + 1 + i] as usize);
        }
        Ok(pos + 1 + len_bytes + len)
    }
}

// ---------------------------------------------------------------------------
// C-Chain transaction extraction
// ---------------------------------------------------------------------------

/// A raw transaction decoded from a C-Chain (Ethereum) block, before ECDSA
/// sender recovery.
#[derive(Debug, Clone)]
pub struct CChainRawTx {
    /// Transaction type: 0 = legacy, 1 = EIP-2930, 2 = EIP-1559.
    pub tx_type: u8,
    /// Sender nonce.
    pub nonce: u64,
    /// Gas price in wei (legacy/EIP-2930) or `maxFeePerGas` (EIP-1559).
    pub gas_price: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient address, or `None` for contract creation.
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Call data / init code.
    pub data: Vec<u8>,
}

/// Block-level fields extracted from a C-Chain block header, needed to build
/// a `BlockContext` for EVM execution.
#[derive(Debug, Clone)]
pub struct CChainBlockFields {
    /// Ethereum block number.
    pub number: u64,
    /// Unix-seconds timestamp.
    pub timestamp: u64,
    /// Gas limit for the block.
    pub gas_limit: u64,
    /// Base fee per gas (EIP-1559). Defaults to 25 gwei for pre-EIP-1559 blocks.
    pub base_fee: u128,
    /// Block producer / coinbase address.
    pub miner: [u8; 20],
}

/// Extract all transactions from a raw C-Chain block (handles both
/// Avalanche-wrapped and raw RLP formats).
///
/// Supports legacy (type-0), EIP-2930 (type-1), and EIP-1559 (type-2)
/// transactions. The `from` field is not recovered here — callers should
/// pre-fund a placeholder sender or perform ECDSA recovery separately.
pub fn extract_cchain_transactions(raw: &[u8]) -> Vec<CChainRawTx> {
    let rlp = strip_avalanche_wrapper(raw);
    if rlp.is_empty() || rlp[0] < 0xc0 {
        return vec![];
    }

    // Navigate: outer list → skip header → skip uncles → txs list
    let (_, outer_start) = match rlp_list_start(rlp, 0) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let after_header = match rlp_skip(rlp, outer_start) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let txs_list_pos = match rlp_skip(rlp, after_header) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    if txs_list_pos >= rlp.len() || rlp[txs_list_pos] < 0xc0 {
        return vec![];
    }

    let txs_end = match rlp_skip(rlp, txs_list_pos) {
        Ok(v) => v,
        Err(_) => rlp.len(),
    };
    let (_, mut pos) = match rlp_list_start(rlp, txs_list_pos) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let mut txs = Vec::new();
    while pos < txs_end && pos < rlp.len() {
        let byte = rlp[pos];
        if byte >= 0xc0 {
            // Legacy RLP list transaction
            if let Some(tx) = parse_legacy_tx(rlp, pos) {
                txs.push(tx);
            }
            match rlp_skip(rlp, pos) {
                Ok(next) => pos = next,
                Err(_) => break,
            }
        } else {
            // EIP-2718 typed transaction encoded as an RLP byte string
            // whose content is [type_byte || rlp_payload]
            match rlp_read_bytes_raw(rlp, pos) {
                Ok((content, next_pos)) => {
                    if !content.is_empty() {
                        if let Some(tx) = parse_typed_tx(content) {
                            txs.push(tx);
                        }
                    }
                    pos = next_pos;
                }
                Err(_) => break,
            }
        }
    }
    txs
}

/// Extract block-level header fields from a raw C-Chain block.
///
/// Handles blocks with varying numbers of header fields (pre- and post-EIP-1559).
/// Returns `None` only if the block is structurally unparseable.
pub fn extract_cchain_block_fields(raw: &[u8]) -> Option<CChainBlockFields> {
    let rlp = strip_avalanche_wrapper(raw);
    if rlp.is_empty() || rlp[0] < 0xc0 {
        return None;
    }

    // Outer list → header list
    let (_, header_start) = rlp_list_start(rlp, 0).ok()?;
    let (_, mut pos) = rlp_list_start(rlp, header_start).ok()?;

    /// Skip a field, returning `false` if out of bounds (graceful end).
    fn skip(data: &[u8], pos: &mut usize) -> bool {
        match rlp_skip(data, *pos) {
            Ok(next) => { *pos = next; true }
            Err(_) => false,
        }
    }

    // field 0: parentHash – skip
    if !skip(rlp, &mut pos) { return None; }
    // field 1: sha3Uncles – skip
    if !skip(rlp, &mut pos) { return None; }
    // field 2: miner (20 bytes, 0x94 prefix)
    let miner = rlp_read_address(rlp, pos).unwrap_or([0u8; 20]);
    if !skip(rlp, &mut pos) { return None; }
    // field 3: stateRoot – skip
    if !skip(rlp, &mut pos) { return None; }
    // field 4: txRoot – skip
    if !skip(rlp, &mut pos) { return None; }
    // field 5: receiptRoot – skip
    if !skip(rlp, &mut pos) { return None; }
    // field 6: bloom – skip
    if !skip(rlp, &mut pos) { return None; }
    // field 7: difficulty – skip
    if !skip(rlp, &mut pos) { return None; }
    // field 8: number
    let number = rlp_read_u64(rlp, pos).unwrap_or(0);
    if !skip(rlp, &mut pos) { return None; }
    // field 9: gasLimit
    let gas_limit = rlp_read_u64(rlp, pos).unwrap_or(30_000_000);
    if !skip(rlp, &mut pos) { return None; }
    // field 10: gasUsed – skip
    if !skip(rlp, &mut pos) { return None; }
    // field 11: timestamp
    let timestamp = rlp_read_u64(rlp, pos).unwrap_or(0);
    // Fields 12+ are optional in synthetic/test blocks
    // field 12: extraData
    if !skip(rlp, &mut pos) {
        return Some(CChainBlockFields { number, timestamp, gas_limit, base_fee: 25_000_000_000, miner });
    }
    // field 13: mixHash
    if !skip(rlp, &mut pos) {
        return Some(CChainBlockFields { number, timestamp, gas_limit, base_fee: 25_000_000_000, miner });
    }
    // field 14: nonce
    if !skip(rlp, &mut pos) {
        return Some(CChainBlockFields { number, timestamp, gas_limit, base_fee: 25_000_000_000, miner });
    }
    // field 15: baseFeePerGas (EIP-1559; absent in pre-London blocks)
    let base_fee = if pos < rlp.len() {
        rlp_read_u128(rlp, pos).unwrap_or(25_000_000_000)
    } else {
        25_000_000_000 // 25 gwei default
    };

    Some(CChainBlockFields { number, timestamp, gas_limit, base_fee, miner })
}

// ---------------------------------------------------------------------------
// C-Chain parsing helpers
// ---------------------------------------------------------------------------

/// Strip Avalanche codec wrapper (0x00 0x00 + 4-byte typeID) if present.
fn strip_avalanche_wrapper(raw: &[u8]) -> &[u8] {
    if raw.len() >= 6 && raw[0] == 0x00 && raw[1] == 0x00 {
        &raw[6..]
    } else {
        raw
    }
}

/// Parse a legacy (type-0) Ethereum transaction from an RLP list.
/// Format: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
fn parse_legacy_tx(data: &[u8], pos: usize) -> Option<CChainRawTx> {
    let (_, mut fp) = rlp_list_start(data, pos).ok()?;
    let nonce = rlp_read_u64(data, fp).unwrap_or(0);
    fp = rlp_skip(data, fp).ok()?;
    let gas_price = rlp_read_u128(data, fp).unwrap_or(0);
    fp = rlp_skip(data, fp).ok()?;
    let gas_limit = rlp_read_u64(data, fp).unwrap_or(21_000);
    fp = rlp_skip(data, fp).ok()?;
    let to = rlp_read_address(data, fp);
    fp = rlp_skip(data, fp).ok()?;
    let value = rlp_read_u128(data, fp).unwrap_or(0);
    fp = rlp_skip(data, fp).ok()?;
    let tx_data = rlp_read_bytes_vec(data, fp).unwrap_or_default();
    Some(CChainRawTx { tx_type: 0, nonce, gas_price, gas_limit, to, value, data: tx_data })
}

/// Parse an EIP-2718 typed transaction. `raw` is `[type_byte || rlp_payload]`.
fn parse_typed_tx(raw: &[u8]) -> Option<CChainRawTx> {
    if raw.is_empty() {
        return None;
    }
    let tx_type = raw[0];
    let payload = &raw[1..];
    if payload.is_empty() || payload[0] < 0xc0 {
        return None;
    }
    let (_, mut fp) = rlp_list_start(payload, 0).ok()?;

    match tx_type {
        0x01 => {
            // EIP-2930: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, ...]
            fp = rlp_skip(payload, fp).ok()?; // chainId
            let nonce = rlp_read_u64(payload, fp).unwrap_or(0);
            fp = rlp_skip(payload, fp).ok()?;
            let gas_price = rlp_read_u128(payload, fp).unwrap_or(0);
            fp = rlp_skip(payload, fp).ok()?;
            let gas_limit = rlp_read_u64(payload, fp).unwrap_or(21_000);
            fp = rlp_skip(payload, fp).ok()?;
            let to = rlp_read_address(payload, fp);
            fp = rlp_skip(payload, fp).ok()?;
            let value = rlp_read_u128(payload, fp).unwrap_or(0);
            fp = rlp_skip(payload, fp).ok()?;
            let data = rlp_read_bytes_vec(payload, fp).unwrap_or_default();
            Some(CChainRawTx { tx_type: 1, nonce, gas_price, gas_limit, to, value, data })
        }
        0x02 => {
            // EIP-1559: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, ...]
            fp = rlp_skip(payload, fp).ok()?; // chainId
            let nonce = rlp_read_u64(payload, fp).unwrap_or(0);
            fp = rlp_skip(payload, fp).ok()?;
            fp = rlp_skip(payload, fp).ok()?; // maxPriorityFeePerGas
            let gas_price = rlp_read_u128(payload, fp).unwrap_or(0); // maxFeePerGas
            fp = rlp_skip(payload, fp).ok()?;
            let gas_limit = rlp_read_u64(payload, fp).unwrap_or(21_000);
            fp = rlp_skip(payload, fp).ok()?;
            let to = rlp_read_address(payload, fp);
            fp = rlp_skip(payload, fp).ok()?;
            let value = rlp_read_u128(payload, fp).unwrap_or(0);
            fp = rlp_skip(payload, fp).ok()?;
            let data = rlp_read_bytes_vec(payload, fp).unwrap_or_default();
            Some(CChainRawTx { tx_type: 2, nonce, gas_price, gas_limit, to, value, data })
        }
        _ => None,
    }
}

/// Read a 20-byte Ethereum address at `pos` (expects `0x94` = 0x80+20 prefix,
/// or `0x80` for null/empty = contract creation).
fn rlp_read_address(data: &[u8], pos: usize) -> Option<[u8; 20]> {
    if pos >= data.len() {
        return None;
    }
    match data[pos] {
        0x80 => None, // null address → contract creation
        0x94 if pos + 21 <= data.len() => {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&data[pos + 1..pos + 21]);
            Some(addr)
        }
        _ => None,
    }
}

/// Read an RLP-encoded big-endian integer as `u128` at `pos`.
fn rlp_read_u128(data: &[u8], pos: usize) -> Result<u128, String> {
    if pos >= data.len() {
        return Err(format!("pos {} out of bounds (len={})", pos, data.len()));
    }
    let first = data[pos];
    if first == 0x80 {
        return Ok(0);
    }
    if first <= 0x7f {
        return Ok(first as u128);
    }
    if first <= 0xb7 {
        let len = (first - 0x80) as usize;
        if len > 16 {
            return Err(format!("u128 field too long: {} bytes", len));
        }
        if pos + 1 + len > data.len() {
            return Err("not enough bytes for u128".to_string());
        }
        let mut value = 0u128;
        for i in 0..len {
            value = (value << 8) | (data[pos + 1 + i] as u128);
        }
        return Ok(value);
    }
    Err(format!("unexpected RLP prefix 0x{:02x} for u128 at pos {}", first, pos))
}

/// Read an RLP byte string at `pos`, returning `(content, next_pos)`.
fn rlp_read_bytes_raw(data: &[u8], pos: usize) -> Result<(&[u8], usize), String> {
    if pos >= data.len() {
        return Err(format!("pos {} out of bounds", pos));
    }
    let first = data[pos];
    if first <= 0x7f {
        return Ok((&data[pos..pos + 1], pos + 1));
    }
    if first <= 0xb7 {
        let len = (first - 0x80) as usize;
        let start = pos + 1;
        if start + len > data.len() {
            return Err("short string OOB".to_string());
        }
        return Ok((&data[start..start + len], start + len));
    }
    if first <= 0xbf {
        let len_bytes = (first - 0xb7) as usize;
        if pos + 1 + len_bytes > data.len() {
            return Err("long string len OOB".to_string());
        }
        let mut len = 0usize;
        for i in 0..len_bytes {
            len = (len << 8) | (data[pos + 1 + i] as usize);
        }
        let start = pos + 1 + len_bytes;
        if start + len > data.len() {
            return Err("long string content OOB".to_string());
        }
        return Ok((&data[start..start + len], start + len));
    }
    Err(format!("pos {} is a list, not a string", pos))
}

/// Read an RLP byte string at `pos` as an owned `Vec<u8>`.
fn rlp_read_bytes_vec(data: &[u8], pos: usize) -> Result<Vec<u8>, String> {
    let (slice, _) = rlp_read_bytes_raw(data, pos)?;
    Ok(slice.to_vec())
}

// ---------------------------------------------------------------------------
// SHA-256 helper
// ---------------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Chain graph
// ---------------------------------------------------------------------------

/// A chain graph built from a collection of parsed `BlockHeader`s.
#[derive(Debug, Default)]
pub struct ChainGraph {
    /// All known headers indexed by block ID.
    pub headers: std::collections::HashMap<[u8; 32], BlockHeader>,
    /// The genesis block ID (parent == [0; 32]).
    pub genesis_id: Option<[u8; 32]>,
    /// The block ID at the highest observed height.
    pub tip_id: Option<[u8; 32]>,
    /// Height of the tip block.
    pub tip_height: u64,
    /// Number of competing siblings (forks detected).
    pub fork_count: usize,
}

impl ChainGraph {
    /// Build a chain graph from a collection of parsed headers.
    pub fn build(blocks: impl IntoIterator<Item = BlockHeader>) -> Self {
        let mut graph = ChainGraph::default();
        let mut parent_children: std::collections::HashMap<[u8; 32], Vec<[u8; 32]>> =
            std::collections::HashMap::new();

        for header in blocks {
            let id = header.id;
            parent_children
                .entry(header.parent_id)
                .or_default()
                .push(id);
            if header.is_genesis() {
                graph.genesis_id = Some(id);
            }
            if header.height > graph.tip_height || graph.tip_id.is_none() {
                graph.tip_height = header.height;
                graph.tip_id = Some(id);
            }
            graph.headers.insert(id, header);
        }

        // Count forks: any parent that has 2+ children
        for children in parent_children.values() {
            if children.len() > 1 {
                graph.fork_count += children.len() - 1;
            }
        }

        graph
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Apricot P-Chain block for testing (type_id 0-4).
    /// Layout: [0..2]=version=0, [2..6]=type_id, [6..38]=parent_id,
    ///         [38..46]=height, [46..54]=extra_data (readable as timestamp for test purposes).
    fn make_apricot_block(
        type_id: u32,
        parent_id: [u8; 32],
        height: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut raw = vec![0u8; 54];
        // Wire format (observed on Fuji v1.14.x):
        // [0..2] codec version = 0
        // [2..6] type ID
        // [6..38] parent ID (32 bytes)
        // [38..46] timestamp (uint64 BE)
        // [46..54] height (uint64 BE)
        raw[2..6].copy_from_slice(&type_id.to_be_bytes());
        raw[6..38].copy_from_slice(&parent_id);
        raw[38..46].copy_from_slice(&timestamp.to_be_bytes());
        raw[46..54].copy_from_slice(&height.to_be_bytes());
        raw
    }

    /// Alias for backward compat in tests that used make_pchain_block.
    fn make_pchain_block(
        type_id: u32,
        parent_id: [u8; 32],
        height: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        make_apricot_block(type_id, parent_id, height, timestamp)
    }

    /// Build a minimal Banff block (typeID 30/31/32).
    /// Layout: [0..2]=version=0, [2..6]=type_id, [6..14]=timestamp,
    ///         [14..46]=parent_id, [46..54]=height.
    fn make_banff_block(
        type_id: u32,
        parent_id: [u8; 32],
        height: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        assert!(type_id == 30 || type_id == 31 || type_id == 32,
            "use make_banff_proposal_block for typeID 29");
        let mut raw = vec![0u8; 54];
        raw[2..6].copy_from_slice(&type_id.to_be_bytes());
        raw[6..14].copy_from_slice(&timestamp.to_be_bytes());
        raw[14..46].copy_from_slice(&parent_id);
        raw[46..54].copy_from_slice(&height.to_be_bytes());
        raw
    }

    /// Build a minimal BanffProposalBlock (typeID 29).
    /// Layout: [0..2]=version, [2..6]=29, [6..14]=timestamp, [14..18]=txs_len=0,
    ///         [18..50]=parent_id, [50..58]=height.
    fn make_banff_proposal_block(
        parent_id: [u8; 32],
        height: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut raw = vec![0u8; 58];
        raw[2..6].copy_from_slice(&29u32.to_be_bytes());
        raw[6..14].copy_from_slice(&timestamp.to_be_bytes());
        // [14..18] = txs slice len = 0 (already zero)
        raw[18..50].copy_from_slice(&parent_id);
        raw[50..58].copy_from_slice(&height.to_be_bytes());
        raw
    }

    // -----------------------------------------------------------------------
    // Apricot P-Chain tests (backward-compatible)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pchain_genesis() {
        let raw = make_pchain_block(0, [0u8; 32], 0, 1_000_000);
        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();
        assert!(h.is_genesis());
        assert_eq!(h.height, 0);
        assert_eq!(h.timestamp, 1_000_000);
        assert_eq!(h.block_type, BlockType::ApricotProposal);
    }

    #[test]
    fn test_parse_pchain_block_types() {
        let cases = [
            (0u32, BlockType::ApricotProposal),
            (1, BlockType::ApricotAbort),
            (2, BlockType::ApricotCommit),
            (3, BlockType::ApricotStandard),
            (99, BlockType::Unknown(99)),
        ];
        for (type_id, expected) in cases {
            let raw = make_pchain_block(type_id, [1u8; 32], 100, 9_999);
            let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();
            assert_eq!(h.block_type, expected);
            assert_eq!(h.height, 100);
            assert_eq!(h.timestamp, 9_999);
        }
    }

    #[test]
    fn test_parse_pchain_too_short() {
        let raw = vec![0u8; 10];
        assert!(BlockHeader::parse(&raw, Chain::PChain).is_err());
    }

    #[test]
    fn test_parse_pchain_id_is_sha256() {
        let raw = make_pchain_block(3, [2u8; 32], 7, 12345);
        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();
        assert_eq!(h.id, sha256(&raw));
        assert_eq!(h.raw_size, raw.len());
    }

    #[test]
    fn test_parse_pchain_parent_id() {
        let parent = [0xABu8; 32];
        let raw = make_pchain_block(1, parent, 42, 0);
        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();
        assert_eq!(h.parent_id, parent);
        assert!(!h.is_genesis());
    }

    // -----------------------------------------------------------------------
    // Banff P-Chain tests — fixes the height extraction bug
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_banff_standard_block() {
        let parent = [0xBBu8; 32];
        let raw = make_banff_block(32, parent, 1_500_000, 1_700_000_000);
        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();
        assert_eq!(h.block_type, BlockType::BanffStandard);
        assert_eq!(h.parent_id, parent);
        assert_eq!(h.height, 1_500_000);
        assert_eq!(h.timestamp, 1_700_000_000);
    }

    #[test]
    fn test_parse_banff_abort_block() {
        let raw = make_banff_block(30, [0u8; 32], 0, 1_600_000_000);
        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();
        assert_eq!(h.block_type, BlockType::BanffAbort);
        assert!(h.is_genesis());
        assert_eq!(h.height, 0);
        assert_eq!(h.timestamp, 1_600_000_000);
    }

    #[test]
    fn test_parse_banff_commit_block() {
        let raw = make_banff_block(31, [0xCCu8; 32], 999, 1_700_000_001);
        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();
        assert_eq!(h.block_type, BlockType::BanffCommit);
        assert_eq!(h.height, 999);
        assert_eq!(h.timestamp, 1_700_000_001);
    }

    #[test]
    fn test_parse_banff_proposal_block() {
        let parent = [0xDDu8; 32];
        let raw = make_banff_proposal_block(parent, 42_000, 1_699_999_999);
        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();
        assert_eq!(h.block_type, BlockType::BanffProposal);
        assert_eq!(h.parent_id, parent);
        assert_eq!(h.height, 42_000);
        assert_eq!(h.timestamp, 1_699_999_999);
    }

    #[test]
    fn test_banff_heights_sequential() {
        // Simulate a chain: genesis -> block1 -> block2
        let g_raw = make_banff_block(32, [0u8; 32], 0, 1_000_000);
        let g = BlockHeader::parse(&g_raw, Chain::PChain).unwrap();
        assert_eq!(g.height, 0);
        assert!(g.is_genesis());

        let b1_raw = make_banff_block(32, g.id, 1, 1_000_001);
        let b1 = BlockHeader::parse(&b1_raw, Chain::PChain).unwrap();
        assert_eq!(b1.height, 1);

        let b2_raw = make_banff_block(32, b1.id, 2, 1_000_002);
        let b2 = BlockHeader::parse(&b2_raw, Chain::PChain).unwrap();
        assert_eq!(b2.height, 2);

        let graph = ChainGraph::build([g, b1, b2]);
        assert_eq!(graph.tip_height, 2);
        assert_eq!(graph.fork_count, 0);
    }

    // -----------------------------------------------------------------------
    // Chain graph tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_chain_graph_linear() {
        // genesis → A → B
        let g_raw = make_pchain_block(3, [0u8; 32], 0, 1000);
        let g = BlockHeader::parse(&g_raw, Chain::PChain).unwrap();
        let g_id = g.id;

        let a_raw = make_pchain_block(3, g_id, 1, 2000);
        let a = BlockHeader::parse(&a_raw, Chain::PChain).unwrap();
        let a_id = a.id;

        let b_raw = make_pchain_block(3, a_id, 2, 3000);
        let b = BlockHeader::parse(&b_raw, Chain::PChain).unwrap();

        let graph = ChainGraph::build([g, a, b]);
        assert_eq!(graph.headers.len(), 3);
        assert_eq!(graph.tip_height, 2);
        assert_eq!(graph.fork_count, 0);
        assert!(graph.genesis_id.is_some());
    }

    #[test]
    fn test_chain_graph_detects_fork() {
        // genesis → A (height 1, ts 2000)
        // genesis → B (height 1, ts 3000)  ← fork!
        let g_raw = make_pchain_block(3, [0u8; 32], 0, 1000);
        let g = BlockHeader::parse(&g_raw, Chain::PChain).unwrap();
        let g_id = g.id;

        let a_raw = make_pchain_block(3, g_id, 1, 2000);
        let a = BlockHeader::parse(&a_raw, Chain::PChain).unwrap();

        let b_raw = make_pchain_block(3, g_id, 1, 3000); // same parent, different ts → different hash
        let b = BlockHeader::parse(&b_raw, Chain::PChain).unwrap();
        // Ensure distinct blocks
        assert_ne!(a.id, b.id);

        let graph = ChainGraph::build([g, a, b]);
        assert_eq!(graph.fork_count, 1);
    }

    // -----------------------------------------------------------------------
    // RLP helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rlp_skip_single_byte() {
        let data = [0x42u8, 0x99];
        assert_eq!(rlp_skip(&data, 0).unwrap(), 1);
    }

    #[test]
    fn test_rlp_skip_short_string() {
        // 0x83 = 0x80 + 3 → 3-byte string
        let data = [0x83u8, 0x01, 0x02, 0x03, 0xff];
        assert_eq!(rlp_skip(&data, 0).unwrap(), 4);
    }

    #[test]
    fn test_rlp_read_u64() {
        // 0x83 0x00 0x01 0x00 = 256
        let data = [0x82u8, 0x01, 0x00];
        assert_eq!(rlp_read_u64(&data, 0).unwrap(), 256);

        // single byte
        let data2 = [0x0fu8];
        assert_eq!(rlp_read_u64(&data2, 0).unwrap(), 15);

        // empty string = 0
        let data3 = [0x80u8];
        assert_eq!(rlp_read_u64(&data3, 0).unwrap(), 0);
    }

    /// Build a minimal synthetic Ethereum block RLP for C-Chain tests.
    ///
    /// Structure: `[header_list, 0xc0 (empty uncles), 0xc0 (empty txs)]`
    /// Header: `parentHash(32) + sha3Uncles(32) + miner(20) + stateRoot(32) +
    ///          txRoot(32) + receiptRoot(32) + bloom(256) + difficulty(0) +
    ///          number(N) + gasLimit(G) + gasUsed(0) + timestamp(T)`
    fn make_cchain_block(parent: [u8; 32], number: u64, timestamp: u64) -> Vec<u8> {
        let mut header_payload: Vec<u8> = Vec::new();
        // 0: parentHash (32 bytes, 0xa0 prefix)
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&parent);
        // 1: sha3Uncles (32 bytes)
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0x1du8; 32]);
        // 2: miner (20 bytes, 0x94 prefix = 0x80+20)
        header_payload.push(0x94);
        header_payload.extend_from_slice(&[0u8; 20]);
        // 3: stateRoot (32 bytes)
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]);
        // 4: txRoot (32 bytes)
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]);
        // 5: receiptRoot (32 bytes)
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]);
        // 6: bloom (256 bytes, 0xb9 0x01 0x00 = long string of 256 bytes)
        header_payload.push(0xb9);
        header_payload.push(0x01);
        header_payload.push(0x00);
        header_payload.extend_from_slice(&[0u8; 256]);
        // 7: difficulty (0x80 = 0)
        header_payload.push(0x80);
        // 8: number
        encode_rlp_u64(&mut header_payload, number);
        // 9: gasLimit
        encode_rlp_u64(&mut header_payload, 8_000_000);
        // 10: gasUsed
        header_payload.push(0x80); // 0
        // 11: timestamp
        encode_rlp_u64(&mut header_payload, timestamp);

        // Wrap header in a list
        let header_list = rlp_list(header_payload);
        // Empty uncles and txs
        let empty = 0xc0u8;

        let mut outer_payload: Vec<u8> = Vec::new();
        outer_payload.extend_from_slice(&header_list);
        outer_payload.push(empty); // uncles
        outer_payload.push(empty); // txs

        rlp_list(outer_payload)
    }

    /// Build a C-Chain block wrapped in an Avalanche codec header.
    fn make_cchain_block_wrapped(parent: [u8; 32], number: u64, timestamp: u64) -> Vec<u8> {
        let rlp = make_cchain_block(parent, number, timestamp);
        let mut wrapped = Vec::with_capacity(6 + rlp.len());
        wrapped.extend_from_slice(&[0x00, 0x00]); // codec version
        wrapped.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // typeID = 1 (placeholder)
        wrapped.extend_from_slice(&rlp);
        wrapped
    }

    fn encode_rlp_u64(buf: &mut Vec<u8>, v: u64) {
        if v == 0 {
            buf.push(0x80);
            return;
        }
        let bytes = v.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let slice = &bytes[start..];
        buf.push(0x80 + slice.len() as u8);
        buf.extend_from_slice(slice);
    }

    fn rlp_list(payload: Vec<u8>) -> Vec<u8> {
        let len = payload.len();
        let mut result = Vec::new();
        if len <= 55 {
            result.push(0xc0 + len as u8);
        } else {
            let len_bytes = len.to_be_bytes();
            let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
            let slice = &len_bytes[start..];
            result.push(0xf7 + slice.len() as u8);
            result.extend_from_slice(slice);
        }
        result.extend_from_slice(&payload);
        result
    }

    fn make_cchain_block_with_state_root(
        parent: [u8; 32],
        number: u64,
        timestamp: u64,
        state_root: [u8; 32],
    ) -> Vec<u8> {
        let mut header_payload: Vec<u8> = Vec::new();
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&parent);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0x1du8; 32]);
        header_payload.push(0x94);
        header_payload.extend_from_slice(&[0u8; 20]);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&state_root);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]);
        header_payload.push(0xb9);
        header_payload.push(0x01);
        header_payload.push(0x00);
        header_payload.extend_from_slice(&[0u8; 256]);
        header_payload.push(0x80);
        encode_rlp_u64(&mut header_payload, number);
        encode_rlp_u64(&mut header_payload, 8_000_000);
        header_payload.push(0x80);
        encode_rlp_u64(&mut header_payload, timestamp);

        let header_list = rlp_list(header_payload);
        let empty = 0xc0u8;
        let mut outer = Vec::new();
        outer.extend_from_slice(&header_list);
        outer.push(empty);
        outer.push(empty);
        rlp_list(outer)
    }

    #[test]
    fn test_extract_state_root() {
        let state_root = [0x42u8; 32];
        let raw = make_cchain_block_with_state_root([0u8; 32], 1, 1_700_000_000, state_root);
        let extracted = BlockHeader::extract_state_root(&raw);
        assert_eq!(extracted, Some(state_root));
    }

    #[test]
    fn test_block_metadata_from_banff_standard() {
        let parent = [0xDEu8; 32];
        let raw = make_banff_block(32, parent, 100, 1_700_000_000);
        let meta = BlockMetadata::from_raw(&raw, Chain::PChain).unwrap();
        assert_eq!(meta.height, 100);
        assert_eq!(meta.timestamp, 1_700_000_000);
        assert_eq!(meta.parent_id, parent);
        assert_eq!(meta.block_type, BlockType::BanffStandard);
        assert_eq!(meta.size_bytes, raw.len());
    }

    #[test]
    fn test_block_metadata_cchain() {
        let parent = [0xCCu8; 32];
        let raw = make_cchain_block(parent, 42, 1_750_000_000);
        let meta = BlockMetadata::from_raw(&raw, Chain::CChain).unwrap();
        assert_eq!(meta.height, 42);
        assert_eq!(meta.block_type, BlockType::CChainEvm);
    }

    #[test]
    fn test_parse_cchain_genesis() {
        let raw = make_cchain_block([0u8; 32], 0, 1_600_000_000);
        let h = BlockHeader::parse(&raw, Chain::CChain).unwrap();
        assert_eq!(h.block_type, BlockType::CChainEvm);
        assert!(h.is_genesis());
        assert_eq!(h.height, 0);
        assert_eq!(h.timestamp, 1_600_000_000);
    }

    #[test]
    fn test_parse_cchain_with_parent() {
        let parent = [0xDEu8; 32];
        let raw = make_cchain_block(parent, 42, 1_700_000_000);
        let h = BlockHeader::parse(&raw, Chain::CChain).unwrap();
        assert_eq!(h.parent_id, parent);
        assert_eq!(h.height, 42);
        assert_eq!(h.timestamp, 1_700_000_000);
        assert!(!h.is_genesis());
    }

    #[test]
    fn test_parse_cchain_wrapped() {
        // Test that Avalanche-wrapped C-Chain blocks are parsed correctly
        let parent = [0xEEu8; 32];
        let raw = make_cchain_block_wrapped(parent, 100, 1_750_000_000);
        let h = BlockHeader::parse(&raw, Chain::CChain).unwrap();
        assert_eq!(h.parent_id, parent);
        assert_eq!(h.height, 100);
        assert_eq!(h.timestamp, 1_750_000_000);
        assert_eq!(h.block_type, BlockType::CChainEvm);
    }

    #[test]
    fn test_block_signature_missing_sig() {
        // Test that small blocks fail signature verification (not enough bytes for sig)
        use blst::min_pk::SecretKey;
        let mut ikm = [0u8; 32];
        ikm[0] = 42;
        let sk = SecretKey::key_gen(&ikm, &[]).expect("valid BLS key");
        let pk = sk.sk_to_pk();
        let pk_bytes = pk.to_bytes();

        let parent = [0xAAu8; 32];
        let raw = make_banff_block(32, parent, 100, 1_700_000_000);
        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();

        // Block is too small to contain a signature
        assert!(h.verify_signature(&pk_bytes).is_err());
    }

    #[test]
    fn test_block_signature_invalid_key() {
        // Test that an invalid public key fails verification
        let parent = [0xAAu8; 32];
        let mut raw = make_banff_block(32, parent, 100, 1_700_000_000);
        // Pad with 96 bytes of zeros to simulate a signature
        raw.extend_from_slice(&[0u8; 96]);

        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();
        let invalid_pk = [0xFFu8; 48]; // Invalid public key

        assert!(h.verify_signature(&invalid_pk).is_err());
    }

    #[test]
    fn test_block_raw_bytes_stored() {
        // Test that raw_bytes are correctly stored in BlockHeader
        let parent = [0xBBu8; 32];
        let raw = make_banff_block(32, parent, 100, 1_700_000_000);
        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();

        assert_eq!(h.raw_bytes, raw);
        assert_eq!(h.raw_size, raw.len());
    }

    // -----------------------------------------------------------------------
    // C-Chain transaction extraction tests
    // -----------------------------------------------------------------------

    /// Build a minimal legacy Ethereum transaction RLP item.
    /// Format: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    fn make_legacy_tx_rlp(nonce: u64, gas_price: u128, gas_limit: u64,
                           to: Option<[u8; 20]>, value: u128, data: &[u8]) -> Vec<u8> {
        let mut fields: Vec<u8> = Vec::new();
        encode_rlp_u64(&mut fields, nonce);
        // gasPrice as u128
        if gas_price == 0 {
            fields.push(0x80);
        } else {
            let bytes = gas_price.to_be_bytes();
            let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
            let slice = &bytes[start..];
            fields.push(0x80 + slice.len() as u8);
            fields.extend_from_slice(slice);
        }
        encode_rlp_u64(&mut fields, gas_limit);
        // to
        match to {
            None => fields.push(0x80), // empty = contract creation
            Some(addr) => {
                fields.push(0x94); // 0x80 + 20
                fields.extend_from_slice(&addr);
            }
        }
        // value as u128
        if value == 0 {
            fields.push(0x80);
        } else {
            let bytes = value.to_be_bytes();
            let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
            let slice = &bytes[start..];
            fields.push(0x80 + slice.len() as u8);
            fields.extend_from_slice(slice);
        }
        // data
        if data.is_empty() {
            fields.push(0x80);
        } else {
            fields.push(0x80 + data.len() as u8);
            fields.extend_from_slice(data);
        }
        // v, r, s (stub values)
        fields.push(0x80); // v = 0
        fields.push(0x80); // r = 0
        fields.push(0x80); // s = 0
        rlp_list(fields)
    }

    /// Build a C-Chain block with one legacy transaction.
    fn make_cchain_block_with_tx(parent: [u8; 32], number: u64, timestamp: u64,
                                  tx: Vec<u8>) -> Vec<u8> {
        let mut header_payload: Vec<u8> = Vec::new();
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&parent);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0x1du8; 32]);
        header_payload.push(0x94);
        header_payload.extend_from_slice(&[0u8; 20]);
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]); // stateRoot
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]); // txRoot
        header_payload.push(0xa0);
        header_payload.extend_from_slice(&[0u8; 32]); // receiptRoot
        header_payload.push(0xb9);
        header_payload.push(0x01);
        header_payload.push(0x00);
        header_payload.extend_from_slice(&[0u8; 256]); // bloom
        header_payload.push(0x80); // difficulty
        encode_rlp_u64(&mut header_payload, number);
        encode_rlp_u64(&mut header_payload, 30_000_000); // gasLimit
        header_payload.push(0x80); // gasUsed
        encode_rlp_u64(&mut header_payload, timestamp);
        header_payload.push(0x80); // extraData
        header_payload.push(0xa0); // mixHash
        header_payload.extend_from_slice(&[0u8; 32]);
        header_payload.extend_from_slice(&[0x88, 0,0,0,0,0,0,0,0]); // nonce (8 bytes)

        let header_list = rlp_list(header_payload);
        let empty = 0xc0u8; // empty uncles

        // txs list: wrap the single tx item
        let txs_list = rlp_list(tx);

        let mut outer_payload: Vec<u8> = Vec::new();
        outer_payload.extend_from_slice(&header_list);
        outer_payload.push(empty); // uncles
        outer_payload.extend_from_slice(&txs_list);
        rlp_list(outer_payload)
    }

    #[test]
    fn test_extract_cchain_transactions_empty_block() {
        // A block with no transactions should return empty vec
        let raw = make_cchain_block([0u8; 32], 1, 1_700_000_000);
        let txs = extract_cchain_transactions(&raw);
        assert_eq!(txs.len(), 0);
    }

    #[test]
    fn test_extract_cchain_transactions_with_one_tx() {
        let to_addr = [0x42u8; 20];
        let tx = make_legacy_tx_rlp(
            5,                      // nonce
            25_000_000_000u128,     // gasPrice (25 gwei)
            21_000,                 // gasLimit
            Some(to_addr),          // to
            1_000_000_000_000_000_000u128, // value (1 ETH)
            &[],                    // data
        );
        let raw = make_cchain_block_with_tx([0u8; 32], 100, 1_700_000_000, tx);
        let txs = extract_cchain_transactions(&raw);
        assert_eq!(txs.len(), 1, "should extract one transaction");
        assert_eq!(txs[0].nonce, 5);
        assert_eq!(txs[0].gas_price, 25_000_000_000);
        assert_eq!(txs[0].gas_limit, 21_000);
        assert_eq!(txs[0].to, Some(to_addr));
        assert_eq!(txs[0].value, 1_000_000_000_000_000_000);
        assert_eq!(txs[0].tx_type, 0);
    }

    #[test]
    fn test_extract_cchain_transactions_contract_creation() {
        let tx = make_legacy_tx_rlp(
            0, 25_000_000_000, 100_000,
            None, // no to = contract creation
            0, &[0x60, 0x00], // init code
        );
        let raw = make_cchain_block_with_tx([0u8; 32], 1, 1_700_000_000, tx);
        let txs = extract_cchain_transactions(&raw);
        assert_eq!(txs.len(), 1);
        assert!(txs[0].to.is_none(), "contract creation should have no to");
        assert_eq!(txs[0].data, vec![0x60, 0x00]);
    }

    #[test]
    fn test_extract_cchain_block_fields() {
        let raw = make_cchain_block([0u8; 32], 42, 1_700_000_000);
        let fields = extract_cchain_block_fields(&raw);
        assert!(fields.is_some(), "should extract block fields");
        let f = fields.unwrap();
        assert_eq!(f.number, 42);
        assert_eq!(f.timestamp, 1_700_000_000);
        assert_eq!(f.gas_limit, 8_000_000); // from make_cchain_block
    }

    #[test]
    fn test_extract_cchain_block_fields_wrapped() {
        let raw = make_cchain_block_wrapped([0u8; 32], 99, 1_750_000_000);
        let fields = extract_cchain_block_fields(&raw);
        assert!(fields.is_some());
        let f = fields.unwrap();
        assert_eq!(f.number, 99);
        assert_eq!(f.timestamp, 1_750_000_000);
    }

    #[test]
    fn test_rlp_read_u128() {
        // Test reading u128 values
        let data = [0x85u8, 0x05, 0xd2, 0x1d, 0xb8, 0x00]; // 5-byte number
        assert!(rlp_read_u128(&data, 0).is_ok());

        // Zero
        let zero = [0x80u8];
        assert_eq!(rlp_read_u128(&zero, 0).unwrap(), 0);

        // Single byte
        let single = [0x0fu8];
        assert_eq!(rlp_read_u128(&single, 0).unwrap(), 15);
    }
}
