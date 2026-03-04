//! Block parsing and chain graph construction.
//!
//! Supports parsing both P-Chain (Avalanche codec) and C-Chain (RLP/Ethereum) blocks.

use sha2::{Digest, Sha256};

/// Raw 32-byte block identifier (SHA-256 of block bytes).
pub type BlockId = [u8; 32];

/// Block type derived from the Avalanche codec typeID (P-Chain) or RLP structure (C-Chain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    /// typeID = 0
    PChainProposal,
    /// typeID = 1
    PChainAbort,
    /// typeID = 2
    PChainCommit,
    /// typeID = 3
    PChainStandard,
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
}

impl BlockHeader {
    /// Parse a raw block into a `BlockHeader`.
    ///
    /// **P-Chain block layout (Banff/Post-Banff):**
    /// - Bytes `[0..2]`: codec version (uint16 BE, usually 0)
    /// - Bytes `[2..6]`: typeID (uint32 BE)
    /// - Bytes `[6..38]`: parentID (32 bytes)
    /// - Bytes `[38..46]`: height (uint64 BE)
    /// - Bytes `[46..54]`: timestamp (uint64 BE)
    ///
    /// **C-Chain block layout:** RLP-encoded Ethereum block
    /// `[header_rlp, uncles_rlp, txs_rlp]` where header contains parentHash, number, timestamp.
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
}

// ---------------------------------------------------------------------------
// P-Chain parser
// ---------------------------------------------------------------------------

fn parse_pchain_block(raw: &[u8], id: BlockId) -> Result<BlockHeader, String> {
    if raw.len() < 54 {
        return Err(format!(
            "P-Chain block too short: {} bytes (need ≥54)",
            raw.len()
        ));
    }

    let type_id = u32::from_be_bytes(raw[2..6].try_into().unwrap());
    let mut parent_id = [0u8; 32];
    parent_id.copy_from_slice(&raw[6..38]);
    let height = u64::from_be_bytes(raw[38..46].try_into().unwrap());
    let timestamp = u64::from_be_bytes(raw[46..54].try_into().unwrap());

    let block_type = match type_id {
        0 => BlockType::PChainProposal,
        1 => BlockType::PChainAbort,
        2 => BlockType::PChainCommit,
        3 => BlockType::PChainStandard,
        t => BlockType::Unknown(t),
    };

    Ok(BlockHeader {
        id,
        parent_id,
        height,
        timestamp,
        block_type,
        raw_size: raw.len(),
    })
}

// ---------------------------------------------------------------------------
// C-Chain / Ethereum RLP parser
// ---------------------------------------------------------------------------

/// Parse an RLP-encoded Ethereum block from the Ancestors protocol.
///
/// Structure: `[header_list, uncles_list, txs_list]` (outer list, 3 items)
/// Header fields (in order):
///   parentHash(0) sha3Uncles(1) miner(2) stateRoot(3) txRoot(4) receiptRoot(5)
///   bloom(6) difficulty(7) number(8) gasLimit(9) gasUsed(10) timestamp(11) …
fn parse_cchain_block(raw: &[u8], id: BlockId) -> Result<BlockHeader, String> {
    if raw.is_empty() {
        return Err("empty C-Chain block".to_string());
    }

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

    /// Build a minimal 54-byte P-Chain block for testing.
    fn make_pchain_block(
        type_id: u32,
        parent_id: [u8; 32],
        height: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut raw = vec![0u8; 54];
        // [0..2] codec version = 0 (already zero)
        raw[2..6].copy_from_slice(&type_id.to_be_bytes());
        raw[6..38].copy_from_slice(&parent_id);
        raw[38..46].copy_from_slice(&height.to_be_bytes());
        raw[46..54].copy_from_slice(&timestamp.to_be_bytes());
        raw
    }

    #[test]
    fn test_parse_pchain_genesis() {
        let raw = make_pchain_block(0, [0u8; 32], 0, 1_000_000);
        let h = BlockHeader::parse(&raw, Chain::PChain).unwrap();
        assert!(h.is_genesis());
        assert_eq!(h.height, 0);
        assert_eq!(h.timestamp, 1_000_000);
        assert_eq!(h.block_type, BlockType::PChainProposal);
    }

    #[test]
    fn test_parse_pchain_block_types() {
        let cases = [
            (0u32, BlockType::PChainProposal),
            (1, BlockType::PChainAbort),
            (2, BlockType::PChainCommit),
            (3, BlockType::PChainStandard),
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
}
