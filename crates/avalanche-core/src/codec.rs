//! Minimal codec for Avalanche serialization, compatible with no_std.
//!
//! Provides simple length-prefixed encoding/decoding without relying on std.

use alloc::vec::Vec;

/// Encode a u32 as 4 big-endian bytes.
pub fn encode_u32(val: u32) -> [u8; 4] {
    val.to_be_bytes()
}

/// Decode a u32 from 4 big-endian bytes.
pub fn decode_u32(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

/// Encode a u64 as 8 big-endian bytes.
pub fn encode_u64(val: u64) -> [u8; 8] {
    val.to_be_bytes()
}

/// Decode a u64 from 8 big-endian bytes.
pub fn decode_u64(data: &[u8]) -> Option<u64> {
    if data.len() < 8 {
        return None;
    }
    let arr: [u8; 8] = data[..8].try_into().ok()?;
    Some(u64::from_be_bytes(arr))
}

/// Length-prefix a byte slice (4-byte BE length header + data).
pub fn length_prefix(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Read a length-prefixed byte slice. Returns (payload, remaining).
pub fn read_length_prefixed(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return None;
    }
    Some((&data[4..4 + len], &data[4 + len..]))
}

/// Encode a 32-byte ID.
pub fn encode_id(id: &[u8; 32]) -> Vec<u8> {
    id.to_vec()
}

/// Decode a 32-byte ID from a slice.
pub fn decode_id(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&data[..32]);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_u32() {
        let encoded = encode_u32(0x12345678);
        assert_eq!(encoded, [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(decode_u32(&encoded), Some(0x12345678));
    }

    #[test]
    fn test_encode_decode_u64() {
        let encoded = encode_u64(0x0102030405060708);
        assert_eq!(decode_u64(&encoded), Some(0x0102030405060708));
    }

    #[test]
    fn test_decode_u32_too_short() {
        assert_eq!(decode_u32(&[0, 1, 2]), None);
    }

    #[test]
    fn test_length_prefix_roundtrip() {
        let data = b"hello world";
        let prefixed = length_prefix(data);
        assert_eq!(prefixed.len(), 4 + data.len());

        let (payload, remaining) = read_length_prefixed(&prefixed).unwrap();
        assert_eq!(payload, data);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_length_prefix_empty() {
        let prefixed = length_prefix(&[]);
        assert_eq!(prefixed, vec![0, 0, 0, 0]);
        let (payload, _) = read_length_prefixed(&prefixed).unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn test_read_length_prefixed_too_short() {
        assert!(read_length_prefixed(&[0, 0, 0, 5, 1, 2, 3]).is_none());
    }

    #[test]
    fn test_encode_decode_id() {
        let id = [0xAA; 32];
        let encoded = encode_id(&id);
        let decoded = decode_id(&encoded).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn test_decode_id_too_short() {
        assert!(decode_id(&[0; 31]).is_none());
    }
}
