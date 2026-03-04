//! Codec module for serialization/deserialization
//!
//! Provides encoding/decoding support for Avalanche messages and data structures.

/// Encode data to bytes
pub fn encode<T: serde::Serialize>(data: &T) -> crate::Result<Vec<u8>> {
    serde_json::to_vec(data).map_err(|e| crate::AvalancheError::SerializationError(e.to_string()))
}

/// Decode bytes to type
pub fn decode<T: for<'de> serde::Deserialize<'de>>(data: &[u8]) -> crate::Result<T> {
    serde_json::from_slice(data).map_err(|e| crate::AvalancheError::DeserializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_encode_decode() {
        let data = json!({"test": "value"});
        let encoded = encode(&data).unwrap();
        let decoded: serde_json::Value = decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }
}
