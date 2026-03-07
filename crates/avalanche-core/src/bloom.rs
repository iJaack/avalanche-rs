//! Bloom filter for peer tracking, compatible with no_std.
//!
//! Simple bloom filter using SHA-256 for hash derivation.

use alloc::vec;
use alloc::vec::Vec;

/// A simple bloom filter for tracking known elements.
pub struct BloomFilter {
    bits: Vec<u8>,
    num_bits: usize,
    num_hashes: u8,
}

impl BloomFilter {
    /// Create a new bloom filter with the given number of bits and hash functions.
    pub fn new(num_bits: usize, num_hashes: u8) -> Self {
        let byte_count = (num_bits + 7) / 8;
        Self {
            bits: vec![0u8; byte_count],
            num_bits,
            num_hashes,
        }
    }

    /// Create with optimal parameters for expected elements and false positive rate.
    /// Uses integer approximation to avoid requiring std's f64::ln().
    pub fn with_capacity(expected_elements: usize, _fp_rate: f64) -> Self {
        // Approximate: ~10 bits per element gives <1% FP rate with 7 hashes
        let num_bits = (expected_elements * 10).max(64);
        let num_hashes = 7u8;
        Self::new(num_bits, num_hashes)
    }

    /// Insert an element into the bloom filter.
    pub fn insert(&mut self, data: &[u8]) {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(data);

        for i in 0..self.num_hashes as usize {
            let h1 = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
            let h2 = u32::from_be_bytes([hash[4], hash[5], hash[6], hash[7]]);
            let bit_index = ((h1 as u64).wrapping_add((i as u64).wrapping_mul(h2 as u64))) % (self.num_bits as u64);
            let byte_idx = bit_index as usize / 8;
            let bit_idx = bit_index as usize % 8;
            if byte_idx < self.bits.len() {
                self.bits[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    /// Check if an element might be in the filter.
    pub fn may_contain(&self, data: &[u8]) -> bool {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(data);

        for i in 0..self.num_hashes as usize {
            let h1 = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
            let h2 = u32::from_be_bytes([hash[4], hash[5], hash[6], hash[7]]);
            let bit_index = ((h1 as u64).wrapping_add((i as u64).wrapping_mul(h2 as u64))) % (self.num_bits as u64);
            let byte_idx = bit_index as usize / 8;
            let bit_idx = bit_index as usize % 8;
            if byte_idx >= self.bits.len() || (self.bits[byte_idx] & (1 << bit_idx)) == 0 {
                return false;
            }
        }
        true
    }

    /// Get the raw bytes of the filter.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Number of bits in the filter.
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_insert_and_query() {
        let mut bf = BloomFilter::new(256, 3);
        bf.insert(b"hello");
        bf.insert(b"world");

        assert!(bf.may_contain(b"hello"));
        assert!(bf.may_contain(b"world"));
    }

    #[test]
    fn test_bloom_filter_false_negative() {
        let mut bf = BloomFilter::new(1024, 5);
        bf.insert(b"item1");
        // A bloom filter should never have false negatives
        assert!(bf.may_contain(b"item1"));
    }

    #[test]
    fn test_bloom_filter_likely_absent() {
        let bf = BloomFilter::new(1024, 5);
        // Empty filter should not contain anything
        assert!(!bf.may_contain(b"anything"));
    }

    #[test]
    fn test_bloom_filter_with_capacity() {
        let mut bf = BloomFilter::with_capacity(100, 0.01);
        assert!(bf.num_bits() > 0);

        for i in 0..100u32 {
            bf.insert(&i.to_be_bytes());
        }

        // All inserted elements should be found
        for i in 0..100u32 {
            assert!(bf.may_contain(&i.to_be_bytes()));
        }
    }

    #[test]
    fn test_bloom_filter_as_bytes() {
        let bf = BloomFilter::new(64, 3);
        assert_eq!(bf.as_bytes().len(), 8); // 64 bits = 8 bytes
    }
}
