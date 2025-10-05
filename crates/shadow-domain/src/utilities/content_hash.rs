//! # Content Hash Utilities
//!
//! Utility functions for content fingerprinting using SHA-256.
//! Supports the duplicate detection system by providing consistent
//! hash calculation across the codebase.

use sha2::{Sha256, Digest};

/// Content hash type for duplicate detection  
pub type ContentHash = [u8; 32];

/// Calculate SHA-256 hash of content bytes
/// 
/// This is the canonical content hash function used throughout the system
/// for duplicate detection and integrity verification.
///
/// # Examples
///
/// ```rust
/// use shadow_crypt::domain::utilities::content_hash::calculate_content_hash;
///
/// let content = b"Hello, World!";
/// let hash = calculate_content_hash(content);
/// assert_eq!(hash.len(), 32); // SHA-256 produces 32-byte hashes
/// ```
pub fn calculate_content_hash(content: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let hash_bytes = hasher.finalize();
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash_bytes);
    hash_array
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_content_hash_deterministic() {
        let content = b"Test content for hash calculation";
        let hash1 = calculate_content_hash(content);
        let hash2 = calculate_content_hash(content);
        assert_eq!(hash1, hash2, "Hash calculation should be deterministic");
    }

    #[test]
    fn test_different_content_different_hashes() {
        let content1 = b"Content one";
        let content2 = b"Content two";
        let hash1 = calculate_content_hash(content1);
        let hash2 = calculate_content_hash(content2);
        assert_ne!(hash1, hash2, "Different content should produce different hashes");
    }

    #[test]
    fn test_empty_content_hash() {
        let content = b"";
        let hash = calculate_content_hash(content);
        // Verify it's a valid 32-byte hash
        assert_eq!(hash.len(), 32);
        // SHA-256 of empty string is a known value
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 
            0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        ];
        assert_eq!(hash, expected, "Empty content should match known SHA-256 hash");
    }
}