//! Content hash types and utilities.
//!
//! Defines the content hash type used throughout the domain for file integrity verification.
//! Centralizes all hash-related logic to improve cohesion and maintainability.
//!
//! ## File Format Compatibility
//! 
//! **IMPORTANT**: The hash size defined here affects the persistent file format.
//! The TLV header format in `header.rs` expects a specific hash size. If you need to
//! change the hash algorithm or size, you MUST:
//! 
//! 1. Update the TLV format constants in `header.rs`
//! 2. Increment the file format version
//! 3. Implement migration logic for existing files
//! 
//! Otherwise, existing encrypted files will become unreadable.

use sha2::{Sha256, Digest};

/// Content hash type for file integrity verification.
/// 
/// Uses SHA-256 which provides 256 bits (32 bytes) of cryptographic hash output.
/// This ensures strong collision resistance for content deduplication and integrity checks.
pub type ContentHash = [u8; 32]; // SHA-256 hash size

/// Content hash size in bytes (SHA-256 = 32 bytes).
/// 
/// This constant should be used whenever the hash size needs to be validated
/// or when working with serialization formats like TLV headers.
pub const CONTENT_HASH_SIZE: usize = 32;

/// Content hash utilities and operations.
pub struct ContentHasher;

impl ContentHasher {
    /// Compute content hash for the given data.
    pub fn hash(data: &[u8]) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Convert content hash to hexadecimal string representation.
    pub fn to_hex(hash: &ContentHash) -> String {
        hash.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }

    /// Validate that data has the correct size for a content hash.
    pub fn validate_size(data: &[u8]) -> bool {
        data.len() == CONTENT_HASH_SIZE
    }

    /// Try to convert a byte slice to a ContentHash.
    /// Returns None if the size is incorrect.
    pub fn from_bytes(data: &[u8]) -> Option<ContentHash> {
        if Self::validate_size(data) {
            let mut hash = [0u8; CONTENT_HASH_SIZE];
            hash.copy_from_slice(data);
            Some(hash)
        } else {
            None
        }
    }
}