//! Content hash functionality - migrated from domain/shared.

use sha2::{Sha256, Digest};

/// Content hash type for file integrity verification (SHA-256).
pub type ContentHash = [u8; 32];

/// Content hash size in bytes (SHA-256 = 32 bytes).
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