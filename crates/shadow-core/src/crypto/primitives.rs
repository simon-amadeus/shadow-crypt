// shadow-core/src/crypto/primitives.rs
// Low-level cryptographic primitives and utilities
// All code related to basic crypto utilities lives here

use crate::errors::CryptoError;

use rand::RngCore;
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;

/// Hash content using SHA-256
/// Pure function - deterministic with same inputs
pub fn hash_content(content: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hasher.finalize().into()
}

/// Generate cryptographically secure random nonce
/// This function has side effects (uses system randomness)
pub fn generate_nonce() -> Result<[u8; 24], CryptoError> {
    let mut nonce = [0u8; 24];
    rand::thread_rng()
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomGeneration)?;
    Ok(nonce)
}

/// Generate cryptographically secure random salt
/// This function has side effects (uses system randomness)
pub fn generate_salt() -> Result<[u8; 16], CryptoError> {
    let mut salt = [0u8; 16];
    rand::thread_rng()
        .try_fill_bytes(&mut salt)
        .map_err(|_| CryptoError::RandomGeneration)?;
    Ok(salt)
}

/// Constant-time equality comparison for security-sensitive data
/// Pure function that prevents timing attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_content_deterministic() {
        let content = b"Hello, World!";
        
        let hash1 = hash_content(content);
        let hash2 = hash_content(content);
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_content_different_inputs() {
        let content1 = b"Hello, World!";
        let content2 = b"Hello, World?";
        
        let hash1 = hash_content(content1);
        let hash2 = hash_content(content2);
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_generate_nonce_different() {
        let nonce1 = generate_nonce().unwrap();
        let nonce2 = generate_nonce().unwrap();
        
        // Should be extremely unlikely to be the same
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_generate_salt_different() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();
        
        // Should be extremely unlikely to be the same
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_constant_time_eq_same() {
        let data = b"test_data";
        assert!(constant_time_eq(data, data));
    }

    #[test]
    fn test_constant_time_eq_different() {
        let data1 = b"test_data1";
        let data2 = b"test_data2";
        assert!(!constant_time_eq(data1, data2));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let data1 = b"short";
        let data2 = b"much_longer";
        assert!(!constant_time_eq(data1, data2));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        let empty = b"";
        assert!(constant_time_eq(empty, empty));
    }
}