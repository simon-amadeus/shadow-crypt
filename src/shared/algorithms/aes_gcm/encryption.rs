//! AES-256-GCM encryption operations
//! 
//! This module provides AES-GCM encryption functionality as part of the
//! AES-256-GCM algorithm implementation.

use crate::shared::core::errors::CryptoError;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use getrandom;

/// Generate a secure random nonce for AES-GCM
/// 
/// # Returns
/// * `Ok([u8; 12])` - 96-bit nonce suitable for GCM
/// * `Err(CryptoError)` - Random number generation failed
/// 
/// # Security
/// This function includes critical nonce reuse detection to prevent
/// catastrophic AES-GCM security failures. Each nonce is:
/// - Cryptographically random (from OS entropy)
/// - Validated for proper entropy patterns
/// - Tracked to prevent session reuse
pub fn generate_secure_nonce() -> Result<[u8; 12], CryptoError> {
    use crate::shared::core::crypto::nonce_tracking::{check_nonce_reuse, validate_nonce_entropy};
    
    // Generate nonce with OS entropy
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce)
        .map_err(|e| CryptoError::CryptographicError(format!("Failed to generate nonce: {}", e)))?;
    
    // Validate entropy quality (detect RNG failures)
    validate_nonce_entropy(&nonce)?;
    
    // Check for reuse within session (defense in depth)
    check_nonce_reuse(&nonce)?;
    
    Ok(nonce)
}

/// Encrypt data using AES-256-GCM
/// 
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must be unique per key)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (can be empty)
/// 
/// # Returns
/// * `Ok(ciphertext)` - Encrypted data with authentication tag appended
/// * `Err(CryptoError)` - Encryption failed
pub fn encrypt_aes_gcm(
    key: &[u8], 
    nonce: &[u8], 
    plaintext: &[u8], 
    aad: &[u8]
) -> Result<Vec<u8>, CryptoError> {
    // Validate key length
    if key.len() != 32 {
        return Err(CryptoError::CryptographicError(
            format!("Invalid key length: expected 32 bytes, got {}", key.len())
        ));
    }
    
    // Validate nonce length
    if nonce.len() != 12 {
        return Err(CryptoError::CryptographicError(
            format!("Invalid nonce length: expected 12 bytes, got {}", nonce.len())
        ));
    }

    // Create cipher instance
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    
    // Create nonce
    let nonce = Nonce::from_slice(nonce);
    
    // Encrypt with additional authenticated data
    let ciphertext = cipher.encrypt(nonce, aes_gcm::aead::Payload {
        msg: plaintext,
        aad,
    })
    .map_err(|e| CryptoError::CryptographicError(format!("AES-GCM encryption failed: {}", e)))?;
    
    Ok(ciphertext)
}

/// Generate a secure random key for AES-256
/// 
/// # Returns
/// * `Ok([u8; 32])` - 256-bit encryption key
/// * `Err(CryptoError)` - Random number generation failed
pub fn generate_random_key() -> Result<[u8; 32], CryptoError> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key)
        .map_err(|e| CryptoError::CryptographicError(format!("Failed to generate key: {}", e)))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_key() {
        let key1 = generate_random_key().unwrap();
        let key2 = generate_random_key().unwrap();
        
        // Keys should be different
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_generate_secure_nonce() {
        let nonce1 = generate_secure_nonce().unwrap();
        let nonce2 = generate_secure_nonce().unwrap();
        
        // Nonces should be different
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 12);
    }

    #[test]
    fn test_encrypt_aes_gcm_basic() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional data";
        
        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
        
        // Ciphertext should be longer than plaintext (includes auth tag)
        assert!(ciphertext.len() > plaintext.len());
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // 16-byte auth tag
    }

    #[test]
    fn test_encrypt_aes_gcm_empty_data() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"";
        let aad = b"";
        
        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
        
        // Even empty plaintext should result in auth tag
        assert_eq!(ciphertext.len(), 16); // Just the 16-byte auth tag
    }

    #[test]
    fn test_encrypt_aes_gcm_invalid_key_length() {
        let short_key = vec![0u8; 16]; // Wrong length
        let nonce = [0u8; 12];
        let plaintext = b"test";
        let aad = b"";
        
        let result = encrypt_aes_gcm(&short_key, &nonce, plaintext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_aes_gcm_invalid_nonce_length() {
        let key = [0u8; 32];
        let short_nonce = vec![0u8; 8]; // Wrong length
        let plaintext = b"test";
        let aad = b"";
        
        let result = encrypt_aes_gcm(&key, &short_nonce, plaintext, aad);
        assert!(result.is_err());
    }
}