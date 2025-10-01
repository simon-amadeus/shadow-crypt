//! AES-256-GCM authenticated encryption implementation
//! 
//! This module provides the core AES-GCM encryption and decryption functions
//! with proper nonce generation and authentication tag handling.

use crate::shared::errors::CryptoError;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use getrandom::getrandom;

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
    use crate::shared::crypto::nonce_tracking::{check_nonce_reuse, validate_nonce_entropy};
    
    // Generate nonce with OS entropy
    let mut nonce = [0u8; 12];
    getrandom(&mut nonce)
        .map_err(|e| CryptoError::CryptographicError(format!("Failed to generate nonce: {}", e)))?;
    
    // CRITICAL: Validate nonce entropy to detect RNG failures
    validate_nonce_entropy(&nonce)?;
    
    // CRITICAL: Check for nonce reuse within session
    check_nonce_reuse(&nonce)?;
    
    Ok(nonce)
}

/// Encrypt data using AES-256-GCM
/// 
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must be unique per encryption)
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
        aad: aad,
    })
    .map_err(|e| CryptoError::CryptographicError(format!("AES-GCM encryption failed: {}", e)))?;
    
    Ok(ciphertext)
}

/// Decrypt data using AES-256-GCM
/// 
/// # Arguments
/// * `key` - 32-byte decryption key
/// * `nonce` - 12-byte nonce used during encryption
/// * `ciphertext` - Encrypted data with authentication tag
/// * `aad` - Additional authenticated data (must match encryption)
/// 
/// # Returns
/// * `Ok(plaintext)` - Decrypted data
/// * `Err(CryptoError)` - Decryption or authentication failed
pub fn decrypt_aes_gcm(
    key: &[u8], 
    nonce: &[u8], 
    ciphertext: &[u8], 
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
    
    // Check minimum ciphertext length (must include 16-byte auth tag)
    if ciphertext.len() < 16 {
        return Err(CryptoError::CryptographicError(
            "Ciphertext too short: must include 16-byte authentication tag".to_string()
        ));
    }

    // Create cipher instance
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    
    // Create nonce
    let nonce = Nonce::from_slice(nonce);
    
    // Decrypt and verify authentication tag
    let plaintext = cipher.decrypt(nonce, aes_gcm::aead::Payload {
        msg: ciphertext,
        aad: aad,
    })
    .map_err(|e| CryptoError::CryptographicError(format!("AES-GCM decryption failed: {}", e)))?;
    
    Ok(plaintext)
}

/// Generate a secure random key for AES-256
/// 
/// # Returns
/// * `Ok([u8; 32])` - 256-bit encryption key
/// * `Err(CryptoError)` - Random number generation failed
pub fn generate_random_key() -> Result<[u8; 32], CryptoError> {
    let mut key = [0u8; 32];
    getrandom(&mut key)
        .map_err(|e| CryptoError::CryptographicError(format!("Failed to generate key: {}", e)))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_nonce() {
        let nonce1 = generate_secure_nonce().unwrap();
        let nonce2 = generate_secure_nonce().unwrap();
        
        // Nonces should be different
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 12);
        assert_eq!(nonce2.len(), 12);
    }

    #[test]
    fn test_generate_random_key() {
        let key1 = generate_random_key().unwrap();
        let key2 = generate_random_key().unwrap();
        
        // Keys should be different
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"Hello, World! This is a test message.";
        let aad = b"additional authenticated data";
        
        // Encrypt
        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
        
        // Ciphertext should be different from plaintext
        assert_ne!(ciphertext.as_slice(), plaintext);
        // Ciphertext should be longer due to auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        
        // Decrypt
        let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext, aad).unwrap();
        
        // Should match original plaintext
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_gcm_empty_data() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"";
        let aad = b"";
        
        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_gcm_invalid_key_length() {
        let key = &[0u8; 16]; // Wrong length
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"test";
        
        let result = encrypt_aes_gcm(key, &nonce, plaintext, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key length"));
    }

    #[test]
    fn test_aes_gcm_invalid_nonce_length() {
        let key = generate_random_key().unwrap();
        let nonce = &[0u8; 8]; // Wrong length
        let plaintext = b"test";
        
        let result = encrypt_aes_gcm(&key, nonce, plaintext, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid nonce length"));
    }

    #[test]
    fn test_aes_gcm_authentication_failure() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"test message";
        let aad = b"original aad";
        
        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
        
        // Try to decrypt with different AAD
        let result = decrypt_aes_gcm(&key, &nonce, &ciphertext, b"wrong aad");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("decryption failed"));
    }

    #[test]
    fn test_aes_gcm_short_ciphertext() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let short_ciphertext = &[0u8; 8]; // Too short to contain auth tag
        
        let result = decrypt_aes_gcm(&key, &nonce, short_ciphertext, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Ciphertext too short"));
    }
}