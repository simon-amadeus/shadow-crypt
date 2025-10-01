//! AES-256-GCM decryption operations
//! 
//! This module provides AES-GCM decryption functionality as part of the
//! AES-256-GCM algorithm implementation.

use crate::shared::core::errors::CryptoError;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::algorithms::aes_gcm::encryption::{encrypt_aes_gcm, generate_random_key, generate_secure_nonce};

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional data";
        
        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_aes_gcm_authentication_failure() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional data";
        let wrong_aad = b"wrong additional data";
        
        let ciphertext = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
        let result = decrypt_aes_gcm(&key, &nonce, &ciphertext, wrong_aad);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_invalid_key_length() {
        let short_key = vec![0u8; 16]; // Wrong length
        let nonce = [0u8; 12];
        let ciphertext = vec![0u8; 32];
        let aad = b"";
        
        let result = decrypt_aes_gcm(&short_key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_invalid_nonce_length() {
        let key = [0u8; 32];
        let short_nonce = vec![0u8; 8]; // Wrong length
        let ciphertext = vec![0u8; 32];
        let aad = b"";
        
        let result = decrypt_aes_gcm(&key, &short_nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_short_ciphertext() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let short_ciphertext = vec![0u8; 8]; // Too short (no auth tag)
        let aad = b"";
        
        let result = decrypt_aes_gcm(&key, &nonce, &short_ciphertext, aad);
        assert!(result.is_err());
    }
}