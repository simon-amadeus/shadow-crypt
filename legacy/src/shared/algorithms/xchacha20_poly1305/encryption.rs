//! XChaCha20-Poly1305 encryption operations
//! 
//! This module provides XChaCha20-Poly1305 encryption functionality with
//! 24-byte nonces that eliminate the need for nonce tracking.

use crate::shared::core::errors::CryptoError;
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use getrandom;

/// Generate a secure random nonce for XChaCha20-Poly1305
/// 
/// # Returns
/// * `Ok([u8; 24])` - 192-bit nonce suitable for XChaCha20-Poly1305
/// * `Err(CryptoError)` - Random number generation failed
/// 
/// # Security Notes
/// XChaCha20-Poly1305 uses 24-byte nonces which provide astronomical collision resistance:
/// - Collision probability: ~2^-96 (vs 2^-48 for AES-GCM)
/// - Safe for billions of encryptions without collision risk
/// - No nonce tracking required - designed for random nonces
/// 
/// This eliminates the critical nonce reuse vulnerability present in AES-GCM
/// stateless file encryption scenarios.
pub fn generate_secure_nonce() -> Result<[u8; 24], CryptoError> {
    // Generate nonce with OS entropy
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce)
        .map_err(|e| CryptoError::CryptographicError(format!("Failed to generate nonce: {}", e)))?;
    
    // Optional: Basic entropy validation (less critical than AES-GCM due to larger nonce space)
    validate_nonce_basic(&nonce)?;
    
    Ok(nonce)
}

/// Basic nonce validation for XChaCha20-Poly1305
/// 
/// Less stringent than AES-GCM validation since 24-byte nonces have
/// astronomical collision resistance even with some entropy reduction.
fn validate_nonce_basic(nonce: &[u8; 24]) -> Result<(), CryptoError> {
    // Check for all-zero nonce (indicates RNG failure)
    if nonce.iter().all(|&b| b == 0) {
        return Err(CryptoError::CryptographicError(
            "CRITICAL: All-zero nonce detected - indicates random number generator failure".to_string()
        ));
    }
    
    // Check for all-same byte (indicates RNG failure)
    let first_byte = nonce[0];
    if nonce.iter().all(|&b| b == first_byte) {
        return Err(CryptoError::CryptographicError(
            format!("CRITICAL: Constant nonce pattern detected (all 0x{:02x}) - indicates RNG failure", first_byte)
        ));
    }
    
    Ok(())
}

/// Encrypt data using XChaCha20-Poly1305
/// 
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 24-byte nonce (safe to be random, no tracking needed)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (can be empty)
/// 
/// # Returns
/// * `Ok(ciphertext)` - Encrypted data with authentication tag appended
/// * `Err(CryptoError)` - Encryption failed
/// 
/// # Security Properties
/// - Authenticated encryption: provides both confidentiality and authenticity
/// - Misuse resistance: safe with random nonces (no catastrophic failure)
/// - Side-channel resistance: constant-time implementation
/// - Large nonce space: ~2^192 possible nonces eliminates collision concern
pub fn encrypt_xchacha20_poly1305(
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
    if nonce.len() != 24 {
        return Err(CryptoError::CryptographicError(
            format!("Invalid nonce length: expected 24 bytes, got {}", nonce.len())
        ));
    }

    // Create cipher instance
    let key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key);
    
    // Create nonce
    let nonce = XNonce::from_slice(nonce);
    
    // Encrypt with additional authenticated data
    let ciphertext = cipher.encrypt(nonce, Payload {
        msg: plaintext,
        aad,
    }).map_err(|e| CryptoError::CryptographicError(
        format!("XChaCha20-Poly1305 encryption failed: {}", e)
    ))?;
    
    Ok(ciphertext)
}

/// Generate a secure random key for XChaCha20-Poly1305
/// 
/// # Returns
/// * `Ok([u8; 32])` - 256-bit key suitable for XChaCha20-Poly1305
/// * `Err(CryptoError)` - Random generation failed
/// 
/// This function is primarily for testing and key generation utilities.
/// In normal operation, keys are derived from passwords using Argon2id.
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
    fn test_generate_secure_nonce() {
        let nonce1 = generate_secure_nonce().unwrap();
        let nonce2 = generate_secure_nonce().unwrap();
        
        assert_eq!(nonce1.len(), 24);
        assert_eq!(nonce2.len(), 24);
        assert_ne!(nonce1, nonce2); // Should be different
    }
    
    #[test]
    fn test_encrypt_xchacha20_poly1305_basic() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional data";
        
        let ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, plaintext, aad).unwrap();
        
        // Ciphertext should be plaintext + 16-byte auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        assert_ne!(&ciphertext[..plaintext.len()], plaintext); // Should be encrypted
    }
    
    #[test]
    fn test_encrypt_xchacha20_poly1305_empty_plaintext() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"";
        let aad = b"";
        
        let ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, plaintext, aad).unwrap();
        
        // Even empty plaintext should produce 16-byte auth tag
        assert_eq!(ciphertext.len(), 16);
    }
    
    #[test]
    fn test_encrypt_xchacha20_poly1305_invalid_key_length() {
        let short_key = vec![0u8; 16]; // Wrong length
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"test";
        
        let result = encrypt_xchacha20_poly1305(&short_key, &nonce, plaintext, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key length"));
    }
    
    #[test]
    fn test_encrypt_xchacha20_poly1305_invalid_nonce_length() {
        let key = generate_random_key().unwrap();
        let short_nonce = vec![0u8; 12]; // AES-GCM nonce length, wrong for XChaCha20
        let plaintext = b"test";
        
        let result = encrypt_xchacha20_poly1305(&key, &short_nonce, plaintext, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid nonce length"));
    }
    
    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = generate_random_key().unwrap();
        let key2 = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"same plaintext";
        
        let ciphertext1 = encrypt_xchacha20_poly1305(&key1, &nonce, plaintext, b"").unwrap();
        let ciphertext2 = encrypt_xchacha20_poly1305(&key2, &nonce, plaintext, b"").unwrap();
        
        assert_ne!(ciphertext1, ciphertext2);
    }
    
    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let key = generate_random_key().unwrap();
        let nonce1 = generate_secure_nonce().unwrap();
        let nonce2 = generate_secure_nonce().unwrap();
        let plaintext = b"same plaintext";
        
        let ciphertext1 = encrypt_xchacha20_poly1305(&key, &nonce1, plaintext, b"").unwrap();
        let ciphertext2 = encrypt_xchacha20_poly1305(&key, &nonce2, plaintext, b"").unwrap();
        
        assert_ne!(ciphertext1, ciphertext2);
    }
    
    #[test]
    fn test_different_aad_produces_different_ciphertext() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"same plaintext";
        
        let ciphertext1 = encrypt_xchacha20_poly1305(&key, &nonce, plaintext, b"aad1").unwrap();
        let ciphertext2 = encrypt_xchacha20_poly1305(&key, &nonce, plaintext, b"aad2").unwrap();
        
        assert_ne!(ciphertext1, ciphertext2);
    }
    
    #[test]
    fn test_validate_nonce_basic_all_zeros() {
        let bad_nonce = [0u8; 24];
        let result = validate_nonce_basic(&bad_nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("All-zero nonce"));
    }
    
    #[test]
    fn test_validate_nonce_basic_constant_pattern() {
        let bad_nonce = [0x42u8; 24];
        let result = validate_nonce_basic(&bad_nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Constant nonce pattern"));
    }
    
    #[test]
    fn test_validate_nonce_basic_good_nonce() {
        // A realistic random-looking nonce
        let good_nonce = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x13, 0x57, 0x9b, 0xdf, 0xfe, 0xdc, 0xba, 0x98,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
        ];
        let result = validate_nonce_basic(&good_nonce);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_generate_random_key() {
        let key1 = generate_random_key().unwrap();
        let key2 = generate_random_key().unwrap();
        
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        assert_ne!(key1, key2); // Should be different
    }
    
    #[test]
    fn test_large_plaintext_encryption() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = vec![0x42u8; 1_000_000]; // 1MB of data
        
        let ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, &plaintext, b"").unwrap();
        
        // Should be plaintext + 16-byte auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        assert_ne!(&ciphertext[..plaintext.len()], plaintext.as_slice());
    }
}