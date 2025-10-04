//! XChaCha20-Poly1305 decryption operations
//! 
//! This module provides XChaCha20-Poly1305 decryption functionality with
//! authenticated decryption and comprehensive error handling.

use crate::shared::core::errors::CryptoError;
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};

/// Decrypt data using XChaCha20-Poly1305
/// 
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 24-byte nonce used during encryption
/// * `ciphertext` - Encrypted data with authentication tag
/// * `aad` - Additional authenticated data (must match encryption)
/// 
/// # Returns
/// * `Ok(plaintext)` - Decrypted data
/// * `Err(CryptoError)` - Decryption or authentication failed
/// 
/// # Security Properties
/// - Authenticated decryption: verifies both integrity and authenticity
/// - Timing attack resistance: constant-time authentication verification
/// - Tamper detection: any modification to ciphertext or AAD causes failure
/// - Side-channel resistance: constant-time implementation
/// 
/// # Authentication Failures
/// Decryption will fail if:
/// - Authentication tag is invalid (data tampered with)
/// - Wrong key used
/// - Wrong nonce used  
/// - AAD doesn't match what was used during encryption
/// - Ciphertext is truncated or corrupted
pub fn decrypt_xchacha20_poly1305(
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
    if nonce.len() != 24 {
        return Err(CryptoError::CryptographicError(
            format!("Invalid nonce length: expected 24 bytes, got {}", nonce.len())
        ));
    }
    
    // Check minimum ciphertext length (must include 16-byte auth tag)
    if ciphertext.len() < 16 {
        return Err(CryptoError::CryptographicError(
            "Ciphertext too short: must include 16-byte authentication tag".to_string()
        ));
    }

    // Create cipher instance
    let key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key);
    
    // Create nonce
    let nonce = XNonce::from_slice(nonce);
    
    // Decrypt with additional authenticated data
    let plaintext = cipher.decrypt(nonce, Payload {
        msg: ciphertext,
        aad,
    }).map_err(|e| CryptoError::CryptographicError(
        format!("XChaCha20-Poly1305 decryption failed: {}", e)
    ))?;
    
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::algorithms::xchacha20_poly1305::encryption::{
        encrypt_xchacha20_poly1305, generate_random_key, generate_secure_nonce
    };
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_basic() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional data";
        
        // Encrypt then decrypt
        let ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&key, &nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_empty_plaintext() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"";
        let aad = b"";
        
        // Encrypt then decrypt
        let ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&key, &nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_large_data() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = vec![0x42u8; 100_000]; // 100KB of data
        let aad = b"large data test";
        
        // Encrypt then decrypt
        let ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, &plaintext, aad).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&key, &nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_invalid_key_length() {
        let short_key = vec![0u8; 16]; // Wrong length
        let nonce = generate_secure_nonce().unwrap();
        let ciphertext = vec![0u8; 32]; // Some ciphertext
        
        let result = decrypt_xchacha20_poly1305(&short_key, &nonce, &ciphertext, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid key length"));
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_invalid_nonce_length() {
        let key = generate_random_key().unwrap();
        let short_nonce = vec![0u8; 12]; // AES-GCM nonce length, wrong for XChaCha20
        let ciphertext = vec![0u8; 32]; // Some ciphertext
        
        let result = decrypt_xchacha20_poly1305(&key, &short_nonce, &ciphertext, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid nonce length"));
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_ciphertext_too_short() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let short_ciphertext = vec![0u8; 8]; // Shorter than 16-byte auth tag
        
        let result = decrypt_xchacha20_poly1305(&key, &nonce, &short_ciphertext, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Ciphertext too short"));
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_wrong_key() {
        let key1 = generate_random_key().unwrap();
        let key2 = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"secret message";
        
        // Encrypt with key1, try to decrypt with key2
        let ciphertext = encrypt_xchacha20_poly1305(&key1, &nonce, plaintext, b"").unwrap();
        let result = decrypt_xchacha20_poly1305(&key2, &nonce, &ciphertext, b"");
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("decryption failed"));
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_wrong_nonce() {
        let key = generate_random_key().unwrap();
        let nonce1 = generate_secure_nonce().unwrap();
        let nonce2 = generate_secure_nonce().unwrap();
        let plaintext = b"secret message";
        
        // Encrypt with nonce1, try to decrypt with nonce2
        let ciphertext = encrypt_xchacha20_poly1305(&key, &nonce1, plaintext, b"").unwrap();
        let result = decrypt_xchacha20_poly1305(&key, &nonce2, &ciphertext, b"");
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("decryption failed"));
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_wrong_aad() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"secret message";
        let aad1 = b"correct aad";
        let aad2 = b"wrong aad";
        
        // Encrypt with aad1, try to decrypt with aad2
        let ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, plaintext, aad1).unwrap();
        let result = decrypt_xchacha20_poly1305(&key, &nonce, &ciphertext, aad2);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("decryption failed"));
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_tampered_ciphertext() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"secret message";
        
        // Encrypt data
        let mut ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, plaintext, b"").unwrap();
        
        // Tamper with the ciphertext
        ciphertext[0] ^= 0x01;
        
        // Decryption should fail
        let result = decrypt_xchacha20_poly1305(&key, &nonce, &ciphertext, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("decryption failed"));
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_tampered_auth_tag() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"secret message";
        
        // Encrypt data
        let mut ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, plaintext, b"").unwrap();
        
        // Tamper with the authentication tag (last 16 bytes)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0x01;
        
        // Decryption should fail
        let result = decrypt_xchacha20_poly1305(&key, &nonce, &ciphertext, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("decryption failed"));
    }
    
    #[test]
    fn test_decrypt_xchacha20_poly1305_consistent_errors() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        let plaintext = b"secret message";
        
        // Encrypt data
        let ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, plaintext, b"").unwrap();
        
        // Different types of authentication failures should produce consistent timing
        let wrong_key = generate_random_key().unwrap();
        let wrong_nonce = generate_secure_nonce().unwrap();
        
        let start1 = std::time::Instant::now();
        let _ = decrypt_xchacha20_poly1305(&wrong_key, &nonce, &ciphertext, b"");
        let time1 = start1.elapsed();
        
        let start2 = std::time::Instant::now();
        let _ = decrypt_xchacha20_poly1305(&key, &wrong_nonce, &ciphertext, b"");
        let time2 = start2.elapsed();
        
        // Times should be roughly similar (constant-time authentication)
        // This is a basic check - proper timing analysis would need many samples
        let ratio = time1.as_nanos() as f64 / time2.as_nanos() as f64;
        assert!(ratio > 0.1 && ratio < 10.0, "Timing difference too large: {}", ratio);
    }
    
    #[test]
    fn test_encrypt_decrypt_round_trip_various_sizes() {
        let key = generate_random_key().unwrap();
        let nonce = generate_secure_nonce().unwrap();
        
        // Test various plaintext sizes
        let sizes = vec![0, 1, 15, 16, 17, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097];
        
        for size in sizes {
            let plaintext = vec![0x42u8; size];
            let aad = format!("test data size {}", size);
            
            let ciphertext = encrypt_xchacha20_poly1305(&key, &nonce, &plaintext, aad.as_bytes()).unwrap();
            let decrypted = decrypt_xchacha20_poly1305(&key, &nonce, &ciphertext, aad.as_bytes()).unwrap();
            
            assert_eq!(decrypted, plaintext, "Round-trip failed for size {}", size);
        }
    }
}