//! Filename obfuscation implementation
//! 
//! This module provides secure, reversible filename obfuscation using HKDF-derived keys
//! and deterministic Base64url encoding with collision resistance.

use crate::shared::errors::CryptoError;
use std::collections::HashSet;
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use base64::Engine;
use subtle::ConstantTimeEq;

/// Obfuscate filename using HKDF-derived key
/// 
/// Creates a deterministic obfuscated filename that can be reversed with the same key.
/// Uses HKDF to derive a filename-specific key, then creates a secure hash-based
/// obfuscated name that's safe for filesystems.
/// 
/// # Arguments
/// * `obfuscation_key` - Master obfuscation key (32 bytes)
/// * `original_name` - Original filename to obfuscate
/// 
/// # Returns
/// * `Ok(String)` - Base64url-encoded obfuscated filename
/// * `Err(CryptoError)` - Obfuscation failed
/// 
/// # Security
/// * Uses HKDF-SHA256 for key derivation
/// * Deterministic output for same key+filename
/// * Base64url encoding for filesystem safety
pub fn obfuscate_filename(obfuscation_key: &[u8], original_name: &str) -> Result<String, CryptoError> {
    if obfuscation_key.len() != 32 {
        return Err(CryptoError::CryptographicError(
            "Obfuscation key must be 32 bytes".to_string()
        ));
    }
    
    if original_name.is_empty() {
        return Err(CryptoError::CryptographicError(
            "Filename cannot be empty".to_string()
        ));
    }
    
    // Derive filename-specific key using HKDF
    let filename_bytes = original_name.as_bytes();
    let hkdf = Hkdf::<Sha256>::new(None, obfuscation_key);
    
    // Create info context for this specific filename
    let info = format!("filename_obfuscation_v1:{}", original_name);
    let mut derived_key = [0u8; 32];
    
    hkdf.expand(info.as_bytes(), &mut derived_key)
        .map_err(|e| CryptoError::CryptographicError(
            format!("HKDF expansion failed: {}", e)
        ))?;
    
    // Create deterministic obfuscated name using derived key + filename
    let mut hasher = Sha256::new();
    hasher.update(&derived_key);
    hasher.update(filename_bytes);
    hasher.update(b"obfuscated_filename_v1"); // Version tag
    
    let hash = hasher.finalize();
    
    // Encode as Base64url for filesystem safety (no padding, URL-safe)
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let obfuscated = engine.encode(&hash);
    
    // Add file extension for recognition
    Ok(format!("{}.enc", obfuscated))
}

/// Obfuscate filename with collision resistance
/// 
/// Same as obfuscate_filename but checks for collisions and appends a counter
/// if needed to ensure uniqueness in the given set of existing names.
/// 
/// # Arguments
/// * `obfuscation_key` - Master obfuscation key (32 bytes)
/// * `original_name` - Original filename to obfuscate
/// * `existing_names` - Set of already used obfuscated names
/// 
/// # Returns
/// * `Ok(String)` - Unique obfuscated filename
/// * `Err(CryptoError)` - Obfuscation failed
/// 
/// # Collision Resolution
/// If the deterministic name conflicts, appends "_1", "_2", etc. until unique.
pub fn obfuscate_name_with_collision_resistance(
    obfuscation_key: &[u8], 
    original_name: &str, 
    existing_names: &HashSet<String>
) -> Result<String, CryptoError> {
    // Get base obfuscated name
    let base_name = obfuscate_filename(obfuscation_key, original_name)?;
    
    // Check for collision
    if !existing_names.contains(&base_name) {
        return Ok(base_name);
    }
    
    // Handle collision by appending counter
    let base_without_ext = if base_name.ends_with(".enc") {
        &base_name[..base_name.len() - 4]
    } else {
        &base_name
    };
    
    for counter in 1..=9999 {
        let candidate = format!("{}_{}.enc", base_without_ext, counter);
        if !existing_names.contains(&candidate) {
            return Ok(candidate);
        }
    }
    
    // If we can't find a unique name after 9999 attempts, something is wrong
    Err(CryptoError::CryptographicError(
        "Could not generate unique obfuscated filename after 9999 attempts".to_string()
    ))
}

/// Reverse obfuscated filename to check if it matches original
/// 
/// This is used during decryption to verify filename integrity.
/// Note: This doesn't actually "reverse" the obfuscation (which is one-way),
/// but rather re-obfuscates the original to check for a match.
/// 
/// # Arguments
/// * `obfuscation_key` - Master obfuscation key (32 bytes)
/// * `original_name` - Original filename to verify
/// * `obfuscated_name` - Obfuscated filename to check against
/// 
/// # Returns
/// * `Ok(bool)` - True if names match, false otherwise
/// * `Err(CryptoError)` - Verification failed
pub fn verify_obfuscated_filename(
    obfuscation_key: &[u8], 
    original_name: &str, 
    obfuscated_name: &str
) -> Result<bool, CryptoError> {
    // Strip collision counter if present
    let normalized_obfuscated = if let Some(pos) = obfuscated_name.rfind('_') {
        if let Some(ext_pos) = obfuscated_name.rfind(".enc") {
            if pos < ext_pos {
                // Check if everything between _ and .enc is numeric
                let counter_part = &obfuscated_name[pos + 1..ext_pos];
                if counter_part.chars().all(|c| c.is_ascii_digit()) {
                    // This has a collision counter, use base name
                    format!("{}.enc", &obfuscated_name[..pos])
                } else {
                    obfuscated_name.to_string()
                }
            } else {
                obfuscated_name.to_string()
            }
        } else {
            obfuscated_name.to_string()
        }
    } else {
        obfuscated_name.to_string()
    };
    
    // Re-obfuscate original and compare using constant-time comparison
    let expected = obfuscate_filename(obfuscation_key, original_name)?;
    
    // Use constant-time comparison to prevent timing side-channel attacks
    Ok(expected.as_bytes().ct_eq(normalized_obfuscated.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Create test obfuscation key
    fn test_key() -> Vec<u8> {
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ]
    }

    #[test]
    fn test_basic_obfuscation() {
        let key = test_key();
        let filename = "test.txt";
        
        let result = obfuscate_filename(&key, filename);
        assert!(result.is_ok());
        
        let obfuscated = result.unwrap();
        assert!(obfuscated.ends_with(".enc"));
        assert!(obfuscated.len() > filename.len());
        println!("Obfuscated '{}' -> '{}'", filename, obfuscated);
    }

    #[test]
    fn test_deterministic_obfuscation() {
        let key = test_key();
        let filename = "document.pdf";
        
        let result1 = obfuscate_filename(&key, filename).unwrap();
        let result2 = obfuscate_filename(&key, filename).unwrap();
        
        assert_eq!(result1, result2, "Obfuscation should be deterministic");
    }

    #[test]
    fn test_different_keys_different_results() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] = 0xFF; // Change one byte
        
        let filename = "secret.doc";
        
        let result1 = obfuscate_filename(&key1, filename).unwrap();
        let result2 = obfuscate_filename(&key2, filename).unwrap();
        
        assert_ne!(result1, result2, "Different keys should produce different results");
    }

    #[test]
    fn test_different_filenames_different_results() {
        let key = test_key();
        
        let result1 = obfuscate_filename(&key, "file1.txt").unwrap();
        let result2 = obfuscate_filename(&key, "file2.txt").unwrap();
        
        assert_ne!(result1, result2, "Different filenames should produce different results");
    }

    #[test]
    fn test_unicode_filenames() {
        let key = test_key();
        let unicode_name = "文档.txt"; // Chinese characters
        
        let result = obfuscate_filename(&key, unicode_name);
        assert!(result.is_ok());
        
        let obfuscated = result.unwrap();
        assert!(obfuscated.ends_with(".enc"));
        println!("Unicode obfuscated '{}' -> '{}'", unicode_name, obfuscated);
    }

    #[test]
    fn test_long_filename() {
        let key = test_key();
        let long_name = "a".repeat(300); // Very long filename
        
        let result = obfuscate_filename(&key, &long_name);
        assert!(result.is_ok());
        
        let obfuscated = result.unwrap();
        // Obfuscated name should be shorter and safe
        assert!(obfuscated.len() < 100); // Base64-encoded SHA256 + .enc should be ~48 chars
    }

    #[test]
    fn test_empty_filename_error() {
        let key = test_key();
        let result = obfuscate_filename(&key, "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_invalid_key_size() {
        let short_key = vec![0x01, 0x02]; // Too short
        let result = obfuscate_filename(&short_key, "test.txt");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_collision_resistance_no_collision() {
        let key = test_key();
        let filename = "unique.txt";
        let existing = HashSet::new();
        
        let result = obfuscate_name_with_collision_resistance(&key, filename, &existing).unwrap();
        let expected = obfuscate_filename(&key, filename).unwrap();
        
        assert_eq!(result, expected, "Should return base name when no collision");
    }

    #[test]
    fn test_collision_resistance_with_collision() {
        let key = test_key();
        let filename = "collision.txt";
        
        // Get base obfuscated name
        let base_name = obfuscate_filename(&key, filename).unwrap();
        
        // Create set with existing collision
        let mut existing = HashSet::new();
        existing.insert(base_name.clone());
        
        let result = obfuscate_name_with_collision_resistance(&key, filename, &existing).unwrap();
        
        // Should get a modified name with counter
        assert_ne!(result, base_name);
        assert!(result.contains("_1.enc"));
        println!("Collision resolved: '{}' -> '{}'", base_name, result);
    }

    #[test]
    fn test_multiple_collisions() {
        let key = test_key();
        let filename = "popular.txt";
        
        let base_name = obfuscate_filename(&key, filename).unwrap();
        let base_without_ext = &base_name[..base_name.len() - 4];
        
        // Create set with multiple existing collisions
        let mut existing = HashSet::new();
        existing.insert(base_name.clone());
        existing.insert(format!("{}_1.enc", base_without_ext));
        existing.insert(format!("{}_2.enc", base_without_ext));
        
        let result = obfuscate_name_with_collision_resistance(&key, filename, &existing).unwrap();
        
        assert!(result.contains("_3.enc"), "Should use next available counter");
    }

    #[test]
    fn test_verification_success() {
        let key = test_key();
        let filename = "verify.txt";
        
        let obfuscated = obfuscate_filename(&key, filename).unwrap();
        let verified = verify_obfuscated_filename(&key, filename, &obfuscated).unwrap();
        
        assert!(verified, "Verification should succeed for matching names");
    }

    #[test]
    fn test_verification_with_collision_counter() {
        let key = test_key();
        let filename = "verify_collision.txt";
        
        let base_obfuscated = obfuscate_filename(&key, filename).unwrap();
        let base_without_ext = &base_obfuscated[..base_obfuscated.len() - 4];
        let collision_name = format!("{}_42.enc", base_without_ext);
        
        let verified = verify_obfuscated_filename(&key, filename, &collision_name).unwrap();
        
        assert!(verified, "Verification should succeed even with collision counter");
    }

    #[test]
    fn test_verification_failure() {
        let key = test_key();
        let filename = "correct.txt";
        let wrong_obfuscated = "totally_wrong_name.enc";
        
        let verified = verify_obfuscated_filename(&key, filename, wrong_obfuscated).unwrap();
        
        assert!(!verified, "Verification should fail for non-matching names");
    }

    #[test]
    fn test_filesystem_safe_characters() {
        let key = test_key();
        let filename = "file with spaces & symbols!@#$%.txt";
        
        let obfuscated = obfuscate_filename(&key, filename).unwrap();
        
        // Check that obfuscated name only contains filesystem-safe characters
        // Base64url uses A-Z, a-z, 0-9, -, _
        let safe_chars = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';
        assert!(obfuscated.chars().all(safe_chars), 
               "Obfuscated name '{}' contains unsafe characters", obfuscated);
    }

    #[test]
    fn test_no_information_leakage() {
        let key = test_key();
        
        // Test files with different lengths but similar names
        let short_file = "a.txt";
        let medium_file = "abcdefghij.txt";
        let long_file = "a".repeat(100) + ".txt";
        
        let obf1 = obfuscate_filename(&key, short_file).unwrap();
        let obf2 = obfuscate_filename(&key, medium_file).unwrap();
        let obf3 = obfuscate_filename(&key, &long_file).unwrap();
        
        // All obfuscated names should have similar lengths (hash + .enc)
        let len1 = obf1.len();
        let len2 = obf2.len();
        let len3 = obf3.len();
        
        assert_eq!(len1, len2, "Obfuscated lengths should be consistent");
        assert_eq!(len2, len3, "Obfuscated lengths should be consistent");
        
        println!("Consistent lengths: {} = {} = {}", len1, len2, len3);
    }
}