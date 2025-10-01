//! Obfuscated filename authentication
//!
//! This module provides functionality to authenticate obfuscated filenames against
//! file contents to prevent file substitution attacks in obfuscated mode.
//!
//! # Security
//! When filename obfuscation is used, an attacker could potentially replace an
//! obfuscated file with a different encrypted file. This module prevents such
//! attacks by binding the obfuscated filename to the file's cryptographic identity.

use crate::shared::errors::CryptoError;
use crate::shared::crypto::KeyMaterial;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

/// Compute authentication tag for obfuscated filename
/// 
/// Creates an HMAC-SHA256 tag that binds the obfuscated filename to the file's
/// cryptographic identity (salt + nonce). This prevents file substitution attacks
/// where an attacker replaces one obfuscated file with another.
/// 
/// # Arguments
/// * `obfuscated_filename` - The obfuscated filename (e.g., "abc123.shadow")
/// * `salt` - File's unique salt (16 bytes)
/// * `nonce` - File's unique nonce (12 bytes)
/// * `keys` - Key material containing the obfuscation key
/// 
/// # Returns
/// * `Ok([u8; 16])` - 16-byte authentication tag (truncated HMAC-SHA256)
/// * `Err(CryptoError)` - Authentication tag computation failed
/// 
/// # Security Properties
/// * Binds obfuscated filename to file's cryptographic identity
/// * Uses HMAC-SHA256 for strong authentication
/// * Truncated to 16 bytes to match other auth tags in header
/// * Uses same key as filename obfuscation for consistency
pub fn compute_filename_auth_tag(
    obfuscated_filename: &str,
    salt: &[u8; 16],
    nonce: &[u8; 12],
    keys: &KeyMaterial,
) -> Result<[u8; 16], CryptoError> {
    // Create HMAC with obfuscation key
    let mut mac = HmacSha256::new_from_slice(keys.obfuscation_key.expose_secret())
        .map_err(|e| CryptoError::CryptographicError(
            format!("Failed to create HMAC: {}", e)
        ))?;
    
    // Include salt and nonce to bind to this specific file
    mac.update(salt);
    mac.update(nonce);
    
    // Include the obfuscated filename
    mac.update(obfuscated_filename.as_bytes());
    
    // Include context string for domain separation
    mac.update(b"filename_auth_v1");
    
    // Finalize and truncate to 16 bytes
    let result = mac.finalize().into_bytes();
    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(&result[..16]);
    
    Ok(auth_tag)
}

/// Verify authentication tag for obfuscated filename
/// 
/// Verifies that the obfuscated filename matches the authentication tag stored
/// in the file header. This prevents file substitution attacks.
/// 
/// # Arguments
/// * `obfuscated_filename` - The obfuscated filename to verify
/// * `expected_tag` - Expected authentication tag from file header
/// * `salt` - File's unique salt (16 bytes)
/// * `nonce` - File's unique nonce (12 bytes)
/// * `keys` - Key material containing the obfuscation key
/// 
/// # Returns
/// * `Ok(bool)` - True if filename is authentic, false if tampered
/// * `Err(CryptoError)` - Verification failed due to crypto error
/// 
/// # Security
/// * Uses constant-time comparison to prevent timing attacks
/// * Returns false for any mismatch (tampered filename)
/// * Uses same computation as `compute_filename_auth_tag`
pub fn verify_filename_auth_tag(
    obfuscated_filename: &str,
    expected_tag: &[u8; 16],
    salt: &[u8; 16],
    nonce: &[u8; 12],
    keys: &KeyMaterial,
) -> Result<bool, CryptoError> {
    // Compute expected tag
    let computed_tag = compute_filename_auth_tag(obfuscated_filename, salt, nonce, keys)?;
    
    // Constant-time comparison
    use subtle::ConstantTimeEq;
    Ok(computed_tag.ct_eq(expected_tag).into())
}

/// Extract obfuscated filename from path for authentication
/// 
/// Helper function to extract just the filename part from a path,
/// which is what gets authenticated.
/// 
/// # Arguments
/// * `file_path` - Full path to the obfuscated file
/// 
/// # Returns
/// * `Ok(String)` - Just the filename part (e.g., "abc123.shadow")
/// * `Err(CryptoError)` - Path contains no filename
pub fn extract_filename_for_auth(file_path: &Path) -> Result<String, CryptoError> {
    file_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| CryptoError::CryptographicError(
            "Cannot extract filename for authentication".to_string()
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::crypto::{derive_master_key, Argon2Params, generate_salt};

    fn test_keys() -> KeyMaterial {
        let salt = generate_salt(16).unwrap();
        let params = Argon2Params::default();
        derive_master_key("test_password", &salt, &params).unwrap()
    }

    #[test]
    fn test_compute_and_verify_auth_tag() {
        let keys = test_keys();
        let salt = [1u8; 16];
        let nonce = [2u8; 12];
        let filename = "abc123def456.shadow";
        
        // Compute auth tag
        let auth_tag = compute_filename_auth_tag(filename, &salt, &nonce, &keys).unwrap();
        
        // Verify should succeed
        assert!(verify_filename_auth_tag(filename, &auth_tag, &salt, &nonce, &keys).unwrap());
    }
    
    #[test]
    fn test_different_filename_fails_verification() {
        let keys = test_keys();
        let salt = [1u8; 16];
        let nonce = [2u8; 12];
        let filename1 = "abc123def456.shadow";
        let filename2 = "different789.shadow";
        
        // Compute auth tag for filename1
        let auth_tag = compute_filename_auth_tag(filename1, &salt, &nonce, &keys).unwrap();
        
        // Verify with filename2 should fail
        assert!(!verify_filename_auth_tag(filename2, &auth_tag, &salt, &nonce, &keys).unwrap());
    }
    
    #[test]
    fn test_different_salt_fails_verification() {
        let keys = test_keys();
        let salt1 = [1u8; 16];
        let salt2 = [2u8; 16];
        let nonce = [3u8; 12];
        let filename = "test123.shadow";
        
        // Compute auth tag with salt1
        let auth_tag = compute_filename_auth_tag(filename, &salt1, &nonce, &keys).unwrap();
        
        // Verify with salt2 should fail
        assert!(!verify_filename_auth_tag(filename, &auth_tag, &salt2, &nonce, &keys).unwrap());
    }
    
    #[test]
    fn test_different_nonce_fails_verification() {
        let keys = test_keys();
        let salt = [1u8; 16];
        let nonce1 = [2u8; 12];
        let nonce2 = [3u8; 12];
        let filename = "test123.shadow";
        
        // Compute auth tag with nonce1
        let auth_tag = compute_filename_auth_tag(filename, &salt, &nonce1, &keys).unwrap();
        
        // Verify with nonce2 should fail
        assert!(!verify_filename_auth_tag(filename, &auth_tag, &salt, &nonce2, &keys).unwrap());
    }
    
    #[test]
    fn test_extract_filename_for_auth() {
        use std::path::PathBuf;
        
        let path = PathBuf::from("/some/directory/abc123.shadow");
        let filename = extract_filename_for_auth(&path).unwrap();
        assert_eq!(filename, "abc123.shadow");
        
        let path = PathBuf::from("relative/path/test456.shadow");
        let filename = extract_filename_for_auth(&path).unwrap();
        assert_eq!(filename, "test456.shadow");
        
        let path = PathBuf::from("just_filename.shadow");
        let filename = extract_filename_for_auth(&path).unwrap();
        assert_eq!(filename, "just_filename.shadow");
    }
    
    #[test]
    fn test_deterministic_auth_tags() {
        let keys = test_keys();
        let salt = [1u8; 16];
        let nonce = [2u8; 12];
        let filename = "test123.shadow";
        
        // Compute auth tag twice
        let auth_tag1 = compute_filename_auth_tag(filename, &salt, &nonce, &keys).unwrap();
        let auth_tag2 = compute_filename_auth_tag(filename, &salt, &nonce, &keys).unwrap();
        
        // Should be identical
        assert_eq!(auth_tag1, auth_tag2);
    }
}