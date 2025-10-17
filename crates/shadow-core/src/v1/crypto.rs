// shadow-core/src/v1/crypto.rs
// Shadow v1.0 Format Cryptographic Specification
//
// V1.0 uses these specific algorithms:
// 🔐 Key Derivation: Argon2id with configurable security profiles
// 🔒 Encryption: XChaCha20-Poly1305 AEAD
// #️⃣  Hashing: SHA-256 for content integrity
//
// This module provides v1-specific convenience functions that use these algorithms.

use crate::algorithms::{argon2, xchacha20_poly1305};
use crate::errors::CryptoError;
use crate::memory::{SecureKey, SecureString};
use sha2::{Digest, Sha256};

// Re-export the specific algorithms used by v1
pub use argon2::SecurityProfile;
pub use xchacha20_poly1305::ALGORITHM_ID;

// === V1 Cryptographic Operations ===
// These functions define exactly how v1 format uses the algorithms

/// V1 key derivation: Argon2id with configurable security profiles
///
/// V1 format uses Argon2id for password-based key derivation.
/// Security profiles allow choosing between fast (test) and secure (production) parameters.
pub fn derive_key(
    password: &SecureString,
    salt: &[u8; 16],
    profile: SecurityProfile,
) -> Result<SecureKey, CryptoError> {
    let argon2 = profile.create_argon2();
    argon2::derive_key(password, salt, &argon2)
}

/// V1 filename key derivation: HKDF-SHA256 from master key
///
/// V1 format derives filename-specific keys from the master key using HKDF.
pub fn derive_filename_key(master_key: &SecureKey) -> Result<SecureKey, CryptoError> {
    argon2::derive_filename_key(master_key)
}

/// V1 content encryption: XChaCha20-Poly1305 with associated data
///
/// V1 format uses XChaCha20-Poly1305 for authenticated encryption.
pub fn encrypt_content(
    plaintext: &[u8],
    key: &SecureKey,
    nonce: &[u8; 24],
    aad: &[u8], // header data for authentication
) -> Result<Vec<u8>, CryptoError> {
    xchacha20_poly1305::encrypt(plaintext, key, nonce, aad)
}

/// V1 content decryption: XChaCha20-Poly1305 with associated data
pub fn decrypt_content(
    ciphertext: &[u8],
    key: &SecureKey,
    nonce: &[u8; 24],
    aad: &[u8], // header data for authentication
) -> Result<Vec<u8>, CryptoError> {
    xchacha20_poly1305::decrypt(ciphertext, key, nonce, aad)
}

/// V1 filename encryption: XChaCha20-Poly1305 with derived key
pub fn encrypt_filename(
    filename: &str,
    filename_key: &SecureKey,
    nonce: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    xchacha20_poly1305::encrypt_filename(filename, filename_key, nonce)
}

/// V1 filename decryption: XChaCha20-Poly1305 with derived key
pub fn decrypt_filename(
    ciphertext: &[u8],
    filename_key: &SecureKey,
    nonce: &[u8; 24],
) -> Result<String, CryptoError> {
    xchacha20_poly1305::decrypt_filename(ciphertext, filename_key, nonce)
}

/// V1 content hashing: SHA-256
///
/// V1 format uses SHA-256 for content integrity verification.
pub fn hash_content(content: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hasher.finalize().into()
}

// === V1 Algorithm Constants ===
// Simple re-exports showing exactly what v1 uses

/// V1 algorithm identifiers
pub mod algorithms {
    /// V1 uses XChaCha20-Poly1305 for encryption
    pub use crate::algorithms::xchacha20_poly1305::ALGORITHM_ID as XCHACHA20_POLY1305;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_profile_descriptions() {
        assert_eq!(SecurityProfile::Test.description(), "Fast (Test-only)");
        assert_eq!(SecurityProfile::Production.description(), "Secure (Production)");
    }

    #[test]
    fn test_production_safety_check() {
        assert!(!SecurityProfile::Test.is_production_safe());
        assert!(SecurityProfile::Production.is_production_safe());
    }

    #[test]
    fn test_argon2_instance_creation() {
        let _test_argon2 = SecurityProfile::Test.create_argon2();
        let _prod_argon2 = SecurityProfile::Production.create_argon2();

        // Verify they're different instances with different parameters
        let test_params = SecurityProfile::Test.argon2_params();
        let prod_params = SecurityProfile::Production.argon2_params();

        assert_ne!(test_params.m_cost(), prod_params.m_cost());
        assert_ne!(test_params.t_cost(), prod_params.t_cost());
    }

    #[test]
    fn test_v1_derive_key_basic() {
        let password = SecureString::new("test_password".to_string());
        let salt = [1u8; 16];

        let result = derive_key(&password, &salt, SecurityProfile::Test);
        assert!(result.is_ok());
    }

    #[test]
    fn test_v1_derive_key_deterministic() {
        let password = SecureString::new("test_password".to_string());
        let salt = [1u8; 16];

        let key1 = derive_key(&password, &salt, SecurityProfile::Test).unwrap();
        let key2 = derive_key(&password, &salt, SecurityProfile::Test).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_v1_hash_content_deterministic() {
        let content = b"Hello, World!";

        let hash1 = hash_content(content);
        let hash2 = hash_content(content);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_v1_hash_content_different_inputs() {
        let content1 = b"Hello, World!";
        let content2 = b"Hello, World?";

        let hash1 = hash_content(content1);
        let hash2 = hash_content(content2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_algorithm_constants() {
        assert_eq!(algorithms::XCHACHA20_POLY1305, 0x01);
    }
}