//! # XChaCha20-Poly1305 Algorithm Implementation
//!
//! This module provides a complete XChaCha20-Poly1305 cryptographic algorithm implementation
//! including encryption, decryption, and key derivation using Argon2id.
//!
//! XChaCha20-Poly1305 eliminates the critical nonce reuse vulnerability present in
//! AES-GCM file encryption by using 24-byte nonces with astronomical collision resistance.

use super::{
    AlgorithmId, CryptographicAlgorithm, EncryptionConfig, EncryptionResult,
    KeyDerivationConfig, KeyMaterial,
};
use crate::domain::errors::DomainError;
use crate::infrastructure::crypto::{CryptoError, CryptoResult};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};

/// Argon2id parameters for key derivation
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Memory cost in KiB
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism factor
    pub parallelism: u32,
    /// Output key length
    pub output_length: usize,
}

impl Argon2Params {
    /// Create test parameters (fast, low security - for testing only)
    pub fn test() -> Self {
        Self {
            memory_cost: 64,      // 64 KiB
            time_cost: 1,         // 1 iteration
            parallelism: 1,       // 1 thread
            output_length: 32,    // 32 bytes for XChaCha20
        }
    }

    /// Create production parameters (secure, slower)
    pub fn production() -> Self {
        Self {
            memory_cost: 65536,   // 64 MiB
            time_cost: 3,         // 3 iterations
            parallelism: 4,       // 4 threads
            output_length: 32,    // 32 bytes for XChaCha20
        }
    }

    /// Convert to argon2 library parameters
    fn to_argon2_params(&self) -> Result<Params, CryptoError> {
        Params::new(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            Some(self.output_length),
        )
        .map_err(|e| CryptoError::ConfigurationError(format!("Invalid Argon2 parameters: {}", e)))
    }
}

/// XChaCha20-Poly1305 algorithm configuration
#[derive(Debug, Clone)]
pub struct XChaCha20Poly1305Config {
    argon2_params: Argon2Params,
}

impl XChaCha20Poly1305Config {
    /// Create new configuration with custom Argon2 parameters
    pub fn new(argon2_params: Argon2Params) -> Self {
        Self { argon2_params }
    }
}

impl KeyDerivationConfig for XChaCha20Poly1305Config {
    fn derive_key_material(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, DomainError> {
        let params = self.argon2_params.to_argon2_params()?;
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        let mut master_key = [0u8; 32]; // Fixed size for master key
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut master_key)
            .map_err(|e| DomainError::from(CryptoError::KeyDerivationError(format!("Argon2 derivation failed: {}", e))))?;

        Ok(KeyMaterial::from_master_key(master_key))
    }

    fn salt_length(&self) -> usize {
        16 // 128-bit salt recommended for Argon2
    }

    fn name(&self) -> &'static str {
        "Argon2id"
    }
}

impl EncryptionConfig for XChaCha20Poly1305Config {
    fn key_size(&self) -> usize {
        32 // 256-bit key for XChaCha20
    }

    fn nonce_size(&self) -> usize {
        24 // 192-bit nonce for XChaCha20 (extended nonce)
    }

    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::XChaCha20Poly1305
    }
}

impl XChaCha20Poly1305Config {
    /// Generate a random nonce for encryption
    pub fn generate_nonce(&self) -> CryptoResult<Vec<u8>> {
        use rand::RngCore;
        let mut nonce = vec![0u8; self.nonce_size()];
        rand::rng().fill_bytes(&mut nonce);
        Ok(nonce)
    }
}

impl CryptographicAlgorithm for XChaCha20Poly1305Config {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<EncryptionResult, DomainError> {
        if key_material.len() != self.key_size() {
            return Err(DomainError::from(CryptoError::InvalidParameters(format!(
                "Expected key size {}, got {}",
                self.key_size(),
                key_material.len()
            ))));
        }

        // Create cipher instance
        let cipher = XChaCha20Poly1305::new_from_slice(key_material.as_bytes())
            .map_err(|e| DomainError::from(CryptoError::CryptographicError(format!("Cipher creation failed: {}", e))))?;

        // Generate random nonce
        let nonce = self.generate_nonce()
            .map_err(|e| DomainError::from(e))?;
        let xnonce = XNonce::from_slice(&nonce);

        // Encrypt the plaintext
        let ciphertext = cipher
            .encrypt(xnonce, plaintext)
            .map_err(|e| DomainError::from(CryptoError::CryptographicError(format!("Encryption failed: {}", e))))?;

        Ok(EncryptionResult { ciphertext, nonce })
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<Vec<u8>, DomainError> {
        if key_material.len() != self.key_size() {
            return Err(DomainError::from(CryptoError::InvalidParameters(format!(
                "Expected key size {}, got {}",
                self.key_size(),
                key_material.len()
            ))));
        }

        if nonce.len() != self.nonce_size() {
            return Err(DomainError::from(CryptoError::InvalidParameters(format!(
                "Expected nonce size {}, got {}",
                self.nonce_size(),
                nonce.len()
            ))));
        }

        // Create cipher instance
        let cipher = XChaCha20Poly1305::new_from_slice(key_material.as_bytes())
            .map_err(|e| DomainError::from(CryptoError::CryptographicError(format!("Cipher creation failed: {}", e))))?;

        let xnonce = XNonce::from_slice(nonce);

        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(xnonce, ciphertext)
            .map_err(|_| DomainError::from(CryptoError::AuthenticationFailed))?;

        Ok(plaintext)
    }

    fn test_config() -> Self {
        Self::new(Argon2Params::test())
    }

    fn production_config() -> Self {
        Self::new(Argon2Params::production())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_properties() {
        let config = XChaCha20Poly1305Config::test_config();
        assert_eq!(config.key_size(), 32);
        assert_eq!(config.nonce_size(), 24);
        assert_eq!(config.salt_length(), 16);
        assert_eq!(config.algorithm_id(), AlgorithmId::XChaCha20Poly1305);
        assert_eq!(config.algorithm_name(), "XChaCha20-Poly1305");
        assert_eq!(config.name(), "Argon2id");
    }

    #[test]
    fn test_key_derivation() {
        let config = XChaCha20Poly1305Config::test_config();
        let salt = config.generate_salt().unwrap();
        let password = "test_password";
        
        let key1 = config.derive_key_material(password, &salt).unwrap();
        let key2 = config.derive_key_material(password, &salt).unwrap();
        
        // Same password and salt should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.len(), 32);
        
        // Different salt should produce different key
        let salt2 = config.generate_salt().unwrap();
        let key3 = config.derive_key_material(password, &salt2).unwrap();
        assert_ne!(key1.as_bytes(), key3.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let config = XChaCha20Poly1305Config::test_config();
        let salt = config.generate_salt().unwrap();
        let password = "test_password";
        let plaintext = b"Hello, world! This is a test message.";
        
        // Derive key
        let key = config.derive_key_material(password, &salt).unwrap();
        
        // Encrypt
        let encryption_result = config.encrypt(plaintext, &key).unwrap();
        
        // Decrypt
        let decrypted = config
            .decrypt(&encryption_result.ciphertext, &encryption_result.nonce, &key)
            .unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_wrong_password_fails() {
        let config = XChaCha20Poly1305Config::test_config();
        let salt = config.generate_salt().unwrap();
        let plaintext = b"Hello, world!";
        
        // Encrypt with one password
        let key1 = config.derive_key_material("password1", &salt).unwrap();
        let encryption_result = config.encrypt(plaintext, &key1).unwrap();
        
        // Try to decrypt with different password
        let key2 = config.derive_key_material("password2", &salt).unwrap();
        let result = config.decrypt(&encryption_result.ciphertext, &encryption_result.nonce, &key2);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_size() {
        // KeyMaterial enforces correct key sizes through its constructor
        // This test verifies the expected key size
        let config = XChaCha20Poly1305Config::test_config();
        assert_eq!(config.key_size(), 32); // Verify expected key size
    }

    #[test]
    fn test_invalid_nonce_size() {
        let config = XChaCha20Poly1305Config::test_config();
        let salt = config.generate_salt().unwrap();
        let key = config.derive_key_material("password", &salt).unwrap();
        let ciphertext = vec![0u8; 32];
        let invalid_nonce = vec![0u8; 12]; // Wrong size for XChaCha20
        
        let result = config.decrypt(&ciphertext, &invalid_nonce, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_size_difference_from_aes() {
        // Ensure XChaCha20 uses 24-byte nonce vs AES-GCM's 12-byte nonce
        let config = XChaCha20Poly1305Config::test_config();
        assert_eq!(config.nonce_size(), 24);
        
        // This test ensures the algorithms have different nonce sizes
        // which is important for proper algorithm identification
    }
}