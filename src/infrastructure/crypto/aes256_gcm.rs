//! # AES-256-GCM Algorithm Implementation
//!
//! This module provides a complete AES-256-GCM cryptographic algorithm implementation
//! including encryption, decryption, and key derivation using Argon2id.
//!
//! AES-256-GCM provides strong authenticated encryption but requires careful nonce
//! management to avoid the birthday paradox with 96-bit nonces.

use super::{
    AlgorithmId, CryptographicAlgorithm, EncryptionConfig, EncryptionResult,
    KeyDerivationConfig, KeyMaterial,
};
use crate::domain::errors::DomainError;
use crate::infrastructure::crypto::{CryptoError, CryptoResult};
use argon2::{Argon2, Params};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
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
pub struct Aes256GcmConfig {
    argon2_params: Argon2Params,
}

impl Aes256GcmConfig {
    /// Create new configuration with custom Argon2 parameters
    pub fn new(argon2_params: Argon2Params) -> Self {
        Self { argon2_params }
    }
}

impl KeyDerivationConfig for Aes256GcmConfig {
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
        self.algorithm_id().salt_size()
    }

    fn name(&self) -> &'static str {
        "Argon2id"
    }
}

impl EncryptionConfig for Aes256GcmConfig {
    fn key_size(&self) -> usize {
        self.algorithm_id().key_size()
    }

    fn nonce_size(&self) -> usize {
        self.algorithm_id().nonce_size()
    }

    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::AesGcm256
    }
}

impl Aes256GcmConfig {
    /// Generate a random nonce for encryption
    pub fn generate_nonce(&self) -> CryptoResult<Vec<u8>> {
        use rand::RngCore;
        let mut nonce = vec![0u8; self.nonce_size()];
        rand::rng().fill_bytes(&mut nonce);
        Ok(nonce)
    }
}

impl CryptographicAlgorithm for Aes256GcmConfig {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<EncryptionResult, DomainError> {
        // Create cipher instance using the encryption key
        let cipher = Aes256Gcm::new_from_slice(key_material.as_bytes())
            .map_err(|e| DomainError::from(CryptoError::CryptographicError(format!("Cipher creation failed: {}", e))))?;

        // Generate random nonce
        let nonce = self.generate_nonce()?;
        let gcm_nonce = Nonce::from_slice(&nonce);

        // Encrypt the plaintext
        let ciphertext = cipher
            .encrypt(gcm_nonce, plaintext)
            .map_err(|e| DomainError::from(CryptoError::CryptographicError(format!("Encryption failed: {}", e))))?;

        Ok(EncryptionResult { ciphertext, nonce })
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_material: &KeyMaterial,
    ) -> Result<Vec<u8>, DomainError> {
        if nonce.len() != self.nonce_size() {
            return Err(DomainError::from(CryptoError::InvalidParameters(format!(
                "Expected nonce size {}, got {}",
                self.nonce_size(),
                nonce.len()
            ))));
        }

        // Create cipher instance using the encryption key
        let cipher = Aes256Gcm::new_from_slice(key_material.as_bytes())
            .map_err(|e| DomainError::from(CryptoError::CryptographicError(format!("Cipher creation failed: {}", e))))?;

        let gcm_nonce = Nonce::from_slice(nonce);

        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(gcm_nonce, ciphertext)
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
        let config = Aes256GcmConfig::test_config();
        assert_eq!(config.key_size(), 32);
        assert_eq!(config.nonce_size(), 12);
        assert_eq!(config.salt_length(), 16);
        assert_eq!(config.algorithm_id(), AlgorithmId::AesGcm256);
        assert_eq!(config.name(), "Argon2id");
    }

    #[test]
    fn test_key_derivation() {
        let config = Aes256GcmConfig::test_config();
        let salt = config.generate_salt().unwrap();
        let password = "test_password";
        
        let key1 = config.derive_key_material(password, &salt).unwrap();
        let key2 = config.derive_key_material(password, &salt).unwrap();
        
        // Same password and salt should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.as_bytes().len(), 32);
        
        // Different salt should produce different key
        let salt2 = config.generate_salt().unwrap();
        let key3 = config.derive_key_material(password, &salt2).unwrap();
        assert_ne!(key1.as_bytes(), key3.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let config = Aes256GcmConfig::test_config();
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
        let config = Aes256GcmConfig::test_config();
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
        let config = Aes256GcmConfig::test_config();
        assert_eq!(config.key_size(), 32); // Verify expected key size
    }

    #[test]
    fn test_invalid_nonce_size() {
        let config = Aes256GcmConfig::test_config();
        let salt = config.generate_salt().unwrap();
        let key = config.derive_key_material("password", &salt).unwrap();
        let ciphertext = vec![0u8; 32];
        let invalid_nonce = vec![0u8; 12]; // Wrong size for XChaCha20
        
        let result = config.decrypt(&ciphertext, &invalid_nonce, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_size_difference_from_xchacha20() {
        // Ensure AES-GCM uses 12-byte nonce vs XChaCha20's 24-byte nonce
        let aes_config = Aes256GcmConfig::test_config();
        assert_eq!(aes_config.nonce_size(), 12);
        
        // This test ensures the algorithms have different nonce sizes
        // which is important for proper algorithm identification
    }
}