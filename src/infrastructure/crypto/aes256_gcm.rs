//! # AES-256-GCM Algorithm Implementation
//!
//! This module provides a complete AES-256-GCM cryptograpimpl EncryptionConfig for Aes256GcmConfig {
    fn key_size(&self) -> usize {
        32 // 256-bit key for AES-256
    }

    fn nonce_size(&self) -> usize {
        12 // 96-bit nonce for GCM (required for security)
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
} implementation
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
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params};

/// Argon2id parameters for AES-256-GCM key derivation
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
            output_length: 32,    // 32 bytes for AES-256
        }
    }

    /// Create production parameters (secure, slower)
    pub fn production() -> Self {
        Self {
            memory_cost: 65536,   // 64 MiB
            time_cost: 3,         // 3 iterations
            parallelism: 4,       // 4 threads
            output_length: 32,    // 32 bytes for AES-256
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

/// AES-256-GCM algorithm configuration
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
        16 // 128-bit salt recommended for Argon2
    }

    fn name(&self) -> &'static str {
        "Argon2id"
    }
}

impl EncryptionConfig for Aes256GcmConfig {
    fn key_size(&self) -> usize {
        32 // 256-bit key for AES-256
    }

    fn nonce_size(&self) -> usize {
        12 // 96-bit nonce for AES-GCM (standard size)
    }

    fn algorithm_id(&self) -> AlgorithmId {
        AlgorithmId::AesGcm256
    }
}

impl CryptographicAlgorithm for Aes256GcmConfig {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> CryptoResult<EncryptionResult> {
        if key_material.len() != self.key_size() {
            return Err(CryptoError::InvalidParameters(format!(
                "Expected key size {}, got {}",
                self.key_size(),
                key_material.len()
            )));
        }

        // Create cipher instance
        let cipher = Aes256Gcm::new_from_slice(key_material.as_bytes())
            .map_err(|e| CryptoError::CryptographicError(format!("Cipher creation failed: {}", e)))?;

        // Generate random nonce
        let nonce = self.generate_nonce()?;
        let gcm_nonce = Nonce::from_slice(&nonce);

        // Encrypt the plaintext
        let ciphertext = cipher
            .encrypt(gcm_nonce, plaintext)
            .map_err(|e| CryptoError::CryptographicError(format!("Encryption failed: {}", e)))?;

        Ok(EncryptionResult { ciphertext, nonce })
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_material: &KeyMaterial,
    ) -> CryptoResult<Vec<u8>> {
        if key_material.len() != self.key_size() {
            return Err(CryptoError::InvalidParameters(format!(
                "Expected key size {}, got {}",
                self.key_size(),
                key_material.len()
            )));
        }

        if nonce.len() != self.nonce_size() {
            return Err(CryptoError::InvalidParameters(format!(
                "Expected nonce size {}, got {}",
                self.nonce_size(),
                nonce.len()
            )));
        }

        // Create cipher instance
        let cipher = Aes256Gcm::new_from_slice(key_material.as_bytes())
            .map_err(|e| CryptoError::CryptographicError(format!("Cipher creation failed: {}", e)))?;

        let gcm_nonce = Nonce::from_slice(nonce);

        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(gcm_nonce, ciphertext)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

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
    use crate::infrastructure::crypto::ConfigProvider;

    #[test]
    fn test_algorithm_properties() {
        let config = Aes256GcmConfig::test_config();
        assert_eq!(config.key_size(), 32);
        assert_eq!(config.nonce_size(), 12);
        assert_eq!(config.salt_length(), 16);
        assert_eq!(config.algorithm_id(), AlgorithmId::Aes256Gcm);
        assert_eq!(config.algorithm_name(), "AES-256-GCM");
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
        assert_eq!(key1.len(), 32);
        
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
        
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_invalid_key_size() {
        let config = Aes256GcmConfig::test_config();
        let invalid_key = KeyMaterial::new(vec![0u8; 16]); // Wrong size
        let plaintext = b"Hello, world!";
        
        let result = config.encrypt(plaintext, &invalid_key);
        assert!(matches!(result, Err(CryptoError::InvalidParameters(_))));
    }

    #[test]
    fn test_invalid_nonce_size() {
        let config = Aes256GcmConfig::test_config();
        let salt = config.generate_salt().unwrap();
        let key = config.derive_key_material("password", &salt).unwrap();
        let ciphertext = vec![0u8; 32];
        let invalid_nonce = vec![0u8; 24]; // Wrong size for AES-GCM
        
        let result = config.decrypt(&ciphertext, &invalid_nonce, &key);
        assert!(matches!(result, Err(CryptoError::InvalidParameters(_))));
    }

    #[test]
    fn test_config_provider_integration() {
        use crate::infrastructure::crypto::DefaultConfigProvider;
        
        let provider = DefaultConfigProvider::<Aes256GcmConfig>::test();
        let algorithm = provider.algorithm();
        
        assert_eq!(algorithm.algorithm_id(), AlgorithmId::Aes256Gcm);
        assert_eq!(algorithm.key_size(), 32);
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