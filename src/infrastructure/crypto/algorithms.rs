//! # Cryptographic Algorithm Abstractions
//!
//! This module provides trait-based abstractions for cryptographic algorithms,
//! enabling clean dependency injection and algorithm independence.
//!
//! ## Design Goals
//!
//! - **Algorithm Independence**: Same interface works with XChaCha20-Poly1305, AES-GCM, and future algorithms
//! - **Security First**: Strong type safety and secure memory management
//! - **Clean Architecture**: Abstractions support domain layer requirements
//! - **Testing Support**: Easy mocking and parameter injection for tests

use crate::infrastructure::crypto::{CryptoError, CryptoResult};
use std::fmt;

/// Secure key material with automatic zeroization
#[derive(Clone)]
pub struct KeyMaterial {
    key: Vec<u8>,
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

impl KeyMaterial {
    /// Create new key material from raw bytes
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Get key as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Get expected key length for validation
    pub fn len(&self) -> usize {
        self.key.len()
    }

    /// Check if key is empty
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("len", &self.key.len())
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Algorithm identifier for header serialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AlgorithmId {
    XChaCha20Poly1305 = 1,
    Aes256Gcm = 2,
}

impl AlgorithmId {
    /// Convert from u16 identifier
    pub fn from_u16(id: u16) -> Result<Self, CryptoError> {
        match id {
            1 => Ok(AlgorithmId::XChaCha20Poly1305),
            2 => Ok(AlgorithmId::Aes256Gcm),
            _ => Err(CryptoError::UnsupportedAlgorithm(id)),
        }
    }

    /// Convert to u16 identifier
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Get human-readable algorithm name
    pub fn name(self) -> &'static str {
        match self {
            AlgorithmId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            AlgorithmId::Aes256Gcm => "AES-256-GCM",
        }
    }
}

/// Encryption/decryption result containing ciphertext and authentication tag
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Trait for key derivation function configuration
pub trait KeyDerivationConfig: Send + Sync + Clone + fmt::Debug {
    /// Derive key material from password and salt
    fn derive_key_material(&self, password: &str, salt: &[u8]) -> CryptoResult<KeyMaterial>;
    
    /// Get recommended salt length in bytes
    fn salt_length(&self) -> usize;
    
    /// Generate a cryptographically secure salt of appropriate length
    fn generate_salt(&self) -> CryptoResult<Vec<u8>> {
        let mut salt = vec![0u8; self.salt_length()];
        getrandom::fill(&mut salt)
            .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
        Ok(salt)
    }
    
    /// Get configuration name for debugging/logging
    fn name(&self) -> &'static str;
}

/// Trait for encryption algorithm configuration  
pub trait EncryptionConfig: Send + Sync + Clone + fmt::Debug {
    /// Get the key size required by this algorithm
    fn key_size(&self) -> usize;
    
    /// Get the nonce size required by this algorithm
    fn nonce_size(&self) -> usize;
    
    /// Get algorithm identifier for header serialization
    fn algorithm_id(&self) -> AlgorithmId;
    
    /// Get human-readable algorithm name
    fn algorithm_name(&self) -> &'static str {
        self.algorithm_id().name()
    }
}

/// Complete cryptographic algorithm interface
/// 
/// Combines key derivation and encryption operations into a single
/// trait that can be used by domain services.
pub trait CryptographicAlgorithm: KeyDerivationConfig + EncryptionConfig {
    /// Encrypt plaintext data using derived key
    fn encrypt(
        &self,
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> CryptoResult<EncryptionResult>;
    
    /// Decrypt ciphertext data using derived key  
    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_material: &KeyMaterial,
    ) -> CryptoResult<Vec<u8>>;
    
    /// Create a test configuration with fast parameters
    fn test_config() -> Self;
    
    /// Create a production configuration with secure parameters
    fn production_config() -> Self;
    
    /// Generate a secure nonce for encryption
    fn generate_nonce(&self) -> CryptoResult<Vec<u8>> {
        let mut nonce = vec![0u8; self.nonce_size()];
        getrandom::fill(&mut nonce)
            .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
        Ok(nonce)
    }
}

/// Configuration provider trait for dependency injection
/// 
/// This trait allows functions to accept configuration without
/// being coupled to specific implementation types.
pub trait ConfigProvider {
    type Algorithm: CryptographicAlgorithm;
    
    /// Get the current algorithm configuration
    fn algorithm(&self) -> &Self::Algorithm;
}

/// Default configuration provider implementation
#[derive(Debug, Clone)]
pub struct DefaultConfigProvider<T: CryptographicAlgorithm> {
    algorithm: T,
}

impl<T: CryptographicAlgorithm> DefaultConfigProvider<T> {
    /// Create new provider with given algorithm configuration
    pub fn new(algorithm: T) -> Self {
        Self { algorithm }
    }
    
    /// Create provider with test configuration (fast parameters)
    pub fn test() -> Self {
        Self::new(T::test_config())
    }
    
    /// Create provider with production configuration (secure parameters)
    pub fn production() -> Self {
        Self::new(T::production_config())
    }
}

impl<T: CryptographicAlgorithm> ConfigProvider for DefaultConfigProvider<T> {
    type Algorithm = T;
    
    fn algorithm(&self) -> &Self::Algorithm {
        &self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_id_conversion() {
        assert_eq!(AlgorithmId::XChaCha20Poly1305.as_u16(), 1);
        assert_eq!(AlgorithmId::Aes256Gcm.as_u16(), 2);
        
        assert_eq!(AlgorithmId::from_u16(1).unwrap(), AlgorithmId::XChaCha20Poly1305);
        assert_eq!(AlgorithmId::from_u16(2).unwrap(), AlgorithmId::Aes256Gcm);
        
        assert!(AlgorithmId::from_u16(999).is_err());
    }

    #[test]
    fn test_algorithm_names() {
        assert_eq!(AlgorithmId::XChaCha20Poly1305.name(), "XChaCha20-Poly1305");
        assert_eq!(AlgorithmId::Aes256Gcm.name(), "AES-256-GCM");
    }

    #[test]
    fn test_key_material_zeroization() {
        let key_data = vec![1, 2, 3, 4, 5];
        let key_material = KeyMaterial::new(key_data.clone());
        
        assert_eq!(key_material.as_bytes(), &key_data);
        assert_eq!(key_material.len(), 5);
        assert!(!key_material.is_empty());
        
        // KeyMaterial will be zeroized when dropped
        drop(key_material);
    }
}