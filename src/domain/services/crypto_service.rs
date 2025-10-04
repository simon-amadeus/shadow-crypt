//! # Domain Cryptographic Service Interfaces
//!
//! This module defines the cryptographic service abstractions that belong in the domain layer.
//! Infrastructure implementations will implement these traits to provide concrete crypto operations.

use crate::domain::entities::{AlgorithmId, KeyMaterial};
use crate::domain::errors::DomainError;

type CryptoResult<T> = Result<T, DomainError>;

/// Encryption/decryption result containing ciphertext and authentication data
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Trait for key derivation function configuration
/// 
/// Abstracts password-based key derivation with secure parameter choices
/// for PBKDF2, Argon2, or other KDF implementations.
pub trait KeyDerivationConfig: Send + Sync + Clone + std::fmt::Debug {
    /// Derive cryptographic key material from password and salt
    /// 
    /// # Security Requirements
    /// - Must use cryptographically secure random salt
    /// - Must apply sufficient work factor to resist brute force attacks
    /// - Must produce key material suitable for the target algorithm
    fn derive_key_material(&self, password: &str, salt: &[u8]) -> CryptoResult<KeyMaterial>;
    
    /// Get recommended salt length in bytes
    fn salt_length(&self) -> usize;
    
    /// Generate a cryptographically secure salt of appropriate length
    fn generate_salt(&self) -> CryptoResult<Vec<u8>> {
        let mut salt = vec![0u8; self.salt_length()];
        getrandom::fill(&mut salt)
            .map_err(|e| DomainError::crypto_error(format!("Random generation failed: {}", e)))?;
        Ok(salt)
    }
    
    /// Get configuration name for debugging/logging
    fn name(&self) -> &'static str;
}

/// Trait for encryption algorithm configuration  
/// 
/// Defines the cryptographic parameters and capabilities of an encryption algorithm.
pub trait EncryptionConfig: Send + Sync + Clone + std::fmt::Debug {
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
/// trait that can be used by domain services. Infrastructure implementations
/// will provide concrete algorithm implementations.
pub trait CryptographicAlgorithm: KeyDerivationConfig + EncryptionConfig {
    /// Encrypt plaintext data using derived key
    /// 
    /// # Security Requirements
    /// - Must generate a unique nonce for each encryption
    /// - Must authenticate the ciphertext with AEAD
    /// - Must validate key material before use
    fn encrypt(
        &self,
        plaintext: &[u8],
        key_material: &KeyMaterial,
    ) -> CryptoResult<EncryptionResult>;
    
    /// Decrypt ciphertext data using derived key  
    /// 
    /// # Security Requirements
    /// - Must verify authentication tag before returning plaintext
    /// - Must validate key material and nonce before decryption
    /// - Must handle timing attack resistance
    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_material: &KeyMaterial,
    ) -> CryptoResult<Vec<u8>>;
    
    /// Create a test configuration with fast parameters
    /// 
    /// Used for unit tests where crypto security is less important than speed.
    fn test_config() -> Self;
    
    /// Create a production configuration with secure parameters
    /// 
    /// Used for real-world encryption with maximum security.
    fn production_config() -> Self;
}

/// Configuration provider for algorithm-specific settings
/// 
/// Provides factory pattern for creating algorithm configurations
/// with appropriate parameters for different environments.
pub trait ConfigProvider: Send + Sync + Clone + std::fmt::Debug {
    type Algorithm: CryptographicAlgorithm;
    
    /// Create algorithm with production security parameters
    fn production_config(&self) -> Self::Algorithm;
    
    /// Create algorithm with test parameters (faster, less secure)
    fn test_config(&self) -> Self::Algorithm;
}

/// Default configuration provider implementation
/// 
/// Provides standard configurations for any algorithm that implements
/// the required production_config() and test_config() methods.
#[derive(Debug, Clone)]
pub struct DefaultConfigProvider<T: CryptographicAlgorithm> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T: CryptographicAlgorithm> DefaultConfigProvider<T> {
    /// Create new default config provider
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: CryptographicAlgorithm> Default for DefaultConfigProvider<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: CryptographicAlgorithm> ConfigProvider for DefaultConfigProvider<T> {
    type Algorithm = T;

    fn production_config(&self) -> Self::Algorithm {
        T::production_config()
    }

    fn test_config(&self) -> Self::Algorithm {
        T::test_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_algorithm_id_serialization() {
        assert_eq!(AlgorithmId::XChaCha20Poly1305.as_u16(), 1);
        assert_eq!(AlgorithmId::AesGcm256.as_u16(), 2);
        assert_eq!(AlgorithmId::from_u16(1).unwrap(), AlgorithmId::XChaCha20Poly1305);
        assert_eq!(AlgorithmId::from_u16(2).unwrap(), AlgorithmId::AesGcm256);
    }
}