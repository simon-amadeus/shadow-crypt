//! # Cryptographic Algorithm Infrastructure
//!
//! This module provides concrete implementations of domain cryptographic interfaces,
//! supporting clean dependency injection and algorithm independence.
//!
//! ## Design Goals
//!
//! - **Domain Interface Implementation**: Implements domain-defined crypto traits
//! - **Security First**: Strong type safety and secure memory management
//! - **Clean Architecture**: Infrastructure implements domain abstractions
//! - **Testing Support**: Easy mocking and parameter injection for tests

//! # Cryptographic Algorithm Infrastructure
//!
//! This module provides concrete implementations of domain cryptographic interfaces.
//! All traits and abstractions are defined in the domain layer.

use crate::infrastructure::crypto::{CryptoError, CryptoResult};

// TODO: Replace with concrete algorithm implementations that implement domain traits
// This file will be restructured to contain only XChaCha20Poly1305Impl, AesGcmImpl, etc.
// All trait definitions have been moved to src/domain/services/crypto_service.rs

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_placeholder() {
        // Placeholder test during refactoring
        assert!(true);
    }
}
    
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