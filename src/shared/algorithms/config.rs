//! Configuration traits for cryptographic operations
//! 
//! This module provides abstractions for algorithm-agnostic configuration
//! of key derivation, encryption parameters, and cryptographic operations.

use crate::shared::core::errors::CryptoError;
use crate::shared::core::crypto::secure_memory::KeyMaterial;

/// Generic trait for key derivation function configuration
pub trait KeyDerivationConfig: Send + Sync + Clone {
    /// Derive key material from password and salt
    fn derive_key_material(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, CryptoError>;
    
    /// Get recommended salt length in bytes
    fn salt_length(&self) -> usize { 16 }
    
    /// Get configuration name for debugging/logging
    fn name(&self) -> &'static str;
}

/// Generic trait for encryption algorithm configuration  
pub trait EncryptionConfig: Send + Sync + Clone {
    /// Get the key size required by this algorithm
    fn key_size(&self) -> usize;
    
    /// Get the nonce size required by this algorithm
    fn nonce_size(&self) -> usize;
    
    /// Get algorithm identifier for header serialization
    fn algorithm_id(&self) -> u16;
    
    /// Get human-readable algorithm name
    fn algorithm_name(&self) -> &'static str;
}

/// Combined configuration for cryptographic operations
/// 
/// This trait combines key derivation and encryption configuration
/// to provide a complete configuration interface for crypto operations.
pub trait CryptoConfig: KeyDerivationConfig + EncryptionConfig {
    /// Create a test configuration with fast parameters
    fn test_config() -> Self;
    
    /// Create a production configuration with secure parameters
    fn production_config() -> Self;
}

/// Configuration provider trait for dependency injection
/// 
/// This trait allows functions to accept configuration without
/// being coupled to specific implementation types.
pub trait ConfigProvider {
    type Config: CryptoConfig;
    
    /// Get the current configuration
    fn config(&self) -> &Self::Config;
}

/// Default configuration provider implementation
pub struct DefaultConfigProvider<T: CryptoConfig> {
    config: T,
}

impl<T: CryptoConfig> DefaultConfigProvider<T> {
    pub fn new(config: T) -> Self {
        Self { config }
    }
    
    pub fn test() -> Self {
        Self::new(T::test_config())
    }
    
    pub fn production() -> Self {
        Self::new(T::production_config())
    }
}

impl<T: CryptoConfig> ConfigProvider for DefaultConfigProvider<T> {
    type Config = T;
    
    fn config(&self) -> &Self::Config {
        &self.config
    }
}