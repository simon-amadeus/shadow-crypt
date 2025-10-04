//! # Deprecated: Cryptographic Configuration Traits
//!
//! This module has been replaced by crypto_service.rs to fix clean architecture violations.
//! All traits have been moved to crypto_service.rs for proper layer separation.

// Re-export everything from crypto_service for compatibility during transition
pub use super::crypto_service::*;
    fn generate_salt(&self) -> CryptoResult<Vec<u8>> {
        let mut salt = vec![0u8; self.salt_length()];
        getrandom::fill(&mut salt)
            .map_err(|_| DomainError::CryptographicError(
                crate::domain::errors::CryptographicError::RandomGenerationFailed
            ))?;
        Ok(salt)
    }
    
    /// Get configuration identifier for debugging and serialization
    fn config_name(&self) -> &'static str;
}

/// Configuration trait for symmetric encryption algorithm parameters
///
/// Abstracts encryption-specific parameters like nonce size, key size,
/// and algorithm identifiers for XChaCha20-Poly1305, AES-256-GCM, etc.
pub trait EncryptionConfig: Send + Sync + Clone + std::fmt::Debug {
    /// Get the key size required by this encryption algorithm (bytes)
    fn key_size(&self) -> usize;
    
    /// Get the nonce size required by this algorithm (bytes)
    fn nonce_size(&self) -> usize;
    
    /// Get the authentication tag size for AEAD algorithms (bytes)
    fn tag_size(&self) -> usize;
    
    /// Get numeric algorithm identifier for TLV header serialization
    fn algorithm_id(&self) -> u16;
    
    /// Get human-readable algorithm name for display/logging
    fn algorithm_name(&self) -> &'static str;
    
    /// Generate cryptographically secure nonce of appropriate length
    fn generate_nonce(&self) -> CryptoResult<Vec<u8>> {
        let mut nonce = vec![0u8; self.nonce_size()];
        getrandom::fill(&mut nonce)
            .map_err(|_| DomainError::CryptographicError(
                crate::domain::errors::CryptographicError::RandomGenerationFailed
            ))?;
        Ok(nonce)
    }
}

/// Combined cryptographic configuration for complete operations
///
/// This trait combines key derivation and encryption configuration
/// to provide a unified interface for cryptographic operations.
/// Implementations should provide both test and production parameter sets.
pub trait CryptoConfig: KeyDerivationConfig + EncryptionConfig {
    /// Create test configuration with fast parameters for development/testing
    /// 
    /// # Security Warning
    /// Test configurations use reduced work factors and should NEVER be used
    /// for production data encryption.
    fn test_config() -> Self where Self: Sized;
    
    /// Create production configuration with cryptographically secure parameters
    /// 
    /// Production configurations use industry-standard security parameters
    /// that provide resistance to current and near-future attacks.
    fn production_config() -> Self where Self: Sized;
    
    /// Validate configuration parameters meet minimum security requirements
    fn validate_security_parameters(&self) -> CryptoResult<()>;
}

/// Provider trait for dependency injection of crypto configurations
///
/// This trait enables clean dependency injection without coupling
/// domain services to specific configuration implementation types.
pub trait ConfigurationProvider {
    type Config: CryptoConfig;
    
    /// Get the current cryptographic configuration
    fn config(&self) -> &Self::Config;
    
    /// Get algorithm identifier for this provider's configuration
    fn algorithm_id(&self) -> u16 {
        self.config().algorithm_id()
    }
    
    /// Get algorithm name for this provider's configuration  
    fn algorithm_name(&self) -> &'static str {
        self.config().algorithm_name()
    }
}

/// Default configuration provider implementation
///
/// Generic provider that wraps any CryptoConfig implementation
/// for use in dependency injection scenarios.
#[derive(Debug, Clone)]
pub struct DefaultConfigProvider<T: CryptoConfig> {
    config: T,
}

impl<T: CryptoConfig> DefaultConfigProvider<T> {
    /// Create provider with custom configuration
    pub fn new(config: T) -> Self {
        Self { config }
    }
    
    /// Create provider with test configuration (fast parameters)
    /// 
    /// # Security Warning  
    /// Only use for development and testing. Never for production data.
    pub fn test() -> Self {
        Self::new(T::test_config())
    }
    
    /// Create provider with production configuration (secure parameters)
    pub fn production() -> Self {
        Self::new(T::production_config())
    }
}

impl<T: CryptoConfig> ConfigurationProvider for DefaultConfigProvider<T> {
    type Config = T;
    
    fn config(&self) -> &Self::Config {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock implementation for testing trait bounds
    #[derive(Debug, Clone)]
    struct MockCryptoConfig;

    impl KeyDerivationConfig for MockCryptoConfig {
        fn derive_key(&self, _password: &str, _salt: &[u8]) -> CryptoResult<KeyMaterial> {
            Ok(KeyMaterial::from_master_key([0u8; 32]))
        }
        
        fn salt_length(&self) -> usize { 16 }
        fn key_length(&self) -> usize { 32 }
        fn config_name(&self) -> &'static str { "mock-kdf" }
    }

    impl EncryptionConfig for MockCryptoConfig {
        fn key_size(&self) -> usize { 32 }
        fn nonce_size(&self) -> usize { 24 }
        fn tag_size(&self) -> usize { 16 }
        fn algorithm_id(&self) -> u16 { 999 }
        fn algorithm_name(&self) -> &'static str { "Mock-Cipher" }
    }

    impl CryptoConfig for MockCryptoConfig {
        fn test_config() -> Self { MockCryptoConfig }
        fn production_config() -> Self { MockCryptoConfig }
        fn validate_security_parameters(&self) -> CryptoResult<()> { Ok(()) }
    }

    #[test]
    fn test_provider_creation() {
        let provider = DefaultConfigProvider::<MockCryptoConfig>::test();
        assert_eq!(provider.algorithm_name(), "Mock-Cipher");
        assert_eq!(provider.algorithm_id(), 999);
    }

    #[test]
    fn test_salt_generation() {
        let config = MockCryptoConfig;
        let salt1 = config.generate_salt().unwrap();
        let salt2 = config.generate_salt().unwrap();
        
        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
        assert_ne!(salt1, salt2); // Should be cryptographically random
    }

    #[test]
    fn test_nonce_generation() {
        let config = MockCryptoConfig;
        let nonce1 = config.generate_nonce().unwrap();
        let nonce2 = config.generate_nonce().unwrap();
        
        assert_eq!(nonce1.len(), 24);
        assert_eq!(nonce2.len(), 24);
        assert_ne!(nonce1, nonce2); // Should be cryptographically random
    }
}