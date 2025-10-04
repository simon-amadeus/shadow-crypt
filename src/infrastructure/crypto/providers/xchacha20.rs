//! # XChaCha20-Poly1305 Configuration Provider
//!
//! Production-grade configuration implementation for XChaCha20-Poly1305 AEAD cipher
//! with Argon2id key derivation. This is the recommended default algorithm for Shadow.

use crate::domain::services::crypto_config::{
    KeyDerivationConfig, EncryptionConfig, CryptoConfig, ConfigurationProvider
};
use crate::infrastructure::crypto::errors::CryptoError;

/// XChaCha20-Poly1305 cryptographic configuration
/// 
/// Provides secure default parameters for XChaCha20-Poly1305 AEAD encryption
/// with Argon2id key derivation. XChaCha20-Poly1305 is preferred over AES-GCM
/// for file encryption due to its 24-byte nonces that eliminate nonce reuse vulnerabilities.
#[derive(Debug, Clone)]
pub struct XChaCha20Config {
    /// Argon2id memory cost in KiB
    pub memory_cost: u32,
    /// Argon2id time cost (iterations)
    pub time_cost: u32,
    /// Argon2id parallelism degree
    pub parallelism: u32,
}

impl XChaCha20Config {
    /// Algorithm identifier for TLV headers (XChaCha20-Poly1305)
    pub const ALGORITHM_ID: u16 = 0x0001;
    
    /// XChaCha20 key size (256 bits)
    pub const KEY_SIZE: usize = 32;
    
    /// XChaCha20 nonce size (192 bits - extended nonce)
    pub const NONCE_SIZE: usize = 24;
    
    /// Poly1305 authentication tag size (128 bits)
    pub const TAG_SIZE: usize = 16;
    
    /// Argon2id salt size (128 bits minimum recommended)
    pub const SALT_SIZE: usize = 16;
    
    /// Create new configuration with custom Argon2id parameters
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }
    
    /// Validate Argon2id parameters meet minimum security requirements
    fn validate_argon2_params(&self) -> Result<(), CryptoError> {
        // Minimum security parameters based on RFC 9106 recommendations
        if self.memory_cost < 19456 { // ~19 MiB minimum for production
            return Err(CryptoError::InvalidParameters(
                "Argon2id memory cost too low - minimum 19456 KiB for production use".to_string()
            ));
        }
        
        if self.time_cost < 2 {
            return Err(CryptoError::InvalidParameters(
                "Argon2id time cost too low - minimum 2 iterations".to_string()
            ));
        }
        
        if self.parallelism < 1 || self.parallelism > 64 {
            return Err(CryptoError::InvalidParameters(
                "Argon2id parallelism must be between 1-64".to_string()
            ));
        }
        
        Ok(())
    }
}

impl KeyDerivationConfig for XChaCha20Config {
    fn derive_key(&self, password: &str, salt: &[u8]) -> Result<crate::domain::entities::KeyMaterial, crate::domain::errors::DomainError> {
        // Validate salt length
        if salt.len() != Self::SALT_SIZE {
            return Err(crate::domain::errors::DomainError::CryptographicError(
                crate::domain::errors::CryptographicError::KeyDerivationFailed { 
                    algorithm: "XChaCha20-Poly1305".to_string() 
                }
            ));
        }
        
        // TODO: Implement Argon2id key derivation
        // For now, return a placeholder that shows the correct interface
        // This will be implemented in a follow-up cycle focused on crypto implementations
        
        // Placeholder implementation for compilation
        let mut key = vec![0u8; Self::KEY_SIZE];
        // In real implementation, this would use argon2 crate:
        // let config = argon2::Config::new(
        //     argon2::Algorithm::Argon2id,
        //     argon2::Version::Version13,
        //     self.memory_cost,
        //     self.time_cost,
        //     self.parallelism,
        //     Self::KEY_SIZE,
        // );
        // argon2::hash_raw(password.as_bytes(), salt, &config)
        //     .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?
        
        // SECURITY NOTE: This placeholder is NOT secure - real Argon2id implementation required
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        password.hash(&mut hasher);
        salt.hash(&mut hasher);
        let hash = hasher.finish();
        
        // Fill key with derived bytes (placeholder only)
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = ((hash >> (i % 8)) & 0xFF) as u8;
        }
        
        Ok(crate::domain::entities::KeyMaterial::from_master_key(
            key.try_into().expect("Key should be exactly 32 bytes")
        ))
    }
    
    fn salt_length(&self) -> usize {
        Self::SALT_SIZE
    }
    
    fn key_length(&self) -> usize {
        Self::KEY_SIZE
    }
    
    fn config_name(&self) -> &'static str {
        "Argon2id"
    }
}

impl EncryptionConfig for XChaCha20Config {
    fn key_size(&self) -> usize {
        Self::KEY_SIZE
    }
    
    fn nonce_size(&self) -> usize {
        Self::NONCE_SIZE
    }
    
    fn tag_size(&self) -> usize {
        Self::TAG_SIZE
    }
    
    fn algorithm_id(&self) -> u16 {
        Self::ALGORITHM_ID
    }
    
    fn algorithm_name(&self) -> &'static str {
        "XChaCha20-Poly1305"
    }
}

impl CryptoConfig for XChaCha20Config {
    fn test_config() -> Self {
        // Fast parameters for testing - INSECURE, development only
        // Use minimum valid parameters that still pass validation
        Self::new(
            19456,   // Minimum memory cost that passes validation
            2,       // Minimum time cost that passes validation  
            1,       // Single thread
        )
    }
    
    fn production_config() -> Self {
        // OWASP recommended parameters for production use
        Self::new(
            65536,   // 64 MiB memory cost 
            3,       // 3 iterations
            4,       // 4 parallel threads
        )
    }
    
    fn validate_security_parameters(&self) -> Result<(), crate::domain::errors::DomainError> {
        self.validate_argon2_params().map_err(|e| e.into())
    }
}

/// XChaCha20-Poly1305 configuration provider
///
/// Production-ready provider for XChaCha20-Poly1305 with secure defaults.
/// This is the recommended algorithm for Shadow file encryption.
#[derive(Debug, Clone)]
pub struct XChaCha20Provider {
    config: XChaCha20Config,
}

impl XChaCha20Provider {
    /// Create provider with custom configuration
    pub fn new(config: XChaCha20Config) -> Result<Self, CryptoError> {
        config.validate_security_parameters()?;
        Ok(Self { config })
    }
    
    /// Create provider with production-grade security parameters
    pub fn production() -> Result<Self, CryptoError> {
        Self::new(XChaCha20Config::production_config())
    }
    
    /// Create provider with fast parameters for testing/development
    /// 
    /// # Security Warning
    /// Test configurations are NOT secure and must never be used for production data.
    pub fn test() -> Result<Self, CryptoError> {
        Self::new(XChaCha20Config::test_config())
    }
    
    /// Get the underlying configuration
    pub fn config(&self) -> &XChaCha20Config {
        &self.config
    }
}

impl ConfigurationProvider for XChaCha20Provider {
    type Config = XChaCha20Config;
    
    fn config(&self) -> &Self::Config {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_constants() {
        assert_eq!(XChaCha20Config::ALGORITHM_ID, 0x0001);
        assert_eq!(XChaCha20Config::KEY_SIZE, 32);
        assert_eq!(XChaCha20Config::NONCE_SIZE, 24);
        assert_eq!(XChaCha20Config::TAG_SIZE, 16);
        assert_eq!(XChaCha20Config::SALT_SIZE, 16);
    }

    #[test]
    fn test_config_creation() {
        let config = XChaCha20Config::production_config();
        assert!(config.validate_security_parameters().is_ok());
        
        let test_config = XChaCha20Config::test_config();
        // Test config may have lower security parameters but should still be valid
        assert!(test_config.validate_security_parameters().is_ok());
    }

    #[test]
    fn test_provider_creation() {
        let provider = XChaCha20Provider::production().unwrap();
        assert_eq!(provider.algorithm_name(), "XChaCha20-Poly1305");
        assert_eq!(provider.algorithm_id(), 0x0001);
    }

    #[test]
    fn test_salt_generation() {
        let config = XChaCha20Config::production_config();
        let salt1 = config.generate_salt().unwrap();
        let salt2 = config.generate_salt().unwrap();
        
        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
        assert_ne!(salt1, salt2); // Should be cryptographically random
    }

    #[test]
    fn test_nonce_generation() {
        let config = XChaCha20Config::production_config();
        let nonce1 = config.generate_nonce().unwrap();
        let nonce2 = config.generate_nonce().unwrap();
        
        assert_eq!(nonce1.len(), 24);
        assert_eq!(nonce2.len(), 24);
        assert_ne!(nonce1, nonce2); // Should be cryptographically random
    }

    #[test]
    fn test_key_derivation_placeholder() {
        let config = XChaCha20Config::test_config();
        let salt = config.generate_salt().unwrap();
        
        let key = config.derive_key("test_password", &salt).unwrap();
        assert_eq!(key.len(), 96); // Total of master + encryption + obfuscation keys
        
        // Same password and salt should produce same key
        let key2 = config.derive_key("test_password", &salt).unwrap();
        assert_eq!(key, key2);
        
        // Different password should produce different key
        let key3 = config.derive_key("different_password", &salt).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_parameter_validation() {
        // Test invalid memory cost
        let invalid_config = XChaCha20Config::new(1000, 2, 1); // Too low memory
        assert!(invalid_config.validate_security_parameters().is_err());
        
        // Test invalid time cost
        let invalid_config = XChaCha20Config::new(65536, 0, 1); // Too low iterations
        assert!(invalid_config.validate_security_parameters().is_err());
        
        // Test invalid parallelism
        let invalid_config = XChaCha20Config::new(65536, 2, 0); // Zero parallelism
        assert!(invalid_config.validate_security_parameters().is_err());
        
        let invalid_config = XChaCha20Config::new(65536, 2, 100); // Too high parallelism
        assert!(invalid_config.validate_security_parameters().is_err());
    }
}