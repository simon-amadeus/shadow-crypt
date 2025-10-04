//! # Crypto Configuration Integration Tests
//!
//! Integration tests demonstrating the configuration provider pattern
//! with end-to-end usage scenarios for XChaCha20-Poly1305.

use shadow_crypt::domain::services::crypto_config::{
    KeyDerivationConfig, EncryptionConfig, CryptoConfig, ConfigurationProvider
};
use shadow_crypt::infrastructure::crypto::providers::XChaCha20Provider;

#[test]
fn test_xchacha20_provider_integration() {
    // Create production provider with secure parameters
    let provider = XChaCha20Provider::production()
        .expect("Failed to create production provider");
    
    // Verify algorithm identification
    assert_eq!(provider.algorithm_name(), "XChaCha20-Poly1305");
    assert_eq!(provider.algorithm_id(), 0x0001);
    
    // Test configuration interface
    let config = provider.config();
    assert_eq!(config.algorithm_name(), "XChaCha20-Poly1305");
    assert_eq!(config.key_size(), 32);
    assert_eq!(config.nonce_size(), 24);
    assert_eq!(config.tag_size(), 16);
    assert_eq!(config.salt_length(), 16);
    assert_eq!(config.key_length(), 32);
}

#[test]
fn test_key_derivation_workflow() {
    // Use test provider for faster execution
    let provider = XChaCha20Provider::test()
        .expect("Failed to create test provider");
    
    let config = provider.config();
    
    // Generate salt and derive key
    let salt = config.generate_salt()
        .expect("Failed to generate salt");
    
    let key = config.derive_key("test_password", &salt)
        .expect("Failed to derive key");
    
    // Verify outputs
    assert_eq!(salt.len(), 16);
    assert_eq!(key.len(), 32);
    
    // Same password + salt should produce same key
    let key2 = config.derive_key("test_password", &salt)
        .expect("Failed to derive key again");
    assert_eq!(key, key2);
    
    // Different password should produce different key
    let key3 = config.derive_key("different_password", &salt)
        .expect("Failed to derive key with different password");
    assert_ne!(key, key3);
}

#[test]
fn test_nonce_generation_workflow() {
    let provider = XChaCha20Provider::test()
        .expect("Failed to create test provider");
    
    let config = provider.config();
    
    // Generate multiple nonces
    let nonce1 = config.generate_nonce()
        .expect("Failed to generate first nonce");
    let nonce2 = config.generate_nonce()
        .expect("Failed to generate second nonce");
    
    // Verify proper length and uniqueness
    assert_eq!(nonce1.len(), 24);
    assert_eq!(nonce2.len(), 24);
    assert_ne!(nonce1, nonce2); // Should be cryptographically unique
}

#[test]
fn test_security_parameter_validation() {
    // Test that production config meets security requirements
    let provider = XChaCha20Provider::production()
        .expect("Production config should be valid");
    
    assert!(provider.config().validate_security_parameters().is_ok());
    
    // Test that test config also meets minimum requirements
    let test_provider = XChaCha20Provider::test()
        .expect("Test config should be valid");
    
    assert!(test_provider.config().validate_security_parameters().is_ok());
}

#[test]
fn test_provider_factory_pattern() {
    // Demonstrate dependency injection usage pattern
    fn use_crypto_provider<P: ConfigurationProvider>(provider: &P) -> (String, u16) {
        (provider.algorithm_name().to_string(), provider.algorithm_id())
    }
    
    let provider = XChaCha20Provider::production()
        .expect("Failed to create provider");
    
    let (name, id) = use_crypto_provider(&provider);
    assert_eq!(name, "XChaCha20-Poly1305");
    assert_eq!(id, 0x0001);
}

#[test]
fn test_configuration_reproducibility() {
    // Test that configuration parameters are consistent
    let provider1 = XChaCha20Provider::production()
        .expect("Failed to create first provider");
    let provider2 = XChaCha20Provider::production()
        .expect("Failed to create second provider");
    
    // Both providers should have identical configurations
    assert_eq!(provider1.algorithm_id(), provider2.algorithm_id());
    assert_eq!(provider1.algorithm_name(), provider2.algorithm_name());
    assert_eq!(provider1.config().key_size(), provider2.config().key_size());
    assert_eq!(provider1.config().nonce_size(), provider2.config().nonce_size());
}

#[test]
fn test_polymorphic_configuration_usage() {
    // Demonstrate generic usage for algorithm-agnostic code
    let provider = XChaCha20Provider::test()
        .expect("Failed to create provider");
    
    // Function that works with any CryptoConfig implementation
    fn derive_session_key<T: CryptoConfig>(config: &T, password: &str) -> Vec<u8> {
        let salt = config.generate_salt().expect("Salt generation failed");
        config.derive_key(password, &salt).expect("Key derivation failed")
    }
    
    let key = derive_session_key(provider.config(), "session_password");
    assert_eq!(key.len(), 32);
}