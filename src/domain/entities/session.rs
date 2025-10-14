//! # CryptoSession Entity
//!
//! Manages cryptographic state and key material for operations.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use super::algorithm::AlgorithmId;
use super::key::KeyMaterial;
use crate::domain::errors::DomainResult;

/// Manages cryptographic state and key material for operations
/// 
/// CryptoSession provides a secure container for cryptographic operations
/// that automatically manages key material lifecycle and algorithm configuration.
/// All sensitive data is automatically zeroized when the session is dropped.
#[derive(Debug)]
pub struct CryptoSession {
    key_material: KeyMaterial,
    algorithm: AlgorithmId,
    salt: [u8; 32],
}

impl CryptoSession {
    /// Create a new CryptoSession with pre-derived key material
    /// 
    /// This method accepts already-derived key material from a domain service.
    /// The entity itself should not perform cryptographic operations.
    /// 
    /// # Arguments
    /// * `key_material` - Pre-derived key material from a key derivation service
    /// * `salt` - The salt used for key derivation (for storage/serialization)
    /// * `algorithm` - The encryption algorithm to use
    /// 
    /// # Returns
    /// A new CryptoSession with the provided key material
    pub fn new(key_material: KeyMaterial, salt: [u8; 32], algorithm: AlgorithmId) -> Self {
        Self {
            key_material,
            algorithm,
            salt,
        }
    }
    
    /// Get the algorithm used by this session
    pub fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }
    
    /// Get the salt used for key derivation
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }
    
    /// Get reference to the encryption key
    /// 
    /// This exposes the encryption key for use by crypto implementations.
    /// Handle with care as this provides access to sensitive cryptographic material.
    pub fn encryption_key(&self) -> &[u8; 32] {
        self.key_material.encryption_key.expose_secret()
    }
    
    /// Get reference to the obfuscation key  
    /// 
    /// This exposes the obfuscation key for filename obfuscation operations.
    /// Handle with care as this provides access to sensitive cryptographic material.
    pub fn obfuscation_key(&self) -> &[u8; 32] {
        self.key_material.obfuscation_key.expose_secret()
    }
    
    /// Get reference to the key material
    /// 
    /// This exposes the complete key material for use by crypto services.
    /// Handle with care as this provides access to sensitive cryptographic material.
    /// 
    /// # Security Note
    /// This method should only be called by domain services that perform 
    /// cryptographic operations. The entity itself should not contain business logic.
    pub fn key_material(&self) -> &KeyMaterial {
        &self.key_material
    }
    
    /// Generate a cryptographically secure salt for key derivation
    /// 
    /// This method generates a random salt suitable for key derivation functions.
    /// The salt should be stored alongside the encrypted data for decryption.
    pub fn generate_salt() -> DomainResult<[u8; 32]> {
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt)
            .map_err(|_| crate::domain::errors::DomainError::CryptographicError(
                crate::domain::errors::CryptographicError::RandomGenerationFailed
            ))?;
        
        Ok(salt)
    }
}

impl Drop for CryptoSession {
    /// Automatic key material zeroization
    /// 
    /// When the CryptoSession is dropped, all sensitive cryptographic material
    /// is automatically zeroized through the KeyMaterial's Drop implementation.
    fn drop(&mut self) {
        // KeyMaterial handles its own secure cleanup via SecureBox
        // Additional session-specific cleanup can be added here if needed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Helper function for tests to create a simple master key from password
    // This is just for testing - real key derivation should use Argon2 in domain services
    fn create_test_master_key(password: &str, salt: &[u8; 32]) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let hash = hasher.finalize();
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash[..32]);
        key
    }
    
    #[test]
    fn crypto_session_creation() {
        let password = "test_password_123";
        let salt = [0x42; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let master_key = create_test_master_key(password, &salt);
        let key_material = KeyMaterial::from_master_key(master_key);
        let session = CryptoSession::new(key_material, salt, algorithm);
        
        assert_eq!(session.algorithm(), algorithm);
        assert_eq!(session.salt(), &salt);
        
        // Keys should be derived and accessible
        assert_eq!(session.encryption_key().len(), 32);
        assert_eq!(session.obfuscation_key().len(), 32);
        
        // Keys should be different from each other
        assert_ne!(session.encryption_key(), session.obfuscation_key());
    }
    
    #[test]
    fn algorithm_id_properties() {
        let xchacha = AlgorithmId::XChaCha20Poly1305;
        assert_eq!(xchacha.name(), "XChaCha20-Poly1305");
        assert_eq!(xchacha.key_size(), 32);
        assert_eq!(xchacha.nonce_size(), 24);
        
        let aes = AlgorithmId::AesGcm256;
        assert_eq!(aes.name(), "AES-256-GCM");
        assert_eq!(aes.key_size(), 32);
        assert_eq!(aes.nonce_size(), 12);
    }
    
    #[test]
    fn key_derivation_is_deterministic() {
        let password = "consistent_password";
        let salt = [0x33; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let master_key1 = create_test_master_key(password, &salt);
        let master_key2 = create_test_master_key(password, &salt);
        let key_material1 = KeyMaterial::from_master_key(master_key1);
        let key_material2 = KeyMaterial::from_master_key(master_key2);
        let session1 = CryptoSession::new(key_material1, salt, algorithm);
        let session2 = CryptoSession::new(key_material2, salt, algorithm);
        
        // Same password + salt should produce same keys
        assert_eq!(session1.encryption_key(), session2.encryption_key());
        assert_eq!(session1.obfuscation_key(), session2.obfuscation_key());
    }
    
    #[test]
    fn different_passwords_produce_different_keys() {
        let salt = [0x44; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let master_key1 = create_test_master_key("password1", &salt);
        let master_key2 = create_test_master_key("password2", &salt);
        let key_material1 = KeyMaterial::from_master_key(master_key1);
        let key_material2 = KeyMaterial::from_master_key(master_key2);
        let session1 = CryptoSession::new(key_material1, salt, algorithm);
        let session2 = CryptoSession::new(key_material2, salt, algorithm);
        
        // Different passwords should produce different keys
        assert_ne!(session1.encryption_key(), session2.encryption_key());
        assert_ne!(session1.obfuscation_key(), session2.obfuscation_key());
    }
    
    #[test]
    fn different_salts_produce_different_keys() {
        let password = "same_password";
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let salt1 = [0x55; 32];
        let salt2 = [0x66; 32];
        let master_key1 = create_test_master_key(password, &salt1);
        let master_key2 = create_test_master_key(password, &salt2);
        let key_material1 = KeyMaterial::from_master_key(master_key1);
        let key_material2 = KeyMaterial::from_master_key(master_key2);
        let session1 = CryptoSession::new(key_material1, salt1, algorithm);
        let session2 = CryptoSession::new(key_material2, salt2, algorithm);
        
        // Different salts should produce different keys
        assert_ne!(session1.encryption_key(), session2.encryption_key());
        assert_ne!(session1.obfuscation_key(), session2.obfuscation_key());
    }
    
    #[test]
    fn debug_does_not_leak_secrets() {
        let password = "secret_password";
        let salt = [0x77; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let master_key = create_test_master_key(password, &salt);
        let key_material = KeyMaterial::from_master_key(master_key);
        let session = CryptoSession::new(key_material, salt, algorithm);
        let debug_output = format!("{:?}", session);
        
        // Debug output should not contain the password
        assert!(!debug_output.contains("secret_password"));
        
        // Should contain algorithm information
        assert!(debug_output.contains("CryptoSession"));
        
        // KeyMaterial debug should be redacted (tested in secure_memory tests)
        assert!(debug_output.contains("[REDACTED]"));
    }
    
    #[test]
    fn salt_generation_produces_unique_values() {
        // Generate multiple salts and verify they are different
        let salt1 = CryptoSession::generate_salt().unwrap();
        let salt2 = CryptoSession::generate_salt().unwrap();
        let salt3 = CryptoSession::generate_salt().unwrap();
        
        // All salts should be 32 bytes
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_eq!(salt3.len(), 32);
        
        // All salts should be different (cryptographically extremely unlikely to be same)
        assert_ne!(salt1, salt2);
        assert_ne!(salt2, salt3);
        assert_ne!(salt1, salt3);
        
        // Salts should not be all zeros
        assert_ne!(salt1, [0u8; 32]);
        assert_ne!(salt2, [0u8; 32]);
        assert_ne!(salt3, [0u8; 32]);
    }
    
    #[test]
    fn crypto_session_with_generated_salt() {
        let password = "test_password";
        let salt = CryptoSession::generate_salt().unwrap();
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let master_key = create_test_master_key(password, &salt);
        let key_material = KeyMaterial::from_master_key(master_key);
        let session = CryptoSession::new(key_material, salt, algorithm);
        
        assert_eq!(session.algorithm(), algorithm);
        assert_eq!(session.salt(), &salt);
        assert_eq!(session.encryption_key().len(), 32);
        assert_eq!(session.obfuscation_key().len(), 32);
    }
}