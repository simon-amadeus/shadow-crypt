//! Cryptographic session entity.
//!
//! Manages cryptographic session state with key material,
//! algorithm configuration, and secure cleanup.

use super::algorithm::AlgorithmId;
use super::key::KeyMaterial;
use crate::domain::errors::DomainResult;

/// Cryptographic session state container.
/// 
/// Holds key material, algorithm configuration, and salt for operations.
/// Sensitive data is automatically zeroized when dropped.
#[derive(Debug)]
pub struct CryptoSession {
    key_material: KeyMaterial,
    algorithm: AlgorithmId,
    salt: [u8; 32],
}

impl CryptoSession {
    /// Create new session with pre-derived key material.
    pub fn new(key_material: KeyMaterial, salt: [u8; 32], algorithm: AlgorithmId) -> Self {
        Self {
            key_material,
            algorithm,
            salt,
        }
    }
    
    /// Get the configured algorithm.
    pub fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }
    
    /// Get the key derivation salt.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }
    
    /// Get the encryption key.
    pub fn encryption_key(&self) -> &[u8; 32] {
        self.key_material.encryption_key.expose_secret()
    }
    
    /// Get the obfuscation key.  
    pub fn obfuscation_key(&self) -> &[u8; 32] {
        self.key_material.obfuscation_key.expose_secret()
    }
    
    /// Get the complete key material.
    pub fn key_material(&self) -> &KeyMaterial {
        &self.key_material
    }
    
    /// Generate a cryptographically secure salt.
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
    fn drop(&mut self) {
        // KeyMaterial handles secure cleanup automatically
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Test key derivation helper
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
    fn creates_session_with_key_material() {
        let password = "test_password_123";
        let salt = [0x42; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let master_key = create_test_master_key(password, &salt);
        let key_material = KeyMaterial::from_master_key(master_key);
        let session = CryptoSession::new(key_material, salt, algorithm);
        
        assert_eq!(session.algorithm(), algorithm);
        assert_eq!(session.salt(), &salt);
        assert_eq!(session.encryption_key().len(), 32);
        assert_eq!(session.obfuscation_key().len(), 32);
        assert_ne!(session.encryption_key(), session.obfuscation_key());
    }
    
    #[test]
    fn algorithm_properties() {
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
    fn deterministic_key_derivation() {
        let password = "consistent_password";
        let salt = [0x33; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let master_key1 = create_test_master_key(password, &salt);
        let master_key2 = create_test_master_key(password, &salt);
        let key_material1 = KeyMaterial::from_master_key(master_key1);
        let key_material2 = KeyMaterial::from_master_key(master_key2);
        let session1 = CryptoSession::new(key_material1, salt, algorithm);
        let session2 = CryptoSession::new(key_material2, salt, algorithm);
        
        assert_eq!(session1.encryption_key(), session2.encryption_key());
        assert_eq!(session1.obfuscation_key(), session2.obfuscation_key());
    }
    
    #[test]
    fn different_passwords_different_keys() {
        let salt = [0x44; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let master_key1 = create_test_master_key("password1", &salt);
        let master_key2 = create_test_master_key("password2", &salt);
        let key_material1 = KeyMaterial::from_master_key(master_key1);
        let key_material2 = KeyMaterial::from_master_key(master_key2);
        let session1 = CryptoSession::new(key_material1, salt, algorithm);
        let session2 = CryptoSession::new(key_material2, salt, algorithm);
        
        assert_ne!(session1.encryption_key(), session2.encryption_key());
        assert_ne!(session1.obfuscation_key(), session2.obfuscation_key());
    }
    
    #[test]
    fn different_salts_different_keys() {
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
        
        assert_ne!(session1.encryption_key(), session2.encryption_key());
        assert_ne!(session1.obfuscation_key(), session2.obfuscation_key());
    }
    
    #[test]
    fn debug_output_security() {
        let password = "secret_password";
        let salt = [0x77; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let master_key = create_test_master_key(password, &salt);
        let key_material = KeyMaterial::from_master_key(master_key);
        let session = CryptoSession::new(key_material, salt, algorithm);
        let debug_output = format!("{:?}", session);
        
        assert!(!debug_output.contains("secret_password"));
        assert!(debug_output.contains("CryptoSession"));
        assert!(debug_output.contains("[REDACTED]"));
    }
    
    #[test]
    fn salt_generation() {
        let salt1 = CryptoSession::generate_salt().unwrap();
        let salt2 = CryptoSession::generate_salt().unwrap();
        let salt3 = CryptoSession::generate_salt().unwrap();
        
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_eq!(salt3.len(), 32);
        
        assert_ne!(salt1, salt2);
        assert_ne!(salt2, salt3);
        assert_ne!(salt1, salt3);
        
        assert_ne!(salt1, [0u8; 32]);
        assert_ne!(salt2, [0u8; 32]);
        assert_ne!(salt3, [0u8; 32]);
    }
    
    #[test]
    fn session_with_generated_salt() {
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