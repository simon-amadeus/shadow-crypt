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
    /// Create a new CryptoSession with derived key material
    /// 
    /// This method takes a password and salt, derives the necessary key material
    /// using secure key derivation, and creates a session ready for cryptographic operations.
    /// 
    /// # Arguments
    /// * `password` - The password to derive keys from
    /// * `salt` - Cryptographic salt for key derivation  
    /// * `algorithm` - The encryption algorithm to use
    /// 
    /// # Returns
    /// A new CryptoSession with securely derived key material
    pub fn new(password: &str, salt: [u8; 32], algorithm: AlgorithmId) -> DomainResult<Self> {
        // For now, use simple key derivation. This will be replaced with proper
        // PBKDF2 or Argon2 when the crypto infrastructure layer is implemented.
        let master_key = Self::derive_master_key(password, &salt)?;
        let key_material = KeyMaterial::from_master_key(master_key);
        
        Ok(Self {
            key_material,
            algorithm,
            salt,
        })
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
    
    /// Encrypt plaintext data using the configured algorithm
    /// 
    /// This method encrypts the provided plaintext using the session's
    /// configured algorithm and automatically manages nonce generation.
    /// 
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// 
    /// # Returns
    /// An EncryptionResult containing the ciphertext and nonce
    pub fn encrypt(&self, plaintext: &[u8]) -> DomainResult<crate::domain::services::EncryptionResult> {
        use crate::infrastructure::crypto::factory::Algorithm;
        use crate::domain::services::CryptographicAlgorithm;
        
        let algorithm = Algorithm::from_id(self.algorithm);
        algorithm.encrypt(plaintext, &self.key_material)
    }
    
    /// Decrypt ciphertext data using the configured algorithm
    /// 
    /// This method decrypts the provided ciphertext using the session's
    /// configured algorithm and the provided nonce.
    /// 
    /// # Arguments
    /// * `ciphertext` - The encrypted data to decrypt
    /// * `nonce` - The nonce used during encryption
    /// 
    /// # Returns
    /// The decrypted plaintext data
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> DomainResult<Vec<u8>> {
        use crate::infrastructure::crypto::factory::Algorithm;
        use crate::domain::services::CryptographicAlgorithm;
        
        let algorithm = Algorithm::from_id(self.algorithm);
        algorithm.decrypt(ciphertext, nonce, &self.key_material)
    }
    
    /// Secure key derivation using the configured algorithm
    /// 
    /// This method uses the algorithm's key derivation configuration to
    /// securely derive key material from the password and salt.
    fn derive_master_key(password: &str, salt: &[u8; 32]) -> DomainResult<[u8; 32]> {
        use crate::infrastructure::crypto::factory::Algorithm;
        use crate::domain::services::KeyDerivationConfig;
        
        // Use the default algorithm's key derivation configuration
        let algorithm = Algorithm::default();
        let key_material = algorithm.derive_key_material(password, salt)?;
        
        // Extract the raw master key
        Ok(*key_material.master_key.expose_secret())
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
    
    #[test]
    fn crypto_session_creation() {
        let password = "test_password_123";
        let salt = [0x42; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let session = CryptoSession::new(password, salt, algorithm).unwrap();
        
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
        
        let session1 = CryptoSession::new(password, salt, algorithm).unwrap();
        let session2 = CryptoSession::new(password, salt, algorithm).unwrap();
        
        // Same password + salt should produce same keys
        assert_eq!(session1.encryption_key(), session2.encryption_key());
        assert_eq!(session1.obfuscation_key(), session2.obfuscation_key());
    }
    
    #[test]
    fn different_passwords_produce_different_keys() {
        let salt = [0x44; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let session1 = CryptoSession::new("password1", salt, algorithm).unwrap();
        let session2 = CryptoSession::new("password2", salt, algorithm).unwrap();
        
        // Different passwords should produce different keys
        assert_ne!(session1.encryption_key(), session2.encryption_key());
        assert_ne!(session1.obfuscation_key(), session2.obfuscation_key());
    }
    
    #[test]
    fn different_salts_produce_different_keys() {
        let password = "same_password";
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let session1 = CryptoSession::new(password, [0x55; 32], algorithm).unwrap();
        let session2 = CryptoSession::new(password, [0x66; 32], algorithm).unwrap();
        
        // Different salts should produce different keys
        assert_ne!(session1.encryption_key(), session2.encryption_key());
        assert_ne!(session1.obfuscation_key(), session2.obfuscation_key());
    }
    
    #[test]
    fn debug_does_not_leak_secrets() {
        let password = "secret_password";
        let salt = [0x77; 32];
        let algorithm = AlgorithmId::XChaCha20Poly1305;
        
        let session = CryptoSession::new(password, salt, algorithm).unwrap();
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
        
        let session = CryptoSession::new(password, salt, algorithm).unwrap();
        
        assert_eq!(session.algorithm(), algorithm);
        assert_eq!(session.salt(), &salt);
        assert_eq!(session.encryption_key().len(), 32);
        assert_eq!(session.obfuscation_key().len(), 32);
    }
}