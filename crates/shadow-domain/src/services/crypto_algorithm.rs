//! # Domain Cryptographic Service Traits
//!
//! This module defines the core cryptographic abstractions that represent business capabilities.
//! These traits define what the domain needs from cryptographic operations without coupling
//! to specific implementations or infrastructure concerns.

use crate::entities::{AlgorithmId, KeyMaterial};
use crate::errors::DomainError;

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, DomainError>;

/// Encryption operation result containing ciphertext and nonce
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Core cryptographic algorithm abstraction
/// 
/// Represents the domain's requirements for cryptographic operations.
/// Implementations should provide authenticated encryption with secure defaults.
pub trait CryptographicAlgorithm: Send + Sync {
    /// Get the algorithm identifier
    fn algorithm_id(&self) -> AlgorithmId;

    /// Encrypt plaintext with authenticated encryption
    /// 
    /// # Parameters
    /// - `plaintext`: Data to encrypt
    /// - `key_material`: Derived key material for encryption
    /// - `associated_data`: Additional authenticated data (not encrypted)
    /// 
    /// # Returns
    /// - `EncryptionResult` containing ciphertext and nonce
    /// 
    /// # Security Requirements
    /// - Must use cryptographically secure random nonce generation
    /// - Must provide authenticated encryption (confidentiality + integrity)
    /// - Must not reuse nonces with the same key
    fn encrypt(
        &self,
        plaintext: &[u8],
        key_material: &KeyMaterial,
        associated_data: &[u8],
    ) -> CryptoResult<EncryptionResult>;

    /// Decrypt ciphertext with authentication verification
    /// 
    /// # Parameters
    /// - `ciphertext`: Encrypted data to decrypt
    /// - `nonce`: Nonce used during encryption
    /// - `key_material`: Derived key material for decryption
    /// - `associated_data`: Additional authenticated data used during encryption
    /// 
    /// # Returns
    /// - Decrypted plaintext bytes
    /// 
    /// # Security Requirements
    /// - Must verify authentication tag before returning plaintext
    /// - Must fail securely on authentication failure
    /// - Must not leak timing information about decryption failures
    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_material: &KeyMaterial,
        associated_data: &[u8],
    ) -> CryptoResult<Vec<u8>>;
}

/// Key derivation function configuration
/// 
/// Abstracts password-based key derivation with secure parameter choices.
/// Implementations should resist brute force attacks with appropriate work factors.
pub trait KeyDerivationConfig: Send + Sync + Clone + std::fmt::Debug {
    /// Derive cryptographic key material from password and salt
    /// 
    /// # Parameters
    /// - `password`: User-provided password
    /// - `salt`: Cryptographically secure random salt
    /// - `key_length`: Required key length in bytes
    /// 
    /// # Returns
    /// - Derived key material suitable for cryptographic operations
    /// 
    /// # Security Requirements
    /// - Must use sufficient work factor to resist brute force attacks
    /// - Must not leak timing information about password length or content
    /// - Must derive exactly `key_length` bytes
    fn derive_key(&self, password: &str, salt: &[u8], key_length: usize) -> CryptoResult<KeyMaterial>;
    
    /// Get the recommended salt size for this KDF
    fn salt_size(&self) -> usize;
    
    /// Get configuration parameters for header serialization
    fn config_params(&self) -> Vec<u8>;
}

/// Encryption algorithm configuration
/// 
/// Provides algorithm-specific parameters and validation logic.
/// Implementations should enforce secure defaults and parameter validation.
pub trait EncryptionConfig: Send + Sync + Clone + std::fmt::Debug {
    /// Validate configuration parameters for security
    /// 
    /// # Returns
    /// - `Ok(())` if configuration is secure
    /// - `Err(DomainError)` if configuration has security issues
    fn validate_security(&self) -> CryptoResult<()>;
    
    /// Get configuration parameters for header serialization
    fn config_params(&self) -> Vec<u8>;
}