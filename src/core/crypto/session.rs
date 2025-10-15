//! Cryptographic session management - migrated and simplified from domain/shared.

use super::types::{AlgorithmId, KeyMaterial};

/// Cryptographic session state container.
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
}