//! AES-GCM configuration implementation
//! 
//! This module provides concrete implementations of the configuration
//! traits for AES-256-GCM with Argon2id key derivation.

use super::config::{KeyDerivationConfig, EncryptionConfig, CryptoConfig};
use super::aes_gcm::key_derivation::{derive_master_key, Argon2Params};
use crate::shared::core::errors::CryptoError;
use crate::shared::core::crypto::secure_memory::KeyMaterial;

/// AES-256-GCM configuration with Argon2id key derivation
#[derive(Debug, Clone)]
pub struct AesGcmConfig {
    argon2_params: Argon2Params,
}

impl AesGcmConfig {
    /// Create new AES-GCM configuration with custom Argon2 parameters
    pub fn new(argon2_params: Argon2Params) -> Self {
        Self { argon2_params }
    }
    
    /// Create configuration with custom parameters
    pub fn with_params(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self::new(Argon2Params::custom(memory_cost, time_cost, parallelism))
    }
    
    /// Get the underlying Argon2 parameters (for migration compatibility)
    pub fn argon2_params(&self) -> &Argon2Params {
        &self.argon2_params
    }
}

impl KeyDerivationConfig for AesGcmConfig {
    fn derive_key_material(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, CryptoError> {
        derive_master_key(password, salt, &self.argon2_params)
    }
    
    fn salt_length(&self) -> usize {
        16 // AES-GCM uses 16-byte salts
    }
    
    fn name(&self) -> &'static str {
        "Argon2id-AES-GCM"
    }
}

impl EncryptionConfig for AesGcmConfig {
    fn key_size(&self) -> usize {
        32 // AES-256 uses 32-byte keys
    }
    
    fn nonce_size(&self) -> usize {
        12 // AES-GCM uses 12-byte nonces
    }
    
    fn algorithm_id(&self) -> u16 {
        1 // V1/V2 AES-GCM algorithm ID
    }
    
    fn algorithm_name(&self) -> &'static str {
        "AES-256-GCM"
    }
}

impl CryptoConfig for AesGcmConfig {
    fn test_config() -> Self {
        Self::new(Argon2Params::test_params())
    }
    
    fn production_config() -> Self {
        Self::new(Argon2Params::production_params())
    }
}

// Backward compatibility: allow conversion from Argon2Params
impl From<Argon2Params> for AesGcmConfig {
    fn from(params: Argon2Params) -> Self {
        Self::new(params)
    }
}

// Backward compatibility: allow conversion to Argon2Params
impl From<&AesGcmConfig> for Argon2Params {
    fn from(config: &AesGcmConfig) -> Self {
        config.argon2_params.clone()
    }
}