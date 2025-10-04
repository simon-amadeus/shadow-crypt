//! XChaCha20-Poly1305 configuration implementation
//! 
//! This module provides concrete implementations of the configuration
//! traits for XChaCha20-Poly1305 with Argon2id key derivation.

use super::config::{KeyDerivationConfig, EncryptionConfig, CryptoConfig};
use super::xchacha20_poly1305::key_derivation::{derive_master_key, Argon2Params};
use crate::shared::core::errors::CryptoError;
use crate::shared::core::crypto::secure_memory::KeyMaterial;

/// XChaCha20-Poly1305 configuration with Argon2id key derivation
#[derive(Debug, Clone)]
pub struct XChaCha20Config {
    argon2_params: Argon2Params,
}

impl XChaCha20Config {
    /// Create new XChaCha20-Poly1305 configuration with custom Argon2 parameters
    pub fn new(argon2_params: Argon2Params) -> Self {
        Self { argon2_params }
    }
    
    /// Create configuration with custom parameters
    pub fn with_params(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        // Create custom params manually since XChaCha20 Argon2Params doesn't have a 'custom' method
        let custom_params = Argon2Params {
            memory_cost,
            time_cost,
            parallelism,
        };
        Self::new(custom_params)
    }
    
    /// Get the underlying Argon2 parameters (for migration compatibility)
    pub fn argon2_params(&self) -> &Argon2Params {
        &self.argon2_params
    }
}

impl KeyDerivationConfig for XChaCha20Config {
    fn derive_key_material(&self, password: &str, salt: &[u8]) -> Result<KeyMaterial, CryptoError> {
        // XChaCha20 requires exactly 32 bytes for salt
        if salt.len() != 32 {
            return Err(CryptoError::CryptographicError(
                format!("XChaCha20 requires 32-byte salt, got {}", salt.len())
            ));
        }
        
        // Convert slice to array
        let mut salt_array = [0u8; 32];
        salt_array.copy_from_slice(salt);
        
        // Derive master key using XChaCha20 key derivation
        let master_key_secret = derive_master_key(password, &salt_array, &self.argon2_params)?;
        
        // Convert SecretVec to KeyMaterial by deriving additional keys
        // Use HKDF to derive encryption and obfuscation keys from master key
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        let master_key_bytes = master_key_secret.expose_secret();
        let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key_bytes);
        
        // Derive encryption key (32 bytes)
        let mut encryption_key_bytes = [0u8; 32];
        hkdf.expand(b"ENCRYPTION", &mut encryption_key_bytes)
            .map_err(|e| CryptoError::CryptographicError(format!("HKDF expansion failed: {}", e)))?;
        
        // Derive obfuscation key (32 bytes)
        let mut obfuscation_key_bytes = [0u8; 32];
        hkdf.expand(b"OBFUSCATION", &mut obfuscation_key_bytes)
            .map_err(|e| CryptoError::CryptographicError(format!("HKDF expansion failed: {}", e)))?;
        
        // Create secure key material
        Ok(KeyMaterial::new(
            master_key_bytes.to_vec(),
            encryption_key_bytes.to_vec(),
            obfuscation_key_bytes.to_vec(),
        ))
    }
    
    fn salt_length(&self) -> usize {
        32 // XChaCha20-Poly1305 uses 32-byte salts for enhanced security
    }
    
    fn name(&self) -> &'static str {
        "Argon2id-XChaCha20-Poly1305"
    }
}

impl EncryptionConfig for XChaCha20Config {
    fn key_size(&self) -> usize {
        32 // XChaCha20-Poly1305 uses 32-byte keys
    }
    
    fn nonce_size(&self) -> usize {
        24 // XChaCha20-Poly1305 uses 24-byte nonces (enhanced collision resistance)
    }
    
    fn algorithm_id(&self) -> u16 {
        2 // V2 XChaCha20-Poly1305 algorithm ID
    }
    
    fn algorithm_name(&self) -> &'static str {
        "XChaCha20-Poly1305"
    }
}

impl CryptoConfig for XChaCha20Config {
    fn test_config() -> Self {
        Self::new(Argon2Params::test_params())
    }
    
    fn production_config() -> Self {
        Self::new(Argon2Params::production_params())
    }
}

// Backward compatibility: allow conversion from Argon2Params  
impl From<Argon2Params> for XChaCha20Config {
    fn from(params: Argon2Params) -> Self {
        Self::new(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::config::ConfigProvider;
    use super::super::DefaultConfigProvider;

    #[test]
    fn test_xchacha20_config_basic() {
        let config = XChaCha20Config::test_config();
        
        assert_eq!(config.algorithm_id(), 2);
        assert_eq!(config.algorithm_name(), "XChaCha20-Poly1305");
        assert_eq!(config.key_size(), 32);
        assert_eq!(config.nonce_size(), 24);
        assert_eq!(config.salt_length(), 32);
        assert_eq!(config.name(), "Argon2id-XChaCha20-Poly1305");
    }
    
    #[test]
    fn test_xchacha20_config_provider() {
        let provider = DefaultConfigProvider::<XChaCha20Config>::test();
        let config = provider.config();
        
        assert_eq!(config.algorithm_id(), 2);
        assert_eq!(config.algorithm_name(), "XChaCha20-Poly1305");
    }
    
    #[test]
    fn test_xchacha20_config_from_params() {
        let params = Argon2Params::test_params();
        let config = XChaCha20Config::from(params);
        
        assert_eq!(config.algorithm_id(), 2);
        assert_eq!(config.key_size(), 32);
    }
    
    #[test]
    fn test_xchacha20_config_key_derivation() {
        let config = XChaCha20Config::test_config();
        let password = "test_password";
        let salt = vec![0u8; 32];
        
        let key_material = config.derive_key_material(password, &salt).unwrap();
        assert_eq!(key_material.master_key.expose_secret().len(), 32);
        assert_eq!(key_material.encryption_key.expose_secret().len(), 32);
        assert_eq!(key_material.obfuscation_key.expose_secret().len(), 32);
    }
    
    #[test]
    fn test_xchacha20_config_custom_params() {
        let config = XChaCha20Config::with_params(64, 2, 1);
        
        assert_eq!(config.argon2_params().memory_cost, 64);
        assert_eq!(config.argon2_params().time_cost, 2);
        assert_eq!(config.argon2_params().parallelism, 1);
    }
}