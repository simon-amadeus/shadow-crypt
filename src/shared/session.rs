//! Session management for multi-file operations
//! 
//! This module provides secure session management to optimize key derivation
//! for multi-file operations. Instead of re-deriving the master key for each
//! file, we cache it securely within the session and reuse it.

use crate::shared::errors::CryptoError;
use crate::shared::algorithms::aes_gcm::key_derivation::{derive_master_key, generate_salt, Argon2Params};
use crate::shared::core::crypto::secure_memory::KeyMaterial;
use std::sync::Arc;

/// Secure session for multi-file operations
/// Caches derived keys to avoid repeated expensive key derivation
pub struct CryptoSession {
    key_material: KeyMaterial,
    params: Argon2Params,
}

impl CryptoSession {
    /// Create a new crypto session by deriving keys from password
    pub fn new(password: &str, params: &Argon2Params) -> Result<Self, CryptoError> {
        // Generate a salt for this session (16 bytes recommended)
        let salt = generate_salt(16)?;
        let key_material = derive_master_key(password, &salt, params)?;
        
        Ok(Self {
            key_material,
            params: params.clone(),
        })
    }

    /// Create a session with specific salt (useful for testing)
    pub fn with_salt(password: &str, salt: &[u8], params: &Argon2Params) -> Result<Self, CryptoError> {
        let key_material = derive_master_key(password, salt, params)?;
        
        Ok(Self {
            key_material,
            params: params.clone(),
        })
    }

    /// Get a reference to the cached master key
    pub fn master_key(&self) -> &[u8] {
        self.key_material.master_key.expose_secret()
    }

    /// Get a reference to the cached encryption key
    pub fn encryption_key(&self) -> &[u8] {
        self.key_material.encryption_key.expose_secret()
    }

    /// Get a reference to the cached obfuscation key
    pub fn obfuscation_key(&self) -> &[u8] {
        self.key_material.obfuscation_key.expose_secret()
    }

    /// Get the Argon2 parameters used for this session
    pub fn params(&self) -> &Argon2Params {
        &self.params
    }

    /// Get reference to the full key material (for compatibility with existing code)
    pub fn key_material(&self) -> &KeyMaterial {
        &self.key_material
    }
}

/// Thread-safe session manager for parallel operations
pub struct SessionManager {
    session: Arc<CryptoSession>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(password: &str, params: &Argon2Params) -> Result<Self, CryptoError> {
        let session = CryptoSession::new(password, params)?;
        Ok(Self {
            session: Arc::new(session),
        })
    }

    /// Get a thread-safe reference to the session
    pub fn session(&self) -> Arc<CryptoSession> {
        self.session.clone()
    }
}

impl Clone for SessionManager {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::algorithms::{AesGcmConfig, CryptoConfig};

    #[test]
    fn test_crypto_session_creation() {
        let config = AesGcmConfig::test_config();
        let params = config.argon2_params();
        let session = CryptoSession::new("test_password", params).unwrap();
        
        assert_eq!(session.master_key().len(), 32);
        assert_eq!(session.encryption_key().len(), 32);
        assert_eq!(session.obfuscation_key().len(), 32);
        assert_eq!(session.params().memory_cost, params.memory_cost);
    }

    #[test]
    fn test_session_manager_clone() {
        let config = AesGcmConfig::test_config();
        let params = config.argon2_params();
        let manager1 = SessionManager::new("test_password", params).unwrap();
        let manager2 = manager1.clone();
        
        // Both managers should reference the same session
        let session1 = manager1.session();
        let session2 = manager2.session();
        let key1 = session1.master_key();
        let key2 = session2.master_key();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_session_with_salt() {
        let config = AesGcmConfig::test_config();
        let params = config.argon2_params();
        let salt = b"test_salt_16byte";
        let session1 = CryptoSession::with_salt("test_password", salt, params).unwrap();
        let session2 = CryptoSession::with_salt("test_password", salt, params).unwrap();
        
        // Same password and salt should produce same keys
        assert_eq!(session1.master_key(), session2.master_key());
        assert_eq!(session1.encryption_key(), session2.encryption_key());
        assert_eq!(session1.obfuscation_key(), session2.obfuscation_key());
    }

    #[test]
    fn test_different_sessions_different_keys() {
        let config = AesGcmConfig::test_config();
        let params = config.argon2_params();
        let session1 = CryptoSession::new("password1", params).unwrap();
        let session2 = CryptoSession::new("password2", params).unwrap();
        
        assert_ne!(session1.master_key(), session2.master_key());
        assert_ne!(session1.encryption_key(), session2.encryption_key());
        assert_ne!(session1.obfuscation_key(), session2.obfuscation_key());
    }
}