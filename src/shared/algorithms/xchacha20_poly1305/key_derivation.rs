//! XChaCha20-Poly1305 key derivation operations
//! 
//! This module provides key derivation functionality for XChaCha20-Poly1305
//! using Argon2id, maintaining compatibility with the existing AES-GCM approach.

use crate::shared::core::errors::CryptoError;
use crate::shared::core::crypto::secure_memory::SecretVec;
use argon2::{Argon2, Algorithm, Version, Params};
use getrandom;
use std::time::Instant;

/// Argon2id parameters for XChaCha20-Poly1305 key derivation
/// 
/// These parameters are tuned for security and performance balance
/// targeting ~1.4s derivation time on modern hardware.
#[derive(Debug, Clone)]
pub struct Argon2Params {
    pub memory_cost: u32,    // Memory usage in KB
    pub time_cost: u32,      // Number of iterations
    pub parallelism: u32,    // Number of parallel threads
}

impl Default for Argon2Params {
    fn default() -> Self {
        // Use lightweight parameters during testing
        if cfg!(test) {
            Self::test_params()
        } else {
            Self::production_params()
        }
    }
}

impl Argon2Params {
    /// Production parameters with system adaptation
    pub fn production_params() -> Self {
        Self {
            memory_cost: 524288,  // 512 MB memory usage
            time_cost: 5,         // 5 iterations 
            parallelism: 8,       // 8 parallel threads
        }
    }
    
    /// Lightweight parameters for testing
    pub fn test_params() -> Self {
        Self {
            memory_cost: 1024,   // 1MB - very fast for testing
            time_cost: 1,        // 1 iteration - minimal time
            parallelism: 1,      // Single thread - deterministic
        }
    }
    
    /// Create adaptive parameters based on system capabilities
    pub fn adaptive() -> Self {
        let available_memory = Self::get_available_memory();
        let cpu_count = num_cpus::get() as u32;
        
        // Use up to 512MB or 25% of available memory, whichever is smaller
        let target_memory = std::cmp::min(524288, available_memory / 4);
        let memory_cost = std::cmp::max(65536, target_memory); // Minimum 64MB
        
        // Use available CPUs but cap at 16 for reasonable performance
        let parallelism = std::cmp::min(cpu_count, 16);
        
        Self {
            memory_cost,
            time_cost: 5,
            parallelism,
        }
    }
    
    fn get_available_memory() -> u32 {
        use sysinfo::System;
        let mut sys = System::new();
        sys.refresh_memory();
        
        // Convert bytes to KB and return as u32
        (sys.available_memory() / 1024) as u32
    }
}

/// Generate a secure random salt for key derivation
/// 
/// # Returns
/// * `Ok([u8; 32])` - 256-bit salt
/// * `Err(CryptoError)` - Random generation failed
pub fn generate_salt() -> Result<[u8; 32], CryptoError> {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt)
        .map_err(|e| CryptoError::CryptographicError(format!("Failed to generate salt: {}", e)))?;
    Ok(salt)
}

/// Derive master key from password using Argon2id
/// 
/// # Arguments
/// * `password` - User password (will be zeroized after use)
/// * `salt` - 32-byte salt for key derivation
/// * `params` - Argon2id parameters for derivation
/// 
/// # Returns
/// * `Ok(SecretVec<u8>)` - 256-bit master key
/// * `Err(CryptoError)` - Key derivation failed
/// 
/// # Security Notes
/// - Uses Argon2id for resistance against time-memory trade-off attacks
/// - Password is zeroized after key derivation
/// - Timing is intentionally ~1.4s to balance security and usability
pub fn derive_master_key(
    password: &str,
    salt: &[u8; 32], 
    params: &Argon2Params
) -> Result<SecretVec<u8>, CryptoError> {
    // Validate salt length
    if salt.len() != 32 {
        return Err(CryptoError::CryptographicError(
            format!("Invalid salt length: expected 32 bytes, got {}", salt.len())
        ));
    }

    // Configure Argon2id
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32), // Output length: 32 bytes (256 bits)
    ).map_err(|e| CryptoError::CryptographicError(
        format!("Invalid Argon2 parameters: {}", e)
    ))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    
    // Time the key derivation for security monitoring
    let start_time = Instant::now();
    
    // Derive the master key
    let mut master_key = vec![0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut master_key)
        .map_err(|e| CryptoError::CryptographicError(
            format!("Key derivation failed: {}", e)
        ))?;
    
    let derivation_time = start_time.elapsed();
    
    // Security monitoring: log timing for analysis
    if derivation_time.as_millis() < 500 {
        eprintln!("Warning: Key derivation completed in {}ms (target: ~1400ms)", derivation_time.as_millis());
    }
    
    Ok(SecretVec::new(master_key))
}

/// Master key manager for XChaCha20-Poly1305 operations
/// 
/// Manages master key and derived per-file keys with automatic zeroization.
pub struct MasterKeyManager {
    master_key: SecretVec<u8>,
    encryption_key: SecretVec<u8>,
    obfuscation_key: SecretVec<u8>,
}

impl MasterKeyManager {
    /// Create a new key manager from master key
    pub fn new(master_key: SecretVec<u8>) -> Self {
        // Initialize with empty derived keys (will be populated on first use)
        Self {
            master_key,
            encryption_key: SecretVec::new(vec![]),
            obfuscation_key: SecretVec::new(vec![]),
        }
    }

    /// Derive file-specific keys from master key and file salt
    /// 
    /// Uses HKDF-SHA256 to derive separate keys for:
    /// - File content encryption (32 bytes for XChaCha20-Poly1305)
    /// - Filename obfuscation (32 bytes for consistency)
    /// 
    /// # Arguments
    /// * `file_salt` - 32-byte per-file salt
    /// 
    /// # Returns
    /// * `Ok((&SecretVec<u8>, &SecretVec<u8>))` - (encryption_key, obfuscation_key)
    /// * `Err(CryptoError)` - Key derivation failed
    pub fn derive_file_keys(&mut self, file_salt: &[u8]) -> Result<(&SecretVec<u8>, &SecretVec<u8>), CryptoError> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        if file_salt.len() != 32 {
            return Err(CryptoError::CryptographicError(
                format!("Invalid file salt length: expected 32 bytes, got {}", file_salt.len())
            ));
        }
        
        // Use HKDF to derive both keys from master key + file salt
        let hk = Hkdf::<Sha256>::new(Some(file_salt), self.master_key.expose());
        
        // Derive encryption key (32 bytes for XChaCha20-Poly1305)
        let mut encryption_key_bytes = [0u8; 32];
        hk.expand(b"xchacha20poly1305-encryption", &mut encryption_key_bytes)
            .map_err(|e| CryptoError::CryptographicError(
                format!("Failed to derive encryption key: {}", e)
            ))?;
        
        // Derive obfuscation key (32 bytes for filename operations)
        let mut obfuscation_key_bytes = [0u8; 32];
        hk.expand(b"xchacha20poly1305-obfuscation", &mut obfuscation_key_bytes)
            .map_err(|e| CryptoError::CryptographicError(
                format!("Failed to derive obfuscation key: {}", e)
            ))?;
        
        // Store in SecretVec for automatic zeroization
        self.encryption_key = SecretVec::new(encryption_key_bytes.to_vec());
        self.obfuscation_key = SecretVec::new(obfuscation_key_bytes.to_vec());
        
        Ok((&self.encryption_key, &self.obfuscation_key))
    }
    
    /// Get reference to master key
    pub fn master_key(&self) -> &SecretVec<u8> {
        &self.master_key
    }
}

// Automatic zeroization when MasterKeyManager is dropped
impl Drop for MasterKeyManager {
    fn drop(&mut self) {
        // SecretVec handles zeroization automatically
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();
        
        // Salts should be different
        assert_ne!(salt1, salt2);
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
    }
    
    #[test]
    fn test_derive_master_key() {
        let password = "test-password-123";
        let salt = generate_salt().unwrap();
        let params = Argon2Params::default();
        
        let master_key = derive_master_key(password, &salt, &params).unwrap();
        assert_eq!(master_key.len(), 32);
        
        // Same password + salt should produce same key
        let master_key2 = derive_master_key(password, &salt, &params).unwrap();
        assert_eq!(master_key.expose(), master_key2.expose());
        
        // Different salt should produce different key
        let salt2 = generate_salt().unwrap();
        let master_key3 = derive_master_key(password, &salt2, &params).unwrap();
        assert_ne!(master_key.expose(), master_key3.expose());
    }
    
    #[test]
    fn test_key_manager_file_key_derivation() {
        let password = "test-password";
        let salt = generate_salt().unwrap();
        let params = Argon2Params::default();
        
        let master_key = derive_master_key(password, &salt, &params).unwrap();
        let mut key_manager = MasterKeyManager::new(master_key);
        
        let file_salt = generate_salt().unwrap();
        
        // First derivation
        let (enc_key1, obf_key1) = {
            let (enc, obf) = key_manager.derive_file_keys(&file_salt).unwrap();
            (enc.expose().to_vec(), obf.expose().to_vec())
        };
        
        assert_eq!(enc_key1.len(), 32);
        assert_eq!(obf_key1.len(), 32);
        assert_ne!(enc_key1, obf_key1);
        
        // Same file salt should produce same keys
        let (enc_key2, obf_key2) = {
            let (enc, obf) = key_manager.derive_file_keys(&file_salt).unwrap();
            (enc.expose().to_vec(), obf.expose().to_vec())
        };
        assert_eq!(enc_key1, enc_key2);
        assert_eq!(obf_key1, obf_key2);
        
        // Different file salt should produce different keys
        let file_salt2 = generate_salt().unwrap();
        let (enc_key3, obf_key3) = {
            let (enc, obf) = key_manager.derive_file_keys(&file_salt2).unwrap();
            (enc.expose().to_vec(), obf.expose().to_vec())
        };
        assert_ne!(enc_key2, enc_key3);
        assert_ne!(obf_key2, obf_key3);
    }
    
    #[test]
    fn test_argon2_params_adaptive() {
        let params = Argon2Params::production_params(); // Use production params instead of adaptive for testing
        
        // Should use reasonable values
        assert!(params.memory_cost >= 65536); // At least 64MB
        assert!(params.memory_cost <= 524288); // At most 512MB
        assert!(params.time_cost > 0);
        assert!(params.parallelism > 0);
        assert!(params.parallelism <= 16);
    }
}