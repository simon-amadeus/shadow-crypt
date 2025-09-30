//! Argon2id key derivation and master key management
//! 
//! This module provides secure password-based key derivation using Argon2id
//! with adaptive parameters and master key management for performance.

use crate::shared::errors::CryptoError;
use crate::shared::crypto::secure_memory::{SecretVec, KeyMaterial};
use argon2::{Argon2, Algorithm, Version, Params};
use hkdf::Hkdf;
use sha2::Sha256;
use getrandom::getrandom;
use sysinfo::{System, SystemExt};
use std::collections::HashMap;

/// Argon2id parameters for key derivation
#[derive(Debug, Clone)]
pub struct Argon2Params {
    pub memory_cost: u32,     // Memory cost in KB
    pub time_cost: u32,       // Time cost (iterations)
    pub parallelism: u32,     // Parallelism degree
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
            memory_cost: determine_optimal_memory_cost(),
            time_cost: 5,
            parallelism: std::cmp::min(8, num_cpus()),
        }
    }
    
    /// Lightweight parameters for testing
    pub fn test_params() -> Self {
        Self {
            memory_cost: 1024,  // 1MB - very fast for testing
            time_cost: 1,       // 1 iteration - minimal time
            parallelism: 1,     // Single thread - deterministic
        }
    }
    
    /// Custom parameters for specific use cases
    pub fn custom(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }
}

/// Determine optimal memory cost based on available system memory
fn determine_optimal_memory_cost() -> u32 {
    // Get total system memory
    let mut system = System::new_all();
    system.refresh_memory();
    
    let total_memory_kb = system.total_memory();
    
    // Use 1/8 of total memory for Argon2, with reasonable bounds
    let recommended_memory_kb = (total_memory_kb / 8).max(32 * 1024).min(512 * 1024);
    
    // Convert to u32, fallback to safe default if overflow
    recommended_memory_kb.try_into().unwrap_or(65536)
}

/// Get number of CPUs for parallelism
fn num_cpus() -> u32 {
    // Get actual CPU count from system
    let mut system = System::new();
    system.refresh_cpu();
    
    let cpu_count = system.cpus().len() as u32;
    
    // Use actual CPU count, but cap at 8 for reasonable memory usage
    cpu_count.min(8).max(1)
}

/// Generate a secure random salt
/// 
/// # Arguments
/// * `length` - Length of salt in bytes (16 recommended)
/// 
/// # Returns
/// * `Ok(Vec<u8>)` - Random salt bytes
/// * `Err(CryptoError)` - Random generation failed
pub fn generate_salt(length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut salt = vec![0u8; length];
    getrandom(&mut salt)
        .map_err(|e| CryptoError::CryptographicError(format!("Failed to generate salt: {}", e)))?;
    Ok(salt)
}

/// Derive master key from password using Argon2id
/// 
/// # Arguments
/// * `password` - User password
/// * `salt` - Random salt (16 bytes recommended)
/// * `params` - Argon2 parameters
/// 
/// # Returns
/// * `Ok(KeyMaterial)` - Derived key material with master, encryption, and obfuscation keys
/// * `Err(CryptoError)` - Key derivation failed
pub fn derive_master_key(
    password: &str, 
    salt: &[u8], 
    params: &Argon2Params
) -> Result<KeyMaterial, CryptoError> {
    // Validate salt length
    if salt.len() < 16 {
        return Err(CryptoError::KeyDerivationError(
            "Salt must be at least 16 bytes".to_string()
        ));
    }
    
    // Create Argon2 parameters
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32) // 256-bit output
    ).map_err(|e| CryptoError::KeyDerivationError(format!("Invalid Argon2 parameters: {}", e)))?;
    
    // Create Argon2 hasher
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    
    // Derive master key
    let mut master_key_bytes = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut master_key_bytes)
        .map_err(|e| CryptoError::KeyDerivationError(format!("Argon2 key derivation failed: {}", e)))?;
    
    // Use HKDF to derive encryption and obfuscation keys from master key
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &master_key_bytes);
    
    // Derive encryption key (32 bytes)
    let mut encryption_key_bytes = [0u8; 32];
    hkdf.expand(b"ENCRYPTION", &mut encryption_key_bytes)
        .map_err(|e| CryptoError::KeyDerivationError(format!("HKDF expansion failed: {}", e)))?;
    
    // Derive obfuscation key (32 bytes)
    let mut obfuscation_key_bytes = [0u8; 32];
    hkdf.expand(b"OBFUSCATION", &mut obfuscation_key_bytes)
        .map_err(|e| CryptoError::KeyDerivationError(format!("HKDF expansion failed: {}", e)))?;
    
    // Create secure key material
    Ok(KeyMaterial::new(
        master_key_bytes.to_vec(),
        encryption_key_bytes.to_vec(),
        obfuscation_key_bytes.to_vec(),
    ))
}

/// Master key manager for efficient key derivation and caching
pub struct MasterKeyManager {
    master_key: SecretVec<u8>,
    derived_keys: HashMap<[u8; 32], DerivedKeySet>, // Salt hash -> Keys mapping
}

/// Set of derived keys for a specific file salt
#[derive(Clone)]
struct DerivedKeySet {
    encryption_key: SecretVec<u8>,
    obfuscation_key: SecretVec<u8>,
}

impl MasterKeyManager {
    /// Create a new master key manager
    /// 
    /// # Arguments
    /// * `password` - User password
    /// * `global_salt` - Global salt for master key derivation
    /// 
    /// # Returns
    /// * `Ok(MasterKeyManager)` - Initialized manager
    /// * `Err(CryptoError)` - Initialization failed
    pub fn new(password: &str, global_salt: &[u8]) -> Result<Self, CryptoError> {
        let params = Argon2Params::default();
        let key_material = derive_master_key(password, global_salt, &params)?;
        
        Ok(Self {
            master_key: key_material.master_key,
            derived_keys: HashMap::new(),
        })
    }
    
    /// Create manager from existing key material
    /// 
    /// # Arguments
    /// * `key_material` - Pre-derived key material
    /// 
    /// # Returns
    /// * `MasterKeyManager` - Initialized manager
    pub fn from_key_material(key_material: KeyMaterial) -> Self {
        Self {
            master_key: key_material.master_key,
            derived_keys: HashMap::new(),
        }
    }
    
    /// Derive file-specific keys from master key using HKDF
    /// 
    /// # Arguments
    /// * `file_salt` - File-specific salt
    /// 
    /// # Returns
    /// * `Ok((&SecretVec<u8>, &SecretVec<u8>))` - (encryption_key, obfuscation_key)
    /// * `Err(CryptoError)` - Key derivation failed
    pub fn derive_file_keys(&mut self, file_salt: &[u8]) -> Result<(&SecretVec<u8>, &SecretVec<u8>), CryptoError> {
        // Hash the salt for cache lookup
        let salt_hash = hash_salt(file_salt)?;
        
        // Check if we already have derived keys for this salt
        if !self.derived_keys.contains_key(&salt_hash) {
            // Derive new keys using HKDF
            let hkdf = Hkdf::<Sha256>::new(Some(file_salt), self.master_key.expose());
            
            // Derive encryption key (32 bytes)
            let mut encryption_key_bytes = [0u8; 32];
            hkdf.expand(b"ENCRYPTION", &mut encryption_key_bytes)
                .map_err(|e| CryptoError::KeyDerivationError(format!("HKDF expansion failed: {}", e)))?;
            
            // Derive obfuscation key (32 bytes)
            let mut obfuscation_key_bytes = [0u8; 32];
            hkdf.expand(b"OBFUSCATION", &mut obfuscation_key_bytes)
                .map_err(|e| CryptoError::KeyDerivationError(format!("HKDF expansion failed: {}", e)))?;
            
            // Create secure key vectors
            let encryption_key = SecretVec::new(encryption_key_bytes.to_vec());
            let obfuscation_key = SecretVec::new(obfuscation_key_bytes.to_vec());
            
            // Cache the derived keys
            let derived_set = DerivedKeySet {
                encryption_key,
                obfuscation_key,
            };
            
            self.derived_keys.insert(salt_hash, derived_set);
        }
        
        // Return references to the cached keys
        let cached_set = self.derived_keys.get(&salt_hash).unwrap();
        Ok((&cached_set.encryption_key, &cached_set.obfuscation_key))
    }
    
    /// Clear all derived keys for security
    pub fn clear_derived_keys(&mut self) {
        self.derived_keys.clear();
    }
    
    /// Get master key for advanced operations
    pub fn master_key(&self) -> &SecretVec<u8> {
        &self.master_key
    }
}

/// Hash salt for cache key generation
fn hash_salt(salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    use sha2::{Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(salt);
    let hash = hasher.finalize();
    
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt(16).unwrap();
        let salt2 = generate_salt(16).unwrap();
        
        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
        assert_ne!(salt1, salt2); // Should be different
    }

    #[test]
    fn test_derive_master_key() {
        let password = "test_password";
        let salt = generate_salt(16).unwrap();
        let params = Argon2Params::default();
        
        let key_material = derive_master_key(password, &salt, &params).unwrap();
        
        assert_eq!(key_material.master_key.expose().len(), 32);
        assert_eq!(key_material.encryption_key.expose().len(), 32);
        assert_eq!(key_material.obfuscation_key.expose().len(), 32);
    }

    #[test]
    fn test_derive_master_key_deterministic() {
        let password = "test_password";
        let salt = vec![1u8; 16];
        let params = Argon2Params::default();
        
        let key1 = derive_master_key(password, &salt, &params).unwrap();
        let key2 = derive_master_key(password, &salt, &params).unwrap();
        
        // Same inputs should produce same key
        assert_eq!(key1.master_key.expose(), key2.master_key.expose());
        assert_eq!(key1.encryption_key.expose(), key2.encryption_key.expose());
        assert_eq!(key1.obfuscation_key.expose(), key2.obfuscation_key.expose());
    }

    #[test]
    fn test_derive_master_key_different_passwords() {
        let salt = vec![1u8; 16];
        let params = Argon2Params::default();
        
        let key1 = derive_master_key("password1", &salt, &params).unwrap();
        let key2 = derive_master_key("password2", &salt, &params).unwrap();
        
        // Different passwords should produce different keys
        assert_ne!(key1.master_key.expose(), key2.master_key.expose());
    }

    #[test]
    fn test_derive_master_key_short_salt() {
        let password = "test_password";
        let short_salt = vec![1u8; 8]; // Too short
        let params = Argon2Params::default();
        
        let result = derive_master_key(password, &short_salt, &params);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Salt must be at least 16 bytes"));
    }

    #[test]
    fn test_master_key_manager() {
        let password = "test_password";
        let global_salt = generate_salt(16).unwrap();
        
        let manager = MasterKeyManager::new(password, &global_salt).unwrap();
        
        assert_eq!(manager.master_key().expose().len(), 32);
    }

    #[test]
    fn test_derive_file_keys() {
        let password = "test_password";
        let global_salt = generate_salt(16).unwrap();
        let file_salt = generate_salt(16).unwrap();
        
        let mut manager = MasterKeyManager::new(password, &global_salt).unwrap();
        
        // First derivation
        let (enc_key1, obf_key1) = manager.derive_file_keys(&file_salt).unwrap();
        
        // Keys should be different from each other
        assert_ne!(enc_key1.expose(), obf_key1.expose());
        
        // Keys should be 32 bytes
        assert_eq!(enc_key1.expose().len(), 32);
        assert_eq!(obf_key1.expose().len(), 32);
        
        // Store the keys for comparison
        let enc_key1_data = enc_key1.expose().to_vec();
        let obf_key1_data = obf_key1.expose().to_vec();
        
        // Second call should return same keys (cached)
        let (enc_key2, obf_key2) = manager.derive_file_keys(&file_salt).unwrap();
        assert_eq!(enc_key1_data, enc_key2.expose());
        assert_eq!(obf_key1_data, obf_key2.expose());
    }

    #[test]
    fn test_derive_file_keys_different_salts() {
        let password = "test_password";
        let global_salt = generate_salt(16).unwrap();
        let file_salt1 = generate_salt(16).unwrap();
        let file_salt2 = generate_salt(16).unwrap();
        
        let mut manager = MasterKeyManager::new(password, &global_salt).unwrap();
        
        let (enc_key1, _) = manager.derive_file_keys(&file_salt1).unwrap();
        let enc_key1_data = enc_key1.expose().to_vec();
        
        let (enc_key2, _) = manager.derive_file_keys(&file_salt2).unwrap();
        
        // Different salts should produce different keys
        assert_ne!(enc_key1_data, enc_key2.expose());
    }

    #[test]
    fn test_clear_derived_keys() {
        let password = "test_password";
        let global_salt = generate_salt(16).unwrap();
        let file_salt = generate_salt(16).unwrap();
        
        let mut manager = MasterKeyManager::new(password, &global_salt).unwrap();
        
        // Derive some keys
        let _ = manager.derive_file_keys(&file_salt).unwrap();
        assert!(!manager.derived_keys.is_empty());
        
        // Clear them
        manager.clear_derived_keys();
        assert!(manager.derived_keys.is_empty());
    }

    #[test]
    fn test_hash_salt() {
        let salt1 = b"test_salt_1";
        let salt2 = b"test_salt_2";
        
        let hash1 = hash_salt(salt1).unwrap();
        let hash2 = hash_salt(salt2).unwrap();
        
        assert_eq!(hash1.len(), 32);
        assert_eq!(hash2.len(), 32);
        assert_ne!(hash1, hash2); // Different salts should produce different hashes
        
        // Same salt should produce same hash
        let hash1_again = hash_salt(salt1).unwrap();
        assert_eq!(hash1, hash1_again);
    }
}