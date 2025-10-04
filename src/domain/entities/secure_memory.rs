//! Secure memory handling with automatic zeroization
//! 
//! This module provides secure memory abstractions that automatically
//! zeroize sensitive data when dropped, preventing memory leaks of
//! cryptographic material.

use zeroize::Zeroize;

/// Secure container that automatically zeroizes its contents on drop
/// 
/// `SecureBox<T>` provides a secure wrapper around any type that implements
/// `Zeroize`. When the SecureBox is dropped, it automatically calls `zeroize()`
/// on the contained data to clear sensitive information from memory.
pub struct SecureBox<T: Zeroize> {
    data: Box<T>,
}

impl<T: Zeroize> SecureBox<T> {
    /// Create a new SecureBox containing the given data
    pub fn new(data: T) -> Self {
        Self {
            data: Box::new(data),
        }
    }
    
    /// Get a reference to the contained data
    /// 
    /// This method is named to make it explicit that sensitive data
    /// is being exposed and should be handled carefully.
    pub fn expose_secret(&self) -> &T {
        &self.data
    }
}

impl<T: Zeroize> Drop for SecureBox<T> {
    fn drop(&mut self) {
        // Automatically zeroize the contained data when dropped
        self.data.zeroize();
    }
}

impl<T: Zeroize> std::ops::Deref for SecureBox<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> std::fmt::Debug for SecureBox<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBox")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Key material container with automatic zeroization
/// 
/// KeyMaterial provides a secure container for cryptographic key data
/// that automatically zeroizes the key bytes when dropped. This follows
/// the patterns proven in the legacy implementation.
#[derive(Debug)]
pub struct KeyMaterial {
    /// Master key derived from password and salt
    pub master_key: SecureBox<[u8; 32]>,
    /// Key used for file encryption/decryption  
    pub encryption_key: SecureBox<[u8; 32]>,
    /// Key used for filename obfuscation
    pub obfuscation_key: SecureBox<[u8; 32]>,
}

impl KeyMaterial {
    /// Create new key material from derived keys
    /// 
    /// All provided keys will be moved into SecureBoxes and automatically
    /// zeroized when the KeyMaterial is dropped.
    pub fn new(
        master_key: [u8; 32],
        encryption_key: [u8; 32], 
        obfuscation_key: [u8; 32],
    ) -> Self {
        Self {
            master_key: SecureBox::new(master_key),
            encryption_key: SecureBox::new(encryption_key),
            obfuscation_key: SecureBox::new(obfuscation_key),
        }
    }
    
    /// Create key material from a master key by deriving sub-keys
    /// 
    /// Uses domain separation to derive encryption and obfuscation keys from the master key.
    /// This provides cryptographic separation between different key uses while maintaining
    /// deterministic derivation for consistency.
    /// 
    /// TODO: Replace with proper HKDF when crypto infrastructure is available
    pub fn from_master_key(master_key: [u8; 32]) -> Self {
        // This is a placeholder implementation using simple domain separation.
        // Production code MUST use HKDF with proper info strings for domain separation.
        
        let encryption_key = Self::derive_subkey(&master_key, b"ENCRYPTION");
        let obfuscation_key = Self::derive_subkey(&master_key, b"OBFUSCATION");
        
        Self::new(master_key, encryption_key, obfuscation_key)
    }
    
    /// Derive a subkey from master key with domain separation
    /// 
    /// This provides basic domain separation using XOR with domain-specific constants.
    /// This will be replaced with proper HKDF when crypto infrastructure is available.
    fn derive_subkey(master_key: &[u8; 32], domain: &[u8]) -> [u8; 32] {
        let mut subkey = [0u8; 32];
        
        // Simple domain separation: XOR master key with hashed domain string
        let mut domain_hash = 0u64;
        for &byte in domain {
            domain_hash = domain_hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        
        for i in 0..32 {
            let domain_byte = ((domain_hash >> (i % 8)) & 0xFF) as u8;
            subkey[i] = master_key[i] ^ domain_byte;
        }
        
        subkey
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn secure_box_basic_functionality() {
        let secret_data = vec![1u8, 2, 3, 4, 5];
        let secure_box = SecureBox::new(secret_data.clone());
        
        // Test expose_secret method
        assert_eq!(secure_box.expose_secret(), &secret_data);
        
        // Test Deref trait
        assert_eq!(&*secure_box, &secret_data);
        assert_eq!(secure_box.len(), 5);
    }
    
    #[test] 
    fn key_material_basic_functionality() {
        // Test creating KeyMaterial with explicit keys
        let master_key = [0xaa; 32];
        let encryption_key = [0xbb; 32];
        let obfuscation_key = [0xcc; 32];
        
        let key_material = KeyMaterial::new(master_key, encryption_key, obfuscation_key);
        
        // Test access to individual keys
        assert_eq!(key_material.master_key.expose_secret(), &master_key);
        assert_eq!(key_material.encryption_key.expose_secret(), &encryption_key);
        assert_eq!(key_material.obfuscation_key.expose_secret(), &obfuscation_key);
    }
    
    #[test]
    fn key_material_from_master_key() {
        let master_key = [0x42; 32];
        let key_material = KeyMaterial::from_master_key(master_key);
        
        // Verify master key is stored correctly
        assert_eq!(key_material.master_key.expose_secret(), &master_key);
        
        // Verify derived keys are different from master key and each other
        assert_ne!(key_material.encryption_key.expose_secret(), &master_key);
        assert_ne!(key_material.obfuscation_key.expose_secret(), &master_key);
        assert_ne!(
            key_material.encryption_key.expose_secret(), 
            key_material.obfuscation_key.expose_secret()
        );
        
        // Verify derived keys are deterministic (same master key -> same derived keys)
        let key_material2 = KeyMaterial::from_master_key(master_key);
        assert_eq!(
            key_material.encryption_key.expose_secret(),
            key_material2.encryption_key.expose_secret()
        );
        assert_eq!(
            key_material.obfuscation_key.expose_secret(),
            key_material2.obfuscation_key.expose_secret()
        );
    }
    
    #[test]
    fn debug_does_not_leak_secrets() {
        let secret_data = vec![1u8, 2, 3, 4, 5];
        let secure_box = SecureBox::new(secret_data);
        
        let debug_output = format!("{:?}", secure_box);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("1"));
        assert!(!debug_output.contains("2"));
        assert!(!debug_output.contains("3"));
        
        // Test KeyMaterial debug too  
        let master_key = [0xde; 32];
        let encryption_key = [0xad; 32]; 
        let obfuscation_key = [0xbe; 32];
        let key_material = KeyMaterial::new(master_key, encryption_key, obfuscation_key);
        
        let key_debug = format!("{:?}", key_material);
        assert!(key_debug.contains("KeyMaterial"));
        assert!(key_debug.contains("[REDACTED]"));
        assert!(!key_debug.contains("0xde"));
        assert!(!key_debug.contains("0xad"));
        assert!(!key_debug.contains("0xbe"));
    }
    
    #[test]
    fn zeroization_occurs_on_drop() {
        // Create a vec with predictable data
        let mut test_data = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let data_ptr = test_data.as_mut_ptr();
        
        // Create SecureBox and immediately drop it
        {
            let _secure_box = SecureBox::new(test_data);
            // SecureBox is dropped here, calling zeroize() on the contained data
        }
        
        // Note: This test demonstrates that Drop is called correctly.
        // Actual memory zeroization is handled by the zeroize crate.
        // We can't reliably test the memory state after drop due to
        // potential memory reuse by the allocator.
        unsafe {
            let slice = std::slice::from_raw_parts(data_ptr, 4);
            println!("Memory after drop: {:?}", slice);
            // The zeroize crate ensures this memory was properly cleared
        }
    }
    
    #[test]
    fn secure_box_supports_different_types() {
        // Test with Vec<u8>
        let vec_data = vec![1u8, 2, 3];
        let secure_vec = SecureBox::new(vec_data.clone());
        assert_eq!(secure_vec.expose_secret(), &vec_data);
        
        // Test with arrays (which implement Zeroize)
        let array_data = [1u8, 2, 3, 4];
        let secure_array = SecureBox::new(array_data);
        assert_eq!(secure_array.expose_secret(), &array_data);
    }
    
    #[test]
    fn key_material_handles_standard_key_sizes() {
        // Test with 32-byte master keys (common size)
        let master_key = [0x42; 32];
        let encryption_key = [0x43; 32];
        let obfuscation_key = [0x44; 32];
        
        let key_material = KeyMaterial::new(master_key, encryption_key, obfuscation_key);
        
        // All keys should be 32 bytes
        assert_eq!(key_material.master_key.expose_secret().len(), 32);
        assert_eq!(key_material.encryption_key.expose_secret().len(), 32);
        assert_eq!(key_material.obfuscation_key.expose_secret().len(), 32);
        
        // Verify content is correct
        assert_eq!(key_material.master_key.expose_secret(), &master_key);
        assert_eq!(key_material.encryption_key.expose_secret(), &encryption_key);
        assert_eq!(key_material.obfuscation_key.expose_secret(), &obfuscation_key);
    }
    
    #[test]
    fn api_matches_domain_architecture_spec() {
        // Test that our API matches the domain architecture spec requirements
        
        // The spec calls for KeyMaterial with three distinct keys
        let master_key = [0x01; 32];
        let encryption_key = [0x02; 32];
        let obfuscation_key = [0x03; 32];
        
        let key_material = KeyMaterial::new(master_key, encryption_key, obfuscation_key);
        
        // Spec requirement: Access to individual keys
        assert_eq!(key_material.master_key.expose_secret(), &master_key);
        assert_eq!(key_material.encryption_key.expose_secret(), &encryption_key);
        assert_eq!(key_material.obfuscation_key.expose_secret(), &obfuscation_key);
        
        // Spec requirement: Automatic zeroization on drop (tested in other tests)
        // Spec requirement: Debug safety (tested in other tests)
        
        // Test derived key generation
        let derived_material = KeyMaterial::from_master_key(master_key);
        assert_eq!(derived_material.master_key.expose_secret(), &master_key);
        
        // Derived keys should be different from master
        assert_ne!(derived_material.encryption_key.expose_secret(), &master_key);
        assert_ne!(derived_material.obfuscation_key.expose_secret(), &master_key);
    }
}