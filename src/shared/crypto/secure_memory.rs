//! Secure memory handling with automatic zeroization
//! 
//! This module provides secure memory abstractions that automatically
//! zeroize sensitive data when dropped, preventing memory leaks of
//! cryptographic material.

use crate::shared::errors::CryptoError;

/// Secure vector that zeroizes its contents on drop
#[derive(Clone)]
pub struct SecretVec<T>
where
    T: Default + Clone,
{
    data: Vec<T>,
}

impl<T> SecretVec<T> 
where 
    T: Default + Clone,
{
    /// Create a new SecretVec from existing data
    pub fn new(data: Vec<T>) -> Self {
        Self { data }
    }
    
    /// Create a new SecretVec with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }
    
    /// Get a reference to the underlying data
    pub fn expose_secret(&self) -> &[T] {
        &self.data
    }
    
    /// Get a reference to the underlying data (alias for expose_secret)
    pub fn expose(&self) -> &[T] {
        &self.data
    }
    
    /// Get the length of the secret data
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if the secret data is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<T> Drop for SecretVec<T>
where
    T: Default + Clone,
{
    fn drop(&mut self) {
        // Overwrite with default values (typically zeros)
        for item in &mut self.data {
            *item = T::default();
        }
        
        // Additional security: try to prevent compiler optimizations
        // from removing the zeroing operation
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl<T> std::fmt::Debug for SecretVec<T>
where
    T: Default + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretVec([REDACTED {} bytes])", self.len())
    }
}

/// Key material container with automatic zeroization
#[derive(Debug)]
pub struct KeyMaterial {
    pub master_key: SecretVec<u8>,           // 32 bytes, auto-zeroized
    pub encryption_key: SecretVec<u8>,       // Derived from master for file encryption
    pub obfuscation_key: SecretVec<u8>,      // Derived from master for filename obfuscation
}

impl KeyMaterial {
    /// Create new key material from raw bytes
    pub fn new(
        master_key: Vec<u8>,
        encryption_key: Vec<u8>,
        obfuscation_key: Vec<u8>,
    ) -> Self {
        Self {
            master_key: SecretVec::new(master_key),
            encryption_key: SecretVec::new(encryption_key),
            obfuscation_key: SecretVec::new(obfuscation_key),
        }
    }
}

/// Securely allocate memory for sensitive data
/// 
/// This function attempts to use memory locking to prevent
/// sensitive data from being swapped to disk.
pub fn secure_alloc(size: usize) -> Result<Vec<u8>, CryptoError> {
    // TODO: Implement secure memory allocation with mlock
    // This is a placeholder for Phase 3 implementation
    Ok(vec![0u8; size])
}

/// Securely zeroize memory
/// 
/// This function ensures that memory is actually overwritten
/// and not optimized away by the compiler.
pub fn secure_zeroize(data: &mut [u8]) {
    // Overwrite with zeros
    for byte in data.iter_mut() {
        *byte = 0;
    }
    
    // Memory barrier to prevent compiler optimizations
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}