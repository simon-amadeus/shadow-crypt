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
        self.data.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for SecureBox<T> {
    fn clone(&self) -> Self {
        Self::new(self.data.as_ref().clone())
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
