// shadow-core/src/types.rs
// Core data types for the Shadow encryption system
// All types are pure data structures with no side effects

use zeroize::Zeroizing;

/// Secure string wrapper to encapsulate zeroize dependency for passwords
#[derive(Debug)]
pub struct SecureString(Zeroizing<String>);

impl SecureString {
    /// Create a new SecureString that will be zeroized when dropped
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
    
    /// Get a string slice of the contents
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    
    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for SecureString {
    fn clone(&self) -> Self {
        Self::new(self.0.as_str().to_string())
    }
}

/// Secure key wrapper for cryptographic keys
#[derive(Debug, Clone)]
pub struct SecureKey(Zeroizing<[u8; 32]>);

impl SecureKey {
    /// Create a new SecureKey that will be zeroized when dropped
    pub fn new(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }
    
    /// Get a slice of the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Secure bytes for sensitive data like derived keys or intermediate values
#[derive(Debug, Clone)]
pub struct SecureBytes(Zeroizing<Vec<u8>>);

impl SecureBytes {
    /// Create a new SecureBytes that will be zeroized when dropped
    pub fn new(data: Vec<u8>) -> Self {
        Self(Zeroizing::new(data))
    }
    
    /// Get a slice of the bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// File metadata containing original filename and content hash
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub original_name: String,
    pub content_hash: [u8; 32],  // SHA-256
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_basic() {
        let s = SecureString::new("test_password".to_string());
        assert_eq!(s.as_str(), "test_password");
        assert!(!s.is_empty());
        
        let empty = SecureString::new(String::new());
        assert!(empty.is_empty());
    }

    #[test]
    fn test_secure_string_clone() {
        let original = SecureString::new("test_password".to_string());
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn test_secure_key_basic() {
        let key_bytes = [42u8; 32];
        let key = SecureKey::new(key_bytes);
        assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn test_secure_key_clone() {
        let key_bytes = [42u8; 32];
        let original = SecureKey::new(key_bytes);
        let cloned = original.clone();
        assert_eq!(original.as_bytes(), cloned.as_bytes());
    }

    #[test]
    fn test_secure_bytes_basic() {
        let data = vec![1, 2, 3, 4, 5];
        let secure_data = SecureBytes::new(data.clone());
        assert_eq!(secure_data.as_slice(), data.as_slice());
    }

    #[test]
    fn test_file_metadata() {
        let metadata = FileMetadata {
            original_name: "test.txt".to_string(),
            content_hash: [0u8; 32],
            size: 1024,
        };
        assert_eq!(metadata.original_name, "test.txt");
        assert_eq!(metadata.size, 1024);
    }
}