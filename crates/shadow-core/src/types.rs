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

/// Complete encryption request containing all necessary data
#[derive(Debug, Clone)]
pub struct EncryptionRequest {
    pub content: Vec<u8>,
    pub metadata: FileMetadata,
    pub password: SecureString,
    pub obfuscate_filename: bool,
}

/// Result of encryption containing header, ciphertext, and suggested output filename
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    pub header: FileHeader,
    pub ciphertext: Vec<u8>,
    pub suggested_filename: String,
}

/// Complete file header as defined in SHADOW_SPECIFICATION_v1.0.md
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub magic: [u8; 8],          // "SHADOW01"
    pub algorithm_id: u8,        // 0x01 for XChaCha20-Poly1305
    pub obfuscation_flag: u8,    // 0x00 or 0x01
    pub content_hash: [u8; 32],  // SHA-256 of original content
    pub filename_data: FilenameData,
    pub salt: [u8; 16],          // Argon2id salt
    pub content_nonce: [u8; 24], // XChaCha20-Poly1305 nonce
}

/// Filename data that can be either plaintext or encrypted
#[derive(Debug, Clone)]
pub enum FilenameData {
    /// Plaintext filename when obfuscation is disabled
    Plaintext(String),
    /// Encrypted filename when obfuscation is enabled
    Encrypted {
        ciphertext: Vec<u8>,
        nonce: [u8; 24],
    },
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

    #[test]
    fn test_filename_data_plaintext() {
        let filename_data = FilenameData::Plaintext("test.txt".to_string());
        match filename_data {
            FilenameData::Plaintext(name) => assert_eq!(name, "test.txt"),
            _ => panic!("Expected plaintext filename"),
        }
    }

    #[test]
    fn test_filename_data_encrypted() {
        let ciphertext = vec![1, 2, 3, 4];
        let nonce = [5u8; 24];
        let filename_data = FilenameData::Encrypted {
            ciphertext: ciphertext.clone(),
            nonce,
        };
        match filename_data {
            FilenameData::Encrypted { ciphertext: ct, nonce: n } => {
                assert_eq!(ct, ciphertext);
                assert_eq!(n, nonce);
            },
            _ => panic!("Expected encrypted filename"),
        }
    }

    #[test]
    fn test_file_header_construction() {
        let header = FileHeader {
            magic: *b"SHADOW01",
            algorithm_id: 0x01,
            obfuscation_flag: 0x00,
            content_hash: [0u8; 32],
            filename_data: FilenameData::Plaintext("test.txt".to_string()),
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        };
        assert_eq!(&header.magic, b"SHADOW01");
        assert_eq!(header.algorithm_id, 0x01);
        assert_eq!(header.obfuscation_flag, 0x00);
    }
}