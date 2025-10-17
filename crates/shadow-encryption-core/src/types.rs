// shadow-encryption-core/src/types.rs
// Encryption-specific types for the functional core
// Pure data structures with no side effects

use shadow_core::{SecureString, FileMetadata, FileHeader, SecurityProfile};

/// Complete encryption request containing all necessary data
/// Pure data structure - immutable and serializable
#[derive(Debug, Clone)]
pub struct EncryptionRequest {
    pub content: Vec<u8>,
    pub metadata: FileMetadata,
    pub password: SecureString,
    pub obfuscate_filename: bool,
    pub security_profile: SecurityProfile,
}

/// Result of encryption operation with header, ciphertext, and filename
/// Pure data structure - ready for serialization by shell layer
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    pub header: FileHeader,
    pub ciphertext: Vec<u8>,
    pub suggested_filename: String,
}

impl EncryptionRequest {
    /// Create a new encryption request
    /// Pure constructor function - no side effects
    pub fn new(
        content: Vec<u8>,
        metadata: FileMetadata,
        password: SecureString,
        obfuscate_filename: bool,
        security_profile: SecurityProfile,
    ) -> Self {
        Self {
            content,
            metadata,
            password,
            obfuscate_filename,
            security_profile,
        }
    }
}

impl EncryptedFile {
    /// Create a new encrypted file result
    /// Pure constructor function - no side effects
    pub fn new(
        header: FileHeader,
        ciphertext: Vec<u8>,
        suggested_filename: String,
    ) -> Self {
        Self {
            header,
            ciphertext,
            suggested_filename,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_request_creation() {
        let content = vec![1, 2, 3, 4];
        let metadata = FileMetadata {
            original_name: "test.txt".to_string(),
            content_hash: [0u8; 32],
            size: 4,
        };
        let password = SecureString::new("test_password".to_string());
        
        let request = EncryptionRequest::new(content.clone(), metadata.clone(), password, false, SecurityProfile::Test);
        
        assert_eq!(request.content, content);
        assert_eq!(request.metadata.original_name, "test.txt");
        assert_eq!(request.obfuscate_filename, false);
    }

    #[test]
    fn test_encrypted_file_creation() {
        let header = FileHeader {
            magic: *b"SHADOW01",
            algorithm_id: 0x01,
            obfuscation_flag: 0x00,
            content_hash: [0u8; 32],
            filename_data: shadow_core::FilenameData::Plaintext("test.txt".to_string()),
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        };
        let ciphertext = vec![5, 6, 7, 8];
        let filename = "test.txt.shadow".to_string();
        
        let encrypted = EncryptedFile::new(header.clone(), ciphertext.clone(), filename.clone());
        
        assert_eq!(encrypted.ciphertext, ciphertext);
        assert_eq!(encrypted.suggested_filename, filename);
        assert_eq!(encrypted.header.magic, *b"SHADOW01");
    }
}