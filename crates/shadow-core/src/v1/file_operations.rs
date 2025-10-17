// shadow-core/src/v1/file_operations.rs
// High-level V1 file encryption/decryption operations
// Pure functions that combine multiple V1 operations

use crate::errors::{CryptoError, SerializationError, ValidationError};
use crate::security::SecurityProfile;
use crate::memory::SecureString;
use crate::FileMetadata;
use super::{
    FileHeader, FilenameData, create_v1_header, V1HeaderRequest, 
    serialize_header, deserialize_header, encrypt_content, decrypt_content
};

/// High-level file encryption operation for V1 format
/// Combines header creation, content encryption, and serialization
#[derive(Debug, thiserror::Error)]
pub enum FileOperationError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
}

/// Complete file encryption request
#[derive(Debug, Clone)]
pub struct EncryptFileRequest {
    pub content: Vec<u8>,
    pub original_filename: String,
    pub password: SecureString,
    pub obfuscate_filename: bool,
    pub security_profile: SecurityProfile,
}

/// Complete encrypted file result
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    pub header: FileHeader,
    pub ciphertext: Vec<u8>,
    pub suggested_filename: String,
}

/// Complete file decryption request
#[derive(Debug, Clone)]  
pub struct DecryptFileRequest {
    pub header_bytes: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub password: SecureString,
    pub security_profile: SecurityProfile,
}

/// Complete decrypted file result
#[derive(Debug, Clone)]
pub struct DecryptedFile {
    pub content: Vec<u8>,
    pub original_filename: String,
    pub metadata: FileMetadata,
}

/// Encrypt a complete file using V1 format
/// Pure function combining all V1 encryption operations
pub fn encrypt_file(request: EncryptFileRequest) -> Result<EncryptedFile, FileOperationError> {
    // Create content hash for metadata
    let content_hash = super::hash_content(&request.content);
    
    // Create V1 header with all version-specific logic
    let v1_request = V1HeaderRequest {
        original_filename: request.original_filename.clone(),
        content_hash,
        password: request.password.clone(),
        security_profile: request.security_profile,
        obfuscate_filename: request.obfuscate_filename,
    };
    
    let v1_result = create_v1_header(v1_request)?;

    // Serialize header for AAD
    let header_bytes = serialize_header(&v1_result.header)?;

    // Encrypt content with header as AAD
    let ciphertext = encrypt_content(&request.content, &v1_result.master_key, &v1_result.content_nonce, &header_bytes)?;

    // Generate suggested output filename
    let suggested_filename = if request.obfuscate_filename {
        generate_random_filename()
    } else {
        format!("{}.shadow", request.original_filename)
    };

    Ok(EncryptedFile {
        header: v1_result.header,
        ciphertext,
        suggested_filename,
    })
}

/// Decrypt a complete file using V1 format
/// Pure function combining all V1 decryption operations  
pub fn decrypt_file(request: DecryptFileRequest) -> Result<DecryptedFile, FileOperationError> {
    // Deserialize header
    let header = deserialize_header(&request.header_bytes)?;
    
    // Note: V1 always encrypts filenames in header, obfuscation flag only affects output filename
    // Use the security profile provided in the request
    
    // Extract filename based on encryption status
    let original_filename = match &header.filename_data {
        FilenameData::Plaintext(name) => name.clone(),
        FilenameData::Encrypted { ciphertext, nonce } => {
            // Derive master key from password and salt
            let master_key = super::derive_key(&request.password, &header.salt, request.security_profile)?;
            // Decrypt filename
            super::decrypt_filename(ciphertext, &master_key, nonce)?
        }
    };

    // Derive master key for content decryption
    let master_key = super::derive_key(&request.password, &header.salt, request.security_profile)?;
    
    // Decrypt content using header as AAD
    let content = decrypt_content(&request.ciphertext, &master_key, &header.content_nonce, &request.header_bytes)?;
    
    // Verify content hash
    let computed_hash = super::hash_content(&content);
    if computed_hash != header.content_hash {
        return Err(FileOperationError::Validation(ValidationError::ContentHashMismatch {
            expected: header.content_hash,
            actual: computed_hash,
        }));
    }

    // Create metadata
    let metadata = FileMetadata {
        original_name: original_filename.clone(),
        content_hash: header.content_hash,
        size: content.len() as u64,
    };

    Ok(DecryptedFile {
        content,
        original_filename,
        metadata,
    })
}

/// Generate random filename for obfuscation
fn generate_random_filename() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    std::ptr::addr_of!(hasher).hash(&mut hasher);
    format!("{:016x}.shadow", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecureString;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original_content = b"Hello, Shadow!".to_vec();
        let password = SecureString::new("correct horse battery staple".to_string());
        
        // Encrypt
        let encrypt_request = EncryptFileRequest {
            content: original_content.clone(),
            original_filename: "test.txt".to_string(),
            password: password.clone(),
            obfuscate_filename: false,
            security_profile: SecurityProfile::Test,
        };
        
        let encrypted = encrypt_file(encrypt_request).unwrap();
        
        // Debug: check what we created
        println!("Header filename_data: {:?}", encrypted.header.filename_data);
        println!("Header obfuscation_flag: {:?}", encrypted.header.obfuscation_flag);
        
        // Serialize header for decryption
        let header_bytes = serialize_header(&encrypted.header).unwrap();
        println!("Serialized header length: {}", header_bytes.len());
        
        // Decrypt
        let decrypt_request = DecryptFileRequest {
            header_bytes,
            ciphertext: encrypted.ciphertext,
            password,
            security_profile: SecurityProfile::Test,
        };
        
        let decrypted = decrypt_file(decrypt_request).unwrap();
        
        // Verify
        assert_eq!(decrypted.content, original_content);
        assert_eq!(decrypted.original_filename, "test.txt");
    }
}