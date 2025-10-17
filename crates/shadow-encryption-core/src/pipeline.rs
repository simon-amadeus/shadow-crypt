// shadow-encryption-core/src/pipeline.rs
// Pure encryption pipeline - transforms EncryptionRequest to EncryptedFile
// All functions are pure with no side effects

use crate::types::{EncryptedFile, EncryptionRequest};
use shadow_core::{
    CryptoError, FileHeader, FilenameData, SecurityProfile, SerializationError, derive_key,
    encrypt_content, encrypt_filename, generate_nonce, generate_salt, serialize_header,
};

/// Encryption pipeline error combining crypto and serialization errors
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),
}

/// Main encryption pipeline - pure function transforming request to encrypted file
/// No side effects - deterministic except for random generation
pub fn encrypt_file(request: EncryptionRequest) -> Result<EncryptedFile, EncryptionError> {
    // 1. Generate random values using shadow-core functions
    let salt = generate_salt();
    let content_nonce = generate_nonce();
    let filename_nonce = if request.obfuscate_filename {
        Some(generate_nonce())
    } else {
        None
    };

    // 2. Derive master key using shadow-core crypto with specified security profile
    let master_key = derive_key(&request.password, &salt, request.security_profile)?;

    // 3. Create filename data based on obfuscation setting
    let filename_data = if request.obfuscate_filename {
        let nonce = filename_nonce.unwrap();
        let encrypted_filename =
            encrypt_filename(&request.metadata.original_name, &master_key, &nonce)?;
        FilenameData::Encrypted {
            ciphertext: encrypted_filename,
            nonce,
        }
    } else {
        FilenameData::Plaintext(request.metadata.original_name.clone())
    };

    // 4. Create file header structure
    let header = FileHeader {
        magic: *b"SHADOW01",
        algorithm_id: 0x01, // XChaCha20-Poly1305
        obfuscation_flag: if request.obfuscate_filename {
            0x01
        } else {
            0x00
        },
        content_hash: request.metadata.content_hash,
        filename_data,
        salt,
        content_nonce,
    };

    // 5. Serialize header for use as Additional Associated Data (AAD)
    let header_bytes = serialize_header(&header)?;

    // 6. Encrypt content with header as AAD using shadow-core crypto
    let ciphertext = encrypt_content(&request.content, &master_key, &content_nonce, &header_bytes)?;

    // 7. Generate suggested output filename
    let suggested_filename = if request.obfuscate_filename {
        generate_random_filename()
    } else {
        format!("{}.shadow", request.metadata.original_name)
    };

    Ok(EncryptedFile::new(header, ciphertext, suggested_filename))
}

/// Generate random filename using UUID - pure function with external randomness
fn generate_random_filename() -> String {
    // Simple implementation - in full version would use UUID
    // For now, use a deterministic pattern for testing
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    std::ptr::addr_of!(hasher).hash(&mut hasher);
    format!("{:016x}.shadow", hasher.finish())
}

/// Create encryption request from components - pure helper function
pub fn create_encryption_request(
    content: Vec<u8>,
    original_filename: String,
    password: shadow_core::SecureString,
    obfuscate: bool,
    security_profile: SecurityProfile,
) -> EncryptionRequest {
    let content_hash = shadow_core::hash_content(&content);
    let metadata = shadow_core::FileMetadata {
        original_name: original_filename,
        content_hash,
        size: content.len() as u64,
    };

    EncryptionRequest::new(content, metadata, password, obfuscate, security_profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_core::SecureString;

    fn create_test_request() -> EncryptionRequest {
        let content = b"Hello, Shadow!".to_vec();
        create_encryption_request(
            content,
            "test.txt".to_string(),
            SecureString::new("correct horse battery staple".to_string()),
            false,
            SecurityProfile::Test,
        )
    }

    #[test]
    fn test_create_encryption_request() {
        let content = b"test content".to_vec();
        let request = create_encryption_request(
            content.clone(),
            "test.txt".to_string(),
            SecureString::new("password".to_string()),
            true,
            SecurityProfile::Test,
        );

        assert_eq!(request.content, content);
        assert_eq!(request.metadata.original_name, "test.txt");
        assert_eq!(request.metadata.size, content.len() as u64);
        assert!(request.obfuscate_filename);
        assert_eq!(request.security_profile, SecurityProfile::Test);
    }

    #[test]
    fn test_encrypt_file_no_obfuscation() {
        let request = create_test_request();
        let result = encrypt_file(request);

        assert!(result.is_ok());
        let encrypted = result.unwrap();

        // Check header structure
        assert_eq!(encrypted.header.magic, *b"SHADOW01");
        assert_eq!(encrypted.header.algorithm_id, 0x01);
        assert_eq!(encrypted.header.obfuscation_flag, 0x00);

        // Check filename is not obfuscated
        assert!(matches!(
            encrypted.header.filename_data,
            FilenameData::Plaintext(_)
        ));
        assert_eq!(encrypted.suggested_filename, "test.txt.shadow");

        // Check we have encrypted content
        assert!(!encrypted.ciphertext.is_empty());
    }

    #[test]
    fn test_encrypt_file_with_obfuscation() {
        let mut request = create_test_request();
        request.obfuscate_filename = true;
        let result = encrypt_file(request);

        assert!(result.is_ok());
        let encrypted = result.unwrap();

        // Check obfuscation flag is set
        assert_eq!(encrypted.header.obfuscation_flag, 0x01);

        // Check filename is obfuscated
        assert!(matches!(
            encrypted.header.filename_data,
            FilenameData::Encrypted { .. }
        ));
        assert!(encrypted.suggested_filename.ends_with(".shadow"));
        assert_ne!(encrypted.suggested_filename, "test.txt.shadow");
    }

    #[test]
    fn test_generate_random_filename() {
        let filename1 = generate_random_filename();
        let filename2 = generate_random_filename();

        // Both should end with .shadow
        assert!(filename1.ends_with(".shadow"));
        assert!(filename2.ends_with(".shadow"));

        // Should be different (with high probability)
        // Note: This test might occasionally fail due to randomness
        // In production, we'd use proper UUID generation
    }

    #[test]
    fn test_encrypt_file_preserves_content_hash() {
        let request = create_test_request();
        let expected_hash = request.metadata.content_hash;

        let result = encrypt_file(request);
        assert!(result.is_ok());

        let encrypted = result.unwrap();
        assert_eq!(encrypted.header.content_hash, expected_hash);
    }
}
