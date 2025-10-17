// shadow-encryption-core/src/validation.rs
// Encryption-specific validation functions
// All functions are pure - no side effects

use crate::types::EncryptionRequest;
use shadow_core::{ValidationError, validate_password_strength};

/// Validate encryption request for completeness and security
/// Pure function - no side effects
pub fn validate_encryption_request(request: &EncryptionRequest) -> Result<(), ValidationError> {
    // Validate password strength using shadow-core
    validate_password_strength(&request.password)?;
    
    // Validate content
    if request.content.is_empty() {
        return Err(ValidationError::EmptyFile);
    }
    
    // Validate metadata
    if request.metadata.original_name.is_empty() {
        return Err(ValidationError::InvalidFilenameData);
    }
    
    // Validate file size limits
    if request.metadata.size != request.content.len() as u64 {
        return Err(ValidationError::InvalidFileSize(request.metadata.size));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_core::{SecureString, FileMetadata};

    fn create_valid_request() -> EncryptionRequest {
        EncryptionRequest {
            content: vec![1, 2, 3, 4],
            metadata: FileMetadata {
                original_name: "test.txt".to_string(),
                content_hash: [0u8; 32],
                size: 4,
            },
            password: SecureString::new("correct horse battery staple".to_string()),
            obfuscate_filename: false,
            security_profile: shadow_core::SecurityProfile::Test,
        }
    }

    #[test]
    fn test_validate_encryption_request_valid() {
        let request = create_valid_request();
        let result = validate_encryption_request(&request);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_encryption_request_weak_password() {
        let mut request = create_valid_request();
        request.password = SecureString::new("123".to_string());
        let result = validate_encryption_request(&request);
        assert!(matches!(result, Err(ValidationError::WeakPassword { .. })));
    }

    #[test]
    fn test_validate_encryption_request_empty_content() {
        let mut request = create_valid_request();
        request.content = vec![];
        request.metadata.size = 0;
        let result = validate_encryption_request(&request);
        assert!(matches!(result, Err(ValidationError::EmptyFile)));
    }

    #[test]
    fn test_validate_encryption_request_empty_filename() {
        let mut request = create_valid_request();
        request.metadata.original_name = String::new();
        let result = validate_encryption_request(&request);
        assert!(matches!(result, Err(ValidationError::InvalidFilenameData)));
    }

    #[test]
    fn test_validate_encryption_request_size_mismatch() {
        let mut request = create_valid_request();
        request.metadata.size = 100; // Doesn't match content length
        let result = validate_encryption_request(&request);
        assert!(matches!(result, Err(ValidationError::InvalidFileSize(_))));
    }
}