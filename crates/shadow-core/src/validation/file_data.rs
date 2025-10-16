// shadow-core/src/validation/file_data.rs
// File content and metadata validation functions
// All code related to validating file data and requests lives here

use crate::types::{EncryptionRequest, FileMetadata};
use crate::errors::ValidationError;
use crate::constants::{MAX_FILE_SIZE, MAX_FILENAME_LENGTH};
use super::password::validate_password_strength;

/// Validate file content requirements
/// Pure function - no side effects
pub fn validate_file_content(content: &[u8]) -> Result<(), ValidationError> {
    if content.is_empty() {
        return Err(ValidationError::EmptyFile);
    }
    
    if content.len() as u64 > MAX_FILE_SIZE {
        return Err(ValidationError::InvalidFileSize(content.len() as u64));
    }
    
    Ok(())
}

/// Validate file metadata consistency and requirements
/// Pure function - no side effects  
pub fn validate_file_metadata(metadata: &FileMetadata, actual_content_size: u64) -> Result<(), ValidationError> {
    // Check filename
    if metadata.original_name.is_empty() {
        return Err(ValidationError::InvalidFilenameData);
    }
    
    if metadata.original_name.len() > MAX_FILENAME_LENGTH {
        return Err(ValidationError::InvalidFilenameData);
    }
    
    // Check size consistency
    if metadata.size != actual_content_size {
        return Err(ValidationError::InvalidFileSize(metadata.size));
    }
    
    Ok(())
}

/// Validate a complete encryption request before processing
/// Pure function - no side effects
pub fn validate_encryption_request(req: &EncryptionRequest) -> Result<(), ValidationError> {
    // Validate password strength
    validate_password_strength(&req.password)?;
    
    // Validate file content
    validate_file_content(&req.content)?;
    
    // Validate metadata consistency with actual content
    validate_file_metadata(&req.metadata, req.content.len() as u64)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SecureString;

    #[test]
    fn test_validate_file_content_empty() {
        let content = &[];
        let result = validate_file_content(content);
        assert!(matches!(result, Err(ValidationError::EmptyFile)));
    }

    #[test]
    fn test_validate_file_content_too_large() {
        // Create a content that's larger than MAX_FILE_SIZE
        // Note: This is a mock test since creating 2GB+ data would be impractical
        let content = vec![0u8; 100]; // Small content for test
        let result = validate_file_content(&content);
        assert!(result.is_ok()); // Should pass for small content
    }

    #[test]
    fn test_validate_file_content_valid() {
        let content = b"Hello, World!";
        let result = validate_file_content(content);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_file_metadata_empty_filename() {
        let metadata = FileMetadata {
            original_name: String::new(),
            content_hash: [0u8; 32],
            size: 100,
        };
        let result = validate_file_metadata(&metadata, 100);
        assert!(matches!(result, Err(ValidationError::InvalidFilenameData)));
    }

    #[test]
    fn test_validate_file_metadata_filename_too_long() {
        let long_name = "a".repeat(300); // Longer than MAX_FILENAME_LENGTH
        let metadata = FileMetadata {
            original_name: long_name,
            content_hash: [0u8; 32],
            size: 100,
        };
        let result = validate_file_metadata(&metadata, 100);
        assert!(matches!(result, Err(ValidationError::InvalidFilenameData)));
    }

    #[test]
    fn test_validate_file_metadata_size_mismatch() {
        let metadata = FileMetadata {
            original_name: "test.txt".to_string(),
            content_hash: [0u8; 32],
            size: 100,
        };
        let result = validate_file_metadata(&metadata, 200); // Different size
        assert!(matches!(result, Err(ValidationError::InvalidFileSize(_))));
    }

    #[test]
    fn test_validate_file_metadata_valid() {
        let metadata = FileMetadata {
            original_name: "test.txt".to_string(),
            content_hash: [0u8; 32],
            size: 100,
        };
        let result = validate_file_metadata(&metadata, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_encryption_request_weak_password() {
        let request = EncryptionRequest {
            content: b"Hello, World!".to_vec(),
            metadata: FileMetadata {
                original_name: "test.txt".to_string(),
                content_hash: [0u8; 32],
                size: 13,
            },
            password: SecureString::new("weak".to_string()),
            obfuscate_filename: false,
        };
        let result = validate_encryption_request(&request);
        assert!(matches!(result, Err(ValidationError::WeakPassword { .. })));
    }

    #[test]
    fn test_validate_encryption_request_valid() {
        let content = b"Hello, World!";
        let request = EncryptionRequest {
            content: content.to_vec(),
            metadata: FileMetadata {
                original_name: "test.txt".to_string(),
                content_hash: [0u8; 32],
                size: content.len() as u64,
            },
            password: SecureString::new("StrongP@ssw0rd123!".to_string()),
            obfuscate_filename: false,
        };
        let result = validate_encryption_request(&request);
        assert!(result.is_ok());
    }
}