// shadow-core/src/validation.rs
// Pure validation functions with no side effects

use crate::types::{EncryptionRequest, FileHeader, FilenameData};
use crate::errors::ValidationError;
use crate::crypto::constant_time_eq;

// Constants from specification
const MAGIC_BYTES: &[u8; 8] = b"SHADOW01";
const ALGORITHM_ID_XCHACHA20_POLY1305: u8 = 0x01;
const OBFUSCATION_FLAG_DISABLED: u8 = 0x00;
const OBFUSCATION_FLAG_ENABLED: u8 = 0x01;
const MIN_HEADER_SIZE: usize = 8 + 1 + 1 + 32 + 1 + 16 + 24; // Without filename data
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
const MAX_FILENAME_LENGTH: usize = 255;

/// Validate an encryption request before processing
/// Pure function - no side effects
pub fn validate_encryption_request(req: &EncryptionRequest) -> Result<(), ValidationError> {
    // Check password
    if req.password.is_empty() {
        return Err(ValidationError::EmptyPassword);
    }
    
    // Check file content
    if req.content.is_empty() {
        return Err(ValidationError::EmptyFile);
    }
    
    // Check file size limit
    if req.content.len() as u64 > MAX_FILE_SIZE {
        return Err(ValidationError::InvalidFileSize(req.content.len() as u64));
    }
    
    // Check filename length
    if req.metadata.original_name.is_empty() {
        return Err(ValidationError::InvalidFilenameData);
    }
    
    if req.metadata.original_name.len() > MAX_FILENAME_LENGTH {
        return Err(ValidationError::InvalidFilenameData);
    }
    
    // Check metadata consistency
    if req.metadata.size != req.content.len() as u64 {
        return Err(ValidationError::InvalidFileSize(req.metadata.size));
    }
    
    Ok(())
}

/// Validate a file header structure
/// Pure function - no side effects
pub fn validate_file_header(header: &FileHeader) -> Result<(), ValidationError> {
    // Check magic bytes
    if !constant_time_eq(&header.magic, MAGIC_BYTES) {
        return Err(ValidationError::InvalidMagic {
            expected: *MAGIC_BYTES,
            actual: header.magic,
        });
    }
    
    // Check algorithm ID
    if header.algorithm_id != ALGORITHM_ID_XCHACHA20_POLY1305 {
        return Err(ValidationError::UnsupportedAlgorithm(header.algorithm_id));
    }
    
    // Check obfuscation flag
    match header.obfuscation_flag {
        OBFUSCATION_FLAG_DISABLED | OBFUSCATION_FLAG_ENABLED => {}
        _ => return Err(ValidationError::InvalidObfuscationFlag(header.obfuscation_flag)),
    }
    
    // Validate filename data consistency with obfuscation flag
    match (&header.filename_data, header.obfuscation_flag) {
        (FilenameData::Plaintext(_), OBFUSCATION_FLAG_DISABLED) => {}
        (FilenameData::Encrypted { .. }, OBFUSCATION_FLAG_ENABLED) => {}
        _ => return Err(ValidationError::InvalidFilenameData),
    }
    
    // Validate filename data content
    match &header.filename_data {
        FilenameData::Plaintext(filename) => {
            if filename.is_empty() || filename.len() > MAX_FILENAME_LENGTH {
                return Err(ValidationError::InvalidFilenameData);
            }
        }
        FilenameData::Encrypted { ciphertext, .. } => {
            if ciphertext.is_empty() || ciphertext.len() > MAX_FILENAME_LENGTH {
                return Err(ValidationError::InvalidFilenameData);
            }
        }
    }
    
    Ok(())
}

/// Check if content hash already exists in a list of hashes
/// Pure function - no side effects
pub fn check_content_duplicate(
    content_hash: &[u8; 32],
    existing_hashes: &[[u8; 32]],
) -> bool {
    existing_hashes.iter().any(|hash| constant_time_eq(hash, content_hash))
}

/// Validate header bytes before parsing
/// Pure function - no side effects
pub fn validate_header_bytes(data: &[u8]) -> Result<(), ValidationError> {
    if data.len() < MIN_HEADER_SIZE {
        return Err(ValidationError::HeaderTooShort {
            expected: MIN_HEADER_SIZE,
            actual: data.len(),
        });
    }
    
    // Check magic bytes without full parsing
    if data.len() >= 8 && !constant_time_eq(&data[..8], MAGIC_BYTES) {
        let mut actual_magic = [0u8; 8];
        actual_magic.copy_from_slice(&data[..8]);
        return Err(ValidationError::InvalidMagic {
            expected: *MAGIC_BYTES,
            actual: actual_magic,
        });
    }
    
    Ok(())
}

/// Validate that content hash matches computed hash
/// Pure function - no side effects
pub fn validate_content_hash(
    content: &[u8],
    expected_hash: &[u8; 32],
) -> Result<(), ValidationError> {
    let computed_hash = crate::crypto::hash_content(content);
    
    if !constant_time_eq(&computed_hash, expected_hash) {
        return Err(ValidationError::ContentHashMismatch {
            expected: *expected_hash,
            actual: computed_hash,
        });
    }
    
    Ok(())
}

/// Validate filename for security and length constraints
/// Pure function - no side effects
pub fn validate_filename(filename: &str) -> Result<(), ValidationError> {
    if filename.is_empty() {
        return Err(ValidationError::InvalidFilenameData);
    }
    
    if filename.len() > MAX_FILENAME_LENGTH {
        return Err(ValidationError::InvalidFilenameData);
    }
    
    // Check for directory traversal attempts
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(ValidationError::InvalidFilenameData);
    }
    
    // Check for reserved characters/names (basic security check)
    let reserved_chars = ['<', '>', ':', '"', '|', '?', '*', '\0'];
    if filename.chars().any(|c| reserved_chars.contains(&c)) {
        return Err(ValidationError::InvalidFilenameData);
    }
    
    Ok(())
}

/// Validate password strength (basic checks)
/// Pure function - no side effects
pub fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    if password.is_empty() {
        return Err(ValidationError::EmptyPassword);
    }
    
    // Basic length check - minimum 8 characters recommended
    if password.len() < 8 {
        return Err(ValidationError::EmptyPassword); // Using existing error for simplicity
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EncryptionRequest, FileMetadata, SecureString, FileHeader, FilenameData};
    use crate::crypto::hash_content;

    fn create_valid_encryption_request() -> EncryptionRequest {
        let content = b"test content".to_vec();
        let content_hash = hash_content(&content);
        
        EncryptionRequest {
            metadata: FileMetadata {
                original_name: "test.txt".to_string(),
                content_hash,
                size: content.len() as u64,
            },
            content,
            password: SecureString::new("password123".to_string()),
            obfuscate_filename: false,
        }
    }

    fn create_valid_header(obfuscated: bool) -> FileHeader {
        let filename_data = if obfuscated {
            FilenameData::Encrypted {
                ciphertext: vec![1, 2, 3, 4],
                nonce: [5u8; 24],
            }
        } else {
            FilenameData::Plaintext("test.txt".to_string())
        };
        
        FileHeader {
            magic: *MAGIC_BYTES,
            algorithm_id: ALGORITHM_ID_XCHACHA20_POLY1305,
            obfuscation_flag: if obfuscated { OBFUSCATION_FLAG_ENABLED } else { OBFUSCATION_FLAG_DISABLED },
            content_hash: [42u8; 32],
            filename_data,
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        }
    }

    #[test]
    fn test_validate_encryption_request_valid() {
        let req = create_valid_encryption_request();
        assert!(validate_encryption_request(&req).is_ok());
    }

    #[test]
    fn test_validate_encryption_request_empty_password() {
        let mut req = create_valid_encryption_request();
        req.password = SecureString::new(String::new());
        
        let result = validate_encryption_request(&req);
        assert!(matches!(result, Err(ValidationError::EmptyPassword)));
    }

    #[test]
    fn test_validate_encryption_request_empty_file() {
        let mut req = create_valid_encryption_request();
        req.content = vec![];
        req.metadata.size = 0;
        
        let result = validate_encryption_request(&req);
        assert!(matches!(result, Err(ValidationError::EmptyFile)));
    }

    #[test]
    fn test_validate_encryption_request_size_mismatch() {
        let mut req = create_valid_encryption_request();
        req.metadata.size = 999; // Different from actual content size
        
        let result = validate_encryption_request(&req);
        assert!(matches!(result, Err(ValidationError::InvalidFileSize(_))));
    }

    #[test]
    fn test_validate_file_header_valid() {
        let header = create_valid_header(false);
        assert!(validate_file_header(&header).is_ok());
    }

    #[test]
    fn test_validate_file_header_valid_encrypted() {
        let header = create_valid_header(true);
        assert!(validate_file_header(&header).is_ok());
    }

    #[test]
    fn test_validate_file_header_invalid_magic() {
        let mut header = create_valid_header(false);
        header.magic = *b"BADMAGIC";
        
        let result = validate_file_header(&header);
        assert!(matches!(result, Err(ValidationError::InvalidMagic { .. })));
    }

    #[test]
    fn test_validate_file_header_unsupported_algorithm() {
        let mut header = create_valid_header(false);
        header.algorithm_id = 0xFF;
        
        let result = validate_file_header(&header);
        assert!(matches!(result, Err(ValidationError::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_validate_file_header_invalid_obfuscation_flag() {
        let mut header = create_valid_header(false);
        header.obfuscation_flag = 0xFF;
        
        let result = validate_file_header(&header);
        assert!(matches!(result, Err(ValidationError::InvalidObfuscationFlag(_))));
    }

    #[test]
    fn test_validate_file_header_filename_obfuscation_mismatch() {
        let mut header = create_valid_header(false);
        header.obfuscation_flag = OBFUSCATION_FLAG_ENABLED; // Mismatch with plaintext filename
        
        let result = validate_file_header(&header);
        assert!(matches!(result, Err(ValidationError::InvalidFilenameData)));
    }

    #[test]
    fn test_check_content_duplicate_found() {
        let content_hash = [42u8; 32];
        let existing_hashes = vec![[1u8; 32], [42u8; 32], [3u8; 32]];
        
        assert!(check_content_duplicate(&content_hash, &existing_hashes));
    }

    #[test]
    fn test_check_content_duplicate_not_found() {
        let content_hash = [42u8; 32];
        let existing_hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        
        assert!(!check_content_duplicate(&content_hash, &existing_hashes));
    }

    #[test]
    fn test_validate_header_bytes_too_short() {
        let data = vec![1, 2, 3]; // Too short
        let result = validate_header_bytes(&data);
        assert!(matches!(result, Err(ValidationError::HeaderTooShort { .. })));
    }

    #[test]
    fn test_validate_header_bytes_invalid_magic() {
        let mut data = vec![0u8; MIN_HEADER_SIZE];
        data[..8].copy_from_slice(b"BADMAGIC");
        
        let result = validate_header_bytes(&data);
        assert!(matches!(result, Err(ValidationError::InvalidMagic { .. })));
    }

    #[test]
    fn test_validate_content_hash_valid() {
        let content = b"test content";
        let hash = hash_content(content);
        
        assert!(validate_content_hash(content, &hash).is_ok());
    }

    #[test]
    fn test_validate_content_hash_mismatch() {
        let content = b"test content";
        let wrong_hash = [42u8; 32];
        
        let result = validate_content_hash(content, &wrong_hash);
        assert!(matches!(result, Err(ValidationError::ContentHashMismatch { .. })));
    }

    #[test]
    fn test_validate_filename_valid() {
        assert!(validate_filename("test.txt").is_ok());
        assert!(validate_filename("document.pdf").is_ok());
        assert!(validate_filename("file_name-123.zip").is_ok());
    }

    #[test]
    fn test_validate_filename_invalid() {
        assert!(validate_filename("").is_err()); // Empty
        assert!(validate_filename("../../../etc/passwd").is_err()); // Directory traversal
        assert!(validate_filename("file/name").is_err()); // Contains slash
        assert!(validate_filename("file\\name").is_err()); // Contains backslash
        assert!(validate_filename("file<name").is_err()); // Reserved character
        assert!(validate_filename("file>name").is_err()); // Reserved character
        assert!(validate_filename("file:name").is_err()); // Reserved character
        assert!(validate_filename("file\"name").is_err()); // Reserved character
        assert!(validate_filename("file|name").is_err()); // Reserved character
        assert!(validate_filename("file?name").is_err()); // Reserved character
        assert!(validate_filename("file*name").is_err()); // Reserved character
    }

    #[test]
    fn test_validate_filename_too_long() {
        let long_filename = "a".repeat(256);
        assert!(validate_filename(&long_filename).is_err());
    }

    #[test]
    fn test_validate_password_strength_valid() {
        assert!(validate_password_strength("password123").is_ok());
        assert!(validate_password_strength("VerySecurePassword!").is_ok());
    }

    #[test]
    fn test_validate_password_strength_invalid() {
        assert!(validate_password_strength("").is_err()); // Empty
        assert!(validate_password_strength("short").is_err()); // Too short
    }
}