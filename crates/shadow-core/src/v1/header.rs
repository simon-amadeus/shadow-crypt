// shadow-core/src/v1/header.rs
// V1-specific file header validation functions

use crate::errors::ValidationError;
use super::validation;
use super::types::FileHeader;

/// Validate a complete file header structure
/// V1-specific validation implementation
pub fn validate_file_header(header: &FileHeader) -> Result<(), ValidationError> {
    validation::validate_file_header(header)
}

/// Validate raw header bytes for basic structure requirements
/// V1-specific validation implementation
pub fn validate_header_bytes(data: &[u8]) -> Result<(), ValidationError> {
    validation::validate_header_bytes(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::constants::{
        ALGORITHM_XCHACHA20_POLY1305, FILENAME_PLAINTEXT, MAGIC,
    };
    use crate::v1::types::{FileHeader, FilenameData};

    fn create_valid_header() -> FileHeader {
        FileHeader {
            magic: *MAGIC,
            algorithm_id: ALGORITHM_XCHACHA20_POLY1305,
            obfuscation_flag: FILENAME_PLAINTEXT,
            content_hash: [0u8; 32],
            filename_data: FilenameData::Plaintext("test.txt".to_string()),
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        }
    }

    #[test]
    fn test_validate_file_header_delegates_to_v1() {
        let header = create_valid_header();
        let result = validate_file_header(&header);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_header_bytes_delegates_to_v1() {
        let mut data = vec![0u8; 100]; // Sufficient size
        data[0..8].copy_from_slice(MAGIC);
        let result = validate_header_bytes(&data);
        assert!(result.is_ok());
    }
}
