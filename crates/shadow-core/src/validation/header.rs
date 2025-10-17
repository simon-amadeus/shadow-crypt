// shadow-core/src/validation/header.rs
// File header validation functions - delegates to format-specific modules

use crate::errors::ValidationError;
use crate::format::v1;

/// Validate a complete file header structure
/// Currently delegates to v1 format validation
pub fn validate_file_header(header: &v1::FileHeader) -> Result<(), ValidationError> {
    v1::validate_file_header(header)
}

/// Validate raw header bytes for basic structure requirements
/// Currently delegates to v1 format validation
pub fn validate_header_bytes(data: &[u8]) -> Result<(), ValidationError> {
    v1::validate_header_bytes(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::v1::{
        ALGORITHM_XCHACHA20_POLY1305, FILENAME_PLAINTEXT, FileHeader, FilenameData, MAGIC,
    };

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
