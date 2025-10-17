// shadow-core/src/v1/validation.rs
// V1 format-specific validation functions

use super::constants::{
    ALGORITHM_XCHACHA20_POLY1305, FILENAME_ENCRYPTED, FILENAME_PLAINTEXT, MAGIC,
    MAX_FILENAME_LENGTH, MIN_HEADER_SIZE,
};
use super::{FileHeader, FilenameData};
use crate::errors::ValidationError;
use subtle::ConstantTimeEq;

/// Constant-time equality comparison for security-sensitive data
/// Pure function that prevents timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Validate a complete v1 file header structure
/// Pure function - no side effects
pub fn validate_file_header(header: &FileHeader) -> Result<(), ValidationError> {
    // Check magic bytes using constant-time comparison
    if !constant_time_eq(&header.magic, MAGIC) {
        return Err(ValidationError::InvalidMagic {
            expected: *MAGIC,
            actual: header.magic,
        });
    }

    // Check algorithm ID
    if header.algorithm_id != ALGORITHM_XCHACHA20_POLY1305 {
        return Err(ValidationError::UnsupportedAlgorithm(header.algorithm_id));
    }

    // Check obfuscation flag
    match header.obfuscation_flag {
        FILENAME_PLAINTEXT | FILENAME_ENCRYPTED => {}
        _ => {
            return Err(ValidationError::InvalidObfuscationFlag(
                header.obfuscation_flag,
            ));
        }
    }

    // Validate filename data consistency with obfuscation flag
    validate_filename_data_consistency(&header.filename_data, header.obfuscation_flag)?;

    // Validate filename data content
    validate_filename_data_content(&header.filename_data)?;

    Ok(())
}

/// Validate raw v1 header bytes for basic structure requirements
/// Pure function - no side effects  
pub fn validate_header_bytes(data: &[u8]) -> Result<(), ValidationError> {
    if data.len() < MIN_HEADER_SIZE {
        return Err(ValidationError::InvalidHeader);
    }

    // Check magic bytes at the start
    if data.len() >= 8 {
        let magic_slice = &data[0..8];
        if !constant_time_eq(magic_slice, MAGIC) {
            return Err(ValidationError::InvalidMagic {
                expected: *MAGIC,
                actual: {
                    let mut actual = [0u8; 8];
                    actual.copy_from_slice(magic_slice);
                    actual
                },
            });
        }
    }

    Ok(())
}

/// Validate that filename data is consistent with obfuscation flag
/// Pure function - no side effects
fn validate_filename_data_consistency(
    filename_data: &FilenameData,
    obfuscation_flag: u8,
) -> Result<(), ValidationError> {
    match (filename_data, obfuscation_flag) {
        (FilenameData::Plaintext(_), FILENAME_PLAINTEXT) => Ok(()),
        (FilenameData::Encrypted { .. }, FILENAME_ENCRYPTED) => Ok(()),
        _ => Err(ValidationError::InvalidFilenameData),
    }
}

/// Validate filename data content requirements
/// Pure function - no side effects
fn validate_filename_data_content(filename_data: &FilenameData) -> Result<(), ValidationError> {
    match filename_data {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_validate_file_header_valid() {
        let header = create_valid_header();
        let result = validate_file_header(&header);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_file_header_invalid_magic() {
        let mut header = create_valid_header();
        header.magic = *b"INVALID1";
        let result = validate_file_header(&header);
        assert!(matches!(result, Err(ValidationError::InvalidMagic { .. })));
    }

    #[test]
    fn test_validate_file_header_invalid_algorithm() {
        let mut header = create_valid_header();
        header.algorithm_id = 0xFF;
        let result = validate_file_header(&header);
        assert!(matches!(
            result,
            Err(ValidationError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn test_validate_file_header_invalid_obfuscation_flag() {
        let mut header = create_valid_header();
        header.obfuscation_flag = 0xFF;
        let result = validate_file_header(&header);
        assert!(matches!(
            result,
            Err(ValidationError::InvalidObfuscationFlag(_))
        ));
    }

    #[test]
    fn test_validate_file_header_inconsistent_filename_data() {
        let mut header = create_valid_header();
        header.obfuscation_flag = FILENAME_ENCRYPTED; // But filename_data is plaintext
        let result = validate_file_header(&header);
        assert!(matches!(result, Err(ValidationError::InvalidFilenameData)));
    }

    #[test]
    fn test_validate_file_header_empty_filename() {
        let mut header = create_valid_header();
        header.filename_data = FilenameData::Plaintext(String::new());
        let result = validate_file_header(&header);
        assert!(matches!(result, Err(ValidationError::InvalidFilenameData)));
    }

    #[test]
    fn test_validate_header_bytes_too_short() {
        let short_data = &[0u8; 10]; // Less than MIN_HEADER_SIZE
        let result = validate_header_bytes(short_data);
        assert!(matches!(result, Err(ValidationError::InvalidHeader)));
    }

    #[test]
    fn test_validate_header_bytes_invalid_magic() {
        let mut data = vec![0u8; MIN_HEADER_SIZE];
        data[0..8].copy_from_slice(b"INVALID1");
        let result = validate_header_bytes(&data);
        assert!(matches!(result, Err(ValidationError::InvalidMagic { .. })));
    }

    #[test]
    fn test_validate_header_bytes_valid() {
        let mut data = vec![0u8; MIN_HEADER_SIZE];
        data[0..8].copy_from_slice(MAGIC);
        let result = validate_header_bytes(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_filename_data_consistency_plaintext_disabled() {
        let filename_data = FilenameData::Plaintext("test.txt".to_string());
        let result = validate_filename_data_consistency(&filename_data, FILENAME_PLAINTEXT);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_filename_data_consistency_encrypted_enabled() {
        let filename_data = FilenameData::Encrypted {
            ciphertext: vec![1, 2, 3],
            nonce: [0u8; 24],
        };
        let result = validate_filename_data_consistency(&filename_data, FILENAME_ENCRYPTED);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_filename_data_consistency_mismatch() {
        let filename_data = FilenameData::Plaintext("test.txt".to_string());
        let result = validate_filename_data_consistency(&filename_data, FILENAME_ENCRYPTED);
        assert!(matches!(result, Err(ValidationError::InvalidFilenameData)));
    }
}
