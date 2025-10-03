//! V2 file format detection
//! 
//! This module provides detection capabilities for Shadow V2 file format

use std::fs::File;
use std::io::Read;
use std::path::Path;
use crate::shared::errors::CryptoError;
use crate::shared::versions::v2::header::MAGIC_NUMBER_V2;

/// Check if a file is a Shadow V2 encrypted file
/// 
/// # Arguments
/// * `file_path` - Path to the file to check
/// 
/// # Returns
/// * `Ok(true)` - File is a Shadow V2 file
/// * `Ok(false)` - File is not a Shadow V2 file
/// * `Err(CryptoError)` - Failed to read file
pub fn is_v2_file(file_path: &Path) -> Result<bool, CryptoError> {
    let mut file = File::open(file_path)
        .map_err(CryptoError::FileSystemError)?;
    
    // Read the magic number
    let mut magic = [0u8; 8];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic == MAGIC_NUMBER_V2),
        Err(_) => Ok(false), // File too small or read error means not V2
    }
}

/// Check if a byte slice starts with V2 magic number
/// 
/// # Arguments
/// * `data` - Byte slice to check
/// 
/// # Returns
/// * `true` - Data starts with V2 magic number
/// * `false` - Data does not start with V2 magic number
pub fn has_v2_magic(data: &[u8]) -> bool {
    data.len() >= 8 && data[0..8] == MAGIC_NUMBER_V2
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_v2_magic_detection() {
        assert!(has_v2_magic(&MAGIC_NUMBER_V2));
        assert!(!has_v2_magic(b"SHADOW1\0"));
        assert!(!has_v2_magic(b"NOTMAGIC"));
        assert!(!has_v2_magic(b"SHORT"));
    }

    #[test]
    fn test_v2_file_detection() {
        // Create a temporary file with V2 magic
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&MAGIC_NUMBER_V2).unwrap();
        temp_file.write_all(b"additional data").unwrap();
        temp_file.flush().unwrap();

        // Test detection
        assert!(is_v2_file(temp_file.path()).unwrap());
    }

    #[test]
    fn test_non_v2_file_detection() {
        // Create a temporary file with V1 magic
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"SHADOW1\0").unwrap();
        temp_file.flush().unwrap();

        // Test detection
        assert!(!is_v2_file(temp_file.path()).unwrap());
    }

    #[test]
    fn test_empty_file_detection() {
        // Create an empty temporary file
        let temp_file = NamedTempFile::new().unwrap();

        // Test detection
        assert!(!is_v2_file(temp_file.path()).unwrap());
    }
}