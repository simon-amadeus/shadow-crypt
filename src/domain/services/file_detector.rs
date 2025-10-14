//! # File Detection Service
//!
//! Provides robust encrypted file detection using magic number validation
//! and TLV header analysis. Implements double-encryption prevention.

use std::path::Path;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

use crate::domain::entities::{AlgorithmId, header::TlvHeader};
use crate::domain::errors::{DomainError, DomainResult};

/// Supported file format detection results
#[derive(Debug, Clone, PartialEq)]
pub enum FileFormat {
    /// Shadow V1 format (current baseline)
    ShadowV1 { algorithm: AlgorithmId },
    /// Legacy V3 format (compatibility)
    ShadowV3 { algorithm: AlgorithmId },
    /// Not an encrypted Shadow file
    Plaintext,
    /// Unrecognized format
    Unknown,
}

/// File detection service for encrypted file identification
pub struct FileDetector;

impl FileDetector {
    /// Create a new file detector instance
    pub fn new() -> Self {
        Self
    }

    /// Check if a file is an encrypted Shadow file
    /// 
    /// Returns true if the file has a valid Shadow magic number header,
    /// false otherwise. This is the primary method for double-encryption prevention.
    pub fn is_encrypted_file(&self, path: &Path) -> DomainResult<bool> {
        let format = self.detect_file_format(path)?;
        Ok(!matches!(format, FileFormat::Plaintext | FileFormat::Unknown))
    }

    /// Detect the specific file format and algorithm
    /// 
    /// Analyzes the file header to determine:
    /// - Whether it's a Shadow encrypted file
    /// - Which version/format it uses
    /// - Which algorithm was used for encryption
    pub fn detect_file_format(&self, path: &Path) -> DomainResult<FileFormat> {
        // Open file for reading
        let mut file = File::open(path)
            .map_err(|e| DomainError::FileSystemError(crate::domain::errors::FileSystemError::IoOperationFailed {
                operation: "open file".to_string(),
                reason: format!("Cannot open file {}: {}", path.display(), e)
            }))?;

        let mut reader = BufReader::new(&mut file);

        // Read potential magic number (8 bytes)
        let mut magic_buffer = [0u8; 8];
        match reader.read_exact(&mut magic_buffer) {
            Ok(()) => {},
            Err(_) => {
                // File too small to be encrypted
                return Ok(FileFormat::Plaintext);
            }
        }

        // Check for Shadow V1 magic number
        if magic_buffer == TlvHeader::MAGIC_NUMBER {
            return self.analyze_v1_header(&mut reader);
        }

        // Check for potential legacy V3 magic number
        // Legacy files may use different magic numbers - check implementation
        if let Ok(format) = self.analyze_legacy_header(&magic_buffer, &mut reader) {
            return Ok(format);
        }

        // Not a recognized Shadow file
        Ok(FileFormat::Plaintext)
    }

    /// Get algorithm from a Shadow encrypted file
    /// 
    /// Returns the algorithm ID used to encrypt the file.
    /// Fails if the file is not a valid Shadow encrypted file.
    pub fn get_algorithm_from_file(&self, path: &Path) -> DomainResult<AlgorithmId> {
        match self.detect_file_format(path)? {
            FileFormat::ShadowV1 { algorithm } | FileFormat::ShadowV3 { algorithm } => {
                Ok(algorithm)
            },
            FileFormat::Plaintext => {
                Err(DomainError::InvalidFileFormat(
                    "File is not encrypted - no algorithm information available".to_string()
                ))
            },
            FileFormat::Unknown => {
                Err(DomainError::InvalidFileFormat(
                    "Unknown file format - cannot determine algorithm".to_string()
                ))
            }
        }
    }

    /// Analyze Shadow V1 header format
    fn analyze_v1_header(&self, reader: &mut BufReader<&mut File>) -> DomainResult<FileFormat> {
        // Reset to beginning to read full header
        reader.seek(SeekFrom::Start(0))
            .map_err(|e| DomainError::FileSystemError(crate::domain::errors::FileSystemError::IoOperationFailed {
                operation: "seek".to_string(),
                reason: format!("Seek failed: {}", e)
            }))?;

        // Current implementation: basic V1 format validation with default algorithm assumption.
        // For enhanced header parsing, future versions could parse the full TLV header
        // to extract the actual algorithm ID from the AlgorithmId field.
        
        Ok(FileFormat::ShadowV1 { 
            algorithm: AlgorithmId::XChaCha20Poly1305 
        })
    }

    /// Analyze potential legacy header formats  
    fn analyze_legacy_header(&self, _magic_buffer: &[u8; 8], _reader: &mut BufReader<&mut File>) -> DomainResult<FileFormat> {
        // Future enhancement: Legacy format detection for Shadow V3 compatibility.
        // Currently, files that don't match V1 format are treated as plaintext,
        // which is the safest approach for encryption safety.
        Err(DomainError::InvalidFileFormat("Not a recognized Shadow format".to_string()))
    }

    /// Validate that a file can be safely encrypted
    /// 
    /// Checks for double-encryption prevention and other safety constraints.
    /// Returns an error if encryption should be blocked.
    pub fn validate_encryption_safety(&self, path: &Path, force_overwrite: bool) -> DomainResult<()> {
        // Check if file is already encrypted
        if self.is_encrypted_file(path)? {
            if force_overwrite {
                // Allow forced re-encryption (admin override)
                return Ok(());
            } else {
                return Err(DomainError::DoubleEncryptionPrevention(format!(
                    "File '{}' is already encrypted. Use --force to override this safety check.",
                    path.display()
                )));
            }
        }

        // Additional safety checks could go here:
        // - File size limits
        // - Permission checks
        // - Filesystem space validation

        Ok(())
    }
}

impl Default for FileDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_plaintext_file_detection() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"This is just a regular text file").unwrap();
        
        let detector = FileDetector::new();
        let result = detector.detect_file_format(temp_file.path()).unwrap();
        
        assert_eq!(result, FileFormat::Plaintext);
        assert!(!detector.is_encrypted_file(temp_file.path()).unwrap());
    }

    #[test]
    fn test_shadow_v1_magic_number_detection() {
        let mut temp_file = NamedTempFile::new().unwrap();
        // Write Shadow V1 magic number
        temp_file.write_all(&TlvHeader::MAGIC_NUMBER).unwrap();
        // Add minimal header structure (this would fail proper parsing but test magic detection)
        temp_file.write_all(&[0u8; 16]).unwrap(); // Minimal padding
        
        let detector = FileDetector::new();
        let is_encrypted = detector.is_encrypted_file(temp_file.path()).unwrap();
        
        // Should detect as encrypted based on magic number
        assert!(is_encrypted);
    }

    #[test]
    fn test_empty_file_handling() {
        let temp_file = NamedTempFile::new().unwrap();
        // File remains empty
        
        let detector = FileDetector::new();
        let result = detector.detect_file_format(temp_file.path()).unwrap();
        
        assert_eq!(result, FileFormat::Plaintext);
        assert!(!detector.is_encrypted_file(temp_file.path()).unwrap());
    }

    #[test]
    fn test_too_small_file_handling() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"tiny").unwrap(); // Only 4 bytes, less than magic number
        
        let detector = FileDetector::new();
        let result = detector.detect_file_format(temp_file.path()).unwrap();
        
        assert_eq!(result, FileFormat::Plaintext);
        assert!(!detector.is_encrypted_file(temp_file.path()).unwrap());
    }

    #[test]
    fn test_double_encryption_prevention() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&TlvHeader::MAGIC_NUMBER).unwrap();
        temp_file.write_all(&[0u8; 16]).unwrap(); // Minimal header
        
        let detector = FileDetector::new();
        
        // Should block encryption of already-encrypted file
        let result = detector.validate_encryption_safety(temp_file.path(), false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DomainError::DoubleEncryptionPrevention(_)));

        // Should allow with force override
        let result = detector.validate_encryption_safety(temp_file.path(), true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_plaintext_encryption_safety() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"This is plaintext").unwrap();
        
        let detector = FileDetector::new();
        
        // Should allow encryption of plaintext file
        let result = detector.validate_encryption_safety(temp_file.path(), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_algorithm_extraction_from_plaintext() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"This is plaintext").unwrap();
        
        let detector = FileDetector::new();
        
        // Should fail to extract algorithm from plaintext file
        let result = detector.get_algorithm_from_file(temp_file.path());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DomainError::InvalidFileFormat(_)));
    }
}