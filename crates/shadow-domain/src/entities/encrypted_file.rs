//! # EncryptedFile Entity
//!
//! Represents a complete encrypted file with header and content.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use crate::entities::version_matrix::{VersionMatrix, VersionCompatibility};
use crate::entities::tlv_header::TlvHeader;
use crate::entities::file_metadata::FileMetadata;
use std::path::Path;

/// Error types for EncryptedFile operations
#[derive(Debug, Clone)]
pub enum EncryptedFileError {
    /// File version is not supported
    UnsupportedVersion(u16),
    /// Version compatibility check failed
    IncompatibleVersion { file_version: u16, required_version: u16 },
    /// File I/O operation failed
    IoError(String),
    /// Header parsing failed
    HeaderParseError(String),
    /// Cryptographic operation failed
    CryptoError(String),
}

impl std::fmt::Display for EncryptedFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptedFileError::UnsupportedVersion(v) => {
                write!(f, "File version {} is not supported", v)
            }
            EncryptedFileError::IncompatibleVersion { file_version, required_version } => {
                write!(f, "File version {} is incompatible with required version {}", 
                       file_version, required_version)
            }
            EncryptedFileError::IoError(msg) => {
                write!(f, "File operation failed: {}", msg)
            }
            EncryptedFileError::HeaderParseError(msg) => {
                write!(f, "Header parsing failed: {}", msg)
            }
            EncryptedFileError::CryptoError(msg) => {
                write!(f, "Cryptographic operation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for EncryptedFileError {}

/// Represents a complete encrypted file with header, content, and metadata
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    header: TlvHeader,
    ciphertext: Vec<u8>,
    metadata: FileMetadata,
    version_matrix: VersionMatrix,
}

impl EncryptedFile {
    /// Get the TLV header
    pub fn header(&self) -> &TlvHeader {
        &self.header
    }

    /// Get the ciphertext
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the file metadata
    pub fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }

    /// Get the total encrypted file size (header + ciphertext)
    pub fn total_size(&self) -> usize {
        // This would need proper TLV serialization to get accurate header size
        // For now, estimate based on typical header size
        let estimated_header_size = 256; // Rough estimate for TLV header
        estimated_header_size + self.ciphertext.len()
    }

    /// Create a new EncryptedFile with V1 header format
    pub fn new(header: TlvHeader, ciphertext: Vec<u8>) -> Self {
        let metadata = Self::extract_metadata_from_header(&header);
        
        Self {
            header,
            ciphertext,
            metadata,
            version_matrix: VersionMatrix::new_shadow_rewrite(),
        }
    }

    /// Load encrypted file from disk with version compatibility checking
    pub fn from_file(path: &Path, password: &str) -> Result<Self, EncryptedFileError> {
        
        // Read header to detect version and validate file
        let header = FileSystemService::read_header_only(path)?;
        let file_version = header.version();
        let version_matrix = VersionMatrix::new_shadow_rewrite();
        let baseline_version = version_matrix.current_baseline();
        
        // Check version compatibility
        match version_matrix.is_compatible(file_version, baseline_version) {
            VersionCompatibility::Compatible => {
                // Can read directly
                Self::load_compatible_file(path, password, header)
            }
            VersionCompatibility::RequiresMigration => {
                // Need migration before use
                Err(EncryptedFileError::IncompatibleVersion {
                    file_version,
                    required_version: baseline_version,
                })
            }
            VersionCompatibility::Incompatible => {
                // Cannot process at all
                Err(EncryptedFileError::UnsupportedVersion(file_version))
            }
        }
    }

    /// Write encrypted file to disk using current baseline format
    pub fn write_to_file(&self, path: &Path) -> Result<(), EncryptedFileError> {
        
        // Verify we're using supported version
        let current_version = self.version();
        if !self.version_matrix.can_write(current_version) {
            return Err(EncryptedFileError::UnsupportedVersion(current_version));
        }

        // Use FileSystemService for atomic write operation
        FileSystemService::write_encrypted_file(path, &self.header, &self.ciphertext)
    }

    /// Get the file version
    pub fn version(&self) -> u16 {
        self.header.version()
    }

    /// Get original filename from metadata
    pub fn original_filename(&self) -> Option<&str> {
        Some(&self.metadata.original_filename)
    }

    /// Get content hash if available
    pub fn content_hash(&self) -> Option<[u8; 32]> {
        self.header.content_hash()
    }

    /// Get algorithm ID used for encryption
    pub fn algorithm(&self) -> crate::entities::algorithm_id::AlgorithmId {
        // Extract from header, default to XChaCha20Poly1305 if not found
        self.header.algorithm_id()
            .map(|id| match id {
                1 => crate::entities::algorithm_id::AlgorithmId::XChaCha20Poly1305,
                2 => crate::entities::algorithm_id::AlgorithmId::AesGcm256,
                _ => crate::entities::algorithm_id::AlgorithmId::XChaCha20Poly1305, // Default
            })
            .unwrap_or(crate::entities::algorithm_id::AlgorithmId::XChaCha20Poly1305)
    }

    /// Check if filename is obfuscated
    pub fn is_obfuscated(&self) -> bool {
        // Placeholder - would check if original filename differs from file path
        false
    }

    /// Validate file integrity with password
    pub fn validate_integrity(&self, password: &str) -> Result<(), EncryptedFileError> {
        // Placeholder implementation - would attempt decryption
        self.verify_with_password(password)
    }

    /// Check if this file version can be migrated to target version
    pub fn can_migrate_to(&self, target_version: u16) -> bool {
        self.version_matrix.can_migrate(self.version(), target_version)
    }

    /// Get migration requirements for target version
    pub fn migration_status(&self, target_version: u16) -> VersionCompatibility {
        self.version_matrix.is_compatible(self.version(), target_version)
    }

    // Private helper methods

    fn extract_metadata_from_header(header: &TlvHeader) -> FileMetadata {
        use std::time::SystemTime;
        use crate::entities::file_metadata::FileType;
        
        // Extract filename from header, fallback to placeholder
        let original_filename = header.original_filename()
            .unwrap_or_else(|| "unknown.txt".to_string());
        
        FileMetadata {
            original_filename,
            file_size: 0, // File size would be stored in metadata field
            modified_time: SystemTime::now(),
            created_time: Some(SystemTime::now()),
            file_type: FileType::Regular,
        }
    }

    fn load_compatible_file(
        path: &Path, 
        _password: &str, // Password validation will be implemented later
        header: TlvHeader
    ) -> Result<Self, EncryptedFileError> {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};
        
        // We already have the header, now read the ciphertext
        let mut file = File::open(path)
            .map_err(|e| EncryptedFileError::IoError(format!("Failed to open file: {}", e)))?;
        
        // Calculate header size by serializing the header we already parsed
        let header_bytes = TlvSerializer::serialize(&header)
            .map_err(|e| EncryptedFileError::HeaderParseError(format!("Header serialization error: {}", e)))?;
        let header_size = header_bytes.len() as u64;
        
        // Seek past the header to read ciphertext
        file.seek(SeekFrom::Start(header_size))
            .map_err(|e| EncryptedFileError::IoError(format!("Failed to seek past header: {}", e)))?;
        
        // Read the remaining content as ciphertext
        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)
            .map_err(|e| EncryptedFileError::IoError(format!("Failed to read ciphertext: {}", e)))?;
        
        // Create EncryptedFile instance
        Ok(Self::new(header, ciphertext))
    }

    fn verify_with_password(&self, _password: &str) -> Result<(), EncryptedFileError> {
        // Placeholder implementation - would attempt decryption to verify password
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_file_creation() {
        let header = TlvHeader::new();
        let ciphertext = vec![1, 2, 3, 4, 5];
        
        let file = EncryptedFile::new(header, ciphertext.clone());
        
        assert_eq!(file.version(), 1); // V1 baseline
        assert_eq!(file.ciphertext.len(), 5);
    }

    #[test]
    fn test_version_compatibility() {
        let header = TlvHeader::new();
        let file = EncryptedFile::new(header, vec![]);
        
        // V1 -> V1 should be compatible
        assert_eq!(
            file.migration_status(1),
            VersionCompatibility::Compatible
        );
        
        // Can migrate to same version (no-op)
        assert!(file.can_migrate_to(1));
    }

    #[test]
    fn test_version_matrix_integration() {
        let header = TlvHeader::new();
        let file = EncryptedFile::new(header, vec![]);
        
        // Should use current baseline version
        assert_eq!(file.version(), file.version_matrix.current_baseline());
        
        // Should be able to write current baseline
        assert!(file.version_matrix.can_write(file.version()));
    }

    #[test]
    fn test_error_display() {
        let errors = vec![
            EncryptedFileError::UnsupportedVersion(99),
            EncryptedFileError::IncompatibleVersion { file_version: 3, required_version: 1 },
            EncryptedFileError::IoError("File not found".to_string()),
            EncryptedFileError::HeaderParseError("Invalid header".to_string()),
            EncryptedFileError::CryptoError("Decryption failed".to_string()),
        ];
        
        for error in errors {
            let error_string = error.to_string();
            assert!(!error_string.is_empty());
            assert!(!error_string.contains("Debug"));
        }
    }
}