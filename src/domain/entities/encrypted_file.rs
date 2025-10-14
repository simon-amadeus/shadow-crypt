//! # EncryptedFile Entity
//!
//! Represents a complete encrypted file with header and content.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use crate::domain::entities::version_matrix::{VersionMatrix, VersionCompatibility};
use crate::domain::entities::header::TlvHeader;
use crate::domain::entities::metadata::FileMetadata;
use crate::domain::entities::AlgorithmId;
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
    /// Missing algorithm ID in header
    MissingAlgorithm,
    /// Unsupported algorithm ID
    UnsupportedAlgorithm(u16),
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
            EncryptedFileError::MissingAlgorithm => {
                write!(f, "Algorithm ID is missing in the file header")
            }
            EncryptedFileError::UnsupportedAlgorithm(id) => {
                write!(f, "Algorithm ID {} is not supported", id)
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
    pub fn new(header: TlvHeader, ciphertext: Vec<u8>, original_metadata: FileMetadata) -> Self {
        Self {
            header,
            ciphertext,
            metadata: original_metadata,
            version_matrix: VersionMatrix::new_shadow_rewrite(),
        }
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

    /// Get the algorithm ID used for encryption
    pub fn algorithm(&self) -> Result<AlgorithmId, EncryptedFileError> {
        let raw_id = self.header.algorithm_id()
            .ok_or(EncryptedFileError::MissingAlgorithm)?;
        
        AlgorithmId::from_u16(raw_id)
            .map_err(|_| EncryptedFileError::UnsupportedAlgorithm(raw_id))
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
        use crate::domain::entities::metadata::FileType;
        
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

    fn verify_with_password(&self, _password: &str) -> Result<(), EncryptedFileError> {
        // Placeholder implementation - would attempt decryption to verify password
        Ok(())
    }
}
