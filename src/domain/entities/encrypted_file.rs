//! # EncryptedFile Entity - Pure Immutable Entity
//!
//! Represents a complete encrypted file - immutable after creation
//! Based on specs/DOMAIN_ARCHITECTURE.md

use crate::domain::entities::version_matrix::{VersionMatrix, VersionCompatibility};
use crate::domain::entities::header::TlvHeader;
use crate::domain::entities::metadata::FileMetadata;
use crate::domain::entities::AlgorithmId;

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

/// Represents a complete encrypted file - immutable after creation
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    header: TlvHeader,
    ciphertext: Vec<u8>,
    metadata: FileMetadata,
    version_matrix: VersionMatrix,
}

impl EncryptedFile {
    /// Create a new EncryptedFile (should only be called by encryption services)
    /// All validation should be done before calling this constructor
    pub fn new(
        header: TlvHeader, 
        ciphertext: Vec<u8>, 
        metadata: FileMetadata
    ) -> Self {
        Self {
            header,
            ciphertext,
            metadata,
            version_matrix: VersionMatrix::new_shadow_rewrite(),
        }
    }

    /// Read-only accessors
    pub fn header(&self) -> &TlvHeader {
        &self.header
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }

    pub fn total_size(&self) -> usize {
        self.header.serialized_size() + self.ciphertext.len()
    }

    /// Derived properties (computed from immutable data)
    pub fn version(&self) -> u16 {
        self.header.version()
    }

    pub fn original_filename(&self) -> Option<&str> {
        self.metadata.original_filename.as_str().into()
    }

    pub fn algorithm(&self) -> Result<AlgorithmId, EncryptedFileError> {
        let raw_id = self.header.algorithm_id()
            .ok_or(EncryptedFileError::MissingAlgorithm)?;
        
        AlgorithmId::from_u16(raw_id)
            .map_err(|_| EncryptedFileError::UnsupportedAlgorithm(raw_id))
    }

    /// Version compatibility queries
    pub fn can_migrate_to(&self, target_version: u16) -> bool {
        self.version_matrix.can_migrate(self.version(), target_version)
    }

    pub fn migration_status(&self, target_version: u16) -> VersionCompatibility {
        self.version_matrix.is_compatible(self.version(), target_version)
    }
}

// Remove all the mutable methods and construction logic
// These should move to domain services like:
// - EncryptionService::encrypt_file() -> Result<EncryptedFile, _>
// - DecryptionService::decrypt_file() -> Result<Vec<u8>, _>
// - FileHeaderBuilder::build() -> Result<TlvHeader, _>
