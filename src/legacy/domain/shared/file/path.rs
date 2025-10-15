//! Typed file paths with compile-time guarantees.
//!
//! Provides type-safe file path handling that prevents invalid operations
//! like reading plaintext from encrypted files.

use std::path::{Path, PathBuf};
use super::metadata::FileMetadata;
use super::header::TlvHeader;
use crate::domain::errors::DomainError;

/// Type-safe file path that knows its content type at compile time.
#[derive(Debug, Clone)]
pub enum TypedFilePath {
    /// Path to a plaintext file that can be encrypted
    Plaintext(PlaintextFilePath),
    /// Path to an encrypted Shadow file that can be decrypted
    Encrypted(EncryptedFilePath),
}

/// Path to a verified plaintext file with its metadata.
#[derive(Debug, Clone)]
pub struct PlaintextFilePath {
    path: PathBuf,
    metadata: FileMetadata,
}

/// Path to a verified encrypted Shadow file with header and metadata.
#[derive(Debug, Clone)]
pub struct EncryptedFilePath {
    path: PathBuf,
    /// File system metadata (includes file size, timestamps, etc.)
    metadata: FileMetadata,
    /// TLV header containing encryption-specific metadata
    header: TlvHeader,
}

impl PlaintextFilePath {
    /// Create a new plaintext file path.
    /// 
    /// Validates that the file is a regular file suitable for encryption.
    pub fn new(path: PathBuf, metadata: FileMetadata) -> Result<Self, DomainError> {
        // Only regular files can be encrypted
        if !metadata.is_regular_file() {
            return Err(DomainError::InputValidationError(
                crate::domain::errors::InputValidationError::InvalidPath {
                    path: path.display().to_string(),
                    reason: "Only regular files can be encrypted".to_string(),
                }
            ));
        }

        Ok(Self { path, metadata })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }
}

impl EncryptedFilePath {
    /// Create a new encrypted file path with header and metadata.
    /// 
    /// The header contains all metadata for encrypted files.
    /// Note: Does not validate file type since encrypted files are detected by content.
    pub fn new(path: PathBuf, metadata: FileMetadata, header: TlvHeader) -> Result<Self, DomainError> {
        Ok(Self {
            path,
            metadata,
            header,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get file system metadata.
    pub fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }

    /// Get the original filename from metadata.
    pub fn original_filename(&self) -> &str {
        self.metadata.original_filename()
    }

    /// Get the TLV header containing encryption-specific metadata.
    pub fn header(&self) -> &TlvHeader {
        &self.header
    }

    /// Get algorithm ID from header.
    pub fn algorithm_id(&self) -> Option<u16> {
        self.header.algorithm_id()
    }
}

impl TypedFilePath {
    /// Create typed path from a raw Path by detecting file content.
    /// 
    /// This is the primary way to create typed paths - no FileHandler dependency.
    pub fn from_path(path: PathBuf) -> Result<Self, DomainError> {
        // Get basic filesystem metadata
        let metadata = FileMetadata::from_path(&path)?;
        
        // Only regular files can be processed
        if !metadata.is_regular_file() {
            return Err(DomainError::InputValidationError(
                crate::domain::errors::InputValidationError::InvalidPath {
                    path: path.display().to_string(),
                    reason: "Only regular files are supported for encryption operations".to_string(),
                }
            ));
        }

        // Check if it's an encrypted Shadow file
        if TlvHeader::is_shadow_file(&path) {
            // Read the header to create encrypted path
            let header = TlvHeader::from_file(&path)
                .map_err(|e| DomainError::InputValidationError(
                    crate::domain::errors::InputValidationError::InvalidPath {
                        path: path.display().to_string(),
                        reason: format!("Failed to read Shadow header: {}", e),
                    }
                ))?;
            Ok(Self::Encrypted(EncryptedFilePath::new(path, metadata, header)?))
        } else {
            // Regular plaintext file
            Ok(Self::Plaintext(PlaintextFilePath::new(path, metadata)?))
        }
    }

    /// Create plaintext typed path directly.
    pub fn plaintext(path: PathBuf, metadata: FileMetadata) -> Result<Self, DomainError> {
        Ok(Self::Plaintext(PlaintextFilePath::new(path, metadata)?))
    }

    /// Create encrypted typed path directly.
    pub fn encrypted(path: PathBuf, metadata: FileMetadata, header: TlvHeader) -> Result<Self, DomainError> {
        Ok(Self::Encrypted(EncryptedFilePath::new(path, metadata, header)?))
    }

    /// Get the underlying path.
    pub fn path(&self) -> &Path {
        match self {
            Self::Plaintext(p) => p.path(),
            Self::Encrypted(p) => p.path(),
        }
    }

    /// Check if this is a plaintext file.
    pub fn is_plaintext(&self) -> bool {
        matches!(self, Self::Plaintext(_))
    }

    /// Check if this is an encrypted file.
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted(_))
    }

    /// Extract plaintext path if available.
    pub fn as_plaintext(&self) -> Option<&PlaintextFilePath> {
        match self {
            Self::Plaintext(p) => Some(p),
            _ => None,
        }
    }

    /// Extract encrypted path if available.
    pub fn as_encrypted(&self) -> Option<&EncryptedFilePath> {
        match self {
            Self::Encrypted(p) => Some(p),
            _ => None,
        }
    }
}