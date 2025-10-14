//! File metadata entity.
//!
//! Represents file system metadata and attributes with secure
//! handling of sensitive information for all file types.

use std::time::SystemTime;
use std::path::Path;
use std::fs;
use crate::domain::errors::{DomainError, FileSystemError};

/// File system metadata and attributes.
/// 
/// Contains file metadata for all file types including encrypted Shadow files.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Current filename
    pub filename: String,
    /// Current file size on disk (not original content size for encrypted files)
    pub file_size: u64,
    pub modified_time: SystemTime,
    pub created_time: Option<SystemTime>,
    pub file_type: FileType,
}

impl FileMetadata {
    /// Extract metadata from a file path with file type detection.
    pub fn from_path(path: &Path) -> Result<Self, DomainError> {
        let metadata = fs::metadata(path)
            .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed { 
                operation: "read file metadata".to_string(),
                reason: e.to_string() 
            }))?;
        
        let file_type = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_file() {
            FileType::Regular
        } else {
            // Check if it's a symlink (Unix-specific)
            #[cfg(unix)]
            {
                if metadata.file_type().is_symlink() {
                    FileType::Symlink
                } else {
                    FileType::Other
                }
            }
            #[cfg(not(unix))]
            {
                FileType::Other
            }
        };

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(Self {
            filename,
            file_size: metadata.len(),
            modified_time: metadata.modified()
                .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed { 
                    operation: "read file modification time".to_string(),
                    reason: e.to_string() 
                }))?,
            created_time: metadata.created().ok(),
            file_type,
        })
    }

    /// Create metadata with known values.
    pub fn new(
        filename: String,
        file_size: u64,
        modified_time: SystemTime,
        created_time: Option<SystemTime>,
        file_type: FileType,
    ) -> Self {
        Self {
            filename,
            file_size,
            modified_time,
            created_time,
            file_type,
        }
    }

    /// Detect if a file appears to be an encrypted Shadow file.
    fn is_shadow_file(path: &Path) -> bool {
        Self::has_shadow_magic_bytes(path)
    }

    /// Check if file starts with Shadow magic bytes.
    /// 
    /// This is the authoritative check for Shadow files - don't rely on extensions.
    fn has_shadow_magic_bytes(path: &Path) -> bool {
        use std::io::Read;
        use super::header::TlvHeader;

        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };

        let mut magic_buffer = [0u8; 6];
        match file.read_exact(&mut magic_buffer) {
            Ok(()) => magic_buffer == TlvHeader::MAGIC_NUMBER,
            Err(_) => false,
        }
    }

    /// Check if this file can be encrypted (regular file).
    pub fn can_be_encrypted(&self) -> bool {
        matches!(self.file_type, FileType::Regular)
    }

    /// Get the file type for pattern matching.
    pub fn file_type(&self) -> &FileType {
        &self.file_type
    }

    /// Check if this is a regular file (suitable for encryption).
    pub fn is_regular_file(&self) -> bool {
        matches!(self.file_type, FileType::Regular)
    }

    /// Get filename.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Get filename (alias for backwards compatibility).
    pub fn original_filename(&self) -> &str {
        &self.filename
    }
}

/// Type of file system entity.
#[derive(Debug, Clone)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Other,
}