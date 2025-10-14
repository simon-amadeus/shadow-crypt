//! File metadata entity.
//!
//! Represents file system metadata and attributes with secure
//! handling of sensitive information.

use std::time::SystemTime;
use std::path::Path;
use std::fs;
use super::memory::SecureBox;

/// File system metadata and attributes.
/// 
/// Contains file metadata with secure storage of the original filename
/// to prevent information disclosure.
#[derive(Debug)]
pub struct FileMetadata {
    /// Original filename - stored securely
    pub original_filename: SecureBox<String>,
    pub file_size: u64,
    pub modified_time: SystemTime,
    pub created_time: Option<SystemTime>,
    pub file_type: FileType,
}

impl FileMetadata {
    /// Extract metadata from a file path.
    pub fn from_path(path: &Path) -> Result<Self, std::io::Error> {
        let metadata = fs::metadata(path)?;
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

        let original_filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(Self {
            original_filename: SecureBox::new(original_filename),
            file_size: metadata.len(),
            modified_time: metadata.modified()?,
            created_time: metadata.created().ok(),
            file_type,
        })
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

impl Clone for FileMetadata {
    fn clone(&self) -> Self {
        Self {
            original_filename: self.original_filename.clone(),
            file_size: self.file_size,
            modified_time: self.modified_time,
            created_time: self.created_time,
            file_type: self.file_type.clone(),
        }
    }
}