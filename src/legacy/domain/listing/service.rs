//! # Listing Domain Slice
//!
//! Everything related to listing and inspecting encrypted files.
//! This slice encapsulates the file discovery and inspection capability.

use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::domain::shared::{
    AlgorithmId,
    EncryptedFilePath,
};
use crate::domain::errors::DomainError;

/// Result type for listing operations
pub type ListingResult<T> = Result<T, DomainError>;

/// Configuration for listing operations
#[derive(Debug, Clone)]
pub struct ListingOptions {
    /// Whether to verify passwords for each file
    pub verify_passwords: bool,
    /// Whether to include subdirectories recursively
    pub recursive: bool,
    /// Whether to show detailed metadata
    pub include_metadata: bool,
    /// File pattern filter (glob-style)
    pub pattern_filter: Option<String>,
}

impl Default for ListingOptions {
    fn default() -> Self {
        Self {
            verify_passwords: false,
            recursive: false,
            include_metadata: true,
            pattern_filter: None,
        }
    }
}

/// Information about a single encrypted file
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// Path to the encrypted file
    pub path: EncryptedFilePath,
    /// Original filename (None if password verification failed)
    pub original_filename: Option<String>,
    /// Algorithm used for encryption
    pub algorithm: AlgorithmId,
    /// File format version
    pub version: u16,
    /// File size in bytes
    pub size: u64,
    /// Last modified time
    pub modified: SystemTime,
    /// Whether the provided password can decrypt this file
    pub password_verified: bool,
    /// Content hash (if available and accessible)
    pub content_hash: Option<String>,
}

/// Result of a directory scan operation
#[derive(Debug, Clone)]
pub struct DirectoryListing {
    /// Directory that was scanned
    pub directory: std::path::PathBuf,
    /// List of encrypted files found
    pub files: Vec<FileInfo>,
    /// Time taken for the scan operation
    pub scan_duration: Duration,
    /// Number of files that couldn't be processed
    pub failed_files: usize,
    /// Options used for the scan
    pub scan_options: ListingOptions,
}

/// Core listing domain service
/// 
/// Defines what the domain needs for file discovery and inspection.
/// This service coordinates with file_operations for actual file access.
pub trait ListingService: Send + Sync {
    /// Scan a directory for encrypted files
    /// 
    /// Discovers and analyzes encrypted files in the given directory.
    /// May use file_operations slice for actual file access.
    fn scan_directory(
        &self,
        directory: &Path,
        password: Option<&str>,
        options: &ListingOptions,
    ) -> ListingResult<DirectoryListing>;

    /// Get detailed information about a single encrypted file
    /// 
    /// Inspects a specific file and extracts all available metadata.
    fn inspect_file(
        &self,
        file_path: &EncryptedFilePath,
        password: Option<&str>,
    ) -> ListingResult<FileInfo>;

    /// Find all encrypted files matching a pattern
    /// 
    /// Searches filesystem for Shadow encrypted files matching criteria.
    fn find_encrypted_files(
        &self,
        search_root: &Path,
        pattern: &str,
        recursive: bool,
    ) -> ListingResult<Vec<EncryptedFilePath>>;

    /// Quick check if a file appears to be an encrypted Shadow file
    /// 
    /// Fast check using magic bytes and file extension.
    fn is_encrypted_file(&self, path: &Path) -> ListingResult<bool>;
}