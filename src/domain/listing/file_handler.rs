//! # Listing File Operations
//!
//! File I/O operations specific to the listing business capability.
//! Handles discovering and inspecting encrypted files.

use std::path::Path;
use crate::domain::shared::{EncryptedFilePath, TypedFilePath, FileMetadata};
use crate::domain::errors::DomainError;

/// Result type for listing file operations
pub type ListingFileResult<T> = Result<T, DomainError>;

/// File operations for listing workflows
pub trait ListingFileHandler: Send + Sync {
    /// Get filesystem metadata for any path
    fn get_file_metadata(&self, path: &Path) -> ListingFileResult<FileMetadata>;
    
    /// Detect file type and create appropriate typed path
    fn detect_file_type(&self, path: &Path) -> ListingFileResult<TypedFilePath>;
    
    /// Verify integrity of an encrypted file for listing
    fn verify_file_integrity(&self, path: &EncryptedFilePath) -> ListingFileResult<bool>;
    
    /// Discover encrypted files in a directory
    fn discover_encrypted_files(&self, directory: &Path) -> ListingFileResult<Vec<EncryptedFilePath>>;
    
    /// Get quick metadata without full file read
    fn get_encrypted_metadata(&self, path: &EncryptedFilePath) -> ListingFileResult<FileMetadata>;
}