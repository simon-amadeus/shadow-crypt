//! # FileRepository Interface
//!
//! Abstracts file system operations for testability and flexibility.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::Path;

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Abstracts file system operations with atomic operations and secure deletion
pub trait FileRepository: Send + Sync {
    /// Read file contents
    fn read_file(&self, path: &Path) -> CryptoResult<Vec<u8>>;
    
    /// Write file contents
    fn write_file(&self, path: &Path, content: &[u8]) -> CryptoResult<()>;
    
    /// Write file atomically (using temporary file)
    fn write_file_atomic(&self, path: &Path, content: &[u8]) -> CryptoResult<()>;
    
    /// Securely delete file 
    fn delete_file_secure(&self, path: &Path) -> CryptoResult<()>;
    
    /// Check if file exists
    fn file_exists(&self, path: &Path) -> bool;
}