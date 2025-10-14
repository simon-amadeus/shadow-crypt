//! # File Operations Domain Slice
//!
//! Core file I/O operations with atomic transactions and type safety.
//! This slice handles the boundary between domain entities and filesystem.

use std::path::Path;

use crate::domain::shared::{
    PlaintextFile,
    EncryptedFile,
    PlaintextFilePath, EncryptedFilePath, TypedFilePath,
    FileMetadata,
};
use crate::domain::errors::DomainError;

/// Result type for file operations
pub type FileResult<T> = Result<T, DomainError>;

/// Transaction handle for atomic multi-file operations
pub trait FileTransaction: Send + Sync {
    /// Commit all operations atomically
    fn commit(self: Box<Self>) -> FileResult<()>;
    
    /// Rollback all operations
    fn rollback(self: Box<Self>) -> FileResult<()>;
}

/// Core file operations service with atomic transactions
/// 
/// Handles the boundary between domain entities and filesystem storage.
/// Provides type-safe operations with atomic transaction support.
pub trait FileHandler: Send + Sync {
    /// Begin an atomic transaction for multiple operations
    fn begin_transaction(&self) -> FileResult<Box<dyn FileTransaction>>;

    // === Type-safe Read Operations ===
    
    /// Read plaintext file from filesystem into memory
    fn read_plaintext(&self, path: &PlaintextFilePath) -> FileResult<PlaintextFile>;
    
    /// Read encrypted file from filesystem into memory
    fn read_encrypted(&self, path: &EncryptedFilePath) -> FileResult<EncryptedFile>;

    // === Type-safe Write Operations ===
    
    /// Write plaintext file to filesystem
    fn write_plaintext(&self, file: &PlaintextFile, path: &PlaintextFilePath) -> FileResult<()>;
    
    /// Write encrypted file to filesystem
    fn write_encrypted(&self, file: &EncryptedFile, path: &EncryptedFilePath) -> FileResult<()>;
    
    /// Write encrypted file with backup
    fn write_encrypted_with_backup(
        &self, 
        file: &EncryptedFile, 
        path: &EncryptedFilePath,
        backup_suffix: &str
    ) -> FileResult<()>;

    // === File Management ===
    
    /// Delete file securely (overwrite before deletion)
    fn delete_secure(&self, path: &Path) -> FileResult<()>;
    
    /// Delete file normally
    fn delete(&self, path: &Path) -> FileResult<()>;

    // === File Discovery and Metadata ===
    
    /// Get filesystem metadata for any path
    fn get_metadata(&self, path: &Path) -> FileResult<FileMetadata>;
    
    /// Detect file type and create appropriate typed path
    fn detect_file_type(&self, path: &Path) -> FileResult<TypedFilePath>;
    
    /// Verify integrity of an encrypted file
    fn verify_integrity(&self, path: &EncryptedFilePath) -> FileResult<bool>;

    // === Batch Operations ===
    
    /// Write multiple encrypted files atomically
    fn write_encrypted_batch(&self, files: &[(&EncryptedFile, &EncryptedFilePath)]) -> FileResult<()>;
}

/// Builder for atomic file transactions
pub struct TransactionBuilder {
    operations: Vec<FileOperation>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    /// Add a read operation to the transaction
    pub fn read_plaintext(mut self, path: &PlaintextFilePath) -> Self {
        self.operations.push(FileOperation::ReadPlaintext(path.path().to_path_buf()));
        self
    }

    /// Add a read encrypted operation to the transaction
    pub fn read_encrypted(mut self, path: &EncryptedFilePath) -> Self {
        self.operations.push(FileOperation::ReadEncrypted(path.path().to_path_buf()));
        self
    }

    /// Add a write operation to the transaction
    pub fn write_plaintext(mut self, path: &PlaintextFilePath, size: u64) -> Self {
        self.operations.push(FileOperation::WritePlaintext(path.path().to_path_buf(), size));
        self
    }

    /// Add a write encrypted operation to the transaction
    pub fn write_encrypted(mut self, path: &EncryptedFilePath, size: u64) -> Self {
        self.operations.push(FileOperation::WriteEncrypted(path.path().to_path_buf(), size));
        self
    }

    /// Add a secure delete operation to the transaction
    pub fn delete_secure(mut self, path: &Path) -> Self {
        self.operations.push(FileOperation::DeleteSecure(path.to_path_buf()));
        self
    }

    /// Build the transaction plan
    pub fn build(self) -> Vec<FileOperation> {
        self.operations
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Types of file operations for transaction planning
#[derive(Debug, Clone)]
pub enum FileOperation {
    ReadPlaintext(std::path::PathBuf),
    ReadEncrypted(std::path::PathBuf),
    WritePlaintext(std::path::PathBuf, u64),
    WriteEncrypted(std::path::PathBuf, u64),
    DeleteSecure(std::path::PathBuf),
    Delete(std::path::PathBuf),
    GetMetadata(std::path::PathBuf),
    VerifyIntegrity(std::path::PathBuf),
}