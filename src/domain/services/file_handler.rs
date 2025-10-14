//! File system operations abstraction.
//!
//! Provides testable file operations with atomic writes and secure deletion.
//! Uses type-safe file paths to prevent invalid operations at compile time.
//!
//! # Transaction Example
//!
//! ```rust
//! let transaction_ops = FileHandler::transaction_builder()
//!     .verify_integrity("file1.txt")
//!     .read_file("file1.txt")
//!     .write_file("file1.shadow", 1024)
//!     .delete_secure("file1.txt")
//!     .commit();
//! ```

use std::path::Path;

use crate::domain::shared::{
    PlaintextFile, EncryptedFile,
    FileMetadata,
    PlaintextFilePath, EncryptedFilePath,
};
use crate::domain::errors::DomainError;

/// Result type for file operations.
pub type FileResult<T> = Result<T, DomainError>;

/// Transaction handle for atomic multi-file operations.
pub trait FileTransaction {
    fn commit(self) -> FileResult<()>;
    fn rollback(self) -> FileResult<()>;
}

/// File system operations with type-safe paths and atomic writes.
pub trait FileHandler: Send + Sync {
    fn begin_transaction(&self) -> FileResult<Box<dyn FileTransaction>>;

    /// Create a transaction builder for complex atomic operations.
    fn transaction_builder() -> TransactionBuilder {
        TransactionBuilder::new()
    }

    // === Core Operations ===
    
    /// Get metadata for any file type (filesystem metadata only).
    /// 
    /// Note: Use TypedFilePath::from_path() for file type detection and typed paths.
    fn get_metadata(&self, path: &Path) -> FileResult<FileMetadata>;

    /// Read plaintext file - compile-time guarantee that path contains plaintext.
    fn read_plaintext_file(&self, path: &PlaintextFilePath) -> FileResult<PlaintextFile>;
    
    /// Read encrypted file - compile-time guarantee that path contains encrypted data.
    fn read_encrypted_file(&self, path: &EncryptedFilePath) -> FileResult<EncryptedFile>;

    // === Write Operations ===
    
    fn write_plaintext_file(&self, file: &PlaintextFile) -> FileResult<()>;
    fn write_encrypted_file(&self, file: &EncryptedFile) -> FileResult<()>;
    fn write_encrypted_file_with_backup(&self, file: &EncryptedFile, backup_suffix: &str) -> FileResult<()>;

    // === Batch Operations ===
    
    fn write_encrypted_files_batch(&self, files: &[&EncryptedFile]) -> FileResult<()>;

    // === File Management ===
    
    fn delete_file_secure(&self, path: &Path) -> FileResult<()>;
    fn delete_file(&self, path: &Path) -> FileResult<()>;

    /// Verify file integrity (type-safe for encrypted files only).
    fn verify_file_integrity(&self, path: &EncryptedFilePath) -> FileResult<bool>;
}

/// File operation types for logging and testing.
#[derive(Debug, Clone, PartialEq)]
pub enum FileOperation {
    Read(String),
    Write(String, usize),
    WriteAtomic(String, usize),
    WriteBatch(Vec<String>, usize),
    DeleteSecure(String),
    Delete(String),
    CheckExists(String),
    GetMetadata(String),
    VerifyIntegrity(String),
    BeginTransaction,
    CommitTransaction,
    RollbackTransaction,
}

/// Builder for constructing atomic transactions with type safety.
pub struct TransactionBuilder {
    operations: Vec<FileOperation>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            operations: vec![FileOperation::BeginTransaction],
        }
    }

    /// Get metadata operation (replaces detect_file_type).
    pub fn get_metadata(mut self, path: &str) -> Self {
        self.operations.push(FileOperation::GetMetadata(path.to_string()));
        self
    }

    /// Read plaintext file operation.
    pub fn read_plaintext_file(mut self, path: &PlaintextFilePath) -> Self {
        self.operations.push(FileOperation::Read(path.path().display().to_string()));
        self
    }

    /// Read encrypted file operation.
    pub fn read_encrypted_file(mut self, path: &EncryptedFilePath) -> Self {
        self.operations.push(FileOperation::Read(path.path().display().to_string()));
        self
    }

    pub fn write_file(mut self, path: &str, size: usize) -> Self {
        self.operations.push(FileOperation::WriteAtomic(path.to_string(), size));
        self
    }

    pub fn write_batch(mut self, paths: Vec<String>, total_size: usize) -> Self {
        self.operations.push(FileOperation::WriteBatch(paths, total_size));
        self
    }

    pub fn delete_secure(mut self, path: &str) -> Self {
        self.operations.push(FileOperation::DeleteSecure(path.to_string()));
        self
    }

    /// Verify integrity of encrypted file.
    pub fn verify_integrity(mut self, path: &EncryptedFilePath) -> Self {
        self.operations.push(FileOperation::VerifyIntegrity(path.path().display().to_string()));
        self
    }

    pub fn commit(mut self) -> Vec<FileOperation> {
        self.operations.push(FileOperation::CommitTransaction);
        self.operations
    }

    pub fn rollback(mut self) -> Vec<FileOperation> {
        self.operations.push(FileOperation::RollbackTransaction);
        self.operations
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}