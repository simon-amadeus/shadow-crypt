//! File system operations abstraction.
//!
//! Provides testable file operations with atomic writes and secure deletion.
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

use crate::domain::{entities::{encrypted_file::EncryptedFile, header::TlvHeader, metadata::FileMetadata, plaintext_file::PlaintextFile}, DomainError};

pub type FileResult<T> = Result<T, DomainError>;

/// Transaction handle for atomic multi-file operations.
pub trait FileTransaction {
    fn commit(self) -> FileResult<()>;
    fn rollback(self) -> FileResult<()>;
}

/// File system operations with atomic writes and secure deletion.
pub trait FileHandler: Send + Sync {
    fn begin_transaction(&self) -> FileResult<Box<dyn FileTransaction>>;

    /// Create a transaction builder for complex atomic operations.
    fn transaction_builder() -> TransactionBuilder {
        TransactionBuilder::new()
    }

    // Read operations
    fn read_plaintext_file(&self, path: &Path) -> FileResult<PlaintextFile>;
    fn read_encrypted_file(&self, path: &Path) -> FileResult<EncryptedFile>;
    /// Read header only for efficient metadata extraction.
    fn read_encrypted_header(&self, path: &Path) -> FileResult<TlvHeader>;
    fn is_encrypted_file(&self, path: &Path) -> FileResult<bool>;
    fn get_metadata(&self, path: &Path) -> FileResult<FileMetadata>;

    // Write operations
    fn write_plaintext_file(&self, file: &PlaintextFile) -> FileResult<()>;
    fn write_encrypted_file(&self, file: &EncryptedFile) -> FileResult<()>;
    fn write_encrypted_file_with_backup(&self, file: &EncryptedFile, backup_suffix: &str) -> FileResult<()>;

    // Batch operations
    /// Read multiple encrypted headers efficiently.
    fn read_encrypted_headers_batch(&self, paths: &[&Path]) -> FileResult<Vec<(String, TlvHeader)>>;
    fn write_encrypted_files_batch(&self, files: &[&EncryptedFile]) -> FileResult<()>;

    // Delete operations
    fn delete_file_secure(&self, path: &Path) -> FileResult<()>;
    fn delete_file(&self, path: &Path) -> FileResult<()>;

    // Validation operations
    fn verify_file_integrity(&self, path: &Path) -> FileResult<bool>;
    fn detect_double_encryption_risk(&self, path: &Path) -> FileResult<bool>;
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

/// Builder for constructing atomic transactions.
pub struct TransactionBuilder {
    operations: Vec<FileOperation>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            operations: vec![FileOperation::BeginTransaction],
        }
    }

    pub fn read_file(mut self, path: &str) -> Self {
        self.operations.push(FileOperation::Read(path.to_string()));
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

    pub fn verify_integrity(mut self, path: &str) -> Self {
        self.operations.push(FileOperation::VerifyIntegrity(path.to_string()));
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