//! # Encryption File Operations
//!
//! File I/O operations specific to the encryption business capability.
//! Handles reading plaintext files and writing encrypted files.

use crate::domain::shared::{PlaintextFile, EncryptedFile, PlaintextFilePath, EncryptedFilePath};
use crate::domain::errors::DomainError;

/// Result type for encryption file operations
pub type EncryptionFileResult<T> = Result<T, DomainError>;

/// File operations for encryption workflows
pub trait EncryptionFileHandler: Send + Sync {
    /// Read plaintext file from filesystem for encryption
    fn read_plaintext_for_encryption(&self, path: &PlaintextFilePath) -> EncryptionFileResult<PlaintextFile>;
    
    /// Write encrypted file to filesystem
    fn write_encrypted_file(&self, file: &EncryptedFile, path: &EncryptedFilePath) -> EncryptionFileResult<()>;
    
    /// Write encrypted file with backup
    fn write_encrypted_with_backup(
        &self, 
        file: &EncryptedFile, 
        path: &EncryptedFilePath,
        backup_suffix: &str
    ) -> EncryptionFileResult<()>;
    
    /// Delete source file securely after encryption
    fn delete_source_securely(&self, path: &PlaintextFilePath) -> EncryptionFileResult<()>;
    
    /// Write multiple encrypted files atomically
    fn write_encrypted_batch(&self, files: &[(&EncryptedFile, &EncryptedFilePath)]) -> EncryptionFileResult<()>;
}