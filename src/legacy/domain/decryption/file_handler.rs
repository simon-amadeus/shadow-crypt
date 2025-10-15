//! # Decryption File Operations
//!
//! File I/O operations specific to the decryption business capability.
//! Handles reading encrypted files and writing plaintext files.

use crate::domain::shared::{PlaintextFile, EncryptedFile, PlaintextFilePath, EncryptedFilePath};
use crate::domain::errors::DomainError;

/// Result type for decryption file operations
pub type DecryptionFileResult<T> = Result<T, DomainError>;

/// File operations for decryption workflows
pub trait DecryptionFileHandler: Send + Sync {
    /// Read encrypted file from filesystem for decryption
    fn read_encrypted_for_decryption(&self, path: &EncryptedFilePath) -> DecryptionFileResult<EncryptedFile>;
    
    /// Write plaintext file to filesystem after decryption
    fn write_decrypted_file(&self, file: &PlaintextFile, path: &PlaintextFilePath) -> DecryptionFileResult<()>;
    
    /// Verify integrity of encrypted file before decryption
    fn verify_encrypted_integrity(&self, path: &EncryptedFilePath) -> DecryptionFileResult<bool>;
    
    /// Delete encrypted file securely after decryption
    fn delete_encrypted_securely(&self, path: &EncryptedFilePath) -> DecryptionFileResult<()>;
}