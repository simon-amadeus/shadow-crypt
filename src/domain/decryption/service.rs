//! # Decryption Domain Slice
//!
//! Everything related to decrypting files - business logic, options, results.
//! This slice encapsulates the decryption capability.

use crate::domain::shared::{
    AlgorithmId,
    plaintext_file::PlaintextFile,
    encrypted_file::EncryptedFile,
};
use crate::domain::errors::DomainError;

/// Result type for decryption operations
pub type DecryptionResult<T> = Result<T, DomainError>;

/// Configuration for decryption operations
#[derive(Debug, Clone)]
pub struct DecryptionOptions {
    /// Whether to verify integrity before decryption
    pub verify_integrity: bool,
    /// Optional custom output filename (None = use original from metadata)
    pub output_filename: Option<String>,
}

impl Default for DecryptionOptions {
    fn default() -> Self {
        Self {
            verify_integrity: true,
            output_filename: None,
        }
    }
}

/// Result of a decryption operation
#[derive(Debug, Clone)]
pub struct DecryptionOutcome {
    /// Original filename recovered from metadata
    pub original_filename: String,
    /// Algorithm that was used for encryption
    pub algorithm: AlgorithmId,
    /// Size of the decrypted output
    pub decrypted_size: u64,
    /// Content hash of the decrypted content (for verification)
    pub content_hash: Option<String>,
}

/// Metadata extracted from encrypted files without full decryption
#[derive(Debug, Clone)]
pub struct EncryptedFileMetadata {
    /// Original filename before encryption
    pub original_filename: String,
    /// Algorithm used for encryption
    pub algorithm: AlgorithmId,
    /// File format version
    pub version: u16,
    /// Content hash (if available in header)
    pub content_hash: Option<String>,
    /// When the file was encrypted (if available)
    pub encrypted_at: Option<std::time::SystemTime>,
}

/// Core decryption domain service
/// 
/// Defines what the domain needs for decryption operations.
/// This is a pure business abstraction - infrastructure provides implementations.
pub trait DecryptionService: Send + Sync {
    /// Decrypt an encrypted file to a plaintext file
    /// 
    /// This is a pure transformation: EncryptedFile → PlaintextFile
    /// No file I/O is performed - that's handled by file_operations slice.
    fn decrypt(
        &self,
        encrypted: &EncryptedFile,
        password: &str,
        options: &DecryptionOptions,
    ) -> DecryptionResult<PlaintextFile>;

    /// Verify that a password can decrypt a file (quick check)
    /// 
    /// Performs authentication verification without full decryption.
    fn verify_password(
        &self,
        encrypted: &EncryptedFile,
        password: &str,
    ) -> DecryptionResult<bool>;

    /// Extract metadata from encrypted file without decryption
    /// 
    /// Reads header information that doesn't require password verification.
    fn extract_metadata(
        &self,
        encrypted: &EncryptedFile,
    ) -> DecryptionResult<EncryptedFileMetadata>;

    /// Extract metadata with password verification
    /// 
    /// Reads header information and verifies password access.
    fn extract_metadata_verified(
        &self,
        encrypted: &EncryptedFile,
        password: &str,
    ) -> DecryptionResult<EncryptedFileMetadata>;
}