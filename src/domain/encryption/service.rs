//! # Encryption Domain Slice
//!
//! Everything related to encrypting files - business logic, options, results.
//! This slice encapsulates the encryption capability.

use crate::domain::shared::{
    AlgorithmId,
    plaintext_file::PlaintextFile,
    encrypted_file::EncryptedFile,
};
use crate::domain::errors::DomainError;

/// Result type for encryption operations
pub type EncryptionResult<T> = Result<T, DomainError>;

/// Configuration for encryption operations
#[derive(Debug, Clone)]
pub struct EncryptionOptions {
    /// Algorithm to use for encryption
    pub algorithm: AlgorithmId,
    /// Whether to verify integrity after encryption
    pub verify_integrity: bool,
    /// Optional custom output filename
    pub output_filename: Option<String>,
}

impl Default for EncryptionOptions {
    fn default() -> Self {
        Self {
            algorithm: AlgorithmId::XChaCha20Poly1305,
            verify_integrity: true,
            output_filename: None,
        }
    }
}

/// Result of an encryption operation
#[derive(Debug, Clone)]
pub struct EncryptionOutcome {
    /// Algorithm used for encryption
    pub algorithm: AlgorithmId,
    /// Content hash of the original file
    pub content_hash: String,
    /// Size of the encrypted output
    pub encrypted_size: u64,
}

/// Core encryption domain service
/// 
/// Defines what the domain needs for encryption operations.
/// This is a pure business abstraction - infrastructure provides implementations.
pub trait EncryptionService: Send + Sync {
    /// Encrypt a plaintext file to an encrypted file
    /// 
    /// This is a pure transformation: PlaintextFile → EncryptedFile
    /// No file I/O is performed - that's handled by file_operations slice.
    fn encrypt(
        &self,
        plaintext: &PlaintextFile,
        password: &str,
        options: &EncryptionOptions,
    ) -> EncryptionResult<EncryptedFile>;

    /// Estimate encryption output size and complexity
    fn estimate_encryption(
        &self,
        input_size: u64,
        algorithm: AlgorithmId,
    ) -> EncryptionResult<EncryptionEstimate>;
}

/// Estimation for encryption planning
#[derive(Debug, Clone)]
pub struct EncryptionEstimate {
    /// Estimated output size in bytes
    pub estimated_size: u64,
    /// Estimated memory usage during encryption
    pub memory_required: u64,
    /// Complexity indicator (for progress estimation)
    pub complexity_factor: f64,
}