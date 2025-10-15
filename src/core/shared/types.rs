//! Core types and error handling for the functional pipeline.

use std::time::Duration;

/// Core result type for all pipeline operations.
pub type CoreResult<T> = Result<T, CoreError>;

/// Unified error type for the functional pipeline.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("File operation failed: {0}")]
    File(#[from] FileError),
    
    #[error("Cryptographic operation failed: {0}")]
    Crypto(#[from] CryptoError),
    
    #[error("Input validation failed: {0}")]
    Validation(#[from] ValidationError),
    
    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),
}

/// File-related errors.
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("File not found: {path}")]
    NotFound { path: String },
    
    #[error("Invalid file type: {path} is {file_type}, expected regular file")]
    InvalidType { path: String, file_type: String },
    
    #[error("File already encrypted: {path}")]
    AlreadyEncrypted { path: String },
    
    #[error("File format error: {reason}")]
    Format { reason: String },
    
    #[error("Permission denied: {path}")]
    Permission { path: String },
}

/// Cryptography-related errors.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Unsupported algorithm: {algorithm_id}")]
    UnsupportedAlgorithm { algorithm_id: u16 },
    
    #[error("Key derivation failed: {reason}")]
    KeyDerivation { reason: String },
    
    #[error("Encryption failed: {reason}")]
    Encryption { reason: String },
    
    #[error("Decryption failed: {reason}")]
    Decryption { reason: String },
    
    #[error("Invalid key material")]
    InvalidKey,
    
    #[error("Authentication failed")]
    AuthenticationFailed,
}

/// Input validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Empty file list")]
    EmptyFileList,
    
    #[error("Invalid pattern: {pattern}")]
    InvalidPattern { pattern: String },
    
    #[error("Invalid password: {reason}")]
    InvalidPassword { reason: String },
    
    #[error("Path validation failed: {path} - {reason}")]
    InvalidPath { path: String, reason: String },
}

/// Performance metrics for pipeline operations.
#[derive(Debug, Clone)]
pub struct Metrics {
    pub duration: Duration,
    pub bytes_processed: u64,
    pub files_processed: usize,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            duration: Duration::ZERO,
            bytes_processed: 0,
            files_processed: 0,
        }
    }
    
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }
    
    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes_processed = bytes;
        self
    }
    
    pub fn with_files(mut self, files: usize) -> Self {
        self.files_processed = files;
        self
    }
}