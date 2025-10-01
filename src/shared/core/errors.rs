//! Comprehensive error handling for the crypto system
//! 
//! This module defines all error types used throughout the application,
//! providing detailed error information and proper error chaining.

use std::fmt;

/// Comprehensive error type for all crypto operations
#[derive(Debug)]
pub enum CryptoError {
    /// Cryptographic operation failed
    CryptographicError(String),
    
    /// File system error
    FileSystemError(std::io::Error),
    
    /// Authentication failed during decryption
    AuthenticationFailed,
    
    /// Header parsing failed
    HeaderParsingError(String),
    
    /// Key derivation failed
    KeyDerivationError(String),
    
    /// Invalid file format
    InvalidFileFormat,
    
    /// File not found
    FileNotFound(String),
    
    /// Unsupported algorithm
    UnsupportedAlgorithm(u16),
    
    /// Random number generation failed
    RandomGenerationFailed,
    
    /// Filename collision limit exceeded
    TooManyCollisions,
    
    /// Operation interrupted
    OperationInterrupted { context: String },
    
    /// Batch processing failed
    BatchProcessingFailed(Vec<CryptoError>),
    
    /// Secure memory allocation failed
    SecureMemoryError,
    
    /// Hardware acceleration not available
    HardwareAccelerationUnavailable,
    
    /// Viewer command failed
    ViewerError(String),
    
    /// Editor command failed
    EditorError(String),
    
    /// Backup creation failed
    BackupError(String),
    
    /// Atomic operation failed
    AtomicOperationFailed(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::CryptographicError(msg) => write!(f, "Cryptographic operation failed: {}", msg),
            CryptoError::FileSystemError(err) => write!(f, "File system error: {}", err),
            CryptoError::AuthenticationFailed => write!(f, "Authentication failed"),
            CryptoError::HeaderParsingError(msg) => write!(f, "Header parsing failed: {}", msg),
            CryptoError::KeyDerivationError(msg) => write!(f, "Key derivation failed: {}", msg),
            CryptoError::InvalidFileFormat => write!(f, "Invalid file format"),
            CryptoError::FileNotFound(path) => write!(f, "File not found: {}", path),
            CryptoError::UnsupportedAlgorithm(id) => write!(f, "Unsupported algorithm: {:#x}", id),
            CryptoError::RandomGenerationFailed => write!(f, "Random number generation failed"),
            CryptoError::TooManyCollisions => write!(f, "Filename collision limit exceeded"),
            CryptoError::OperationInterrupted { context } => write!(f, "Operation interrupted: {}", context),
            CryptoError::BatchProcessingFailed(errors) => write!(f, "Batch processing failed: {} errors", errors.len()),
            CryptoError::SecureMemoryError => write!(f, "Secure memory allocation failed"),
            CryptoError::HardwareAccelerationUnavailable => write!(f, "Hardware acceleration not available"),
            CryptoError::ViewerError(msg) => write!(f, "Viewer command failed: {}", msg),
            CryptoError::EditorError(msg) => write!(f, "Editor command failed: {}", msg),
            CryptoError::BackupError(msg) => write!(f, "Backup creation failed: {}", msg),
            CryptoError::AtomicOperationFailed(msg) => write!(f, "Atomic operation failed: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::FileSystemError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(error: std::io::Error) -> Self {
        CryptoError::FileSystemError(error)
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, CryptoError>;