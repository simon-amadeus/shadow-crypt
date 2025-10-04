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

impl CryptoError {
    /// Get user-friendly error message with actionable suggestions
    pub fn user_friendly_message(&self) -> String {
        match self {
            CryptoError::AuthenticationFailed => {
                "Decryption failed - this usually means an incorrect password.\n\n\
                Suggestions:\n\
                • Double-check your password (case-sensitive)\n\
                • Verify the file wasn't corrupted during transfer\n\
                • Make sure this is a valid encrypted file".to_string()
            }
            CryptoError::FileSystemError(err) => {
                match err.kind() {
                    std::io::ErrorKind::PermissionDenied => {
                        "Permission denied - you don't have access to this file or directory.\n\n\
                        Suggestions:\n\
                        • Check file permissions with 'ls -la'\n\
                        • Run with appropriate user privileges\n\
                        • Verify the parent directory is writable".to_string()
                    }
                    std::io::ErrorKind::NotFound => {
                        "File or directory not found.\n\n\
                        Suggestions:\n\
                        • Check the file path for typos\n\
                        • Use 'ls' to verify the file exists\n\
                        • Make sure you're in the correct directory".to_string()
                    }
                    std::io::ErrorKind::AlreadyExists => {
                        "Output file already exists.\n\n\
                        Suggestions:\n\
                        • Use --force flag to overwrite existing files\n\
                        • Choose a different output location\n\
                        • Move or rename the existing file first".to_string()
                    }
                    _ => format!("File system error: {}\n\nSuggestion: Check file permissions and disk space", err)
                }
            }
            CryptoError::InvalidFileFormat => {
                "Invalid file format - this doesn't appear to be a valid encrypted file.\n\n\
                Suggestions:\n\
                • Make sure the file has a .shadow extension\n\
                • Check if the file was corrupted during transfer\n\
                • Verify this file was encrypted with Shadow".to_string()
            }
            CryptoError::FileNotFound(path) => {
                format!("File not found: {}\n\n\
                Suggestions:\n\
                • Check the file path for typos\n\
                • Use 'find' command to locate the file\n\
                • Make sure the file wasn't moved or deleted", path)
            }
            CryptoError::HeaderParsingError(msg) => {
                format!("File header is corrupted or invalid: {}\n\n\
                Suggestions:\n\
                • The file may be corrupted - try recovering from backup\n\
                • Verify file integrity with checksum if available\n\
                • Contact support if you have the original file", msg)
            }
            CryptoError::UnsupportedAlgorithm(id) => {
                format!("Unsupported encryption algorithm: {:#x}\n\n\
                Suggestions:\n\
                • This file may be from a newer version of Shadow\n\
                • Update to the latest version of Shadow\n\
                • Use the shadowmigrate tool to check compatibility", id)
            }
            CryptoError::TooManyCollisions => {
                "Filename obfuscation failed due to too many collisions.\n\n\
                Suggestions:\n\
                • Try encrypting files in smaller batches\n\
                • Use a different output directory\n\
                • Contact support if this persists".to_string()
            }
            _ => self.to_string()
        }
    }
    
    /// Check if this error suggests a wrong password
    pub fn suggests_wrong_password(&self) -> bool {
        matches!(self, CryptoError::AuthenticationFailed)
    }
    
    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(self, 
            CryptoError::AuthenticationFailed |
            CryptoError::FileSystemError(_) |
            CryptoError::FileNotFound(_)
        )
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, CryptoError>;