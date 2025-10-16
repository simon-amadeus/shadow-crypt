// shadow-shell/src/errors.rs
// Error types for the shell layer - may involve side effects

use std::path::PathBuf;
use std::io;
use thiserror::Error;
use shadow_core::{CryptoError, ValidationError, SerializationError};

/// Shell-level errors that may involve I/O side effects
#[derive(Debug, Error)]
pub enum ShellError {
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),
    
    #[error("Not a file: {0}")]
    NotAFile(PathBuf),
    
    #[error("Not a directory: {0}")]
    NotADirectory(PathBuf),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(PathBuf),
    
    #[error("Output file already exists: {0}")]
    OutputExists(PathBuf),
    
    #[error("Invalid filename: {0}")]
    InvalidFilename(String),
    
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),
    
    #[error("User input error: {0}")]
    UserInput(String),
    
    #[error("Password confirmation mismatch")]
    PasswordMismatch,
    
    #[error("Operation cancelled by user")]
    Cancelled,
    
    #[error("Duplicate content found")]
    DuplicateContent {
        original_file: PathBuf,
        content_hash: String,
    },
    
    #[error("Glob pattern error: {0}")]
    GlobPattern(String),
    
    #[error("No files matched the pattern")]
    NoFilesMatched,
    
    #[error("Too many files to process: {count} (limit: {limit})")]
    TooManyFiles { count: usize, limit: usize },
    
    #[error("File too large: {size} bytes (limit: {limit} bytes)")]
    FileTooLarge { size: u64, limit: u64 },
    
    #[error("Insufficient disk space")]
    InsufficientDiskSpace,
    
    #[error("Temporary file creation failed")]
    TempFileCreation,
    
    #[error("Atomic operation failed")]
    AtomicOperationFailed,
}

/// Convenience type for shell operation results
pub type ShellResult<T> = Result<T, ShellError>;

impl ShellError {
    /// Create a duplicate content error with formatted hash
    pub fn duplicate_content(original_file: PathBuf, content_hash: &[u8; 32]) -> Self {
        Self::DuplicateContent {
            original_file,
            content_hash: hex::encode(content_hash),
        }
    }
    
    /// Check if error indicates a recoverable condition
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            ShellError::PasswordMismatch
                | ShellError::UserInput(_)
                | ShellError::Cancelled
                | ShellError::OutputExists(_)
        )
    }
    
    /// Check if error indicates user intervention is needed
    pub fn needs_user_intervention(&self) -> bool {
        matches!(
            self,
            ShellError::OutputExists(_)
                | ShellError::PermissionDenied(_)
                | ShellError::InsufficientDiskSpace
                | ShellError::DuplicateContent { .. }
        )
    }
    
    /// Get exit code for this error
    pub fn exit_code(&self) -> i32 {
        match self {
            ShellError::FileNotFound(_) => 2,
            ShellError::NotAFile(_) => 2,
            ShellError::NotADirectory(_) => 2,
            ShellError::PermissionDenied(_) => 13,
            ShellError::OutputExists(_) => 17,
            ShellError::InvalidFilename(_) => 22,
            ShellError::Io(_) => 5,
            ShellError::Crypto(_) => 65,
            ShellError::Validation(_) => 64,
            ShellError::Serialization(_) => 74,
            ShellError::UserInput(_) => 64,
            ShellError::PasswordMismatch => 64,
            ShellError::Cancelled => 130,
            ShellError::DuplicateContent { .. } => 66,
            ShellError::GlobPattern(_) => 64,
            ShellError::NoFilesMatched => 66,
            ShellError::TooManyFiles { .. } => 69,
            ShellError::FileTooLarge { .. } => 27,
            ShellError::InsufficientDiskSpace => 28,
            ShellError::TempFileCreation => 73,
            ShellError::AtomicOperationFailed => 74,
        }
    }
}

// For testing and debugging
impl PartialEq for ShellError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ShellError::FileNotFound(a), ShellError::FileNotFound(b)) => a == b,
            (ShellError::NotAFile(a), ShellError::NotAFile(b)) => a == b,
            (ShellError::NotADirectory(a), ShellError::NotADirectory(b)) => a == b,
            (ShellError::PermissionDenied(a), ShellError::PermissionDenied(b)) => a == b,
            (ShellError::OutputExists(a), ShellError::OutputExists(b)) => a == b,
            (ShellError::InvalidFilename(a), ShellError::InvalidFilename(b)) => a == b,
            (ShellError::Crypto(a), ShellError::Crypto(b)) => a == b,
            (ShellError::Validation(a), ShellError::Validation(b)) => a == b,
            (ShellError::Serialization(a), ShellError::Serialization(b)) => a == b,
            (ShellError::UserInput(a), ShellError::UserInput(b)) => a == b,
            (ShellError::PasswordMismatch, ShellError::PasswordMismatch) => true,
            (ShellError::Cancelled, ShellError::Cancelled) => true,
            (
                ShellError::DuplicateContent { original_file: a1, content_hash: a2 },
                ShellError::DuplicateContent { original_file: b1, content_hash: b2 }
            ) => a1 == b1 && a2 == b2,
            (ShellError::GlobPattern(a), ShellError::GlobPattern(b)) => a == b,
            (ShellError::NoFilesMatched, ShellError::NoFilesMatched) => true,
            (
                ShellError::TooManyFiles { count: a1, limit: a2 },
                ShellError::TooManyFiles { count: b1, limit: b2 }
            ) => a1 == b1 && a2 == b2,
            (
                ShellError::FileTooLarge { size: a1, limit: a2 },
                ShellError::FileTooLarge { size: b1, limit: b2 }
            ) => a1 == b1 && a2 == b2,
            (ShellError::InsufficientDiskSpace, ShellError::InsufficientDiskSpace) => true,
            (ShellError::TempFileCreation, ShellError::TempFileCreation) => true,
            (ShellError::AtomicOperationFailed, ShellError::AtomicOperationFailed) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_content_error() {
        let path = PathBuf::from("test.txt");
        let hash = [42u8; 32];
        let error = ShellError::duplicate_content(path.clone(), &hash);
        
        match error {
            ShellError::DuplicateContent { original_file, content_hash } => {
                assert_eq!(original_file, path);
                assert_eq!(content_hash, hex::encode(hash));
            }
            _ => panic!("Expected DuplicateContent error"),
        }
    }

    #[test]
    fn test_error_recoverability() {
        assert!(ShellError::PasswordMismatch.is_recoverable());
        assert!(ShellError::Cancelled.is_recoverable());
        assert!(!ShellError::FileNotFound(PathBuf::from("test")).is_recoverable());
    }

    #[test]
    fn test_error_user_intervention() {
        assert!(ShellError::OutputExists(PathBuf::from("test")).needs_user_intervention());
        assert!(ShellError::PermissionDenied(PathBuf::from("test")).needs_user_intervention());
        assert!(!ShellError::Cancelled.needs_user_intervention());
    }

    #[test]
    fn test_exit_codes() {
        assert_eq!(ShellError::FileNotFound(PathBuf::from("test")).exit_code(), 2);
        assert_eq!(ShellError::PermissionDenied(PathBuf::from("test")).exit_code(), 13);
        assert_eq!(ShellError::Cancelled.exit_code(), 130);
    }

    #[test]
    fn test_error_equality() {
        let path = PathBuf::from("test.txt");
        let err1 = ShellError::FileNotFound(path.clone());
        let err2 = ShellError::FileNotFound(path);
        let err3 = ShellError::Cancelled;
        
        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_error_display() {
        let path = PathBuf::from("test.txt");
        let error = ShellError::FileNotFound(path);
        let display = format!("{}", error);
        assert!(display.contains("File not found"));
        assert!(display.contains("test.txt"));
    }
}