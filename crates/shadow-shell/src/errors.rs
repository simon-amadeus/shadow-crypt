// shadow-shell/src/errors.rs
// Error types for the shell layer - may involve side effects

use shadow_core::{CryptoError, SerializationError, ValidationError};
use std::io;
use std::path::PathBuf;
use thiserror::Error;

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

    #[error(
        "Duplicate content found: '{original_file}' has the same content as existing file '{conflicting_file}'"
    )]
    DuplicateContent {
        original_file: PathBuf,
        conflicting_file: PathBuf,
        content_hash: String,
    },

    #[error("No files matched the pattern")]
    NoFilesMatched,

    #[error("Too many files to process: {count} (limit: {limit})")]
    TooManyFiles { count: usize, limit: usize },

    #[error("File too large: {size} bytes (limit: {limit} bytes)")]
    FileTooLarge { size: u64, limit: u64 },

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
            original_file: original_file.clone(),
            conflicting_file: PathBuf::from("unknown"), // Fallback for backwards compatibility
            content_hash: hex::encode(content_hash),
        }
    }

    /// Create a duplicate content error with conflicting file information
    pub fn duplicate_content_with_file(
        original_file: PathBuf,
        conflicting_file: PathBuf,
        content_hash: &[u8; 32],
    ) -> Self {
        Self::DuplicateContent {
            original_file,
            conflicting_file,
            content_hash: hex::encode(content_hash),
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
                ShellError::DuplicateContent {
                    original_file: a1,
                    conflicting_file: a2,
                    content_hash: a3,
                },
                ShellError::DuplicateContent {
                    original_file: b1,
                    conflicting_file: b2,
                    content_hash: b3,
                },
            ) => a1 == b1 && a2 == b2 && a3 == b3,
            (ShellError::NoFilesMatched, ShellError::NoFilesMatched) => true,
            (
                ShellError::TooManyFiles {
                    count: a1,
                    limit: a2,
                },
                ShellError::TooManyFiles {
                    count: b1,
                    limit: b2,
                },
            ) => a1 == b1 && a2 == b2,
            (
                ShellError::FileTooLarge {
                    size: a1,
                    limit: a2,
                },
                ShellError::FileTooLarge {
                    size: b1,
                    limit: b2,
                },
            ) => a1 == b1 && a2 == b2,

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
            ShellError::DuplicateContent {
                original_file,
                conflicting_file,
                content_hash,
            } => {
                assert_eq!(original_file, path);
                assert_eq!(conflicting_file, PathBuf::from("unknown"));
                assert_eq!(content_hash, hex::encode(hash));
            }
            _ => panic!("Expected DuplicateContent error"),
        }
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
