// shadow-shell/src/errors.rs
// Error types for the shell layer - may involve side effects

use std::io;
use std::path::PathBuf;
use thiserror::Error;

// /// Convenience type for shell operation results
pub type EncryptionResult<T> = Result<T, EncryptionError>;

/// Shell-level errors that may involve I/O side effects
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("No input files provided")]
    NoFilesProvided,

    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    #[error("Not a file: {0}")]
    NotAFile(PathBuf),

    #[error("Permission denied: {0}")]
    PermissionDenied(PathBuf),

    #[error("Output file already exists: {0}")]
    OutputExists(PathBuf),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("User input error: {0}")]
    UserInput(String),

    #[error("Password cannot be empty")]
    EmptyPassword,

    #[error("Passwords do not match")]
    PasswordsDoNotMatch,

    #[error("Password error: {0}")]
    Password(String),
}
