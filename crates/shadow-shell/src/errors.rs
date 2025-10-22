use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Convenience type for workflow results.
pub type WorkflowResult<T> = Result<T, WorkflowError>;

#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error("No input files provided")]
    NoFilesProvided,

    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    #[error("Not a file: {0}")]
    NotAFile(PathBuf),

    #[error("Invalid filename: {0}")]
    InvalidFilename(PathBuf),

    #[error("File metadata error: {0}")]
    FileMetadataError(PathBuf),

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

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Salt generation error: {0}")]
    SaltGeneration(String),

    #[error("Nonce generation error: {0}")]
    NonceGeneration(String),
}
