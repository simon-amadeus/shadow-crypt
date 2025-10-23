use shadow_core::v1::{encryption::EncryptionError, key_ops::KeyDerivationError};
use std::io;
use thiserror::Error;

/// Convenience type for workflow results.
pub type WorkflowResult<T> = Result<T, WorkflowError>;

#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error("User input error: {0}")]
    UserInput(String),

    #[error("Password error: {0}")]
    Password(String),

    #[error("File error: {0}")]
    File(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Key derivation error: {0}")]
    KeyDerivation(#[from] KeyDerivationError),

    #[error("Salt generation error: {0}")]
    SaltGeneration(String),

    #[error("Nonce generation error: {0}")]
    NonceGeneration(String),

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] EncryptionError),
}
