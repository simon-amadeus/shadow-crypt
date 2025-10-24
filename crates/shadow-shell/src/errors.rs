use shadow_core::errors::{CryptError, HeaderError, KeyDerivationError};
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

    #[error("Cryptography error: {0}")]
    CryptographyError(#[from] CryptError),

    #[error("Header error: {0}")]
    HeaderError(#[from] HeaderError),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Listing error: {0}")]
    Listing(String),
}
