use shadow_crypt_core::archive::ArchiveError;
use shadow_crypt_core::errors::{CryptError, FileError, HeaderError, KeyDerivationError};
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

    #[error("{0}")]
    Format(#[from] FileError),

    #[error("{0}")]
    Archive(#[from] ArchiveError),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Like [`WorkflowError::Decryption`], but every failed file failed
    /// authentication (wrong password, or corrupted files).
    #[error("Decryption error: {0}")]
    Authentication(String),

    #[error("Listing error: {0}")]
    Listing(String),

    /// A failure while processing one file of a batch, keeping the
    /// underlying error's kind intact.
    #[error("'{filename}': {source}")]
    PerFile {
        filename: String,
        source: Box<WorkflowError>,
    },
}

impl WorkflowError {
    pub fn per_file(filename: &str, source: WorkflowError) -> Self {
        WorkflowError::PerFile {
            filename: filename.to_string(),
            source: Box::new(source),
        }
    }

    /// True when the error means the content did not authenticate: a wrong
    /// password, or a corrupted/tampered file. Indistinguishable by design.
    pub fn is_authentication_failure(&self) -> bool {
        match self {
            WorkflowError::Format(FileError::Crypt(CryptError::DecryptionError(_))) => true,
            WorkflowError::Authentication(_) => true,
            WorkflowError::PerFile { source, .. } => source.is_authentication_failure(),
            _ => false,
        }
    }

    /// Process exit code for this error, so scripts can react:
    /// 1 = operation failed, 2 = invalid usage or input,
    /// 3 = authentication failure (wrong password or corrupted file).
    pub fn exit_code(&self) -> i32 {
        if self.is_authentication_failure() {
            return 3;
        }
        match self {
            WorkflowError::UserInput(_) | WorkflowError::Password(_) => 2,
            WorkflowError::PerFile { source, .. } => source.exit_code(),
            _ => 1,
        }
    }
}
