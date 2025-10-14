//! # Encryption Domain Slice
//!
//! Business capability: Encrypting plaintext files to encrypted files.

pub mod service;
pub mod file_handler;

// Re-export public interface
pub use service::{
    EncryptionService,
    EncryptionOptions,
    EncryptionOutcome,
    EncryptionEstimate,
    EncryptionResult,
};

pub use file_handler::{
    EncryptionFileHandler,
    EncryptionFileResult,
};