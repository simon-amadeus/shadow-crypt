//! # Decryption Domain Slice
//!
//! Business capability: Decrypting encrypted files to plaintext files.

pub mod service;
pub mod file_handler;

// Re-export public interface
pub use service::{
    DecryptionService,
    DecryptionOptions,
    DecryptionOutcome,
    EncryptedFileMetadata,
    DecryptionResult,
};

pub use file_handler::{
    DecryptionFileHandler,
    DecryptionFileResult,
};