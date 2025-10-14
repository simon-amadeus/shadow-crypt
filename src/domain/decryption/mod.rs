//! # Decryption Domain Slice
//!
//! Business capability: Decrypting encrypted files to plaintext files.

pub mod service;

// Re-export public interface
pub use service::{
    DecryptionService,
    DecryptionOptions,
    DecryptionOutcome,
    EncryptedFileMetadata,
    DecryptionResult,
};