//! # Encryption Domain Slice
//!
//! Business capability: Encrypting plaintext files to encrypted files.

pub mod service;

// Re-export public interface
pub use service::{
    EncryptionService,
    EncryptionOptions,
    EncryptionOutcome,
    EncryptionEstimate,
    EncryptionResult,
};