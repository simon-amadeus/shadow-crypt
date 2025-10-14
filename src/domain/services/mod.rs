//! # Domain Services
//!
//! Core business services that orchestrate domain operations.

pub mod crypto_algorithm;
pub mod crypto_config;
pub mod crypto_service;
pub mod encryption_service;
pub mod decryption_service;
pub mod listing_service;
pub mod file_handler;
pub mod password_service;

// Re-export key traits from the new crypto service
pub use crypto_service::{
    CryptographicAlgorithm, 
    KeyDerivationConfig, 
    EncryptionConfig, 
    EncryptionResult, 
    ConfigProvider,
    DefaultConfigProvider
};

// Re-export file handler services
pub use file_handler::{FileHandler, FileTransaction, FileResult, TransactionBuilder, FileOperation};

// Re-export encryption services
pub use encryption_service::{EncryptionService};

// Re-export decryption services
pub use decryption_service::{DecryptionOptions, DecryptionResult};

// Re-export listing services
pub use listing_service::{ListingService, DirectoryListing, EncryptedFileInfo};

// Re-export password services
pub use password_service::{PasswordVerificationService, PasswordVerificationError};

// Legacy re-exports for compatibility during transition
pub use crypto_algorithm::{CryptographicAlgorithm as LegacyCryptographicAlgorithm, KeyDerivationConfig as LegacyKeyDerivationConfig, EncryptionConfig as LegacyEncryptionConfig, EncryptionResult as LegacyEncryptionResult, CryptoResult};
