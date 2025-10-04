//! # Domain Services
//!
//! Core business services that orchestrate domain operations.

pub mod crypto_algorithm;
pub mod crypto_config;
pub mod crypto_service;
pub mod encryption_service;
pub mod decryption_service;
pub mod listing_service;
pub mod migration_service;

// Re-export key traits from the new crypto service
pub use crypto_service::{
    CryptographicAlgorithm, 
    KeyDerivationConfig, 
    EncryptionConfig, 
    EncryptionResult, 
    ConfigProvider,
    DefaultConfigProvider
};

// Legacy re-exports for compatibility during transition
pub use crypto_algorithm::{CryptographicAlgorithm as LegacyCryptographicAlgorithm, KeyDerivationConfig as LegacyKeyDerivationConfig, EncryptionConfig as LegacyEncryptionConfig, EncryptionResult as LegacyEncryptionResult, CryptoResult};