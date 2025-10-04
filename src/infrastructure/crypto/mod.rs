//! # Cryptographic Infrastructure Module
//!
//! Core cryptographic implementations and secure memory management.
//! Implements domain cryptographic interfaces with concrete algorithms.

pub mod errors;
pub mod providers;
pub mod algorithms;
pub mod xchacha20_poly1305;
pub mod aes256_gcm;
pub mod factory;

pub use errors::{CryptoError, CryptoResult};
// Import domain abstractions - infrastructure implements these interfaces
pub use crate::domain::entities::{AlgorithmId, KeyMaterial};
pub use crate::domain::services::{
    CryptographicAlgorithm, EncryptionResult,
    KeyDerivationConfig, EncryptionConfig, ConfigProvider, DefaultConfigProvider,
};
pub use xchacha20_poly1305::XChaCha20Poly1305Config;
pub use aes256_gcm::Aes256GcmConfig;
pub use factory::Algorithm;