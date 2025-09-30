//! Shared components and cryptographic primitives
//! 
//! This module contains the core functionality shared across all use cases:
//! - Cryptographic operations (AES-GCM, Argon2, etc.)
//! - File header format and serialization
//! - Error handling and recovery
//! - File detection utilities

pub mod crypto;
pub mod header;
pub mod file_detection;
pub mod errors;
pub mod secure_delete;
pub mod migration;

// Re-export commonly used types for convenience
pub use errors::CryptoError;
pub use header::{Header, AlgorithmId, VersionInfo, CURRENT_VERSION};
pub use migration::MigrationSystem;