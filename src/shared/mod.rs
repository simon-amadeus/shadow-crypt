//! Shared components and cryptographic primitives
//! 
//! This module contains the core functionality shared across all use cases:
//! - Cryptographic operations (AES-GCM, Argon2, etc.)
//! - File header format and serialization
//! - Error handling and recovery
//! - File detection utilities

pub mod crypto;
pub mod metadata;
pub mod algorithms;
pub mod header_core;
pub mod header;
pub mod file_detection;
pub mod errors;
pub mod secure_delete;

// Re-export commonly used types for convenience
pub use errors::CryptoError;
pub use header::{Header, AlgorithmId, FileMetadata};
pub use algorithms::{CURRENT_VERSION, VersionInfo};
pub use metadata::CompressionType;