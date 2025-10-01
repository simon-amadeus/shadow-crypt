//! Shared components and cryptographic primitives
//! 
//! This module contains the core functionality shared across all use cases:
//! - Cryptographic operations (AES-GCM, Argon2, etc.)
//! - File header format and serialization
//! - Error handling and recovery
//! - File detection utilities

pub mod core;
pub mod crypto;
pub mod metadata;
pub mod algorithms;
pub mod header_core;
pub mod header;
pub mod versioning;
pub mod version_dispatch;
pub mod filename_auth;

// Re-export from core for backward compatibility
pub use core::errors;
pub use core::file_detection;
pub use core::secure_delete;

// Re-export commonly used types for convenience
pub use core::errors::CryptoError;
pub use header::{Header, AlgorithmId, FileMetadata};
pub use versioning::{VersionedHeader, HeaderV1, detect_version, CompatibilityMatrix};
pub use version_dispatch::{AnyHeader, VersionMigrator, MigrationPlan, MigrationStep, MigrationOperation};
pub use algorithms::{CURRENT_VERSION, VersionInfo};
pub use metadata::CompressionType;