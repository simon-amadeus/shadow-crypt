//! # Core - Functional Pipeline Architecture
//!
//! Pure functional core implementing the encryption pipeline with vertical slicing.
//! Organized by business capabilities rather than technical layers.
//!
//! ## Architecture Principles
//!
//! - **Vertical Slicing**: Modules organized by business concern
//! - **Pure Functions**: All transformations are pure, side effects isolated  
//! - **Monadic Composition**: Pipeline uses Result<T, E> for error handling
//! - **Data-First**: Simple structs + functions, not complex entities
//!
//! ## Module Organization
//!
//! - `crypto/` - Cryptography vertical slice (algorithms, keys, hashing)
//! - `files/` - File handling vertical slice (detection, format, operations)  
//! - `encryption/` - Encryption workflow vertical slice (pipeline, jobs, validation)

// ============================================================================
// CORE MODULES
// ============================================================================

pub mod types;
pub mod pipeline;
pub mod crypto;
pub mod files;
pub mod encryption;

// ============================================================================
// CONVENIENT RE-EXPORTS
// ============================================================================

// Core types and utilities
pub use types::{CoreResult, CoreError};
pub use pipeline::{Pipeline, PipelineStep};

// Crypto vertical slice
pub use crypto::{
    AlgorithmId, SecureBox, ContentHash, ContentHasher,
    KeyMaterial, KeyDerivationParams, CryptoSession,
};

// Files vertical slice  
pub use files::{
    FileJob, FileInfo, FileType, TlvHeader, TlvFieldType,
    PlaintextData, EncryptedData,
};

// Encryption vertical slice
pub use encryption::{
    EncryptionPipeline, EncryptionJob, EncryptionResult,
    EncryptionOptions, EncryptionReport,
};