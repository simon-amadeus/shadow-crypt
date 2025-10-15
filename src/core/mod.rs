//! # Core - Functional Pipeline Architecture
//!
//! Pure functional core implementing cryptographic workflows using vertical slicing.
//! Organized by business capabilities rather than technical layers.
//!
//! ## Architecture Principles
//!
//! - **Vertical Slicing**: Business capabilities as independent modules
//! - **Shared Module**: Common utilities isolated in shared infrastructure  
//! - **Pure Functions**: All transformations are pure, side effects isolated  
//! - **Monadic Composition**: Pipeline uses Result<T, E> for error handling
//! - **Data-First**: Simple structs + functions, not complex entities
//!
//! ## Module Organization
//!
//! - `shared/` - Common utilities and infrastructure (crypto, files, types)
//! - `encryption/` - Encryption workflow vertical slice (pipeline, jobs, validation)
//! - `decryption/` - Decryption workflow vertical slice (future)
//! - `listing/` - File listing workflow vertical slice (future)

// ============================================================================
// CORE MODULES - VERTICAL SLICES
// ============================================================================

pub mod shared;
pub mod encryption;

// Future vertical slices:
// pub mod decryption;
// pub mod listing;

// ============================================================================
// CONVENIENT RE-EXPORTS FROM SHARED INFRASTRUCTURE
// ============================================================================

// Core types and utilities
pub use shared::{CoreResult, CoreError};

// Crypto infrastructure
pub use shared::{
    AlgorithmId, SecureBox, ContentHash, ContentHasher,
    KeyMaterial, KeyDerivationParams, CryptoSession,
};

// File infrastructure  
pub use shared::{
    FileJob, FileInfo, FileType, EncryptedData,
    TlvHeader, TlvFieldType, PlaintextData,
};

// ============================================================================
// CONVENIENT RE-EXPORTS FROM VERTICAL SLICES
// ============================================================================

// Encryption vertical slice
pub use encryption::{
    EncryptionPipeline, EncryptionJob, EncryptionResult,
    EncryptionOptions, EncryptionReport,
};