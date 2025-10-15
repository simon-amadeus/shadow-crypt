//! # Shared Module
//!
//! Common utilities and infrastructure shared across all vertical slices
//! at the core level. Contains cryptographic primitives, file handling
//! utilities, and common types.
//!
//! ## Organization
//!
//! - `crypto/` - Cryptographic operations, algorithms, and key management
//! - `files/` - File system operations, format handling, and I/O utilities  
//! - `types.rs` - Common type definitions and error types
//!
//! This module provides the foundational capabilities that vertical slices
//! (encryption, decryption, listing) can compose together.

// ============================================================================
// SHARED INFRASTRUCTURE MODULES
// ============================================================================

pub mod types;
pub mod crypto;
pub mod files;
pub mod progress;
pub mod pipeline;

// ============================================================================
// CONVENIENT RE-EXPORTS FOR VERTICAL SLICES
// ============================================================================

// Types
pub use types::{CoreResult, CoreError, FileError, CryptoError, ValidationError};

// Progress reporting
pub use progress::ProgressStep;

// Pipeline combinators
pub use pipeline::ProcessContinue;

// Crypto infrastructure
pub use crypto::{
    AlgorithmId, SecureBox,
    KeyMaterial, KeyDerivationParams, CryptoSession,
};

// File infrastructure  
pub use files::{
    FileJob, FileInfo, FileType, EncryptedData,
    TlvHeader, TlvFieldType, PlaintextData, ContentHash, ContentHasher,
};