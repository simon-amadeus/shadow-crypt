//! # Domain Layer - Vertical Slices by Business Capability
//! 
//! This module organizes domain logic by business capabilities rather than technical layers.
//! Each slice encapsulates everything needed for a specific business function.
//!
//! ## Architecture
//!
//! **Capability-Based Slices:**
//! - `encryption` - Encrypting plaintext files to encrypted files
//! - `decryption` - Decrypting encrypted files to plaintext files  
//! - `listing` - Discovering and inspecting encrypted files
//!
//! **Shared Foundation:**
//! - `shared/file` - File entities, paths, operations and transactions
//! - `shared/crypto` - Cryptographic primitives and algorithms  
//! - `errors` - Domain-wide error types
//!
//! ## Design Principles
//!
//! - **Vertical Slicing**: Group by business capability, not technical concern
//! - **Topic-Based Sharing**: Shared concepts organized by cohesion 
//! - **Clean Interfaces**: Each slice exposes only what other slices need
//! - **Dependency Direction**: Slices depend on shared, not on each other
//! - **Pure Domain**: No infrastructure dependencies within slices

// ============================================================================
// BUSINESS CAPABILITY SLICES  
// ============================================================================

pub mod encryption;
pub mod decryption; 
pub mod listing;

// ============================================================================
// SHARED FOUNDATION
// ============================================================================

pub mod shared;
pub mod errors;

// ============================================================================
// PUBLIC DOMAIN API - ORGANIZED BY CAPABILITY
// ============================================================================

// Re-export by business capability for clean external API

/// File encryption capability
pub mod encrypt {
    pub use crate::domain::encryption::{
        EncryptionService, EncryptionOptions, EncryptionOutcome, EncryptionEstimate
    };
}

/// File decryption capability  
pub mod decrypt {
    pub use crate::domain::decryption::{
        DecryptionService, DecryptionOptions, DecryptionOutcome, EncryptedFileMetadata
    };
}

/// File listing and inspection capability
pub mod list {
    pub use crate::domain::listing::{
        ListingService, ListingOptions, FileInfo, DirectoryListing
    };
}

/// File I/O operations capability
pub mod files {
    // Each vertical slice has its own file operations
    // No shared file handler needed - too generic
    pub use crate::domain::encryption::EncryptionFileHandler;
    pub use crate::domain::decryption::DecryptionFileHandler;
    pub use crate::domain::listing::ListingFileHandler;
}

/// Shared domain types and entities - organized by topic
pub mod types {
    pub use crate::domain::shared::{
        // Algorithm identification
        AlgorithmId,
        // File entities and operations
        PlaintextFile, EncryptedFile,
        PlaintextFilePath, EncryptedFilePath, TypedFilePath,
        FileMetadata, FileType,
        // File format structure
        TlvHeader, TlvHeaderBuilder, TlvFieldType,
        // Crypto primitives
        KeyMaterial, ContentHash, CryptoSession,
    };
}

// Re-export common error types
pub use errors::{DomainError, DomainResult};

// ============================================================================
// CONVENIENCE RE-EXPORTS FOR COMMON USAGE
// ============================================================================

// Most commonly used types for infrastructure implementations
pub use encryption::EncryptionService;
pub use decryption::DecryptionService; 
pub use listing::ListingService;

// Most commonly used data types
pub use shared::{AlgorithmId, PlaintextFile, EncryptedFile};