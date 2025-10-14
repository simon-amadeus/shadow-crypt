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
//! - `file_operations` - Type-safe file I/O with atomic transactions
//!
//! **Shared Foundation:**
//! - `shared` - Common entities, value objects, and types
//! - `errors` - Domain-wide error types
//!
//! ## Design Principles
//!
//! - **Vertical Slicing**: Group by business capability, not technical concern
//! - **Clean Interfaces**: Each slice exposes only what other slices need
//! - **Dependency Direction**: Slices depend on shared, not on each other
//! - **Pure Domain**: No infrastructure dependencies within slices

// ============================================================================
// BUSINESS CAPABILITY SLICES  
// ============================================================================

pub mod encryption;
pub mod decryption; 
pub mod listing;
pub mod file_operations;

// ============================================================================
// SHARED FOUNDATION
// ============================================================================

pub mod shared;
pub mod errors;

// Legacy services directory (will be removed after migration)
pub mod services;

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
    pub use crate::domain::file_operations::{
        FileHandler, FileTransaction, TransactionBuilder, FileOperation
    };
}

/// Shared domain types and entities
pub mod types {
    pub use crate::domain::shared::{
        AlgorithmId,
        plaintext_file::PlaintextFile,
        encrypted_file::EncryptedFile,
        path::{PlaintextFilePath, EncryptedFilePath, TypedFilePath},
        metadata::FileMetadata,
        hash::ContentHash,
        header::TlvHeader,
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
pub use file_operations::FileHandler;

// Most commonly used data types
pub use shared::{AlgorithmId, plaintext_file::PlaintextFile, encrypted_file::EncryptedFile};