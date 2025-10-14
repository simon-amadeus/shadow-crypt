//! # Domain Services (Legacy)
//!
//! This module contains legacy service abstractions that will be migrated
//! to the new vertical slice structure in domain::{encryption,decryption,listing,file_operations}.
//!
//! TODO: Remove this module once migration is complete.

pub mod simple;
pub mod core_traits;
pub mod file_handler;

// ============================================================================
// LEGACY ABSTRACTIONS - FOR BACKWARDS COMPATIBILITY
// ============================================================================

// Re-export the simplified domain abstractions for compatibility
pub use simple::{
    // Core operations
    ShadowService, CryptoProvider, PasswordHandler,
    // Configuration
    EncryptionOptions, DecryptionOptions,
    // Data types
    FileInfo, TypedFilePath,
    // Result type
    DomainResult,
};

// Keep existing file handler (it's good)
pub use file_handler::{FileHandler, FileTransaction, FileResult, TransactionBuilder, FileOperation};

// Legacy re-exports for compatibility during migration
pub use simple::CryptoProvider as EncryptionService;
pub use simple::CryptoProvider as DecryptionService;  
pub use simple::ShadowService as ListingService;
