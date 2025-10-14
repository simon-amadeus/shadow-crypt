//! # Domain Services
//!
//! Simplified domain service abstractions - keep it simple!
//!
//! This module provides clean, focused abstractions for what the domain needs
//! without over-engineering. Infrastructure provides implementations.

pub mod simple;
pub mod core_traits;
pub mod encryption_service;
pub mod decryption_service;
pub mod listing_service;
pub mod file_handler;

// ============================================================================
// PRIMARY SIMPLIFIED ABSTRACTIONS
// ============================================================================

// Re-export the simplified domain abstractions
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

// ============================================================================
// LEGACY COMPATIBILITY - TO BE REMOVED GRADUALLY
// ============================================================================

// Keep existing abstractions for now to avoid breaking everything
// TODO: Migrate infrastructure and application layers to use simple:: traits

// File operations (keep the good one)
pub use file_handler::{FileHandler, FileTransaction, FileResult, TransactionBuilder, FileOperation};

// Legacy core traits (for infrastructure that hasn't migrated yet)
pub use core_traits::{
    EncryptionService as ComplexEncryptionService,
    DecryptionService as ComplexDecryptionService,
    ListingService as ComplexListingService,
};

// Create some re-exports for compatibility
pub use simple::CryptoProvider as EncryptionService;  // Simple abstraction
pub use simple::CryptoProvider as DecryptionService;  // Same interface  
pub use simple::ShadowService as ListingService;      // High-level service
