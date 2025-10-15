//! # File Topic - All File-Related Concerns
//!
//! This module groups all file-related domain concepts together:
//! - File entities (plaintext, encrypted)
//! - File paths and metadata  
//! - File operations and transactions
//!
//! Organized by cohesion rather than technical patterns.

// ============================================================================
// FILE ENTITIES & VALUE OBJECTS
// ============================================================================

pub mod plaintext_file;
pub mod encrypted_file;
pub mod path;
pub mod metadata;
pub mod header;

// ============================================================================
// PUBLIC API - ORGANIZED BY CONCERN
// ============================================================================

// File entities
pub use plaintext_file::PlaintextFile;
pub use encrypted_file::EncryptedFile;

// File paths and metadata
pub use path::{PlaintextFilePath, EncryptedFilePath, TypedFilePath};
pub use metadata::{FileMetadata, FileType};
pub use header::{TlvHeader, TlvHeaderBuilder, TlvFieldType};