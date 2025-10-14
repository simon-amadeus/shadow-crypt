//! # Shared Domain Foundation - Organized by Topic
//!
//! Common domain concepts organized by business concern rather than technical pattern.
//! This improves cohesion by grouping related concepts together.
//!
//! ## Topic Organization
//!
//! - **`file`** - Everything related to files (entities, paths, operations)
//! - **`crypto`** - Everything related to cryptography (algorithms, keys, sessions)
//!
//! This organization makes it easier to find related concepts and understand
//! the relationships between domain objects.

// ============================================================================
// BUSINESS TOPICS
// ============================================================================

pub mod file;
pub mod crypto;

// ============================================================================
// CONVENIENT RE-EXPORTS BY TOPIC
// ============================================================================

// File-related exports
pub use file::{
    plaintext_file::PlaintextFile, 
    encrypted_file::EncryptedFile,
    path::{PlaintextFilePath, EncryptedFilePath, TypedFilePath}, 
    metadata::{FileMetadata, FileType},
    header::{TlvHeader, TlvHeaderBuilder, TlvFieldType},
    handler::{FileHandler, FileTransaction, TransactionBuilder, FileOperation},
};

// Crypto-related exports  
pub use crypto::{
    algorithm::AlgorithmId,
    key::{KeyMaterial, KeyDerivationParams}, 
    memory::SecureBox,
    hash::{ContentHash, ContentHasher, CONTENT_HASH_SIZE},
    session::CryptoSession,
};
