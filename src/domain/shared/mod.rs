//! Domain entities.
//!
//! Core business entities representing fundamental concepts
//! in the Shadow file encryption system.

pub mod algorithm;
pub mod key;
pub mod encrypted_file;
pub mod hash;
pub mod plaintext_file;
pub mod session;
pub mod metadata;
pub mod header;
pub mod memory;
pub mod path;

// Re-export key types for easier access
pub use algorithm::AlgorithmId;
pub use hash::{ContentHash, ContentHasher, CONTENT_HASH_SIZE};
pub use key::{KeyMaterial, KeyDerivationParams};
pub use memory::SecureBox;
pub use session::CryptoSession;
pub use path::{TypedFilePath, PlaintextFilePath, EncryptedFilePath};
pub use metadata::{FileMetadata, FileType};