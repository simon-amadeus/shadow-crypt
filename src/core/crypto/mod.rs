//! Crypto vertical slice - all cryptography-related functionality.

pub mod types;
pub mod hash;
pub mod session;
pub mod operations;

// Use real crypto operations for production
pub use operations::*;

// Re-export commonly used types
pub use types::{AlgorithmId, SecureBox, KeyMaterial, KeyDerivationParams};
pub use hash::{ContentHash, ContentHasher, CONTENT_HASH_SIZE};
pub use session::CryptoSession;