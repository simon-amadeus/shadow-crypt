//! # Domain Entities
//!
//! Core business entities representing the fundamental concepts
//! in the Shadow file encryption domain.

pub mod algorithm;
pub mod key;
pub mod encrypted_file;
pub mod plaintext_file;
pub mod session;
pub mod metadata;
pub mod header;
pub mod memory;

// Re-export key types for easier access
pub use algorithm::AlgorithmId;
pub use key::{KeyMaterial, KeyDerivationParams};
pub use memory::SecureBox;
pub use session::CryptoSession;