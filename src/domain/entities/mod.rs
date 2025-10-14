//! # Domain Entities
//!
//! Core business entities representing the fundamental concepts
//! in the Shadow file encryption domain.

pub mod algorithm;
pub mod key_material;
pub mod encrypted_file;
pub mod plaintext_file;
pub mod crypto_session;
pub mod duplicate_detector;
pub mod metadata;
pub mod header;
pub mod version_matrix;
pub mod memory;

// Re-export key types for easier access
pub use algorithm::AlgorithmId;
pub use key_material::KeyMaterial;
pub use memory::SecureBox;
pub use crypto_session::CryptoSession;