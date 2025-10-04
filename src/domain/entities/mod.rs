//! # Domain Entities
//!
//! Core business entities representing the fundamental concepts
//! in the Shadow file encryption domain.

pub mod algorithm_id;
pub mod key_material;
pub mod encrypted_file;
pub mod plaintext_file;
pub mod crypto_session;
pub mod duplicate_detector;
pub mod file_metadata;
pub mod tlv_header;
pub mod version_matrix;
pub mod secure_memory;

// Re-export key types for easier access
pub use algorithm_id::AlgorithmId;
pub use key_material::{KeyMaterial, SecureBox};
pub use secure_memory::SecureBox as LegacySecureBox;
pub use crypto_session::CryptoSession;