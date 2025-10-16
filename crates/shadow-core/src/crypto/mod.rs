// shadow-core/src/crypto/mod.rs
// Organized cryptographic operations with improved cohesion
// All crypto operations grouped by their primary purpose

pub mod keys;           // Key derivation and key management operations
pub mod encryption;     // Encryption and decryption operations  
pub mod primitives;     // Low-level crypto primitives and utilities

// Re-export the main public API
pub use keys::{derive_key, derive_filename_key};
pub use encryption::{encrypt_content, decrypt_content, encrypt_filename, decrypt_filename};
pub use primitives::{hash_content, generate_nonce, generate_salt, constant_time_eq};