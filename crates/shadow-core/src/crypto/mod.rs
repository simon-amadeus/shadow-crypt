// shadow-core/src/crypto/mod.rs
// Organized cryptographic operations with improved cohesion
// All crypto operations grouped by their primary purpose

pub mod config; // Security profile configurations
pub mod encryption; // Encryption and decryption operations
pub mod keys; // Key derivation and key management operations
pub mod primitives; // Low-level crypto primitives and utilities

// Re-export the main public API
pub use config::SecurityProfile;
pub use encryption::{decrypt_content, decrypt_filename, encrypt_content, encrypt_filename};
pub use keys::{derive_filename_key, derive_key};
pub use primitives::{constant_time_eq, generate_nonce, generate_salt, hash_content};
