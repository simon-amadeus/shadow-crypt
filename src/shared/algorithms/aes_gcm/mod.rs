//! AES-256-GCM algorithm implementation
//! 
//! This module provides a complete AES-256-GCM cryptographic algorithm implementation
//! including encryption, decryption, key derivation, and nonce generation.

pub mod encryption;
pub mod decryption;
pub mod key_derivation;

// Re-export commonly used functions for convenience
pub use encryption::{encrypt_aes_gcm, generate_secure_nonce, generate_random_key};
pub use decryption::decrypt_aes_gcm;
pub use key_derivation::{derive_master_key, generate_salt, Argon2Params, MasterKeyManager};