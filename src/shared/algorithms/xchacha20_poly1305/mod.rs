//! XChaCha20-Poly1305 algorithm implementation
//! 
//! This module provides a complete XChaCha20-Poly1305 cryptographic algorithm implementation
//! including encryption, decryption, key derivation, and nonce generation.
//! 
//! XChaCha20-Poly1305 eliminates the critical nonce reuse vulnerability present in
//! AES-GCM file encryption by using 24-byte nonces with astronomical collision resistance.

pub mod encryption;
pub mod decryption;
pub mod key_derivation;

// Re-export commonly used functions for convenience
pub use encryption::{encrypt_xchacha20_poly1305, generate_secure_nonce, generate_random_key};
pub use decryption::decrypt_xchacha20_poly1305;
pub use key_derivation::{derive_master_key, generate_salt, Argon2Params, MasterKeyManager};