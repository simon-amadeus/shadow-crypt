//! Cryptographic primitives and secure operations
//! 
//! This module provides the core cryptographic functionality used throughout
//! the application, including AES-GCM encryption, Argon2 key derivation,
//! secure memory handling, and other security primitives.

pub mod aes;
pub mod argon2;
pub mod secure_memory;

// Re-export commonly used types and functions
pub use aes::{encrypt_aes_gcm, decrypt_aes_gcm, generate_secure_nonce};
pub use argon2::{derive_master_key, Argon2Params, MasterKeyManager};
pub use secure_memory::{SecretVec, KeyMaterial};