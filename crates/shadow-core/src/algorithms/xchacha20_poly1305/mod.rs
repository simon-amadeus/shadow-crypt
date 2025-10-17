// shadow-core/src/crypto/algorithms/xchacha20_poly1305/mod.rs
// XChaCha20-Poly1305 algorithm vertical slice
// All XChaCha20-Poly1305 related functionality in one place

pub mod constants;
pub mod core;

// Re-export main functionality
pub use constants::*;
pub use core::{encrypt, decrypt, encrypt_filename, decrypt_filename};