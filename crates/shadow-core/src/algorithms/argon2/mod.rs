// shadow-core/src/crypto/algorithms/argon2/mod.rs
// Argon2 key derivation vertical slice
// All Argon2 related functionality in one place

pub mod constants;
pub mod core;
pub mod profiles;

// Re-export main functionality
pub use constants::*;
pub use core::{derive_key, derive_filename_key};
pub use profiles::SecurityProfile;