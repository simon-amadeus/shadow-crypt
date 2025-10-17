// shadow-core/src/crypto/algorithms/argon2/mod.rs
// Argon2 key derivation vertical slice
// All Argon2 related functionality in one place

pub mod core;
pub mod profiles;

// Re-export main functionality
pub use core::{derive_key, derive_filename_key, generate_salt};
pub use profiles::SecurityProfile;