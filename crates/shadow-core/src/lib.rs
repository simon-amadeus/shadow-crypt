// shadow-core/src/lib.rs
// Core cryptographic functionality for the Shadow file encryption format

mod algorithms; // Cryptographic algorithm implementations
pub mod memory;

pub mod security; // Algorithm-agnostic security profiles
pub mod v1;

// Re-export main types and utilities
pub use algorithms::{argon2, xchacha20_poly1305};
pub use security::SecurityProfile;

// Convenience re-exports for algorithm functions
// pub use argon2::{derive_key, generate_salt};
// pub use xchacha20_poly1305::{decrypt, encrypt, generate_nonce};
