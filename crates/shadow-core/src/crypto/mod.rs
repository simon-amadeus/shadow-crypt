// shadow-core/src/crypto/mod.rs
// Basic cryptographic utilities and primitives
// Algorithm-specific code is now in src/algorithms/

pub mod primitives; // Low-level crypto primitives and utilities

// Re-export utilities
pub use primitives::{constant_time_eq, generate_nonce, generate_salt};
