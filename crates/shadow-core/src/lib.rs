// shadow-core/src/lib.rs
// Core cryptographic functionality for the Shadow file encryption format

mod algorithms; // Cryptographic algorithm implementations

pub mod errors; // Error types organized by domain
pub mod memory; // Secure memory types with zeroization
pub mod metadata; // File metadata and information
pub mod validation; // Generic validation functions (version-agnostic)
pub mod v1; // Version 1.0 format implementation (complete & self-contained)

// Re-export main types and utilities
pub use algorithms::{argon2, xchacha20_poly1305};
pub use errors::{CryptoError, SerializationError, ValidationError};
pub use memory::{SecureBytes, SecureKey, SecureString};
pub use metadata::FileMetadata;
pub use validation::{
    check_content_duplicate, validate_password_format, validate_password_strength,
};

// Convenience re-exports for algorithm functions
pub use argon2::{derive_key, generate_salt};
pub use xchacha20_poly1305::{encrypt, decrypt, generate_nonce};
