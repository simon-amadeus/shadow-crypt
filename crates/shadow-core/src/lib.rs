// shadow-core/src/lib.rs
// Pure cryptographic core for Shadow encryption tool
//
// This crate contains only pure functions with no side effects.
// All cryptographic operations, data types, and validation logic
// are implemented here without any I/O dependencies.

pub mod crypto; // Generic cryptographic operations (version-agnostic)
pub mod errors; // Error types organized by domain
pub mod memory; // Secure memory types with zeroization
pub mod metadata; // File metadata and information
pub mod validation; // Generic validation functions (version-agnostic)
pub mod v1; // Version 1.0 format implementation (complete & self-contained)

// Re-export only generic, version-agnostic types and functions
pub use crypto::{
    constant_time_eq, decrypt_content, decrypt_filename, derive_filename_key,
    encrypt_content, encrypt_filename, generate_nonce, generate_salt,
};
pub use errors::{CryptoError, SerializationError, ValidationError};
pub use memory::{SecureBytes, SecureKey, SecureString};
pub use metadata::FileMetadata;
pub use validation::{
    check_content_duplicate, validate_password_format, validate_password_strength,
};

// NOTE: Version-specific items are NOT re-exported.
// Use explicit imports for clarity:
//   use shadow_core::v1::{SecurityProfile, derive_key, FileHeader, ...};
//
// This makes version usage explicit and supports migration scenarios:
//   - Decrypt with v1::decrypt_content()
//   - Encrypt with v2::encrypt_content()
