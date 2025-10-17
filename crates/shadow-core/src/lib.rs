// shadow-core/src/lib.rs
// Pure cryptographic core for Shadow encryption tool
//
// This crate contains only pure functions with no side effects.
// All cryptographic operations, data types, and validation logic
// are implemented here without any I/O dependencies.

pub mod crypto; // Cryptographic operations (modular)
pub mod errors; // Error types organized by domain
pub mod format; // Modular file format handling
pub mod memory; // Secure memory types with zeroization
pub mod metadata; // File metadata and information
pub mod validation; // Validation functions (modular)

// Re-export key types and functions for convenient access
pub use crypto::{
    SecurityProfile, constant_time_eq, decrypt_content, decrypt_filename, derive_filename_key,
    derive_key, encrypt_content, encrypt_filename, generate_nonce, generate_salt, hash_content,
};
pub use errors::{CryptoError, SerializationError, ValidationError};
pub use format::v1::{
    EncryptedFile, FileHeader, FilenameData, deserialize_header, serialize_header,
};
pub use memory::{SecureBytes, SecureKey, SecureString};
pub use metadata::FileMetadata;
pub use validation::{
    check_content_duplicate, validate_file_content, validate_file_header, validate_file_metadata,
    validate_header_bytes, validate_password_format, validate_password_strength,
};
