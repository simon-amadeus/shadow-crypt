// shadow-core/src/lib.rs
// Pure cryptographic core for Shadow encryption tool
// 
// This crate contains only pure functions with no side effects.
// All cryptographic operations, data types, and validation logic
// are implemented here without any I/O dependencies.

pub mod memory;      // Secure memory types with zeroization  
pub mod metadata;    // File metadata and information
pub mod errors;      // Error types organized by domain
pub mod crypto;      // Cryptographic operations (modular)
pub mod format;      // Modular file format handling
pub mod validation;  // Validation functions (modular)

// Re-export key types and functions for convenient access
pub use memory::{
    SecureString, SecureKey, SecureBytes
};
pub use metadata::{
    FileMetadata
};
pub use format::v1::{
    FileHeader, FilenameData, EncryptedFile,
    serialize_header, deserialize_header
};
pub use errors::{
    CryptoError, ValidationError, SerializationError
};
pub use crypto::{
    SecurityProfile,
    derive_key, derive_filename_key,
    encrypt_content, decrypt_content, 
    encrypt_filename, decrypt_filename,
    hash_content, generate_nonce, generate_salt, constant_time_eq
};
pub use validation::{
    validate_file_header, check_content_duplicate, validate_header_bytes,
    validate_password_strength, validate_password_format,
    validate_file_content, validate_file_metadata
};