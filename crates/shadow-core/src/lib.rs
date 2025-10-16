// shadow-core/src/lib.rs
// Pure cryptographic core for Shadow encryption tool
// 
// This crate contains only pure functions with no side effects.
// All cryptographic operations, data types, and validation logic
// are implemented here without any I/O dependencies.

pub mod types;
pub mod errors;
pub mod crypto;
pub mod file_format;
pub mod validation;

// Re-export key types and functions for convenient access
pub use types::{
    SecureString, SecureKey, SecureBytes,
    FileMetadata, FileHeader, FilenameData, 
    EncryptionRequest, EncryptedFile
};
pub use errors::{
    CryptoError, ValidationError, SerializationError
};
pub use crypto::{
    derive_key, encrypt_content, decrypt_content, 
    encrypt_filename, decrypt_filename,
    hash_content, generate_nonce, generate_salt
};
pub use file_format::{
    serialize_header, deserialize_header, 
    serialize_encrypted_file, deserialize_encrypted_file
};
pub use validation::{
    validate_encryption_request, validate_file_header, 
    check_content_duplicate, validate_header_bytes,
    validate_password_strength
};