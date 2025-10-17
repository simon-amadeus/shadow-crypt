// shadow-core/src/v1/mod.rs
// Version 1.0 Shadow format - complete self-contained implementation
//
// This module contains ALL code specific to Shadow v1.0 format:
// - File format structures and serialization
// - Cryptographic algorithms and parameters  
// - Validation rules and logic
// - Constants and specifications
//
// Future versions (v2, etc.) will be separate sibling modules.

pub mod constants;     // V1 format constants and specifications
pub mod crypto;        // V1 cryptographic algorithms and parameters
pub mod file_data;     // V1 file content and metadata validation
pub mod file_operations; // V1 high-level encrypt/decrypt operations
pub mod header;        // V1 header validation
pub mod header_builder; // V1 header construction with version-specific logic
pub mod serialization; // V1 serialization/deserialization
pub mod types;         // V1 data structures
pub mod validation;    // V1 format-specific validation

// Re-export main V1 API for convenience
pub use constants::*;
pub use crypto::{derive_key, hash_content, encrypt_content, encrypt_filename, decrypt_content, decrypt_filename};
pub use crate::security::SecurityProfile;
pub use file_data::{validate_file_content, validate_file_metadata};
pub use file_operations::{
    encrypt_file, decrypt_file, EncryptFileRequest, DecryptFileRequest, 
    EncryptedFile, DecryptedFile, FileOperationError
};
pub use header::{validate_file_header, validate_header_bytes};
pub use header_builder::{create_v1_header, V1HeaderRequest, V1HeaderResult};
pub use serialization::{deserialize_header, serialize_header};
pub use types::{FileHeader, FilenameData};
pub use validation::{validate_file_header as validate_v1_file_header, validate_header_bytes as validate_v1_header_bytes};
