// shadow-core/src/v1/header_builder.rs
// V1-specific header construction with all version-specific logic

use crate::memory::{SecureKey, SecureString};
use crate::security::SecurityProfile;
use crate::errors::CryptoError;
use super::{FileHeader, FilenameData, derive_key, encrypt_filename};
use super::constants::*;

/// V1 header construction parameters
pub struct V1HeaderRequest {
    pub original_filename: String,
    pub content_hash: [u8; 32],
    pub password: SecureString,
    pub security_profile: SecurityProfile,
    pub obfuscate_filename: bool,
}

/// V1 header construction result
pub struct V1HeaderResult {
    pub header: FileHeader,
    pub master_key: SecureKey,
    pub salt: [u8; 16], 
    pub content_nonce: [u8; 24],
}

/// Create a V1 file header with all version-specific logic encapsulated
/// 
/// This function handles:
/// - V1-specific magic bytes and algorithm ID
/// - Always encrypts filenames for security (obfuscation flag controls output filename only)
/// - V1-specific salt/nonce generation
/// - V1-specific key derivation
pub fn create_v1_header(request: V1HeaderRequest) -> Result<V1HeaderResult, CryptoError> {
    // Generate V1-specific random values
    let salt = crate::algorithms::argon2::generate_salt();
    let content_nonce = crate::algorithms::xchacha20_poly1305::generate_nonce();
    let filename_nonce = crate::algorithms::xchacha20_poly1305::generate_nonce();

    // Derive master key using V1 method
    let master_key = derive_key(&request.password, &salt, request.security_profile)?;

    // Always encrypt filename in header for security
    let encrypted_filename = encrypt_filename(&request.original_filename, &master_key, &filename_nonce)?;
    let filename_data = FilenameData::Encrypted {
        ciphertext: encrypted_filename,
        nonce: filename_nonce,
    };

    // Create V1 header with all version-specific fields
    let header = FileHeader {
        magic: *MAGIC,
        algorithm_id: ALGORITHM_XCHACHA20_POLY1305,
        obfuscation_flag: if request.obfuscate_filename {
            FILENAME_ENCRYPTED
        } else {
            FILENAME_PLAINTEXT  
        },
        content_hash: request.content_hash,
        filename_data,
        salt,
        content_nonce,
    };

    Ok(V1HeaderResult {
        header,
        master_key,
        salt,
        content_nonce,
    })
}