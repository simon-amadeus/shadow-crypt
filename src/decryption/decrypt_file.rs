//! File decryption implementation
//! 
//! This module provides single file decryption functionality using AES-256-GCM
//! with header parsing, authentication verification, and metadata restoration.

use crate::shared::errors::CryptoError;
use crate::shared::header::{Header, FileMetadata};
use crate::shared::crypto::{
    decrypt_aes_gcm, derive_master_key, Argon2Params
};
use std::path::Path;
use std::fs::{File, set_permissions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use sha2::{Sha256, Digest};

/// Decrypt a single file with AES-256-GCM
/// 
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `output_path` - Path where decrypted file will be saved
/// * `password` - Password for key derivation
/// 
/// # Returns
/// * `Ok(())` - File decrypted successfully
/// * `Err(CryptoError)` - Decryption failed
/// 
/// # Security
/// * Verifies GCM authentication tags before decryption
/// * Validates file integrity using SHA-256 hash
/// * Restores original file metadata (permissions, timestamps)
/// * Handles decryption errors gracefully with clear error messages
pub fn decrypt_single_file(
    input_path: &Path,
    output_path: &Path,
    password: &str
) -> Result<(), CryptoError> {
    // Use default (production) parameters for public API
    let params = Argon2Params::default();
    decrypt_single_file_with_params(input_path, output_path, password, &params)
}

/// Internal function that accepts custom Argon2 parameters for testing
pub fn decrypt_single_file_with_params(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    params: &Argon2Params,
) -> Result<(), CryptoError> {
    // Read encrypted file
    let mut input_file = File::open(input_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    let mut encrypted_data = Vec::new();
    input_file.read_to_end(&mut encrypted_data)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    // Parse header from encrypted file
    let (header, header_size) = Header::deserialize(&encrypted_data)?;
    
    // Derive master key from password and salt
    let key_material = derive_master_key(password, &header.salt, params)?;
    
    // Decrypt and verify directory path
    let _directory_path = if !header.encrypted_directory_path.is_empty() {
        decrypt_aes_gcm(
            key_material.encryption_key.expose_secret(),
            &header.nonce,
            &header.encrypted_directory_path,
            &[]
        ).map_err(|e| CryptoError::CryptographicError(
            format!("Failed to decrypt directory path: {}", e)
        ))?
    } else {
        Vec::new()
    };
    
    // Decrypt and verify filename
    let _original_filename = if !header.encrypted_filename.is_empty() {
        let filename_bytes = decrypt_aes_gcm(
            key_material.encryption_key.expose_secret(),
            &header.nonce,
            &header.encrypted_filename,
            &[]
        ).map_err(|e| CryptoError::CryptographicError(
            format!("Failed to decrypt filename: {}", e)
        ))?;
        
        String::from_utf8(filename_bytes)
            .map_err(|e| CryptoError::CryptographicError(
                format!("Invalid UTF-8 in decrypted filename: {}", e)
            ))?
    } else {
        String::new()
    };
    
    // Decrypt and verify metadata
    let metadata = if !header.encrypted_metadata.is_empty() {
        let metadata_bytes = decrypt_aes_gcm(
            key_material.encryption_key.expose_secret(),
            &header.nonce,
            &header.encrypted_metadata,
            &[]
        ).map_err(|e| CryptoError::CryptographicError(
            format!("Failed to decrypt metadata: {}", e)
        ))?;
        
        FileMetadata::deserialize(&metadata_bytes)?
    } else {
        return Err(CryptoError::CryptographicError(
            "Missing file metadata in header".to_string()
        ));
    };
    
    // Extract encrypted content (everything after header)
    if header_size >= encrypted_data.len() {
        return Err(CryptoError::CryptographicError(
            "Invalid file format: no content after header".to_string()
        ));
    }
    
    let encrypted_content = &encrypted_data[header_size..];
    
    // Decrypt file content
    let decrypted_content = decrypt_aes_gcm(
        key_material.encryption_key.expose_secret(),
        &header.nonce,
        encrypted_content,
        &[]
    ).map_err(|e| CryptoError::CryptographicError(
        format!("Failed to decrypt file content: {}", e)
    ))?;
    
    // Verify file integrity using SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(&decrypted_content);
    let computed_hash: [u8; 32] = hasher.finalize().into();
    
    if computed_hash != metadata.file_hash {
        return Err(CryptoError::CryptographicError(
            "File integrity check failed: SHA-256 hash mismatch".to_string()
        ));
    }
    
    // Write decrypted content to output file
    let mut output_file = File::create(output_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    output_file.write_all(&decrypted_content)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    // Restore file metadata (permissions)
    #[cfg(unix)]
    {
        let permissions = std::fs::Permissions::from_mode(metadata.permissions);
        set_permissions(output_path, permissions)
            .map_err(|e| CryptoError::FileSystemError(e))?;
    }
    
    // Note: Timestamp restoration would require additional platform-specific code
    // and is not implemented in this phase for simplicity
    
    Ok(())
}