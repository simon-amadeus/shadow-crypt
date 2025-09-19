//! File encryption implementation
//! 
//! This module provides single file encryption functionality using AES-256-GCM
//! with secure header generation and metadata preservation.

use crate::shared::errors::CryptoError;
use crate::shared::header::{Header, FileMetadata, AlgorithmId};
use crate::shared::crypto::{
    generate_secure_nonce, encrypt_aes_gcm, derive_master_key, generate_salt, Argon2Params
};
use std::path::Path;
use std::fs::{File, metadata};
use std::io::{Read, Write};
use std::time::SystemTime;
use sha2::{Sha256, Digest};

/// Encrypt a single file with AES-256-GCM
/// 
/// # Arguments
/// * `input_path` - Path to the file to encrypt
/// * `output_path` - Path where encrypted file will be saved
/// * `password` - Password for key derivation
/// * `obfuscate_filename` - Whether to obfuscate the original filename (Phase 6 feature)
/// 
/// # Returns
/// * `Ok(())` - File encrypted successfully
/// * `Err(CryptoError)` - Encryption failed
/// 
/// # Security
/// * Uses AES-256-GCM authenticated encryption
/// * Derives keys using Argon2id with secure parameters
/// * Stores original metadata securely in header
/// * Generates unique salt and nonce per file
pub fn encrypt_single_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    obfuscate_filename: bool,
) -> Result<(), CryptoError> {
    // Read input file
    let mut input_file = File::open(input_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    // Get file metadata
    let file_metadata = extract_file_metadata(input_path, &plaintext)?;
    
    // Generate cryptographic materials
    let salt = generate_salt(16)?;
    let params = Argon2Params::default();
    let key_material = derive_master_key(password, &salt, &params)?;
    let nonce = generate_secure_nonce()?;
    
    // Create header
    let mut header = create_encryption_header(
        input_path,
        &file_metadata,
        &salt,
        &nonce,
        obfuscate_filename,
    )?;
    
    // Encrypt metadata
    let metadata_bytes = file_metadata.serialize();
    let encrypted_metadata = encrypt_aes_gcm(
        key_material.encryption_key.expose_secret(),
        &nonce,
        &metadata_bytes,
        &[]
    )?;
    header.encrypted_metadata = encrypted_metadata.clone();
    header.metadata_length = encrypted_metadata.len() as u16;
    
    // Encrypt filename
    if let Some(filename) = input_path.file_name() {
        if let Some(filename_str) = filename.to_str() {
            let filename_bytes = filename_str.as_bytes();
            let encrypted_filename = encrypt_aes_gcm(
                key_material.encryption_key.expose_secret(),
                &nonce,
                filename_bytes,
                &[]
            )?;
            header.encrypted_filename = encrypted_filename.clone();
            header.filename_length = encrypted_filename.len() as u16;
        }
    }
    
    // Encrypt directory path
    if let Some(parent) = input_path.parent() {
        if let Some(parent_str) = parent.to_str() {
            let path_bytes = parent_str.as_bytes();
            let encrypted_path = encrypt_aes_gcm(
                key_material.encryption_key.expose_secret(),
                &nonce,
                path_bytes,
                &[]
            )?;
            header.encrypted_directory_path = encrypted_path.clone();
            header.directory_path_length = encrypted_path.len() as u16;
        }
    }
    
    // Encrypt file content
    let ciphertext = encrypt_aes_gcm(
        key_material.encryption_key.expose_secret(),
        &nonce,
        &plaintext,
        &[]  // No additional authenticated data for now
    )?;
    
    // Write encrypted file atomically
    write_encrypted_file(output_path, &header, &ciphertext)?;
    
    Ok(())
}

/// Extract metadata from a file for secure storage
fn extract_file_metadata(file_path: &Path, content: &[u8]) -> Result<FileMetadata, CryptoError> {
    let file_meta = metadata(file_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    // Calculate SHA-256 hash of original content
    let mut hasher = Sha256::new();
    hasher.update(content);
    let file_hash: [u8; 32] = hasher.finalize().into();
    
    // Extract timestamps
    let created = file_meta.created().unwrap_or(SystemTime::now());
    let modified = file_meta.modified().unwrap_or(SystemTime::now());
    let accessed = file_meta.accessed().unwrap_or(SystemTime::now());
    
    // Extract permissions (Unix-style, default for other platforms)
    #[cfg(unix)]
    let permissions = {
        use std::os::unix::fs::PermissionsExt;
        file_meta.permissions().mode()
    };
    
    #[cfg(not(unix))]
    let permissions = if file_meta.permissions().readonly() { 0o444 } else { 0o644 };
    
    let mut metadata = FileMetadata::new();
    metadata.permissions = permissions;
    metadata.created = created;
    metadata.modified = modified;
    metadata.accessed = accessed;
    metadata.file_hash = file_hash;
    
    Ok(metadata)
}

/// Create encryption header with all metadata
fn create_encryption_header(
    _file_path: &Path,
    _metadata: &FileMetadata,
    salt: &[u8],
    nonce: &[u8],
    _obfuscate_filename: bool,
) -> Result<Header, CryptoError> {
    let salt_array: [u8; 16] = salt.try_into()
        .map_err(|_| CryptoError::CryptographicError("Invalid salt length".to_string()))?;
    let nonce_array: [u8; 12] = nonce.try_into()
        .map_err(|_| CryptoError::CryptographicError("Invalid nonce length".to_string()))?;
    
    let header = Header::new(
        AlgorithmId::AesGcm256,
        salt_array,
        nonce_array,
    );
    
    Ok(header)
}

/// Write encrypted file atomically to prevent corruption
fn write_encrypted_file(
    output_path: &Path,
    header: &Header,
    ciphertext: &[u8],
) -> Result<(), CryptoError> {
    // Create temporary file for atomic write
    let temp_path = output_path.with_extension("tmp");
    
    {
        let mut output_file = File::create(&temp_path)
            .map_err(|e| CryptoError::FileSystemError(e))?;
        
        // Write header
        let header_bytes = header.serialize();
        output_file.write_all(&header_bytes)
            .map_err(|e| CryptoError::FileSystemError(e))?;
        
        // Write encrypted content
        output_file.write_all(ciphertext)
            .map_err(|e| CryptoError::FileSystemError(e))?;
        
        // Ensure data is written to disk
        output_file.flush()
            .map_err(|e| CryptoError::FileSystemError(e))?;
    }
    
    // Atomically move temporary file to final location
    std::fs::rename(&temp_path, output_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_single_file_basic() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("test.txt");
        let output_path = temp_dir.path().join("test.enc");
        
        // Create test file
        std::fs::write(&input_path, "Hello, World!").unwrap();
        
        // Test encryption
        let result = encrypt_single_file(&input_path, &output_path, "password123", false);
        
        assert!(result.is_ok(), "Encryption should succeed");
        assert!(output_path.exists(), "Encrypted file should be created");
        
        // Verify encrypted content is different
        let original = std::fs::read(&input_path).unwrap();
        let encrypted = std::fs::read(&output_path).unwrap();
        assert_ne!(original, encrypted);
        assert!(encrypted.len() > original.len(), "Encrypted file should be larger");
        
        // Check that encrypted file starts with magic number
        assert_eq!(&encrypted[0..4], b"ENC3", "Should start with ENC3 magic number");
    }

    #[test]
    fn test_encrypt_nonexistent_file() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("nonexistent.txt");
        let output_path = temp_dir.path().join("test.enc");
        
        let result = encrypt_single_file(&input_path, &output_path, "password123", false);
        assert!(result.is_err(), "Should fail for nonexistent file");
    }
}