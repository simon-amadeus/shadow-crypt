//! V3-only file encryption implementation
//! 
//! This module provides clean V3-only file encryption using XChaCha20-Poly1305
//! with TLV field-based metadata storage.

use crate::shared::errors::CryptoError;
use crate::shared::header::{Header, AlgorithmId};
use crate::shared::metadata::FileMetadata;
use crate::shared::versions::v3::TlvFieldType;
use crate::shared::versioning::VersionedHeader;
use crate::shared::algorithms::xchacha20_poly1305::{
    generate_secure_nonce, encrypt_xchacha20_poly1305, derive_master_key, generate_salt, Argon2Params
};
use std::path::Path;
use std::fs::{File, metadata};
use std::io::{Read, Write};
use std::time::SystemTime;
use sha2::{Sha256, Digest};

/// Encrypt a single file with XChaCha20-Poly1305 (V3-only)
pub fn encrypt_single_file_v3(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    obfuscate_filename: bool,
) -> Result<(), CryptoError> {
    // Read input file
    let mut input_file = File::open(input_path)
        .map_err(CryptoError::FileSystemError)?;
    
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)
        .map_err(CryptoError::FileSystemError)?;
    
    // Get file metadata
    let file_metadata = extract_file_metadata(input_path, &plaintext)?;
    
    // Generate cryptographic materials (V3 uses 32-byte salt)
    let salt = generate_salt()?;
    let master_key = derive_master_key(password, &salt, &Argon2Params::default())?;
    let nonce = generate_secure_nonce()?;
    
    // Determine actual output path
    let actual_output_path = if obfuscate_filename {
        // For now, disable obfuscation until we update the function signature
        // TODO: Update generate_obfuscated_output_path to work with V3 key format
        output_path.to_path_buf()
    } else {
        output_path.to_path_buf()
    };
    
    // Create V3 header with XChaCha20-Poly1305
    let mut header = Header::new(
        AlgorithmId::ChaCha20Poly1305,
        nonce.to_vec(),
        salt,
    );
    
    // Encrypt and store metadata in TLV field
    let metadata_bytes = file_metadata.serialize();
    let encrypted_metadata = encrypt_xchacha20_poly1305(
        master_key.expose_secret(),
        &nonce,
        &metadata_bytes,
        &[]
    )?;
    header.tlv_fields.add_field(TlvFieldType::FileMetadata, encrypted_metadata);
    
    // Encrypt and store filename in TLV field
    if let Some(filename) = input_path.file_name() {
        if let Some(filename_str) = filename.to_str() {
            let filename_bytes = filename_str.as_bytes();
            let encrypted_filename = encrypt_xchacha20_poly1305(
                master_key.expose_secret(),
                &nonce,
                filename_bytes,
                &[]
            )?;
            header.tlv_fields.add_field(TlvFieldType::OriginalFilename, encrypted_filename);
        }
    }
    
    // Encrypt and store directory path in TLV field
    if let Some(parent) = input_path.parent() {
        if let Some(parent_str) = parent.to_str() {
            let path_bytes = parent_str.as_bytes();
            let encrypted_path = encrypt_xchacha20_poly1305(
                master_key.expose_secret(),
                &nonce,
                path_bytes,
                &[]
            )?;
            header.tlv_fields.add_field(TlvFieldType::DirectoryPath, encrypted_path);
        }
    }
    
    // Encrypt file content
    let ciphertext = encrypt_xchacha20_poly1305(
        master_key.expose_secret(),
        &nonce,
        &plaintext,
        &[]
    )?;
    
    // Write encrypted file atomically
    write_encrypted_file_v3(&actual_output_path, &header, &ciphertext)?;
    
    Ok(())
}

/// Write encrypted file atomically to prevent corruption (V3-only)
fn write_encrypted_file_v3(
    output_path: &Path,
    header: &Header,
    ciphertext: &[u8],
) -> Result<(), CryptoError> {
    let temp_path = output_path.with_extension("tmp");
    
    {
        let mut output_file = File::create(&temp_path)
            .map_err(CryptoError::FileSystemError)?;
        
        // Write header
        let header_bytes = header.serialize();
        output_file.write_all(&header_bytes)
            .map_err(CryptoError::FileSystemError)?;
        
        // Write ciphertext
        output_file.write_all(ciphertext)
            .map_err(CryptoError::FileSystemError)?;
    }
    
    // Atomic rename
    std::fs::rename(&temp_path, output_path)
        .map_err(CryptoError::FileSystemError)?;
    
    Ok(())
}

/// Extract file metadata for encryption (V3-only)
fn extract_file_metadata(input_path: &Path, content: &[u8]) -> Result<FileMetadata, CryptoError> {
    let file_metadata = metadata(input_path)
        .map_err(CryptoError::FileSystemError)?;
    
    let mut hasher = Sha256::new();
    hasher.update(content);
    let content_hash: [u8; 32] = hasher.finalize().into();
    
    let modified_time = file_metadata.modified()
        .unwrap_or(SystemTime::UNIX_EPOCH);
    
    let created_time = file_metadata.created()
        .unwrap_or(SystemTime::UNIX_EPOCH);
    
    let accessed_time = file_metadata.accessed()
        .unwrap_or(SystemTime::UNIX_EPOCH);
    
    Ok(FileMetadata {
        permissions: 0o644, // Default permissions
        created: created_time,
        modified: modified_time,
        accessed: accessed_time,
        file_hash: content_hash,
        compression: Some(crate::shared::header::CompressionType::None),
        created_by: "shadow-crypt-v3".to_string(),
        custom_attributes: std::collections::HashMap::new(),
    })
}