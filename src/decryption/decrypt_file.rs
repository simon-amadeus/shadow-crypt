//! V3-only file decryption implementation
//! 
//! This module provides V3-only file decryption functionality using
//! TLV field-based metadata retrieval and XChaCha20-Poly1305 decryption.

use crate::shared::core::errors::CryptoError;
use crate::shared::header::Header;
use crate::shared::metadata::FileMetadata;
use crate::shared::versioning::VersionedHeader;
use crate::shared::versions::v3::TlvFieldType;
use crate::shared::algorithms::xchacha20_poly1305::{
    decrypt_xchacha20_poly1305, derive_master_key, Argon2Params
};
use crate::shared::algorithms::AlgorithmId;
use std::path::Path;
use std::fs::{File, set_permissions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use sha2::{Sha256, Digest};

/// Decrypt a single file (V3-only)
/// 
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `output_path` - Path where decrypted file will be saved
/// * `password` - Password for key derivation
/// 
/// # Returns
/// * `Ok(())` - File decrypted successfully
/// * `Err(CryptoError)` - Decryption failed
pub fn decrypt_single_file_v3(
    input_path: &Path,
    output_path: &Path,
    password: &str
) -> Result<(), CryptoError> {
    // Read encrypted file
    let mut file = File::open(input_path)
        .map_err(CryptoError::FileSystemError)?;
    
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)
        .map_err(CryptoError::FileSystemError)?;

    // Deserialize V3 header
    let (header, header_size) = Header::deserialize(&encrypted_data)?;
    
    // Verify this is XChaCha20-Poly1305
    if header.algorithm_id != AlgorithmId::ChaCha20Poly1305 {
        return Err(CryptoError::UnsupportedAlgorithm(
            header.algorithm_id as u16
        ));
    }

    // Extract encrypted content
    let encrypted_content = &encrypted_data[header_size..];
    
    // Derive master key
    let params = Argon2Params::default();
    let master_key = derive_master_key(password, &header.salt, &params)?;

    // Decrypt content
    let decrypted_content = decrypt_xchacha20_poly1305(
        master_key.expose_secret(),
        &header.nonce,
        encrypted_content,
        &[]
    )?;

    // Extract metadata from TLV fields
    let metadata = extract_metadata_from_tlv(&header)?;

    // Verify file hash if present
    if metadata.file_hash != [0u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&decrypted_content);
        let actual_hash: [u8; 32] = hasher.finalize().into();
        
        if actual_hash != metadata.file_hash {
            return Err(CryptoError::CryptographicError(
                "File hash verification failed".to_string()
            ));
        }
    }

    // Write decrypted file
    let mut output_file = File::create(output_path)
        .map_err(CryptoError::FileSystemError)?;
    
    output_file.write_all(&decrypted_content)
        .map_err(CryptoError::FileSystemError)?;

    // Restore file metadata
    restore_file_metadata(output_path, &metadata)?;

    Ok(())
}

/// Extract metadata from TLV fields
fn extract_metadata_from_tlv(header: &Header) -> Result<FileMetadata, CryptoError> {
    let now = std::time::SystemTime::now();
    let mut metadata = FileMetadata {
        permissions: 0o644,  // Default permissions
        created: now,
        modified: now,
        accessed: now,
        file_hash: [0u8; 32],  // Default empty hash
        compression: None,
        created_by: format!("shadow-v3"),
        custom_attributes: std::collections::HashMap::new(),
    };

    // Extract content hash
    if let Some(hash_data) = header.tlv_fields.get_field(TlvFieldType::ContentHash) {
        if hash_data.len() == 32 {
            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(hash_data);
            metadata.file_hash = hash_array;
        }
    }

    // TODO: Extract other metadata fields from TLV when the types are available
    // For now, we'll use defaults

    Ok(metadata)
}

/// Restore file metadata (permissions, timestamps)
fn restore_file_metadata(path: &Path, metadata: &FileMetadata) -> Result<(), CryptoError> {
    use std::fs;

    // Restore permissions
    let std_permissions = fs::Permissions::from_mode(metadata.permissions);
    set_permissions(path, std_permissions)
        .map_err(CryptoError::FileSystemError)?;

    // TODO: Restore timestamps when SystemTime serialization is implemented
    // For now, we'll skip timestamp restoration as it requires proper serialization

    Ok(())
}