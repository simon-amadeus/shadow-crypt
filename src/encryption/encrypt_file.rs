//! File encryption implementation
//! 
//! This module provides single file encryption functionality using AES-256-GCM
//! with secure header generation and metadata preservation.

use crate::shared::errors::CryptoError;
use crate::shared::header::{Header, FileMetadata, AlgorithmId};
use crate::shared::algorithms::{Algorithm};
use crate::shared::algorithms::aes_gcm::{
    generate_secure_nonce, encrypt_aes_gcm, derive_master_key, generate_salt, Argon2Params
};
use crate::encryption::filename_obfuscation::obfuscate_filename;
use std::path::{Path, PathBuf};
use std::fs::{File, metadata};
use std::io::{Read, Write};
use std::time::SystemTime;
use sha2::{Sha256, Digest};

/// Encrypt a single file with AES-256-GCM
/// 
/// # Arguments
/// * `input_path` - Path to the file to encrypt
/// * `output_path` - Base path for output (will be modified if obfuscation is enabled)
/// * `password` - Password for key derivation
/// * `obfuscate_filename` - Whether to obfuscate the original filename
/// 
/// # Returns
/// * `Ok(())` - File encrypted successfully
/// * `Err(CryptoError)` - Encryption failed
/// 
/// # Behavior
/// * If obfuscate_filename is false: saves to exact output_path
/// * If obfuscate_filename is true: creates obfuscated filename in same directory as output_path
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
    // Use default (production) parameters for public API
    let params = Argon2Params::default();
    encrypt_single_file_with_params(input_path, output_path, password, obfuscate_filename, &params)
}

/// Encrypt a single file with progress reporting
pub fn encrypt_single_file_with_progress(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    obfuscate_filename: bool,
    show_progress: bool,
) -> Result<(), CryptoError> {
    let params = Argon2Params::default();
    encrypt_single_file_with_params_and_progress(input_path, output_path, password, obfuscate_filename, &params, show_progress)
}

/// Encrypt a single file with algorithm selection and custom parameters
pub fn encrypt_single_file_with_algorithm_and_params(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    obfuscate_filename: bool,
    algorithm: Algorithm,
    params: &Argon2Params,
) -> Result<(), CryptoError> {
    match algorithm {
        Algorithm::AES256GCM => {
            encrypt_single_file_with_params(input_path, output_path, password, obfuscate_filename, params)
        }
        Algorithm::XChaCha20Poly1305 => {
            // TODO: Implement XChaCha20-Poly1305 encryption dispatch
            Err(CryptoError::CryptographicError(
                "XChaCha20-Poly1305 encryption not yet implemented in dispatch".to_string()
            ))
        }
    }
}

/// Internal function that accepts custom Argon2 parameters for testing
pub fn encrypt_single_file_with_params(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    obfuscate_filename: bool,
    params: &Argon2Params,
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
    let key_material = derive_master_key(password, &salt, params)?;
    let nonce = generate_secure_nonce()?;
    
    // Determine actual output path (obfuscated or original)
    let actual_output_path = if obfuscate_filename {
        generate_obfuscated_output_path(input_path, output_path, &key_material)?
    } else {
        output_path.to_path_buf()
    };
    
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
    
    // Compute obfuscated filename authentication if needed
    if obfuscate_filename {
        use crate::shared::filename_auth::{compute_filename_auth_tag, extract_filename_for_auth};
        let obfuscated_filename = extract_filename_for_auth(&actual_output_path)?;
        let auth_tag = compute_filename_auth_tag(
            &obfuscated_filename,
            &header.salt,
            &header.nonce,
            &key_material
        )?;
        header.obfuscated_filename_auth_tag = auth_tag;
    }
    
    // Write encrypted file atomically
    write_encrypted_file(&actual_output_path, &header, &ciphertext)?;
    
    if obfuscate_filename {
        println!("🎭 File saved with obfuscated name: {}", actual_output_path.display());
    }
    
    Ok(())
}

/// Internal function with custom Argon2 parameters and optional progress reporting
pub fn encrypt_single_file_with_params_and_progress(
    input_path: &Path,
    output_path: &Path,
    password: &str,
    obfuscate_filename: bool,
    params: &Argon2Params,
    show_progress: bool,
) -> Result<(), CryptoError> {
    use crate::shared::progress::SingleFileProgress;
    
    let mut progress = SingleFileProgress::new(show_progress);
    
    // Phase 1: File I/O
    progress.start_phase("Reading file");
    let mut input_file = File::open(input_path)
        .map_err(|e| {
            progress.end_phase_with_error(&format!("Failed to open file: {}", e));
            CryptoError::FileSystemError(e)
        })?;
    
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext)
        .map_err(|e| {
            progress.end_phase_with_error(&format!("Failed to read file: {}", e));
            CryptoError::FileSystemError(e)
        })?;
    
    let file_metadata = extract_file_metadata(input_path, &plaintext)?;
    progress.end_phase();
    
    // Phase 2: Key derivation (usually the slowest part)
    progress.start_phase("Deriving encryption key");
    let salt = generate_salt(16)?;
    let key_material = derive_master_key(password, &salt, params)
        .map_err(|e| {
            progress.end_phase_with_error(&format!("Key derivation failed: {}", e));
            e
        })?;
    progress.end_phase();
    
    // Phase 3: Cryptographic operations
    progress.start_phase("Encrypting data");
    let nonce = generate_secure_nonce()?;
    
    // Determine actual output path
    let actual_output_path = if obfuscate_filename {
        generate_obfuscated_output_path(input_path, output_path, &key_material)?
    } else {
        output_path.to_path_buf()
    };
    
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
    
    // Main content encryption
    let ciphertext = encrypt_aes_gcm(
        key_material.encryption_key.expose_secret(),
        &nonce,
        &plaintext,
        &header.serialize()
    )?;
    
    // Filename authentication if obfuscation enabled
    if obfuscate_filename {
        use crate::shared::filename_auth::{compute_filename_auth_tag, extract_filename_for_auth};
        let obfuscated_filename = extract_filename_for_auth(&actual_output_path)?;
        let auth_tag = compute_filename_auth_tag(
            &obfuscated_filename,
            &header.salt,
            &header.nonce,
            &key_material
        )?;
        header.obfuscated_filename_auth_tag = auth_tag;
    }
    progress.end_phase();
    
    // Phase 4: Write output
    progress.start_phase("Writing encrypted file");
    write_encrypted_file(&actual_output_path, &header, &ciphertext)
        .map_err(|e| {
            progress.end_phase_with_error(&format!("Failed to write file: {}", e));
            e
        })?;
    progress.end_phase();
    
    if show_progress {
        let total_time = progress.total_elapsed();
        println!("✅ Encryption completed in {}", crate::shared::performance::format_duration(total_time));
        
        if obfuscate_filename {
            println!("🎭 File saved with obfuscated name: {}", actual_output_path.display());
        }
    } else if obfuscate_filename {
        println!("🎭 File saved with obfuscated name: {}", actual_output_path.display());
    }
    
    Ok(())
}

/// Generate obfuscated output path for the encrypted file
/// 
/// Takes the input filename, obfuscates it using the derived key,
/// and creates a new output path in the same directory as the specified output path.
/// 
/// # Arguments
/// * `input_path` - Original file path (for extracting filename)
/// * `output_path` - Base output path (for extracting directory)
/// * `key_material` - Derived cryptographic keys
/// 
/// # Returns
/// * `Ok(PathBuf)` - Obfuscated output path
/// * `Err(CryptoError)` - Obfuscation failed
fn generate_obfuscated_output_path(
    input_path: &Path, 
    output_path: &Path, 
    key_material: &crate::shared::core::crypto::KeyMaterial
) -> Result<PathBuf, CryptoError> {
    // Extract original filename
    let original_filename = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CryptoError::FileSystemError(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid input filename")
        ))?;
    
    // Generate obfuscated filename
    let obfuscated_name = obfuscate_filename(
        key_material.obfuscation_key.expose_secret(),
        original_filename
    )?;
    
    // Use the directory from output_path, but with obfuscated filename
    let output_dir = output_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    
    Ok(output_dir.join(obfuscated_name))
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
        let output_path = temp_dir.path().join("test.shadow");
        
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
        assert_eq!(&encrypted[0..6], b"SHADOW", "Should start with SHADOW magic number");
    }

    #[test]
    fn test_encrypt_nonexistent_file() {
        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("nonexistent.txt");
        let output_path = temp_dir.path().join("test.shadow");
        
        let result = encrypt_single_file(&input_path, &output_path, "password123", false);
        assert!(result.is_err(), "Should fail for nonexistent file");
    }
}