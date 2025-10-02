//! File scanning implementation for Phase 8
//! 
//! This module provides directory scanning to find encrypted files and extract
//! their metadata without requiring full file decryption.

use crate::shared::errors::CryptoError;
use crate::shared::file_detection::{is_encrypted_file, read_header_only};
use crate::shared::algorithms::aes_gcm::{derive_master_key, Argon2Params};
use crate::decryption::filename_restoration::restore_original_filename;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// File information structure containing metadata for display
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub original_name: String,
    pub obfuscated_name: String, // Added: always store the obfuscated filename
    pub encrypted_path: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
    pub encrypted_size: u64,
    pub filename_decrypted: bool, // Track if filename was successfully decrypted
}

/// List encrypted files in a directory with their original names
/// 
/// This function scans a directory for encrypted files, reads their headers,
/// and attempts to restore original filenames using the provided password.
/// Files with authentication failures are still listed but show encrypted names.
pub fn list_encrypted_files(directory: &Path, password: &str) -> Result<Vec<FileInfo>, CryptoError> {
    list_encrypted_files_with_params(directory, password, &Argon2Params::default())
}

/// List encrypted files in a directory with custom Argon2 parameters
/// 
/// This function scans a directory for encrypted files, reads their headers,
/// and attempts to restore original filenames using the provided password and parameters.
/// Files with authentication failures are still listed but show encrypted names.
pub fn list_encrypted_files_with_params(directory: &Path, password: &str, params: &Argon2Params) -> Result<Vec<FileInfo>, CryptoError> {
    if !directory.is_dir() {
        return Err(CryptoError::InvalidFileFormat);
    }
    
    let mut files = Vec::new();
    let entries = fs::read_dir(directory)?;
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        
        // Skip directories and non-encrypted files
        if path.is_dir() {
            continue;
        }
        
        // Check if file is encrypted by magic number
        if !is_encrypted_file(&path)? {
            continue;
        }
        
        // Get file metadata
        let metadata = fs::metadata(&path)?;
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let encrypted_size = metadata.len();
        
        // Read header to get size and filename information
        let header = match read_header_only(&path) {
            Ok(h) => h,
            Err(_) => continue, // Skip files with unreadable headers
        };
        
        // Calculate original content size (encrypted content minus GCM tag)
        let header_size = header.serialize().len();
        let encrypted_content_size = encrypted_size.saturating_sub(header_size as u64);
        let original_size = encrypted_content_size.saturating_sub(16); // Subtract GCM auth tag
        
        // Try to extract original filename from header
        let (original_name, filename_decrypted) = match extract_original_filename(&header, password, params) {
            Ok(name) => (name, true),
            Err(_) => {
                // If filename restoration fails, show that filename is encrypted
                ("[ENCRYPTED]".to_string(), false)
            }
        };
        
        // Always capture the obfuscated (current) filename from the filesystem
        let obfuscated_name = path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        
        files.push(FileInfo {
            original_name,
            obfuscated_name,
            encrypted_path: path,
            size: original_size,
            modified,
            encrypted_size,
            filename_decrypted,
        });
    }
    
    // Sort files by decryption status first (successful decryptions first),
    // then alphabetically by original name for successfully decrypted files only.
    // This prevents filename guessing attacks by users with wrong passwords.
    files.sort_by(|a, b| {
        match (a.filename_decrypted, b.filename_decrypted) {
            // Both successfully decrypted - sort alphabetically by original name
            (true, true) => a.original_name.cmp(&b.original_name),
            // Successfully decrypted files come first
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            // Both failed decryption - preserve original filesystem order (no sorting)
            (false, false) => std::cmp::Ordering::Equal,
        }
    });
    
    Ok(files)
}

/// Extract original filename from encrypted file header
/// 
/// This function derives keys from password and attempts to decrypt the filename.
/// It's a helper function used by list_encrypted_files.
fn extract_original_filename(header: &crate::shared::header::Header, password: &str, params: &Argon2Params) -> Result<String, CryptoError> {
    // Derive key material from password using header salt
    let key_material = derive_master_key(password, &header.salt, params)?;
    
    // Use existing filename restoration logic from Phase 7
    restore_original_filename(header, &key_material)
}