//! File scanning implementation for encrypted file discovery and metadata extraction
//! 
//! This module provides directory scanning to find encrypted files and extract
//! their metadata without requiring full file decryption.

use crate::shared::errors::CryptoError;
use crate::shared::file_detection::{is_encrypted_file};
use crate::shared::algorithms::{AesGcmConfig, CryptoConfig, DefaultConfigProvider, ConfigProvider};
use crate::shared::versions::v3::HeaderV3;
use crate::shared::versioning::{detect_version, VersionedHeader};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::io::Read;

/// File information structure containing metadata for display
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub original_name: String,
    pub obfuscated_name: String,
    pub encrypted_path: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
    pub encrypted_size: u64,
    pub filename_decrypted: bool,
}

/// List encrypted files in a directory with their original names
pub fn list_encrypted_files(directory: &Path, password: &str) -> Result<Vec<FileInfo>, CryptoError> {
    let provider = DefaultConfigProvider::<AesGcmConfig>::production();
    list_encrypted_files_with_config(directory, password, &provider)
}

/// List encrypted files in a directory using trait-based configuration
pub fn list_encrypted_files_with_config<P: ConfigProvider>(
    directory: &Path, 
    password: &str, 
    provider: &P
) -> Result<Vec<FileInfo>, CryptoError> {
    if !directory.is_dir() {
        return Err(CryptoError::InvalidFileFormat);
    }
    
    let mut files = Vec::new();
    let entries = fs::read_dir(directory)?;
    let config = provider.config();
    
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
        let metadata = entry.metadata()?;
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let encrypted_size = metadata.len();
        
        // Only handle V3 files now
        let file_info = match detect_and_read_v3_header(&path, password, config) {
            Ok(info) => info,
            Err(_) => continue, // Skip files with unreadable headers or wrong password
        };
        
        // Always capture the obfuscated (current) filename from the filesystem
        let obfuscated_name = path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        
        files.push(FileInfo {
            original_name: file_info.original_name,
            obfuscated_name,
            encrypted_path: path,
            size: file_info.original_size,
            modified,
            encrypted_size,
            filename_decrypted: file_info.filename_decrypted,
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

/// Information extracted from a header file
struct HeaderFileInfo {
    original_name: String,
    original_size: u64,
    filename_decrypted: bool,
}

/// Detect file version and extract header information (V3 only)
fn detect_and_read_v3_header<C: CryptoConfig>(
    path: &Path,
    _password: &str,
    _config: &C,
) -> Result<HeaderFileInfo, CryptoError> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    // Verify this is a V3 file
    let version = detect_version(&buffer)?;
    if version != 3 {
        return Err(CryptoError::HeaderParsingError(
            format!("Unsupported version: {}. Only V3 files are supported.", version)
        ));
    }
    
    extract_v3_file_info(&buffer)
}

/// Extract file info from V3 header
fn extract_v3_file_info(buffer: &[u8]) -> Result<HeaderFileInfo, CryptoError> {
    let (header, _) = HeaderV3::deserialize(buffer)?;
    
    // Calculate original content size
    let header_size = header.serialize().len();
    let encrypted_content_size = buffer.len().saturating_sub(header_size);
    let original_size = encrypted_content_size.saturating_sub(16) as u64; // Subtract auth tag
    
    // V3 filename restoration not yet implemented - placeholder
    let original_name = "[ENCRYPTED]".to_string();
    let filename_decrypted = false;
    
    Ok(HeaderFileInfo {
        original_name,
        original_size,
        filename_decrypted,
    })
}

/// List encrypted files in a directory with custom Argon2 parameters (legacy)
/// 
/// **DEPRECATED**: Use `list_encrypted_files_with_config` instead for better configurability.
pub fn list_encrypted_files_with_params(directory: &Path, password: &str, params: &crate::shared::algorithms::aes_gcm::Argon2Params) -> Result<Vec<FileInfo>, CryptoError> {
    use crate::shared::algorithms::aes_gcm_config::AesGcmConfig;
    // Convert legacy params to modern config
    let config = AesGcmConfig::new(params.clone());
    let provider = DefaultConfigProvider::new(config);
    list_encrypted_files_with_config(directory, password, &provider)
}