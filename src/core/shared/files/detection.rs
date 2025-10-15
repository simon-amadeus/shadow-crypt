//! File type detection functionality.

use std::path::Path;
use std::fs;
use std::io::Read;
use super::types::FileType;
use crate::core::shared::types::{CoreResult, FileError};

/// Detect the type of a file.
pub fn detect_file_type(path: &Path) -> CoreResult<FileType> {
    let metadata = fs::metadata(path)
        .map_err(|_e| FileError::NotFound { 
            path: path.display().to_string() 
        })?;

    if metadata.is_dir() {
        return Ok(FileType::Directory);
    }

    if !metadata.is_file() {
        // Check for symlinks on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if metadata.file_type().is_symlink() {
                return Ok(FileType::Symlink);
            }
        }
        return Ok(FileType::Other);
    }

    // Check if it's an encrypted Shadow file
    if is_encrypted_file(path)? {
        Ok(FileType::EncryptedShadow)
    } else {
        Ok(FileType::Regular)
    }
}

/// Check if a file is an encrypted Shadow file by examining magic bytes.
pub fn is_encrypted_file(path: &Path) -> CoreResult<bool> {
    let mut file = fs::File::open(path)
        .map_err(|_e| FileError::NotFound { 
            path: path.display().to_string() 
        })?;

    // Read magic number (6 bytes)
    let mut magic_buffer = [0u8; 6];
    let bytes_read = file.read(&mut magic_buffer)
        .map_err(|e| FileError::Format { 
            reason: format!("Failed to read file header: {}", e) 
        })?;

    if bytes_read < 6 {
        return Ok(false); // File too small to be a Shadow file
    }

    // Check for Shadow file magic bytes
    Ok(magic_buffer == *b"SHADOW")
}

/// Check if a file is a regular file suitable for encryption.
pub fn is_encryptable_file(path: &Path) -> CoreResult<bool> {
    let file_type = detect_file_type(path)?;
    Ok(file_type.is_encryptable())
}

/// Check if a file is already encrypted.
pub fn is_already_encrypted(path: &Path) -> CoreResult<bool> {
    let file_type = detect_file_type(path)?;
    Ok(file_type.is_encrypted())
}