//! File type detection functionality.

use std::path::Path;
use std::fs;
use std::io::Read;
use super::types::FileType;
use crate::core::types::{CoreResult, FileError};

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

    // Read first few bytes to check for Shadow file signature
    let mut buffer = [0u8; 8];
    let bytes_read = file.read(&mut buffer)
        .map_err(|e| FileError::Format { 
            reason: format!("Failed to read file header: {}", e) 
        })?;

    if bytes_read < 4 {
        return Ok(false); // File too small to be a Shadow file
    }

    // Check for Shadow file magic bytes (simplified for now)
    // In a real implementation, this would check the TLV header format
    // For now, we'll use a simple heuristic based on file structure
    Ok(has_shadow_structure(&buffer[..bytes_read]))
}

/// Check if the buffer contains Shadow file structure.
fn has_shadow_structure(buffer: &[u8]) -> bool {
    // This is a simplified check - in reality you'd parse the TLV header
    // For now, check if it looks like structured binary data
    if buffer.len() < 4 {
        return false;
    }

    // Check for reasonable version number (first 2 bytes as little-endian)
    let version = u16::from_le_bytes([buffer[0], buffer[1]]);
    if version == 0 || version > 100 {
        return false; // Unreasonable version number
    }

    // Check for reasonable field count (next 2 bytes)
    let field_count = u16::from_le_bytes([buffer[2], buffer[3]]);
    if field_count == 0 || field_count > 50 {
        return false; // Unreasonable field count
    }

    true // Looks like it could be a Shadow file
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