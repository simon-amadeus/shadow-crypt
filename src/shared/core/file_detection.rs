//! File detection utilities
//! 
//! This module provides functions to detect encrypted files by examining
//! their headers and magic numbers without requiring full decryption.

use crate::shared::core::errors::CryptoError;
use crate::shared::header::Header;
use crate::shared::versioning::VersionedHeader;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Check if a file is encrypted by examining its magic number
pub fn is_encrypted_file(path: &Path) -> Result<bool, CryptoError> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 8]; // Read 8 bytes to handle both V1 and V2 formats
    
    match file.read(&mut magic) {
        Ok(bytes_read) if bytes_read >= 6 => {
            // Check for V1 format: "SHADOW" (6 bytes)
            if &magic[..6] == b"SHADOW" {
                if bytes_read >= 8 && &magic[..8] == b"SHADOW2\0" {
                    Ok(true) // V2 format: "SHADOW2\0" (8 bytes)
                } else {
                    Ok(true) // V1 format: "SHADOW" (6 bytes)  
                }
            } else {
                Ok(false) // Not a Shadow encrypted file
            }
        },
        _ => Ok(false), // File too small or read error
    }
}

/// Read and parse just the header from an encrypted file (V3 only)
pub fn read_header_only(path: &Path) -> Result<Header, CryptoError> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    let (header, _) = Header::deserialize(&buffer)?;
    
    // V3 validate() checks magic number and other properties
    header.validate()?;
    
    Ok(header)
}

/// Get the total header size for an encrypted file
pub fn get_header_size(path: &Path) -> Result<usize, CryptoError> {
    let header = read_header_only(path)?;
    Ok(header.serialize().len())
}

/// Check if file has valid encrypted format and supported algorithm (V3 only)
pub fn validate_encrypted_file(path: &Path) -> Result<(), CryptoError> {
    let header = read_header_only(path)?;
    
    // V3 validate() already checks magic number and algorithm support
    header.validate()?;
    
    Ok(())
}