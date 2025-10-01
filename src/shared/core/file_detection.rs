//! File detection utilities
//! 
//! This module provides functions to detect encrypted files by examining
//! their headers and magic numbers without requiring full decryption.

use crate::shared::core::errors::CryptoError;
use crate::shared::header::Header;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Check if a file is encrypted by examining its magic number
pub fn is_encrypted_file(path: &Path) -> Result<bool, CryptoError> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 6];
    
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(&magic == b"SHADOW"),
        Err(_) => Ok(false), // File too small or other read error
    }
}

/// Read and parse just the header from an encrypted file
pub fn read_header_only(path: &Path) -> Result<Header, CryptoError> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    let (header, _) = Header::deserialize(&buffer)?;
    
    if !header.validate_magic() {
        return Err(CryptoError::InvalidFileFormat);
    }
    
    if !header.supports_algorithm() {
        return Err(CryptoError::UnsupportedAlgorithm(header.algorithm_id as u16));
    }
    
    Ok(header)
}

/// Get the total header size for an encrypted file
pub fn get_header_size(path: &Path) -> Result<usize, CryptoError> {
    let header = read_header_only(path)?;
    Ok(header.serialize().len())
}

/// Check if file has valid encrypted format and supported algorithm
pub fn validate_encrypted_file(path: &Path) -> Result<(), CryptoError> {
    let header = read_header_only(path)?;
    
    if !header.validate_magic() {
        return Err(CryptoError::InvalidFileFormat);
    }
    
    if !header.supports_algorithm() {
        return Err(CryptoError::UnsupportedAlgorithm(header.algorithm_id as u16));
    }
    
    Ok(())
}