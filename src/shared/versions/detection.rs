//! Version detection from file headers
//! 
//! This module provides functionality to detect the Shadow file format version
//! from raw header data.

use crate::shared::core::errors::CryptoError;

/// Detect the version of a Shadow file from its header bytes
pub fn detect_version(data: &[u8]) -> Result<u16, CryptoError> {
    if data.len() < 8 {
        return Err(CryptoError::HeaderParsingError("Header too short".to_string()));
    }
    
    // Check magic number
    if &data[0..6] != b"SHADOW" {
        return Err(CryptoError::InvalidFileFormat);
    }
    
    // Extract version (bytes 6-7, little endian)
    let version = u16::from_le_bytes([data[6], data[7]]);
    
    Ok(version)
}