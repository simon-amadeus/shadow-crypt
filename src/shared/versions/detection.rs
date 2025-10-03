//! Version detection from file headers
//! 
//! This module provides functionality to detect the Shadow file format version
//! from raw header data.

use crate::shared::core::errors::CryptoError;
use crate::shared::versions::v1::header::MAGIC_NUMBER_V1;
use crate::shared::versions::v2::header::MAGIC_NUMBER_V2;

/// Detect the version of a Shadow file from its header bytes
pub fn detect_version(data: &[u8]) -> Result<u16, CryptoError> {
    if data.len() < 8 {
        return Err(CryptoError::HeaderParsingError("Header too short".to_string()));
    }
    
    // Check for V2 magic number first (newer format) - 8 bytes
    if data.len() >= 8 && data[0..8] == MAGIC_NUMBER_V2 {
        return Ok(2);
    }
    
    // Check for V1 magic number - 6 bytes "SHADOW" + 2 bytes version
    if data.len() >= 6 && data[0..6] == MAGIC_NUMBER_V1 {
        // Extract version from bytes 6-7 for V1 format
        if data.len() >= 8 {
            let version = u16::from_le_bytes([data[6], data[7]]);
            return Ok(version);
        }
    }
    
    Err(CryptoError::InvalidFileFormat)
}