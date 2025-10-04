//! Version detection from file headers
//! 
//! This module provides functionality to detect the Shadow file format version
//! from raw header data.

use crate::shared::core::errors::CryptoError;
use crate::shared::versions::v3::{MAGIC_NUMBER_V3, VERSION_V3};

/// Detect the version of a Shadow file from its header bytes
pub fn detect_version(data: &[u8]) -> Result<u16, CryptoError> {
    if data.len() < 8 {
        return Err(CryptoError::HeaderParsingError("Header too short".to_string()));
    }
    
    // Check for V3 magic number (6 bytes "SHADOW" + 2 bytes version)
    if data.len() >= 6 && data[0..6] == *MAGIC_NUMBER_V3 {
        // Extract version from bytes 6-7
        if data.len() >= 8 {
            let version = u16::from_le_bytes([data[6], data[7]]);
            if version == VERSION_V3 {
                return Ok(version);
            }
        }
    }
    
    Err(CryptoError::HeaderParsingError(
        "Unsupported file format or version. Only V3 files are supported.".to_string()
    ))
}