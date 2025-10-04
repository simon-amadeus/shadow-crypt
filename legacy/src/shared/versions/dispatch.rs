//! Runtime version dispatch for Shadow file operations
//! 
//! This module provides functionality to dispatch operations to the appropriate
//! version-specific handler based on detected file version.

use crate::shared::core::errors::CryptoError;
use crate::shared::versions::detection::detect_version;
use crate::shared::versions::v3::HeaderV3;
use crate::shared::versioning::VersionedHeader;

/// Unified header interface that dispatches to version-specific implementations
#[derive(Debug)]
pub enum AnyHeader {
    V3(HeaderV3),
    // Future versions will be added here
}

impl AnyHeader {
    /// Create a new header of the current version (V3)
    pub fn new_current(
        algorithm_id: crate::shared::algorithms::AlgorithmId,
        nonce: Vec<u8>,
        salt: [u8; 32],
    ) -> Self {
        AnyHeader::V3(HeaderV3::new(algorithm_id, nonce, salt))
    }

    /// Deserialize a header from bytes, auto-detecting version
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError> {
        let version = detect_version(data)?;
        
        match version {
            3 => {
                let (header, size) = HeaderV3::deserialize(data)?;
                Ok((AnyHeader::V3(header), size))
            }
            _ => Err(CryptoError::HeaderParsingError(
                format!("Unsupported version: {}. Only V3 files are supported.", version)
            )),
        }
    }
    
    /// Serialize the header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            AnyHeader::V3(header) => header.serialize(),
        }
    }
    
    /// Get the version number of this header
    pub fn version(&self) -> u16 {
        match self {
            AnyHeader::V3(_) => 3,
        }
    }
}