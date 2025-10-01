//! Runtime version dispatch for Shadow file operations
//! 
//! This module provides functionality to dispatch operations to the appropriate
//! version-specific handler based on detected file version.

use crate::shared::core::errors::CryptoError;
use crate::shared::versions::detection::detect_version;
use crate::shared::versions::v1;

/// Unified header interface that dispatches to version-specific implementations
#[derive(Debug)]
pub enum AnyHeader {
    V1(v1::Header),
    // Future versions will be added here
    // V2(v2::Header),
}

impl AnyHeader {
    /// Create a new header of the current version (V1)
    pub fn new_current(
        algorithm_id: crate::shared::algorithms::AlgorithmId,
        salt: [u8; 16],
        nonce: [u8; 12],
    ) -> Self {
        AnyHeader::V1(v1::Header::new(algorithm_id, salt, nonce))
    }
    
    /// Deserialize a header from bytes, auto-detecting version
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError> {
        let version = detect_version(data)?;
        
        match version {
            1 => {
                let (header, size) = v1::Header::deserialize(data)?;
                Ok((AnyHeader::V1(header), size))
            }
            _ => Err(CryptoError::UnsupportedAlgorithm(version)),
        }
    }
    
    /// Serialize the header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            AnyHeader::V1(header) => header.serialize(),
        }
    }
    
    /// Get the version number of this header
    pub fn version(&self) -> u16 {
        match self {
            AnyHeader::V1(_) => 1,
        }
    }
}