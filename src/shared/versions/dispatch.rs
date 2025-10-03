//! Runtime version dispatch for Shadow file operations//! Runtime version dispatch for Shadow file operations//! Runtime version dispatch for Shadow file operations

//! 

//! This module provides functionality to dispatch operations to the appropriate//! //! 

//! version-specific handler based on detected file version.

//! This module provides functionality to dispatch operations to the appropriate//! This module provides functionality to dispatch operations to the appropriate

use crate::shared::core::errors::CryptoError;

use crate::shared::versions::detection::detect_version;//! version-specific handler based on detected file version.//! version-specific handler based on detected file version.

use crate::shared::versions::v3::HeaderV3;

use crate::shared::versioning::VersionedHeader;



/// Unified header interface that dispatches to version-specific implementationsuse crate::shared::core::errors::CryptoError;use crate::shared::core::errors::CryptoError;

#[derive(Debug)]

pub enum AnyHeader {use crate::shared::versions::detection::detect_version;use crate::shared::versions::detection::detect_version;

    V3(HeaderV3),

    // Future versions will be added hereuse crate::shared::versions::v3::HeaderV3;use crate::shared::versions::v3::HeaderV3;

}

use crate::shared::versioning::VersionedHeader;use crate::shared::versioning::VersionedHeader;

impl AnyHeader {

    /// Create a new header of the current version (V3)

    pub fn new_current(

        algorithm_id: crate::shared::algorithms::AlgorithmId,/// Unified header interface that dispatches to version-specific implementations/// Unified header interface that dispatches to version-specific implementations

        nonce: Vec<u8>,

        salt: [u8; 32],#[derive(Debug)]#[derive(Debug)]

    ) -> Self {

        AnyHeader::V3(HeaderV3::new(algorithm_id, nonce, salt))pub enum AnyHeader {pub enum AnyHeader {

    }

        V3(HeaderV3),    V3(HeaderV3),

    /// Deserialize a header from bytes, auto-detecting version

    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError> {    // Future versions will be added here    // Future versions will be added here

        let version = detect_version(data)?;

        }}

        match version {

            3 => {

                let (header, size) = HeaderV3::deserialize(data)?;

                Ok((AnyHeader::V3(header), size))impl AnyHeader {impl AnyHeader {

            }

            _ => Err(CryptoError::HeaderParsingError(    /// Create a new header of the current version (V3)    /// Create a new header of the current version (V3)

                format!("Unsupported version: {}. Only V3 files are supported.", version)

            )),    pub fn new_current(    pub fn new_current(

        }

    }        algorithm_id: crate::shared::algorithms::AlgorithmId,        algorithm_id: crate::shared::algorithms::AlgorithmId,

    

    /// Serialize the header to bytes        nonce: Vec<u8>,        nonce: Vec<u8>,

    pub fn serialize(&self) -> Vec<u8> {

        match self {        salt: [u8; 32],        salt: [u8; 32],

            AnyHeader::V3(header) => header.serialize(),

        }    ) -> Self {    ) -> Self {

    }

            AnyHeader::V3(HeaderV3::new(algorithm_id, nonce, salt))        AnyHeader::V3(HeaderV3::new(algorithm_id, nonce, salt))

    /// Get the version number of this header

    pub fn version(&self) -> u16 {    }    }

        match self {

            AnyHeader::V3(_) => 3,        

        }

    }    /// Deserialize a header from bytes, auto-detecting version    /// Deserialize a header from bytes, auto-detecting version

}
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError> {    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError> {

        let version = detect_version(data)?;        let version = detect_version(data)?;

                

        match version {        match version {

            3 => {            3 => {

                let (header, size) = HeaderV3::deserialize(data)?;                let (header, size) = HeaderV3::deserialize(data)?;

                Ok((AnyHeader::V3(header), size))                Ok((AnyHeader::V3(header), size))

            }            }

            _ => Err(CryptoError::HeaderParsingError(            _ => Err(CryptoError::HeaderParsingError(

                format!("Unsupported version: {}. Only V3 files are supported.", version)                format!("Unsupported version: {}. Only V3 files are supported.", version)

            )),            )),

        }        }

    }    }

        

    /// Serialize the header to bytes    /// Serialize the header to bytes

    pub fn serialize(&self) -> Vec<u8> {    pub fn serialize(&self) -> Vec<u8> {

        match self {        match self {

            AnyHeader::V3(header) => header.serialize(),            AnyHeader::V3(header) => header.serialize(),

        }        }

    }    }

        

    /// Get the version number of this header    /// Get the version number of this header

    pub fn version(&self) -> u16 {    pub fn version(&self) -> u16 {

        match self {        match self {

            AnyHeader::V3(_) => 3,            AnyHeader::V3(_) => 3,

        }        }

    }    }

}}
            AnyHeader::V1(_) => 1,
        }
    }
}