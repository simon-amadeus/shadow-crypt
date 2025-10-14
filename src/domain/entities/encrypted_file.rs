//! EncryptedFile Entity - Immutable encrypted file representation
//! 
//! This entity represents a complete encrypted file with header and ciphertext.
//! All instances are immutable after creation to ensure data integrity.

use crate::domain::entities::header::TlvHeader;
use crate::domain::entities::AlgorithmId;

/// Errors that can occur during EncryptedFile operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptedFileError {
    /// Missing algorithm ID in header
    MissingAlgorithm,
    /// Unsupported algorithm ID
    UnsupportedAlgorithm(u16),
}

impl std::fmt::Display for EncryptedFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAlgorithm => write!(f, "Algorithm ID missing in file header"),
            Self::UnsupportedAlgorithm(id) => write!(f, "Algorithm ID {} not supported", id),
        }
    }
}

impl std::error::Error for EncryptedFileError {}

/// Immutable encrypted file entity
/// 
/// Contains all components of an encrypted file: header and ciphertext.
/// Created by encryption services and consumed by decryption services.
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    header: TlvHeader,
    ciphertext: Vec<u8>,
}

impl EncryptedFile {
    /// Creates a new EncryptedFile
    /// 
    /// Should only be called by encryption services after validation.
    pub fn new(header: TlvHeader, ciphertext: Vec<u8>) -> Self {
        Self {
            header,
            ciphertext,
        }
    }

    // Accessors

    /// Returns reference to the file header
    pub fn header(&self) -> &TlvHeader {
        &self.header
    }

    /// Returns reference to the encrypted content
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }



    /// Returns total file size in bytes (header + ciphertext)
    pub fn total_size(&self) -> usize {
        self.header.serialized_size() + self.ciphertext.len()
    }

    /// Returns ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        self.ciphertext.len()
    }

    /// Returns true if ciphertext is empty
    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }

    // Derived properties

    /// Returns file format version
    pub fn version(&self) -> u16 {
        self.header.version()
    }

    /// Returns original filename if available
    pub fn original_filename(&self) -> Option<String> {
        self.header.original_filename()
    }

    /// Returns encryption algorithm used for this file
    pub fn algorithm(&self) -> Result<AlgorithmId, EncryptedFileError> {
        let raw_id = self.header.algorithm_id()
            .ok_or(EncryptedFileError::MissingAlgorithm)?;
        
        AlgorithmId::from_u16(raw_id)
            .map_err(|_| EncryptedFileError::UnsupportedAlgorithm(raw_id))
    }


}
