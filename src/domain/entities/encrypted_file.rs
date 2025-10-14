//! EncryptedFile Entity - Immutable encrypted file representation
//! 
//! This entity represents a complete encrypted file with header and ciphertext.
//! All instances are immutable after creation to ensure data integrity.

use crate::domain::entities::header::TlvHeader;
use crate::domain::entities::AlgorithmId;
use crate::domain::entities::memory::SecureBox;
use uuid::Uuid;

/// Errors that can occur during EncryptedFile operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptedFileError {
    /// Missing algorithm ID in header
    MissingAlgorithm,
    /// Unsupported algorithm ID
    UnsupportedAlgorithm(u16),
    /// Missing original filename in header
    MissingOriginalFilename,
}

impl std::fmt::Display for EncryptedFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAlgorithm => write!(f, "Algorithm ID missing in file header"),
            Self::UnsupportedAlgorithm(id) => write!(f, "Algorithm ID {} not supported", id),
            Self::MissingOriginalFilename => write!(f, "Original filename missing in file header"),
        }
    }
}

impl std::error::Error for EncryptedFileError {}

/// Immutable encrypted file entity
/// 
/// Contains all components of an encrypted file: header, ciphertext, and storage filenames.
/// Both filenames have .shadow extension and are ready for storage.
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    header: TlvHeader,
    ciphertext: Vec<u8>,
    /// Plaintext filename for normal storage (original_name.shadow) - secured
    plaintext_filename: Option<SecureBox<String>>,
    /// Obfuscated filename for privacy storage (uuid.shadow)
    obfuscated_filename: String,
}

impl EncryptedFile {
    /// Creates a builder for constructing EncryptedFile instances
    pub fn builder(header: TlvHeader, ciphertext: Vec<u8>) -> EncryptedFileBuilder {
        EncryptedFileBuilder::new(header, ciphertext)
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

    /// Returns the plaintext filename for normal storage (includes .shadow extension)
    pub fn plaintext_filename(&self) -> Option<&str> {
        self.plaintext_filename.as_ref().map(|secured| secured.expose_secret().as_str())
    }

    /// Returns the obfuscated filename for privacy-focused storage (includes .shadow extension)
    pub fn obfuscated_filename(&self) -> &str {
        &self.obfuscated_filename
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



    /// Returns encryption algorithm used for this file
    pub fn algorithm(&self) -> Result<AlgorithmId, EncryptedFileError> {
        let raw_id = self.header.algorithm_id()
            .ok_or(EncryptedFileError::MissingAlgorithm)?;
        
        AlgorithmId::from_u16(raw_id)
            .map_err(|_| EncryptedFileError::UnsupportedAlgorithm(raw_id))
    }
}

/// Builder for constructing EncryptedFile instances
pub struct EncryptedFileBuilder {
    header: TlvHeader,
    ciphertext: Vec<u8>,
    original_filename: Option<SecureBox<String>>,
}

impl EncryptedFileBuilder {
    /// Create a new builder with required components
    pub fn new(header: TlvHeader, ciphertext: Vec<u8>) -> Self {
        Self {
            header,
            ciphertext,
            original_filename: None,
        }
    }

    /// Set the original filename (used to create plaintext filename)
    pub fn with_original_filename(mut self, filename: SecureBox<String>) -> Self {
        self.original_filename = Some(filename);
        self
    }

    /// Build the EncryptedFile
    pub fn build(self) -> EncryptedFile {
        // Create secured plaintext filename if original filename was provided
        let plaintext_filename = self.original_filename
            .map(|secured_name| {
                let plaintext_with_ext = format!("{}.shadow", secured_name.expose_secret());
                SecureBox::new(plaintext_with_ext)
            });
        
        // Always create obfuscated filename
        let obfuscated_filename = format!("{}.shadow", Uuid::new_v4());
        
        EncryptedFile {
            header: self.header,
            ciphertext: self.ciphertext,
            plaintext_filename,
            obfuscated_filename,
        }
    }
}
