//! Encrypted file entity.
//! 
//! Immutable representation of an encrypted file with header, ciphertext,
//! and storage filenames ready for writing to disk.

use crate::domain::entities::header::TlvHeader;
use crate::domain::entities::AlgorithmId;
use crate::domain::entities::memory::SecureBox;
use crate::domain::errors::{DomainError, FormatError};
use uuid::Uuid;

/// Encrypted file with header and ciphertext.
/// 
/// Contains all components needed for storage: header, encrypted content,
/// and both plaintext and obfuscated filenames with .shadow extension.
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    header: TlvHeader,
    ciphertext: Vec<u8>,
    /// Plaintext filename with .shadow extension
    plaintext_filename: Option<SecureBox<String>>,
    /// Obfuscated filename with .shadow extension (UUID-based)
    obfuscated_filename: String,
}

impl EncryptedFile {
    /// Create a builder for constructing encrypted files.
    pub fn builder(header: TlvHeader, ciphertext: Vec<u8>) -> EncryptedFileBuilder {
        EncryptedFileBuilder::new(header, ciphertext)
    }

    /// Get the file header.
    pub fn header(&self) -> &TlvHeader {
        &self.header
    }

    /// Get the encrypted content.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the plaintext filename (includes .shadow extension).
    pub fn plaintext_filename(&self) -> Option<&str> {
        self.plaintext_filename.as_ref().map(|secured| secured.expose_secret().as_str())
    }

    /// Get the obfuscated filename (includes .shadow extension).
    pub fn obfuscated_filename(&self) -> &str {
        &self.obfuscated_filename
    }

    /// Get total file size in bytes (header + ciphertext).
    pub fn total_size(&self) -> usize {
        self.header.serialized_size() + self.ciphertext.len()
    }

    /// Get ciphertext size in bytes.
    pub fn ciphertext_size(&self) -> usize {
        self.ciphertext.len()
    }

    /// Check if ciphertext is empty.
    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }

    /// Get file format version.
    pub fn version(&self) -> u16 {
        self.header.version()
    }

    /// Get encryption algorithm used for this file.
    pub fn algorithm(&self) -> Result<AlgorithmId, DomainError> {
        let raw_id = self.header.algorithm_id()
            .ok_or_else(|| DomainError::FormatError(FormatError::MissingRequiredField { 
                field: "algorithm_id".to_string() 
            }))?;
        
        AlgorithmId::from_u16(raw_id)
            .map_err(|_| DomainError::unsupported_algorithm(raw_id))
    }
}

/// Builder for constructing encrypted files.
pub struct EncryptedFileBuilder {
    header: TlvHeader,
    ciphertext: Vec<u8>,
    original_filename: Option<SecureBox<String>>,
}

impl EncryptedFileBuilder {
    /// Create a new builder with required components.
    pub fn new(header: TlvHeader, ciphertext: Vec<u8>) -> Self {
        Self {
            header,
            ciphertext,
            original_filename: None,
        }
    }

    /// Set the original filename for plaintext filename generation.
    pub fn with_original_filename(mut self, filename: SecureBox<String>) -> Self {
        self.original_filename = Some(filename);
        self
    }

    /// Build the encrypted file.
    pub fn build(self) -> EncryptedFile {
        // Create plaintext filename if original filename was provided
        let plaintext_filename = self.original_filename
            .map(|secured_name| {
                let plaintext_with_ext = format!("{}.shadow", secured_name.expose_secret());
                SecureBox::new(plaintext_with_ext)
            });
        
        // Generate obfuscated filename
        let obfuscated_filename = format!("{}.shadow", Uuid::new_v4());
        
        EncryptedFile {
            header: self.header,
            ciphertext: self.ciphertext,
            plaintext_filename,
            obfuscated_filename,
        }
    }
}
