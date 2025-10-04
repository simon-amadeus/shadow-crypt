//! TLV Header System V1 - Proof of Concept
//!
//! This module implements the Type-Length-Value header system for V1 format,
//! preserving the proven V3 TLV design patterns while implementing clean architecture.

use std::collections::HashMap;

/// TLV field types for header metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum TlvFieldType {
    /// Original filename before encryption
    OriginalFilename = 0x01,
    /// Directory path of original file
    DirectoryPath = 0x02,
    /// File metadata (timestamps, permissions, etc.)
    FileMetadata = 0x03,
    /// Compression settings (if any)
    CompressionSettings = 0x04,
    /// Key derivation parameters (salt, iterations, etc.)
    KeyDerivationParams = 0x05,
    /// Custom user-defined attributes
    CustomAttributes = 0x06,
    /// SHA-256 content hash for duplicate detection
    ContentHash = 0x07,
    /// Algorithm identifier
    AlgorithmId = 0x08,
    /// Version information
    Version = 0x09,
    /// Nonce/IV data
    Nonce = 0x0A,
    /// Extension marker for unknown fields
    ExtensionMarker = 0xFF,
}

impl From<u8> for TlvFieldType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => TlvFieldType::OriginalFilename,
            0x02 => TlvFieldType::DirectoryPath,
            0x03 => TlvFieldType::FileMetadata,
            0x04 => TlvFieldType::CompressionSettings,
            0x05 => TlvFieldType::KeyDerivationParams,
            0x06 => TlvFieldType::CustomAttributes,
            0x07 => TlvFieldType::ContentHash,
            0x08 => TlvFieldType::AlgorithmId,
            0x09 => TlvFieldType::Version,
            0x0A => TlvFieldType::Nonce,
            _ => TlvFieldType::ExtensionMarker,
        }
    }
}

/// A single TLV field containing typed data
#[derive(Debug, Clone)]
pub struct TlvField {
    field_type: TlvFieldType,
    data: Vec<u8>,
}

impl TlvField {
    /// Create a new TLV field
    pub fn new(field_type: TlvFieldType, data: Vec<u8>) -> Self {
        Self { field_type, data }
    }

    /// Get the field type
    pub fn field_type(&self) -> TlvFieldType {
        self.field_type
    }

    /// Get the field data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the field length
    pub fn length(&self) -> u32 {
        self.data.len() as u32
    }
}

/// Collection of TLV fields forming a complete header
#[derive(Debug, Clone)]
pub struct TlvHeader {
    pub(crate) fields: HashMap<TlvFieldType, Vec<u8>>,
    magic_number: [u8; 8],
    version: u16,
}

impl TlvHeader {
    /// Magic number for Shadow V1 files
    pub const MAGIC_NUMBER: [u8; 8] = *b"SHADOW01";
    /// Current version number
    pub const VERSION: u16 = 1;

    /// Create a new empty header
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            magic_number: Self::MAGIC_NUMBER,
            version: Self::VERSION,
        }
    }

    /// Add a field to the header
    pub fn add_field(&mut self, field_type: TlvFieldType, data: Vec<u8>) {
        self.fields.insert(field_type, data);
    }

    /// Get a field from the header
    pub fn get_field(&self, field_type: TlvFieldType) -> Option<&Vec<u8>> {
        self.fields.get(&field_type)
    }

    /// Get the magic number
    pub fn magic_number(&self) -> &[u8; 8] {
        &self.magic_number
    }

    /// Get the version
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Check if this header has the correct magic number
    pub fn is_valid_shadow_file(&self) -> bool {
        self.magic_number == Self::MAGIC_NUMBER
    }

    /// Get original filename if present
    pub fn original_filename(&self) -> Option<String> {
        self.get_field(TlvFieldType::OriginalFilename)
            .and_then(|data| String::from_utf8(data.clone()).ok())
    }

    /// Get content hash if present
    pub fn content_hash(&self) -> Option<[u8; 32]> {
        self.get_field(TlvFieldType::ContentHash)
            .and_then(|data| {
                if data.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(data);
                    Some(hash)
                } else {
                    None
                }
            })
    }

    /// Set original filename
    pub fn set_original_filename(&mut self, filename: &str) {
        self.add_field(TlvFieldType::OriginalFilename, filename.as_bytes().to_vec());
    }

    /// Set content hash
    pub fn set_content_hash(&mut self, hash: [u8; 32]) {
        self.add_field(TlvFieldType::ContentHash, hash.to_vec());
    }

    /// Set algorithm ID
    pub fn set_algorithm_id(&mut self, algorithm: u8) {
        self.add_field(TlvFieldType::AlgorithmId, vec![algorithm]);
    }

    /// Set nonce/IV data
    pub fn set_nonce(&mut self, nonce: Vec<u8>) {
        self.add_field(TlvFieldType::Nonce, nonce);
    }
}

impl Default for TlvHeader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_field_creation() {
        let data = b"test_filename.txt".to_vec();
        let field = TlvField::new(TlvFieldType::OriginalFilename, data.clone());
        
        assert_eq!(field.field_type(), TlvFieldType::OriginalFilename);
        assert_eq!(field.data(), data.as_slice());
        assert_eq!(field.length(), data.len() as u32);
    }

    #[test]
    fn test_header_creation_and_fields() {
        let mut header = TlvHeader::new();
        
        assert_eq!(header.magic_number(), &TlvHeader::MAGIC_NUMBER);
        assert_eq!(header.version(), TlvHeader::VERSION);
        assert!(header.is_valid_shadow_file());

        // Test filename operations
        header.set_original_filename("test.txt");
        assert_eq!(header.original_filename(), Some("test.txt".to_string()));

        // Test content hash operations
        let hash = [0x42u8; 32];
        header.set_content_hash(hash);
        assert_eq!(header.content_hash(), Some(hash));

        // Test algorithm ID
        header.set_algorithm_id(1);
        assert_eq!(header.get_field(TlvFieldType::AlgorithmId), Some(&vec![1]));

        // Test nonce
        let nonce = vec![1, 2, 3, 4];
        header.set_nonce(nonce.clone());
        assert_eq!(header.get_field(TlvFieldType::Nonce), Some(&nonce));
    }

    #[test]
    fn test_field_type_conversion() {
        assert_eq!(TlvFieldType::from(0x01), TlvFieldType::OriginalFilename);
        assert_eq!(TlvFieldType::from(0x07), TlvFieldType::ContentHash);
        assert_eq!(TlvFieldType::from(0x42), TlvFieldType::ExtensionMarker);
    }

    #[test]
    fn test_extensibility_unknown_fields() {
        // Unknown field types should map to ExtensionMarker
        let unknown_field = TlvFieldType::from(0x99);
        assert_eq!(unknown_field, TlvFieldType::ExtensionMarker);
    }
}