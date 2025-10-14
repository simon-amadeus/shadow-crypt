//! TLV Header System V1
//!
//! This module implements the Type-Length-Value header system for Shadow file format.
//!
//! ## Design Principles
//!
//! - **Extensibility**: Unknown field types are handled gracefully for forward compatibility
//! - **Algorithm Agnostic**: Header format independent of specific encryption algorithms
//! - **Version Evolution**: Clean upgrade path for future V1 → V2+ format evolution
//!
//! ## Field Type Organization
//!
//! The TLV field type space is organized for systematic evolution:
//! - **0x01-0x0F**: Core metadata (filename, timestamps)
//! - **0x10-0x2F**: Cryptographic parameters (algorithm, nonce, key derivation)
//! - **0x30-0x4F**: Content integrity (hashes, signatures, checksums)
//! - **0x70-0x8F**: User-defined and application-specific fields
//! - **0x90-0xFE**: Reserved for future extensions
//! - **0xFF**: Extension marker for unknown field handling
//!
//! ## Security Considerations
//!
//! - Field size limits prevent DoS attacks
//! - UTF-8 validation prevents encoding attacks
//! - Deterministic serialization ensures reproducible outputs

use std::collections::HashMap;
use std::io::{Read, Cursor};

/// TLV field types for header metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum TlvFieldType {
    // Core metadata (0x01-0x0F)
    OriginalFilename = 0x01,
    
    // Cryptographic parameters (0x10-0x2F)
    AlgorithmId = 0x10,
    Nonce = 0x11,
    KeyDerivationParams = 0x12,
    
    // Content integrity (0x30-0x4F)
    ContentHash = 0x30,
    HeaderIntegrity = 0x31,
    
    // User-defined (0x70-0x8F)
    CustomAttributes = 0x70,
    Version = 0x71,
    
    // Extension marker
    ExtensionMarker = 0xFF,
}

impl TlvFieldType {
    /// Check if this field type requires specific validation
    pub fn requires_validation(&self) -> bool {
        matches!(self, 
            TlvFieldType::ContentHash | 
            TlvFieldType::HeaderIntegrity |
            TlvFieldType::AlgorithmId
        )
    }
    
    /// Get expected field size for fixed-size fields
    pub fn expected_size(&self) -> Option<usize> {
        match self {
            TlvFieldType::ContentHash => Some(32),
            TlvFieldType::HeaderIntegrity => Some(32),
            TlvFieldType::AlgorithmId => Some(2),
            _ => None,
        }
    }
}

impl From<u8> for TlvFieldType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => TlvFieldType::OriginalFilename,
            0x10 => TlvFieldType::AlgorithmId,
            0x11 => TlvFieldType::Nonce,
            0x12 => TlvFieldType::KeyDerivationParams,
            0x30 => TlvFieldType::ContentHash,
            0x31 => TlvFieldType::HeaderIntegrity,
            0x70 => TlvFieldType::CustomAttributes,
            0x71 => TlvFieldType::Version,
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
    /// Create a new TLV field with validation
    pub fn new(field_type: TlvFieldType, data: Vec<u8>) -> Result<Self, HeaderError> {
        // Validate field size for fixed-size fields
        if let Some(expected_size) = field_type.expected_size() {
            if data.len() != expected_size {
                return Err(HeaderError::InvalidFieldLength {
                    field_type,
                    expected: expected_size,
                    actual: data.len(),
                });
            }
        }
        
        // Validate UTF-8 for string fields
        if matches!(field_type, TlvFieldType::OriginalFilename) {
            String::from_utf8(data.clone()).map_err(HeaderError::InvalidFilename)?;
        }
        
        Ok(Self { field_type, data })
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
    magic_number: [u8; 6],
    version: u16,
}

impl TlvHeader {
    /// Magic number for Shadow V1 files
    pub const MAGIC_NUMBER: [u8; 6] = *b"SHADOW";
    /// Current version number
    pub const VERSION: u16 = 1;
    /// Maximum field size (1MB)
    pub const MAX_FIELD_SIZE: u32 = 1024 * 1024;
    /// Maximum number of fields
    pub const MAX_FIELD_COUNT: usize = 256;
    /// Maximum header size (2MB)
    pub const MAX_HEADER_SIZE: usize = 2 * 1024 * 1024;
    /// Header length prefix size
    pub const HEADER_LENGTH_SIZE: usize = 4;

    /// Create a new empty header
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            magic_number: Self::MAGIC_NUMBER,
            version: Self::VERSION,
        }
    }

    /// Add a field to the header with validation
    pub fn add_field(&mut self, field_type: TlvFieldType, data: Vec<u8>) -> Result<(), HeaderError> {
        if self.fields.len() >= Self::MAX_FIELD_COUNT {
            return Err(HeaderError::TooManyFields(self.fields.len()));
        }
        
        if data.len() > Self::MAX_FIELD_SIZE as usize {
            return Err(HeaderError::FieldTooLarge {
                size: data.len(),
                max: Self::MAX_FIELD_SIZE as usize,
            });
        }
        
        // Use TlvField validation
        let _field = TlvField::new(field_type, data.clone())?;
        
        self.fields.insert(field_type, data);
        Ok(())
    }

    /// Get a field from the header
    pub fn get_field(&self, field_type: TlvFieldType) -> Option<&Vec<u8>> {
        self.fields.get(&field_type)
    }

    /// Get the magic number
    pub fn magic_number(&self) -> &[u8; 6] {
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
    pub fn set_original_filename(&mut self, filename: &str) -> Result<(), HeaderError> {
        if filename.is_empty() {
            return Err(HeaderError::EmptyFilename);
        }
        if filename.len() > 4096 {
            return Err(HeaderError::FieldTooLarge { 
                size: filename.len(), 
                max: 4096 
            });
        }
        
        self.add_field(TlvFieldType::OriginalFilename, filename.as_bytes().to_vec())
    }

    /// Set content hash
    pub fn set_content_hash(&mut self, hash: [u8; 32]) -> Result<(), HeaderError> {
        self.add_field(TlvFieldType::ContentHash, hash.to_vec())
    }

    /// Set algorithm ID as raw u16
    pub fn set_algorithm_id(&mut self, algorithm_id: u16) -> Result<(), HeaderError> {
        self.add_field(TlvFieldType::AlgorithmId, algorithm_id.to_le_bytes().to_vec())
    }

    /// Get algorithm ID as raw u16
    pub fn algorithm_id(&self) -> Option<u16> {
        self.get_field(TlvFieldType::AlgorithmId)
            .and_then(|data| {
                if data.len() == 2 {
                    let bytes = [data[0], data[1]];
                    Some(u16::from_le_bytes(bytes))
                } else {
                    None
                }
            })
    }

    /// Set nonce/IV data
    pub fn set_nonce(&mut self, nonce: Vec<u8>) -> Result<(), HeaderError> {
        if nonce.is_empty() {
            return Err(HeaderError::EmptyNonce);
        }
        self.add_field(TlvFieldType::Nonce, nonce)
    }

    /// Get nonce/IV data if present
    pub fn nonce(&self) -> Option<&Vec<u8>> {
        self.get_field(TlvFieldType::Nonce)
    }

    /// Calculate total serialized size (including length prefix)
    pub fn serialized_size(&self) -> usize {
        Self::HEADER_LENGTH_SIZE + // header length prefix
        8 + // magic (6) + version (2)
        self.fields.iter()
            .map(|(_, data)| 5 + data.len()) // type (1) + length (4) + data
            .sum::<usize>()
    }

    /// Validate header integrity
    pub fn validate(&self) -> Result<(), HeaderError> {
        if self.fields.len() > Self::MAX_FIELD_COUNT {
            return Err(HeaderError::TooManyFields(self.fields.len()));
        }
        
        if self.serialized_size() > Self::MAX_HEADER_SIZE {
            return Err(HeaderError::HeaderTooLarge {
                size: self.serialized_size(),
                max: Self::MAX_HEADER_SIZE,
            });
        }
        
        // Validate each field
        for (field_type, data) in &self.fields {
            let _field = TlvField::new(*field_type, data.clone())?;
        }
        
        Ok(())
    }

    /// Validate that all required cryptographic fields are present
    pub fn validate_for_encryption(&self) -> Result<(), HeaderError> {
        self.validate()?;
        
        if self.algorithm_id().is_none() {
            return Err(HeaderError::MissingRequiredField(TlvFieldType::AlgorithmId));
        }
        
        if self.nonce().is_none() {
            return Err(HeaderError::MissingRequiredField(TlvFieldType::Nonce));
        }
        
        Ok(())
    }

    /// Get original filename with proper error handling
    pub fn original_filename_checked(&self) -> Result<Option<String>, HeaderError> {
        match self.get_field(TlvFieldType::OriginalFilename) {
            Some(data) => Ok(Some(String::from_utf8(data.clone()).map_err(HeaderError::InvalidFilename)?)),
            None => Ok(None),
        }
    }

    /// Serialize header to bytes with length prefix
    pub fn to_bytes(&self) -> Result<Vec<u8>, HeaderError> {
        self.validate()?;
        
        let mut buffer = Vec::new();
        let header_content = self.serialize_header_content()?;
        
        buffer.extend_from_slice(&(header_content.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&header_content);
        
        Ok(buffer)
    }

    /// Serialize header content (without length prefix)
    fn serialize_header_content(&self) -> Result<Vec<u8>, HeaderError> {
        let mut buffer = Vec::new();
        
        // Write magic number and version
        buffer.extend_from_slice(&self.magic_number);
        buffer.extend_from_slice(&self.version.to_le_bytes());
        
        // Sort fields by type for deterministic output
        let mut sorted_fields: Vec<_> = self.fields.iter().collect();
        sorted_fields.sort_by_key(|(field_type, _)| **field_type);
        
        // Write each field as Type(1) + Length(4) + Value(n)
        for (field_type, data) in sorted_fields {
            if data.len() > Self::MAX_FIELD_SIZE as usize {
                return Err(HeaderError::FieldTooLarge {
                    size: data.len(),
                    max: Self::MAX_FIELD_SIZE as usize,
                });
            }
            
            buffer.push(*field_type as u8);
            buffer.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buffer.extend_from_slice(data);
        }
        
        Ok(buffer)
    }

    /// Deserialize header from bytes (with length prefix)
    pub fn from_bytes(data: &[u8]) -> Result<Self, HeaderError> {
        if data.len() < Self::HEADER_LENGTH_SIZE {
            return Err(HeaderError::TruncatedHeader);
        }
        
        let mut cursor = Cursor::new(data);
        
        // Read header length
        let mut length_bytes = [0u8; 4];
        cursor.read_exact(&mut length_bytes).map_err(HeaderError::Io)?;
        let header_length = u32::from_le_bytes(length_bytes) as usize;
        
        if header_length > Self::MAX_HEADER_SIZE {
            return Err(HeaderError::HeaderTooLarge {
                size: header_length,
                max: Self::MAX_HEADER_SIZE,
            });
        }
        
        if data.len() < Self::HEADER_LENGTH_SIZE + header_length {
            return Err(HeaderError::TruncatedHeader);
        }
        
        let header_data = &data[Self::HEADER_LENGTH_SIZE..Self::HEADER_LENGTH_SIZE + header_length];
        Self::from_header_content(header_data)
    }

    /// Deserialize from header content (without length prefix)
    fn from_header_content(data: &[u8]) -> Result<Self, HeaderError> {
        let mut cursor = Cursor::new(data);
        
        // Read magic number
        let mut magic = [0u8; 6];
        cursor.read_exact(&mut magic).map_err(HeaderError::Io)?;
        if magic != Self::MAGIC_NUMBER {
            return Err(HeaderError::InvalidMagicNumber);
        }
        
        // Read version
        let mut version_bytes = [0u8; 2];
        cursor.read_exact(&mut version_bytes).map_err(HeaderError::Io)?;
        let version = u16::from_le_bytes(version_bytes);
        if version != Self::VERSION {
            return Err(HeaderError::UnsupportedVersion(version));
        }
        
        // Read TLV fields
        let mut fields = HashMap::new();
        let mut field_count = 0;
        
        while cursor.position() < data.len() as u64 {
            if field_count >= Self::MAX_FIELD_COUNT {
                return Err(HeaderError::TooManyFields(field_count));
            }
            
            // Read type
            let mut type_byte = [0u8; 1];
            if cursor.read(&mut type_byte).map_err(HeaderError::Io)? == 0 {
                break;
            }
            let field_type = TlvFieldType::from(type_byte[0]);
            
            // Read length
            let mut length_bytes = [0u8; 4];
            cursor.read_exact(&mut length_bytes).map_err(HeaderError::Io)?;
            let length = u32::from_le_bytes(length_bytes);
            
            if length > Self::MAX_FIELD_SIZE {
                return Err(HeaderError::FieldTooLarge {
                    size: length as usize,
                    max: Self::MAX_FIELD_SIZE as usize,
                });
            }
            
            // Read value
            let mut value = vec![0u8; length as usize];
            cursor.read_exact(&mut value).map_err(HeaderError::Io)?;
            
            // Validate field before inserting
            let _field = TlvField::new(field_type, value.clone())?;
            
            fields.insert(field_type, value);
            field_count += 1;
        }
        
        let header = Self {
            fields,
            magic_number: Self::MAGIC_NUMBER,
            version: Self::VERSION,
        };
        
        header.validate()?;
        Ok(header)
    }

    /// Get header content for integrity calculation (excludes HeaderIntegrity field)
    pub fn content_for_integrity(&self) -> Result<Vec<u8>, HeaderError> {
        let mut temp_header = self.clone();
        temp_header.fields.remove(&TlvFieldType::HeaderIntegrity);
        temp_header.serialize_header_content()
    }
}

impl Default for TlvHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing TLV headers with validation
pub struct TlvHeaderBuilder {
    header: TlvHeader,
}

impl TlvHeaderBuilder {
    pub fn new() -> Self {
        Self {
            header: TlvHeader::new(),
        }
    }

    pub fn filename(mut self, filename: &str) -> Result<Self, HeaderError> {
        self.header.set_original_filename(filename)?;
        Ok(self)
    }

    pub fn algorithm_id(mut self, algorithm_id: u16) -> Result<Self, HeaderError> {
        self.header.set_algorithm_id(algorithm_id)?;
        Ok(self)
    }

    pub fn nonce(mut self, nonce: Vec<u8>) -> Result<Self, HeaderError> {
        self.header.set_nonce(nonce)?;
        Ok(self)
    }

    pub fn content_hash(mut self, hash: [u8; 32]) -> Result<Self, HeaderError> {
        self.header.set_content_hash(hash)?;
        Ok(self)
    }

    pub fn build(self) -> Result<TlvHeader, HeaderError> {
        self.header.validate()?;
        Ok(self.header)
    }

    pub fn build_for_encryption(self) -> Result<TlvHeader, HeaderError> {
        self.header.validate_for_encryption()?;
        Ok(self.header)
    }
}

impl Default for TlvHeaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during header operations
#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    #[error("Invalid UTF-8 in filename: {0}")]
    InvalidFilename(#[from] std::string::FromUtf8Error),
    #[error("Field too large: {size} bytes (max: {max})")]
    FieldTooLarge { size: usize, max: usize },
    #[error("Header too large: {size} bytes (max: {max})")]
    HeaderTooLarge { size: usize, max: usize },
    #[error("Too many fields: {count} (max: {max})", count = .0, max = TlvHeader::MAX_FIELD_COUNT)]
    TooManyFields(usize),
    #[error("Invalid magic number")]
    InvalidMagicNumber,
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u16),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Truncated header")]
    TruncatedHeader,
    #[error("Invalid field length for {field_type:?}: expected {expected}, actual {actual}")]
    InvalidFieldLength {
        field_type: TlvFieldType,
        expected: usize,
        actual: usize,
    },
    #[error("Missing required field: {0:?}")]
    MissingRequiredField(TlvFieldType),
    #[error("Empty nonce not allowed")]
    EmptyNonce,
    #[error("Empty filename not allowed")]
    EmptyFilename,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let mut header = TlvHeader::new();
        header.set_original_filename("test.txt").unwrap();
        header.set_content_hash([42u8; 32]).unwrap();
        
        let bytes = header.to_bytes().unwrap();
        let recovered = TlvHeader::from_bytes(&bytes).unwrap();
        
        assert_eq!(header.original_filename(), recovered.original_filename());
        assert_eq!(header.content_hash(), recovered.content_hash());
    }

    #[test]
    fn test_field_validation() {
        // Test invalid hash length
        let result = TlvField::new(TlvFieldType::ContentHash, vec![0u8; 16]);
        assert!(result.is_err());
        
        // Test valid hash length
        let result = TlvField::new(TlvFieldType::ContentHash, vec![0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_size_limits() {
        let mut header = TlvHeader::new();
        
        // Test field too large
        let large_data = vec![0u8; (TlvHeader::MAX_FIELD_SIZE as usize) + 1];
        let result = header.add_field(TlvFieldType::CustomAttributes, large_data);
        assert!(matches!(result, Err(HeaderError::FieldTooLarge { .. })));
    }
}
