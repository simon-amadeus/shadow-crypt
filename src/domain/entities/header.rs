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

// =============================================================================
// Field Types and Field Implementation
// =============================================================================

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

// =============================================================================
// TLV Header - Pure Immutable Entity
// =============================================================================

/// Collection of TLV fields forming a complete header
#[derive(Debug, Clone)]
pub struct TlvHeader {
    fields: HashMap<TlvFieldType, Vec<u8>>,
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

    /// Create a new header (should only be called by builders/services)
    pub fn new(
        fields: HashMap<TlvFieldType, Vec<u8>>,
        version: Option<u16>
    ) -> Result<Self, HeaderError> {
        let header = Self {
            fields,
            magic_number: Self::MAGIC_NUMBER,
            version: version.unwrap_or(Self::VERSION),
        };
        
        header.validate()?;
        Ok(header)
    }

    // -------------------------------------------------------------------------
    // Read-only Accessors
    // -------------------------------------------------------------------------

    /// Get a field by type
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

    // -------------------------------------------------------------------------
    // Convenience Accessors for Common Fields
    // -------------------------------------------------------------------------

    /// Get algorithm ID as u16
    pub fn algorithm_id(&self) -> Option<u16> {
        self.get_field(TlvFieldType::AlgorithmId)
            .and_then(|data| {
                if data.len() == 2 {
                    Some(u16::from_le_bytes([data[0], data[1]]))
                } else {
                    None
                }
            })
    }

    /// Get nonce bytes
    pub fn nonce(&self) -> Option<&[u8]> {
        self.get_field(TlvFieldType::Nonce).map(|v| v.as_slice())
    }

    /// Get original filename as String
    pub fn original_filename(&self) -> Option<String> {
        self.get_field(TlvFieldType::OriginalFilename)
            .and_then(|data| String::from_utf8(data.clone()).ok())
    }

    /// Get original filename with proper error handling
    pub fn original_filename_checked(&self) -> Result<Option<String>, HeaderError> {
        match self.get_field(TlvFieldType::OriginalFilename) {
            Some(data) => Ok(Some(String::from_utf8(data.clone()).map_err(HeaderError::InvalidFilename)?)),
            None => Ok(None),
        }
    }

    /// Get content hash as fixed-size array
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

    // -------------------------------------------------------------------------
    // Size and Validation
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Serialization
    // -------------------------------------------------------------------------

    /// Serialize header to bytes with length prefix
    pub fn to_bytes(&self) -> Result<Vec<u8>, HeaderError> {
        self.validate()?;
        
        let header_content = self.serialize_header_content()?;
        let mut buffer = Vec::with_capacity(Self::HEADER_LENGTH_SIZE + header_content.len());
        
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

    /// Get header content for integrity calculation (excludes HeaderIntegrity field)
    pub fn content_for_integrity(&self) -> Result<Vec<u8>, HeaderError> {
        let mut temp_header = self.clone();
        temp_header.fields.remove(&TlvFieldType::HeaderIntegrity);
        temp_header.serialize_header_content()
    }

    // -------------------------------------------------------------------------
    // Deserialization
    // -------------------------------------------------------------------------

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
}

impl Default for TlvHeader {
    fn default() -> Self {
        Self {
            fields: HashMap::new(),
            magic_number: Self::MAGIC_NUMBER,
            version: Self::VERSION,
        }
    }
}

// =============================================================================
// Header Builder
// =============================================================================

/// Builder for constructing TLV headers with validation
pub struct TlvHeaderBuilder {
    fields: HashMap<TlvFieldType, Vec<u8>>,
    version: Option<u16>,
}

impl TlvHeaderBuilder {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            version: None,
        }
    }

    pub fn filename(mut self, filename: &str) -> Result<Self, HeaderError> {
        if filename.is_empty() {
            return Err(HeaderError::EmptyFilename);
        }
        
        let field = TlvField::new(TlvFieldType::OriginalFilename, filename.as_bytes().to_vec())?;
        self.fields.insert(TlvFieldType::OriginalFilename, field.data().to_vec());
        Ok(self)
    }

    pub fn algorithm_id(mut self, algorithm_id: u16) -> Result<Self, HeaderError> {
        let field = TlvField::new(TlvFieldType::AlgorithmId, algorithm_id.to_le_bytes().to_vec())?;
        self.fields.insert(TlvFieldType::AlgorithmId, field.data().to_vec());
        Ok(self)
    }

    pub fn nonce(mut self, nonce: Vec<u8>) -> Result<Self, HeaderError> {
        if nonce.is_empty() {
            return Err(HeaderError::EmptyNonce);
        }
        
        let field = TlvField::new(TlvFieldType::Nonce, nonce)?;
        self.fields.insert(TlvFieldType::Nonce, field.data().to_vec());
        Ok(self)
    }

    pub fn content_hash(mut self, hash: [u8; 32]) -> Result<Self, HeaderError> {
        let field = TlvField::new(TlvFieldType::ContentHash, hash.to_vec())?;
        self.fields.insert(TlvFieldType::ContentHash, field.data().to_vec());
        Ok(self)
    }

    pub fn version(mut self, version: u16) -> Self {
        self.version = Some(version);
        self
    }

    pub fn build(self) -> Result<TlvHeader, HeaderError> {
        TlvHeader::new(self.fields, self.version)
    }

    pub fn build_for_encryption(self) -> Result<TlvHeader, HeaderError> {
        let header = TlvHeader::new(self.fields, self.version)?;
        header.validate_for_encryption()?;
        Ok(header)
    }
}

impl Default for TlvHeaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Error Types
// =============================================================================

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

    // =============================================================================
    // TlvFieldType Tests
    // =============================================================================

    #[test]
    fn test_field_type_from_u8() {
        assert_eq!(TlvFieldType::from(0x01), TlvFieldType::OriginalFilename);
        assert_eq!(TlvFieldType::from(0x10), TlvFieldType::AlgorithmId);
        assert_eq!(TlvFieldType::from(0x11), TlvFieldType::Nonce);
        assert_eq!(TlvFieldType::from(0x30), TlvFieldType::ContentHash);
        assert_eq!(TlvFieldType::from(0xFF), TlvFieldType::ExtensionMarker);
        assert_eq!(TlvFieldType::from(0x99), TlvFieldType::ExtensionMarker); // Unknown type
    }

    #[test]
    fn test_field_type_requires_validation() {
        assert!(TlvFieldType::ContentHash.requires_validation());
        assert!(TlvFieldType::HeaderIntegrity.requires_validation());
        assert!(TlvFieldType::AlgorithmId.requires_validation());
        assert!(!TlvFieldType::OriginalFilename.requires_validation());
        assert!(!TlvFieldType::Nonce.requires_validation());
    }

    #[test]
    fn test_field_type_expected_size() {
        assert_eq!(TlvFieldType::ContentHash.expected_size(), Some(32));
        assert_eq!(TlvFieldType::HeaderIntegrity.expected_size(), Some(32));
        assert_eq!(TlvFieldType::AlgorithmId.expected_size(), Some(2));
        assert_eq!(TlvFieldType::OriginalFilename.expected_size(), None);
        assert_eq!(TlvFieldType::Nonce.expected_size(), None);
    }

    // =============================================================================
    // TlvField Tests
    // =============================================================================

    #[test]
    fn test_tlv_field_new_valid() {
        let field = TlvField::new(TlvFieldType::OriginalFilename, b"test.txt".to_vec()).unwrap();
        assert_eq!(field.field_type(), TlvFieldType::OriginalFilename);
        assert_eq!(field.data(), b"test.txt");
        assert_eq!(field.length(), 8);
    }

    #[test]
    fn test_tlv_field_fixed_size_validation() {
        // Valid fixed-size field
        let hash = [0u8; 32];
        let field = TlvField::new(TlvFieldType::ContentHash, hash.to_vec()).unwrap();
        assert_eq!(field.data().len(), 32);

        // Invalid fixed-size field
        let result = TlvField::new(TlvFieldType::ContentHash, vec![0u8; 16]);
        assert!(matches!(result, Err(HeaderError::InvalidFieldLength { .. })));
    }

    #[test]
    fn test_tlv_field_utf8_validation() {
        // Valid UTF-8
        let field = TlvField::new(TlvFieldType::OriginalFilename, "test.txt".as_bytes().to_vec()).unwrap();
        assert_eq!(field.data(), b"test.txt");

        // Invalid UTF-8
        let invalid_utf8 = vec![0xFF, 0xFE];
        let result = TlvField::new(TlvFieldType::OriginalFilename, invalid_utf8);
        assert!(matches!(result, Err(HeaderError::InvalidFilename(_))));
    }

    #[test]
    fn test_tlv_field_algorithm_id() {
        let field = TlvField::new(TlvFieldType::AlgorithmId, 0x1234u16.to_le_bytes().to_vec()).unwrap();
        assert_eq!(field.data(), &0x1234u16.to_le_bytes());
        assert_eq!(field.length(), 2);

        // Invalid size for algorithm ID
        let result = TlvField::new(TlvFieldType::AlgorithmId, vec![0x12]);
        assert!(matches!(result, Err(HeaderError::InvalidFieldLength { .. })));
    }

    // =============================================================================
    // TlvHeader Basic Tests
    // =============================================================================

    #[test]
    fn test_tlv_header_default() {
        let header = TlvHeader::default();
        assert_eq!(header.magic_number(), &TlvHeader::MAGIC_NUMBER);
        assert_eq!(header.version(), TlvHeader::VERSION);
        assert!(header.is_valid_shadow_file());
    }

    #[test]
    fn test_tlv_header_new_empty() {
        let header = TlvHeader::new(HashMap::new(), None).unwrap();
        assert_eq!(header.version(), TlvHeader::VERSION);
        assert!(header.get_field(TlvFieldType::OriginalFilename).is_none());
    }

    #[test]
    fn test_tlv_header_new_with_version() {
        let header = TlvHeader::new(HashMap::new(), Some(2)).unwrap();
        assert_eq!(header.version(), 2);
    }

    // =============================================================================
    // TlvHeader Accessor Tests
    // =============================================================================

    #[test]
    fn test_tlv_header_accessors() {
        let mut fields = HashMap::new();
        fields.insert(TlvFieldType::OriginalFilename, b"test.txt".to_vec());
        fields.insert(TlvFieldType::AlgorithmId, 0x1234u16.to_le_bytes().to_vec());
        fields.insert(TlvFieldType::Nonce, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        fields.insert(TlvFieldType::ContentHash, [0xABu8; 32].to_vec());

        let header = TlvHeader::new(fields, None).unwrap();

        // Test basic accessors
        assert_eq!(header.get_field(TlvFieldType::OriginalFilename).unwrap(), b"test.txt");
        assert_eq!(header.algorithm_id().unwrap(), 0x1234);
        assert_eq!(header.nonce().unwrap(), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(header.original_filename().unwrap(), "test.txt");
        assert_eq!(header.content_hash().unwrap(), [0xABu8; 32]);
    }

    #[test]
    fn test_tlv_header_algorithm_id_invalid_size() {
        let mut fields = HashMap::new();
        fields.insert(TlvFieldType::AlgorithmId, vec![0x12]); // Wrong size

        let header = TlvHeader::new(fields, None);
        assert!(matches!(header, Err(HeaderError::InvalidFieldLength { .. })));
    }

    #[test]
    fn test_tlv_header_original_filename_checked() {
        let mut fields = HashMap::new();
        fields.insert(TlvFieldType::OriginalFilename, b"test.txt".to_vec());
        let header = TlvHeader::new(fields, None).unwrap();

        let filename = header.original_filename_checked().unwrap();
        assert_eq!(filename, Some("test.txt".to_string()));

        // Test with missing filename
        let empty_header = TlvHeader::new(HashMap::new(), None).unwrap();
        let filename = empty_header.original_filename_checked().unwrap();
        assert_eq!(filename, None);
    }

    #[test]
    fn test_tlv_header_content_hash_invalid_size() {
        let mut fields = HashMap::new();
        fields.insert(TlvFieldType::ContentHash, vec![0xAB; 16]); // Wrong size

        let header = TlvHeader::new(fields, None);
        assert!(matches!(header, Err(HeaderError::InvalidFieldLength { .. })));
    }

    // =============================================================================
    // TlvHeader Validation Tests
    // =============================================================================

    #[test]
    fn test_tlv_header_validate_too_many_fields() {
        let mut fields = HashMap::new();
        // This would be impractical to test with actual MAX_FIELD_COUNT
        // Instead, we'll create a scenario where validation fails
        for i in 0..300u8 {
            fields.insert(TlvFieldType::from(i), vec![i]);
        }

        let result = TlvHeader::new(fields, None);
        assert!(matches!(result, Err(HeaderError::TooManyFields(_))));
    }

    #[test]
    fn test_tlv_header_validate_for_encryption() {
        // Missing algorithm ID
        let header = TlvHeader::new(HashMap::new(), None).unwrap();
        let result = header.validate_for_encryption();
        assert!(matches!(result, Err(HeaderError::MissingRequiredField(TlvFieldType::AlgorithmId))));

        // Missing nonce
        let mut fields = HashMap::new();
        fields.insert(TlvFieldType::AlgorithmId, 0x1234u16.to_le_bytes().to_vec());
        let header = TlvHeader::new(fields, None).unwrap();
        let result = header.validate_for_encryption();
        assert!(matches!(result, Err(HeaderError::MissingRequiredField(TlvFieldType::Nonce))));

        // Valid for encryption
        let mut fields = HashMap::new();
        fields.insert(TlvFieldType::AlgorithmId, 0x1234u16.to_le_bytes().to_vec());
        fields.insert(TlvFieldType::Nonce, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let header = TlvHeader::new(fields, None).unwrap();
        assert!(header.validate_for_encryption().is_ok());
    }

    // =============================================================================
    // TlvHeader Serialization Tests
    // =============================================================================

    #[test]
    fn test_tlv_header_serialized_size() {
        let header = TlvHeader::new(HashMap::new(), None).unwrap();
        let expected_size = 4 + // length prefix
                           6 + // magic number
                           2;  // version
        assert_eq!(header.serialized_size(), expected_size);

        // With fields
        let mut fields = HashMap::new();
        fields.insert(TlvFieldType::OriginalFilename, b"test.txt".to_vec());
        fields.insert(TlvFieldType::AlgorithmId, 0x1234u16.to_le_bytes().to_vec());
        let header = TlvHeader::new(fields, None).unwrap();
        
        let expected_size = 4 + // length prefix
                           6 + // magic number
                           2 + // version
                           1 + 4 + 8 + // filename field (type + length + data)
                           1 + 4 + 2;  // algorithm field (type + length + data)
        assert_eq!(header.serialized_size(), expected_size);
    }

    #[test]
    fn test_tlv_header_to_bytes() {
        let mut fields = HashMap::new();
        fields.insert(TlvFieldType::OriginalFilename, b"test.txt".to_vec());
        fields.insert(TlvFieldType::AlgorithmId, 0x1234u16.to_le_bytes().to_vec());
        let header = TlvHeader::new(fields, None).unwrap();

        let bytes = header.to_bytes().unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(bytes.len(), header.serialized_size());

        // Verify it starts with length prefix
        let length = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(length as usize, bytes.len() - 4);
    }

    #[test]
    fn test_tlv_header_content_for_integrity() {
        let mut fields = HashMap::new();
        fields.insert(TlvFieldType::OriginalFilename, b"test.txt".to_vec());
        fields.insert(TlvFieldType::HeaderIntegrity, [0xABu8; 32].to_vec());
        let header = TlvHeader::new(fields, None).unwrap();

        let content = header.content_for_integrity().unwrap();
        
        // Should contain filename but not header integrity
        assert!(content.len() > 8); // At least magic + version
        
        // Verify integrity field is excluded by checking serialized content
        let with_integrity = header.serialize_header_content().unwrap();
        assert!(with_integrity.len() > content.len());
    }

    // =============================================================================
    // TlvHeader Deserialization Tests
    // =============================================================================

    #[test]
    fn test_tlv_header_roundtrip() {
        let mut fields = HashMap::new();
        fields.insert(TlvFieldType::OriginalFilename, b"test.txt".to_vec());
        fields.insert(TlvFieldType::AlgorithmId, 0x1234u16.to_le_bytes().to_vec());
        fields.insert(TlvFieldType::Nonce, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let original = TlvHeader::new(fields, None).unwrap();

        let bytes = original.to_bytes().unwrap();
        let deserialized = TlvHeader::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.version(), original.version());
        assert_eq!(deserialized.algorithm_id(), original.algorithm_id());
        assert_eq!(deserialized.nonce(), original.nonce());
        assert_eq!(deserialized.original_filename(), original.original_filename());
    }

    #[test]
    fn test_tlv_header_from_bytes_truncated() {
        // Too short for length prefix
        let result = TlvHeader::from_bytes(&[1, 2]);
        assert!(matches!(result, Err(HeaderError::TruncatedHeader)));

        // Length prefix but not enough data
        let mut bytes = vec![0u8; 4];
        bytes.extend_from_slice(&100u32.to_le_bytes()); // Claims 100 bytes but we don't provide them
        let result = TlvHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(HeaderError::TruncatedHeader)));
    }

    #[test]
    fn test_tlv_header_from_bytes_invalid_magic() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&14u32.to_le_bytes()); // length
        buffer.extend_from_slice(b"BADMAG"); // wrong magic
        buffer.extend_from_slice(&1u16.to_le_bytes()); // version

        let result = TlvHeader::from_bytes(&buffer);
        assert!(matches!(result, Err(HeaderError::InvalidMagicNumber)));
    }

    #[test]
    fn test_tlv_header_from_bytes_unsupported_version() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&8u32.to_le_bytes()); // length
        buffer.extend_from_slice(b"SHADOW"); // magic
        buffer.extend_from_slice(&99u16.to_le_bytes()); // unsupported version

        let result = TlvHeader::from_bytes(&buffer);
        assert!(matches!(result, Err(HeaderError::UnsupportedVersion(99))));
    }

    #[test]
    fn test_tlv_header_from_bytes_field_too_large() {
        let mut buffer = Vec::new();
        let content_length = 8 + 1 + 4; // magic + version + type + length (no actual data)
        buffer.extend_from_slice(&(content_length as u32).to_le_bytes());
        buffer.extend_from_slice(b"SHADOW");
        buffer.extend_from_slice(&1u16.to_le_bytes());
        buffer.push(0x01); // field type
        buffer.extend_from_slice(&(TlvHeader::MAX_FIELD_SIZE + 1).to_le_bytes()); // too large

        let result = TlvHeader::from_bytes(&buffer);
        assert!(matches!(result, Err(HeaderError::FieldTooLarge { .. })));
    }

    #[test]
    fn test_tlv_header_from_bytes_header_too_large() {
        let large_size = TlvHeader::MAX_HEADER_SIZE + 1;
        let mut buffer = vec![0u8; 4];
        buffer[0..4].copy_from_slice(&(large_size as u32).to_le_bytes());

        let result = TlvHeader::from_bytes(&buffer);
        assert!(matches!(result, Err(HeaderError::HeaderTooLarge { .. })));
    }

    // =============================================================================
    // TlvHeaderBuilder Tests
    // =============================================================================

    #[test]
    fn test_header_builder_new() {
        let builder = TlvHeaderBuilder::new();
        let header = builder.build().unwrap();
        assert_eq!(header.version(), TlvHeader::VERSION);
        assert!(header.get_field(TlvFieldType::OriginalFilename).is_none());
    }

    #[test]
    fn test_header_builder_default() {
        let builder = TlvHeaderBuilder::default();
        let header = builder.build().unwrap();
        assert_eq!(header.version(), TlvHeader::VERSION);
    }

    #[test]
    fn test_header_builder_filename() {
        let header = TlvHeaderBuilder::new()
            .filename("test.txt")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(header.original_filename().unwrap(), "test.txt");
    }

    #[test]
    fn test_header_builder_filename_empty() {
        let result = TlvHeaderBuilder::new().filename("");
        assert!(matches!(result, Err(HeaderError::EmptyFilename)));
    }

    #[test]
    fn test_header_builder_algorithm_id() {
        let header = TlvHeaderBuilder::new()
            .algorithm_id(0x1234)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(header.algorithm_id().unwrap(), 0x1234);
    }

    #[test]
    fn test_header_builder_nonce() {
        let nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let header = TlvHeaderBuilder::new()
            .nonce(nonce.clone())
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(header.nonce().unwrap(), &nonce);
    }

    #[test]
    fn test_header_builder_nonce_empty() {
        let result = TlvHeaderBuilder::new().nonce(vec![]);
        assert!(matches!(result, Err(HeaderError::EmptyNonce)));
    }

    #[test]
    fn test_header_builder_content_hash() {
        let hash = [0xABu8; 32];
        let header = TlvHeaderBuilder::new()
            .content_hash(hash)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(header.content_hash().unwrap(), hash);
    }

    #[test]
    fn test_header_builder_version() {
        let header = TlvHeaderBuilder::new()
            .version(2)
            .build()
            .unwrap();

        assert_eq!(header.version(), 2);
    }

    #[test]
    fn test_header_builder_chaining() {
        let nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hash = [0xCDu8; 32];
        
        let header = TlvHeaderBuilder::new()
            .filename("secret.txt").unwrap()
            .algorithm_id(0x5678).unwrap()
            .nonce(nonce.clone()).unwrap()
            .content_hash(hash).unwrap()
            .version(1)
            .build()
            .unwrap();

        assert_eq!(header.original_filename().unwrap(), "secret.txt");
        assert_eq!(header.algorithm_id().unwrap(), 0x5678);
        assert_eq!(header.nonce().unwrap(), &nonce);
        assert_eq!(header.content_hash().unwrap(), hash);
        assert_eq!(header.version(), 1);
    }

    #[test]
    fn test_header_builder_build_for_encryption() {
        // Missing required fields
        let result = TlvHeaderBuilder::new()
            .filename("test.txt")
            .unwrap()
            .build_for_encryption();
        assert!(matches!(result, Err(HeaderError::MissingRequiredField(_))));

        // Valid for encryption
        let nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let header = TlvHeaderBuilder::new()
            .filename("test.txt").unwrap()
            .algorithm_id(0x1234).unwrap()
            .nonce(nonce).unwrap()
            .build_for_encryption()
            .unwrap();

        assert!(header.validate_for_encryption().is_ok());
    }

    // =============================================================================
    // Integration Tests
    // =============================================================================

    #[test]
    fn test_full_encryption_header_workflow() {
        // Create a header suitable for encryption
        let nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let content_hash = [0xDEu8; 32];
        
        let header = TlvHeaderBuilder::new()
            .filename("confidential.pdf").unwrap()
            .algorithm_id(0x0001).unwrap() // ChaCha20Poly1305
            .nonce(nonce.clone()).unwrap()
            .content_hash(content_hash).unwrap()
            .build_for_encryption()
            .unwrap();

        // Verify all expected fields are present
        assert_eq!(header.original_filename().unwrap(), "confidential.pdf");
        assert_eq!(header.algorithm_id().unwrap(), 0x0001);
        assert_eq!(header.nonce().unwrap(), &nonce);
        assert_eq!(header.content_hash().unwrap(), content_hash);
        assert!(header.is_valid_shadow_file());

        // Test serialization roundtrip
        let serialized = header.to_bytes().unwrap();
        let deserialized = TlvHeader::from_bytes(&serialized).unwrap();
        
        assert_eq!(deserialized.original_filename(), header.original_filename());
        assert_eq!(deserialized.algorithm_id(), header.algorithm_id());
        assert_eq!(deserialized.nonce(), header.nonce());
        assert_eq!(deserialized.content_hash(), header.content_hash());
    }

    #[test]
    fn test_deterministic_serialization() {
        // Create the same header twice with fields added in different orders
        let nonce = vec![1, 2, 3, 4];
        
        let header1 = TlvHeaderBuilder::new()
            .filename("test.txt").unwrap()
            .algorithm_id(0x1234).unwrap()
            .nonce(nonce.clone()).unwrap()
            .build()
            .unwrap();

        let header2 = TlvHeaderBuilder::new()
            .nonce(nonce).unwrap()
            .algorithm_id(0x1234).unwrap()
            .filename("test.txt").unwrap()
            .build()
            .unwrap();

        // Serialization should be identical due to field sorting
        let bytes1 = header1.to_bytes().unwrap();
        let bytes2 = header2.to_bytes().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_backward_compatibility_unknown_fields() {
        // Create a header with an unknown field type by manually constructing bytes
        let mut buffer = Vec::new();
        
        // Header length will be calculated
        let _content_start = buffer.len() + 4;
        buffer.extend_from_slice(&0u32.to_le_bytes()); // placeholder for length
        
        // Magic and version
        buffer.extend_from_slice(b"SHADOW");
        buffer.extend_from_slice(&1u16.to_le_bytes());
        
        // Known field: filename
        buffer.push(0x01); // OriginalFilename
        buffer.extend_from_slice(&8u32.to_le_bytes()); // length
        buffer.extend_from_slice(b"test.txt");
        
        // Unknown field type that should be handled gracefully
        buffer.push(0x99); // Unknown type -> becomes ExtensionMarker
        buffer.extend_from_slice(&4u32.to_le_bytes()); // length
        buffer.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        
        // Update length
        let content_length = buffer.len() - 4;
        buffer[0..4].copy_from_slice(&(content_length as u32).to_le_bytes());
        
        // Should parse successfully, treating unknown field as ExtensionMarker
        let header = TlvHeader::from_bytes(&buffer).unwrap();
        assert_eq!(header.original_filename().unwrap(), "test.txt");
        assert!(header.get_field(TlvFieldType::ExtensionMarker).is_some());
    }

    // =============================================================================
    // Error Display Tests
    // =============================================================================

    #[test]
    fn test_header_error_display() {
        let errors = vec![
            HeaderError::EmptyFilename,
            HeaderError::EmptyNonce,
            HeaderError::InvalidMagicNumber,
            HeaderError::UnsupportedVersion(99),
            HeaderError::TruncatedHeader,
            HeaderError::FieldTooLarge { size: 2000000, max: 1000000 },
            HeaderError::HeaderTooLarge { size: 3000000, max: 2000000 },
            HeaderError::TooManyFields(300),
            HeaderError::InvalidFieldLength { 
                field_type: TlvFieldType::ContentHash, 
                expected: 32, 
                actual: 16 
            },
            HeaderError::MissingRequiredField(TlvFieldType::AlgorithmId),
        ];

        for error in errors {
            let display = format!("{}", error);
            assert!(!display.is_empty());
            assert!(display.len() > 10); // Reasonable error message length
        }
    }
}
