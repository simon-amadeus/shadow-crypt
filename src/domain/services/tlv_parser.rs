//! TLV Parsing Domain Contract
//!
//! This module defines the domain-level contract for TLV header parsing and serialization.
//! The domain defines WHAT parsing means (business rules, validation, semantics)
//! while infrastructure implementations define HOW it's done (binary format, I/O).

use crate::domain::entities::tlv_header::TlvHeader;

/// Domain errors for TLV parsing operations
#[derive(Debug, Clone, PartialEq)]
pub enum TlvParsingError {
    /// Invalid header magic number - not a Shadow file
    InvalidMagicNumber,
    /// Corrupted or malformed TLV structure
    CorruptedStructure(String),
    /// Field data violates domain business rules
    InvalidFieldData { field_type: u8, reason: String },
    /// Insufficient data to complete parsing
    InsufficientData,
    /// Field length exceeds security limits
    FieldTooLarge { field_type: u8, length: u32, max_allowed: u32 },
}

impl std::fmt::Display for TlvParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlvParsingError::InvalidMagicNumber => 
                write!(f, "File is not a valid Shadow encrypted file"),
            TlvParsingError::CorruptedStructure(msg) => 
                write!(f, "Corrupted TLV structure: {}", msg),
            TlvParsingError::InvalidFieldData { field_type, reason } => 
                write!(f, "Invalid data for field type 0x{:02x}: {}", field_type, reason),
            TlvParsingError::InsufficientData => 
                write!(f, "Incomplete TLV data"),
            TlvParsingError::FieldTooLarge { field_type, length, max_allowed } => 
                write!(f, "Field type 0x{:02x} length {} exceeds maximum {}", field_type, length, max_allowed),
        }
    }
}

impl std::error::Error for TlvParsingError {}

/// Domain contract for TLV header parsing and serialization
/// 
/// This trait defines the business rules and semantics for TLV operations.
/// Infrastructure implementations handle the binary format details.
pub trait TlvParser {
    /// Parse a TLV header from bytes, returning header and any remaining data
    /// 
    /// Domain rules:
    /// - Must validate magic number and version
    /// - Must enforce field length security limits  
    /// - Must stop at invalid field types for robustness
    /// - Must preserve unknown field types for forward compatibility
    /// - Must handle malformed data gracefully
    fn parse_header_with_remainder(data: &[u8]) -> Result<(TlvHeader, &[u8]), TlvParsingError>;
    
    /// Parse a TLV header from bytes (convenience method)
    fn parse_header(data: &[u8]) -> Result<TlvHeader, TlvParsingError> {
        let (header, _) = Self::parse_header_with_remainder(data)?;
        Ok(header)
    }
    
    /// Serialize a TLV header to bytes
    /// 
    /// Domain rules:
    /// - Must produce deterministic output
    /// - Must use canonical field ordering
    /// - Must validate field data before serialization
    fn serialize_header(header: &TlvHeader) -> Result<Vec<u8>, TlvParsingError>;
    
    /// Validate that a field type is recognized by this parser
    /// 
    /// Domain rules:
    /// - Standard field types (0x01-0x0A) are always valid
    /// - Future field types (0x0B-0xFE) are valid for forward compatibility  
    /// - Null field type (0x00) is always invalid (corrupted data)
    /// - Extension marker (0xFF) is valid
    fn is_valid_field_type(field_type: u8) -> bool;
    
    /// Get the maximum allowed field length for security
    /// 
    /// Domain rule: Large field lengths could indicate DoS attacks or corrupted data
    fn max_field_length() -> u32;
    
    /// Validate field data according to domain business rules
    /// 
    /// Each field type may have specific validation requirements
    fn validate_field_data(field_type: u8, data: &[u8]) -> Result<(), TlvParsingError>;
    
    /// Parse TLV header from a reader without loading entire content into memory
    /// 
    /// This enables efficient header extraction from large encrypted files.
    /// Domain rules:
    /// - Must read minimal data necessary (header only)
    /// - Must validate magic number early to fail fast on invalid files
    /// - Must handle streaming I/O errors gracefully
    /// - Must preserve reader position at start of ciphertext
    fn parse_header_from_reader<R: std::io::Read + std::io::Seek>(
        reader: &mut R
    ) -> Result<TlvHeader, TlvParsingError>;
}

/// Domain validation rules for TLV field types
pub struct TlvFieldValidation;

impl TlvFieldValidation {
    /// Maximum filename length (reasonable limit for cross-platform compatibility)
    pub const MAX_FILENAME_LENGTH: usize = 255;
    
    /// Maximum directory path length  
    pub const MAX_PATH_LENGTH: usize = 4096;
    
    /// Standard hash lengths
    pub const SHA256_LENGTH: usize = 32;
    
    /// Validate filename field data
    pub fn validate_filename(data: &[u8]) -> Result<(), TlvParsingError> {
        if data.len() > Self::MAX_FILENAME_LENGTH {
            return Err(TlvParsingError::InvalidFieldData {
                field_type: 0x01,
                reason: format!("Filename too long: {} bytes (max {})", data.len(), Self::MAX_FILENAME_LENGTH),
            });
        }
        
        // Must be valid UTF-8
        std::str::from_utf8(data).map_err(|_| TlvParsingError::InvalidFieldData {
            field_type: 0x01,
            reason: "Filename contains invalid UTF-8".to_string(),
        })?;
        
        Ok(())
    }
    
    /// Validate directory path field data
    pub fn validate_directory_path(data: &[u8]) -> Result<(), TlvParsingError> {
        if data.len() > Self::MAX_PATH_LENGTH {
            return Err(TlvParsingError::InvalidFieldData {
                field_type: 0x02,
                reason: format!("Path too long: {} bytes (max {})", data.len(), Self::MAX_PATH_LENGTH),
            });
        }
        
        // Must be valid UTF-8
        std::str::from_utf8(data).map_err(|_| TlvParsingError::InvalidFieldData {
            field_type: 0x02,
            reason: "Directory path contains invalid UTF-8".to_string(),
        })?;
        
        Ok(())
    }
    
    /// Validate content hash field data
    pub fn validate_content_hash(data: &[u8]) -> Result<(), TlvParsingError> {
        if data.len() != Self::SHA256_LENGTH {
            return Err(TlvParsingError::InvalidFieldData {
                field_type: 0x07,
                reason: format!("Content hash must be {} bytes, got {}", Self::SHA256_LENGTH, data.len()),
            });
        }
        Ok(())
    }
    
    /// Validate algorithm ID field data  
    pub fn validate_algorithm_id(data: &[u8]) -> Result<(), TlvParsingError> {
        if data.len() != 1 {
            return Err(TlvParsingError::InvalidFieldData {
                field_type: 0x08,
                reason: format!("Algorithm ID must be 1 byte, got {}", data.len()),
            });
        }
        Ok(())
    }
}