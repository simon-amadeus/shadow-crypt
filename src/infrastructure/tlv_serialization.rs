//! TLV Header Serialization Infrastructure
//!
//! This module provides binary serialization and deserialization for TLV headers,
//! implementing the wire format for Shadow V1 files.
//!
//! The infrastructure implements the domain TlvParser trait, handling binary I/O
//! while delegating business rules to the domain layer.

use crate::domain::entities::tlv_header::{TlvField, TlvFieldType, TlvHeader};
use crate::domain::services::tlv_parser::{TlvParser, TlvParsingError, TlvFieldValidation};
use std::io::{self, Cursor, Read, Write};

/// Legacy TLV serialization error types (maintained for backward compatibility)
/// New code should use domain TlvParsingError instead
#[derive(Debug)]
pub enum TlvSerializationError {
    /// I/O error during serialization/deserialization
    Io(io::Error),
    /// Invalid TLV data format
    InvalidFormat(String),
    /// Insufficient data for complete TLV field
    InsufficientData,
    /// Invalid magic number
    InvalidMagicNumber,
}

impl From<TlvParsingError> for TlvSerializationError {
    fn from(err: TlvParsingError) -> Self {
        match err {
            TlvParsingError::InvalidMagicNumber => TlvSerializationError::InvalidMagicNumber,
            TlvParsingError::InsufficientData => TlvSerializationError::InsufficientData,
            TlvParsingError::CorruptedStructure(msg) => TlvSerializationError::InvalidFormat(msg),
            TlvParsingError::InvalidFieldData { reason, .. } => TlvSerializationError::InvalidFormat(reason),
            TlvParsingError::FieldTooLarge { field_type, length, max_allowed } => {
                TlvSerializationError::InvalidFormat(format!(
                    "Field type 0x{:02x} length {} exceeds maximum {}", field_type, length, max_allowed
                ))
            }
        }
    }
}

impl From<TlvSerializationError> for TlvParsingError {
    fn from(err: TlvSerializationError) -> Self {
        match err {
            TlvSerializationError::InvalidMagicNumber => TlvParsingError::InvalidMagicNumber,
            TlvSerializationError::InsufficientData => TlvParsingError::InsufficientData,
            TlvSerializationError::InvalidFormat(msg) => TlvParsingError::CorruptedStructure(msg),
            TlvSerializationError::Io(io_err) => TlvParsingError::CorruptedStructure(format!("I/O error: {}", io_err)),
        }
    }
}

impl From<io::Error> for TlvSerializationError {
    fn from(error: io::Error) -> Self {
        TlvSerializationError::Io(error)
    }
}

impl std::fmt::Display for TlvSerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlvSerializationError::Io(err) => write!(f, "I/O error: {}", err),
            TlvSerializationError::InvalidFormat(msg) => write!(f, "Invalid TLV format: {}", msg),
            TlvSerializationError::InsufficientData => write!(f, "Insufficient data for TLV field"),
            TlvSerializationError::InvalidMagicNumber => write!(f, "Invalid magic number"),
        }
    }
}

impl std::error::Error for TlvSerializationError {}

/// TLV header serializer/deserializer implementing domain contract
pub struct TlvSerializer;

impl TlvParser for TlvSerializer {
    fn parse_header_with_remainder(data: &[u8]) -> Result<(TlvHeader, &[u8]), TlvParsingError> {
        Self::deserialize_with_remainder_domain(data)
    }
    
    fn serialize_header(header: &TlvHeader) -> Result<Vec<u8>, TlvParsingError> {
        Self::serialize_domain(header)
    }
    
    fn is_valid_field_type(field_type: u8) -> bool {
        // Domain rule: Only reject null bytes (likely corrupted data)
        // Accept all other values for forward compatibility
        field_type != 0x00
    }
    
    fn max_field_length() -> u32 {
        Self::MAX_FIELD_LENGTH as u32
    }
    
    fn validate_field_data(field_type: u8, data: &[u8]) -> Result<(), TlvParsingError> {
        match field_type {
            0x01 => TlvFieldValidation::validate_filename(data),
            0x02 => TlvFieldValidation::validate_directory_path(data),
            0x07 => TlvFieldValidation::validate_content_hash(data),
            0x08 => TlvFieldValidation::validate_algorithm_id(data),
            _ => Ok(()), // Unknown fields are accepted for forward compatibility
        }
    }
    
    fn parse_header_from_reader<R: std::io::Read + std::io::Seek>(
        reader: &mut R
    ) -> Result<TlvHeader, TlvParsingError> {
        Self::parse_header_from_reader_impl(reader).map_err(|e| e.into())
    }
}

impl TlvSerializer {
    /// Maximum allowed field length (64KB) - prevents DoS attacks from malicious files
    const MAX_FIELD_LENGTH: usize = 65536;
    
    /// Size of TLV field header: 1 byte type + 4 bytes length
    const FIELD_HEADER_SIZE: usize = 5;
    
    /// Domain-aware deserialization with remainder
    fn deserialize_with_remainder_domain(data: &[u8]) -> Result<(TlvHeader, &[u8]), TlvParsingError> {
        Self::deserialize_with_remainder(data).map_err(|e| e.into())
    }
    
    /// Domain-aware serialization
    fn serialize_domain(header: &TlvHeader) -> Result<Vec<u8>, TlvParsingError> {
        Self::serialize(header).map_err(|e| e.into())
    }
    
    /// Serialize a TLV header to bytes
    /// 
    /// Format: [Magic(8)][Version(2)][TLV Fields...]
    /// TLV Field Format: [Type(1)][Length(4)][Value(Length)]
    pub fn serialize(header: &TlvHeader) -> Result<Vec<u8>, TlvSerializationError> {
        let mut buffer = Vec::new();
        
        // Write magic number
        buffer.write_all(header.magic_number())?;
        
        // Write version (little-endian)
        buffer.write_all(&header.version().to_le_bytes())?;
        
        // Serialize TLV fields in deterministic order
        let mut field_types: Vec<_> = header.fields.keys().collect();
        field_types.sort();
        
        for &field_type in field_types {
            let data = header.get_field(field_type).unwrap();
            Self::serialize_field(&mut buffer, field_type, data)?;
        }
        
        Ok(buffer)
    }
    
    /// Deserialize a TLV header from bytes and return remaining bytes
    pub fn deserialize_with_remainder(data: &[u8]) -> Result<(TlvHeader, &[u8]), TlvSerializationError> {
        let mut cursor = Cursor::new(data);
        
        // Read and validate magic number
        let mut magic = [0u8; 8];
        cursor.read_exact(&mut magic)?;
        if magic != TlvHeader::MAGIC_NUMBER {
            return Err(TlvSerializationError::InvalidMagicNumber);
        }
        
        // Read version
        let mut version_bytes = [0u8; 2];
        cursor.read_exact(&mut version_bytes)?;
        let _version = u16::from_le_bytes(version_bytes);
        
        // Create header with read values
        let mut header = TlvHeader::new();
        
        // Read TLV fields until we hit an invalid field type or run out of data
        loop {
            let current_pos = cursor.position() as usize;
            
            // Check if we have enough bytes for a field header (type + length)
            if current_pos + Self::FIELD_HEADER_SIZE > data.len() {
                break; // Not enough data for another field header
            }
            
            // Peek at the field type to check validity
            let field_type_byte = data[current_pos];
            if !Self::is_valid_field_type(field_type_byte) {
                // Hit an invalid field type - this is the natural boundary between header and ciphertext
                break;
            }
            
            // Peek at the length to validate before reading
            let length_bytes = &data[current_pos + 1..current_pos + Self::FIELD_HEADER_SIZE];
            let length = u32::from_le_bytes([
                length_bytes[0], length_bytes[1], 
                length_bytes[2], length_bytes[3]
            ]) as usize;
            
            // Validate length before proceeding
            if length > Self::MAX_FIELD_LENGTH {
                // Suspiciously large field - probably not a real TLV field
                break;
            }
            
            // Check if we have enough data for the complete field
            if current_pos + Self::FIELD_HEADER_SIZE + length > data.len() {
                break; // Not enough data for this field's value
            }
            
            // Try to read the field - if validation fails, we stop here
            match Self::deserialize_field(&mut cursor) {
                Ok(field) => {
                    header.add_field(field.field_type(), field.data().to_vec());
                }
                Err(TlvSerializationError::InvalidFormat(_)) => {
                    // Hit invalid field format - stop parsing here
                    break;
                }
                Err(e) => {
                    // Other errors should be propagated
                    return Err(e);
                }
            }
        }
        
        // Return header and remaining bytes (ciphertext)
        let header_end = cursor.position() as usize;
        let remaining = &data[header_end..];
        Ok((header, remaining))
    }
    
    /// Deserialize a TLV header from bytes
    pub fn deserialize(data: &[u8]) -> Result<TlvHeader, TlvSerializationError> {
        let (header, _) = Self::deserialize_with_remainder(data)?;
        Ok(header)
    }
    
    /// Serialize a single TLV field
    fn serialize_field(
        buffer: &mut Vec<u8>, 
        field_type: TlvFieldType, 
        data: &[u8]
    ) -> Result<(), TlvSerializationError> {
        // Write type
        buffer.write_all(&[field_type as u8])?;
        
        // Write length (little-endian)
        let length = data.len() as u32;
        buffer.write_all(&length.to_le_bytes())?;
        
        // Write value
        buffer.write_all(data)?;
        
        Ok(())
    }
    
    /// Deserialize a single TLV field
    fn deserialize_field(cursor: &mut Cursor<&[u8]>) -> Result<TlvField, TlvSerializationError> {
        // Read type
        let mut type_byte = [0u8; 1];
        cursor.read_exact(&mut type_byte)?;
        let field_type_raw = type_byte[0];
        
        // Validate field type before conversion to prevent ExtensionMarker mapping
        if !Self::is_valid_field_type(field_type_raw) {
            return Err(TlvSerializationError::InvalidFormat(
                format!("Invalid TLV field type: 0x{:02x}", field_type_raw)
            ));
        }
        
        let field_type = TlvFieldType::from(field_type_raw);
        
        // Read length
        let mut length_bytes = [0u8; 4];
        cursor.read_exact(&mut length_bytes)?;
        let length = u32::from_le_bytes(length_bytes) as usize;
        
        // Validate field length to prevent DoS attacks
        if length > Self::MAX_FIELD_LENGTH {
            return Err(TlvSerializationError::InvalidFormat(
                format!("Field length {} exceeds maximum {}", length, Self::MAX_FIELD_LENGTH)
            ));
        }
        
        // Check if we have enough data
        let remaining = cursor.get_ref().len() as u64 - cursor.position();
        if remaining < length as u64 {
            return Err(TlvSerializationError::InsufficientData);
        }
        
        // Read value
        let mut data = vec![0u8; length];
        cursor.read_exact(&mut data)?;
        
        Ok(TlvField::new(field_type, data))
    }
    
    /// Check if a byte represents a valid TLV field type
    /// For robustness: 0x00 is always invalid (likely corrupted data)
    /// For forward compatibility: 0x01-0xFE are valid (current and future field types)
    /// 0xFF is the official extension marker
    fn is_valid_field_type(byte: u8) -> bool {
        byte != 0x00 // Only reject null bytes - everything else could be valid
    }
    
    /// Parse TLV header from a streaming reader without loading entire file
    /// 
    /// This is a more efficient approach for large files as it:
    /// 1. Reads header data incrementally
    /// 2. Stops at the header boundary without reading ciphertext
    /// 3. Leaves reader positioned at start of ciphertext
    /// 4. Uses minimal memory regardless of file size
    pub fn parse_header_from_reader_impl<R: std::io::Read + std::io::Seek>(
        reader: &mut R
    ) -> Result<TlvHeader, TlvSerializationError> {
        use std::io::SeekFrom;
        
        // Save starting position for potential rollback
        let start_pos = reader.stream_position()
            .map_err(|e| TlvSerializationError::InvalidFormat(format!("Stream positioning error: {}", e)))?;
        
        // Read and validate magic number (8 bytes)
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)
            .map_err(|e| TlvSerializationError::Io(e))?;
        
        if magic != TlvHeader::MAGIC_NUMBER {
            // Rollback on invalid magic
            let _ = reader.seek(SeekFrom::Start(start_pos));
            return Err(TlvSerializationError::InvalidMagicNumber);
        }
        
        // Read version (2 bytes)
        let mut version_bytes = [0u8; 2];
        reader.read_exact(&mut version_bytes)
            .map_err(|e| TlvSerializationError::Io(e))?;
        let _version = u16::from_le_bytes(version_bytes);
        
        // Create header
        let mut header = TlvHeader::new();
        
        // Read TLV fields one by one until we hit invalid field type or EOF
        loop {
            // Try to read field type (1 byte)
            let mut type_buf = [0u8; 1];
            match reader.read_exact(&mut type_buf) {
                Ok(()) => {
                    let field_type = type_buf[0];
                    
                    // Check if this is a valid field type
                    if !Self::is_valid_field_type(field_type) {
                        // Hit invalid field type - rewind 1 byte and stop
                        let _ = reader.seek(SeekFrom::Current(-1));
                        break;
                    }
                    
                    // Try to read field length (4 bytes)
                    let mut length_buf = [0u8; 4];
                    match reader.read_exact(&mut length_buf) {
                        Ok(()) => {
                            let length = u32::from_le_bytes(length_buf) as usize;
                            
                            // Validate field length
                            if length > Self::MAX_FIELD_LENGTH {
                                // Suspiciously large field - rewind and stop parsing
                                let _ = reader.seek(SeekFrom::Current(-5)); // Rewind type + length
                                break;
                            }
                            
                            // Try to read field value
                            let mut value_buf = vec![0u8; length];
                            match reader.read_exact(&mut value_buf) {
                                Ok(()) => {
                                    // Successfully read complete field - add it to header
                                    header.add_field(field_type.into(), value_buf);
                                }
                                Err(_) => {
                                    // Can't read complete field value - rewind and stop
                                    let _ = reader.seek(SeekFrom::Current(-5)); // Rewind type + length
                                    break;
                                }
                            }
                        }
                        Err(_) => {
                            // Can't read complete length - this is likely start of ciphertext
                            // Rewind the field type byte and stop
                            let _ = reader.seek(SeekFrom::Current(-1));
                            break;
                        }
                    }
                }
                Err(_) => {
                    // EOF or read error - stop parsing here
                    break;
                }
            }
        }
        
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_header_roundtrip() {
        let mut header = TlvHeader::new();
        header.set_original_filename("test.txt");
        header.set_content_hash([0x42u8; 32]);
        header.set_algorithm_id(1);
        
        let serialized = TlvSerializer::serialize(&header).unwrap();
        let deserialized = TlvSerializer::deserialize(&serialized).unwrap();
        
        assert_eq!(deserialized.magic_number(), header.magic_number());
        assert_eq!(deserialized.version(), header.version());
        assert_eq!(deserialized.original_filename(), Some("test.txt".to_string()));
        assert_eq!(deserialized.content_hash(), Some([0x42u8; 32]));
        assert_eq!(deserialized.get_field(TlvFieldType::AlgorithmId), Some(&vec![1]));
    }
    
    #[test]
    fn test_invalid_magic_number() {
        let mut data = vec![0u8; 10]; // Wrong magic number
        data.extend_from_slice(&1u16.to_le_bytes()); // Version
        
        let result = TlvSerializer::deserialize(&data);
        assert!(matches!(result, Err(TlvSerializationError::InvalidMagicNumber)));
    }
    
    #[test]
    fn test_insufficient_data_graceful_handling() {
        let mut data = Vec::new();
        data.extend_from_slice(&TlvHeader::MAGIC_NUMBER);
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(0x01); // Type
        data.extend_from_slice(&10u32.to_le_bytes()); // Length: 10
        data.extend_from_slice(b"short"); // Only 5 bytes instead of 10
        
        // With the new implementation, this should gracefully stop parsing
        // and return a valid header with no fields (since the incomplete field is ignored)
        let result = TlvSerializer::deserialize(&data);
        assert!(result.is_ok(), "Should gracefully handle insufficient data");
        
        let header = result.unwrap();
        assert_eq!(header.version(), 1);
        assert!(header.original_filename().is_none(), "Should not have parsed incomplete field");
    }
    
    #[test]
    fn test_empty_header() {
        let header = TlvHeader::new();
        let serialized = TlvSerializer::serialize(&header).unwrap();
        let deserialized = TlvSerializer::deserialize(&serialized).unwrap();
        
        assert_eq!(deserialized.magic_number(), header.magic_number());
        assert_eq!(deserialized.version(), header.version());
        assert_eq!(deserialized.original_filename(), None);
    }
    
    #[test]
    fn test_deterministic_serialization() {
        let mut header = TlvHeader::new();
        header.set_original_filename("test.txt");
        header.set_algorithm_id(1);
        header.set_content_hash([0x42u8; 32]);
        
        let serialized1 = TlvSerializer::serialize(&header).unwrap();
        let serialized2 = TlvSerializer::serialize(&header).unwrap();
        
        assert_eq!(serialized1, serialized2, "Serialization should be deterministic");
    }
}