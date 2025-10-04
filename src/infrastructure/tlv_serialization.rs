//! TLV Header Serialization Infrastructure
//!
//! This module provides binary serialization and deserialization for TLV headers,
//! implementing the wire format for Shadow V1 files.

use crate::domain::entities::tlv_header::{TlvField, TlvFieldType, TlvHeader};
use std::io::{self, Cursor, Read, Write};

/// Error types for TLV serialization operations
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

/// TLV header serializer/deserializer
pub struct TlvSerializer;

impl TlvSerializer {
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
    
    /// Deserialize a TLV header from bytes
    pub fn deserialize(data: &[u8]) -> Result<TlvHeader, TlvSerializationError> {
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
        // Note: In a real implementation, we'd support version validation here
        
        // Read TLV fields
        while cursor.position() < data.len() as u64 {
            let field = Self::deserialize_field(&mut cursor)?;
            header.add_field(field.field_type(), field.data().to_vec());
        }
        
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
        let field_type = TlvFieldType::from(type_byte[0]);
        
        // Read length
        let mut length_bytes = [0u8; 4];
        cursor.read_exact(&mut length_bytes)?;
        let length = u32::from_le_bytes(length_bytes) as usize;
        
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
    fn test_insufficient_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&TlvHeader::MAGIC_NUMBER);
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(0x01); // Type
        data.extend_from_slice(&10u32.to_le_bytes()); // Length: 10
        data.extend_from_slice(b"short"); // Only 5 bytes instead of 10
        
        let result = TlvSerializer::deserialize(&data);
        assert!(matches!(result, Err(TlvSerializationError::InsufficientData)));
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