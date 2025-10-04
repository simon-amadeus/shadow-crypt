//! TLV (Type-Length-Value) system proof of concept for V3 header
//! 
//! This validates the core TLV field design before full implementation.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TlvFieldType {
    OriginalFilename = 0x01,
    DirectoryPath = 0x02,
    FileMetadata = 0x03,
    CompressionSettings = 0x04,
    KeyDerivationParams = 0x05,
    CustomAttributes = 0x06,
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
            0xFF => TlvFieldType::ExtensionMarker,
            _ => TlvFieldType::ExtensionMarker, // Unknown types go to extension
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlvField {
    pub field_type: TlvFieldType,
    pub data: Vec<u8>,
}

impl TlvField {
    pub fn new(field_type: TlvFieldType, data: Vec<u8>) -> Self {
        Self { field_type, data }
    }
    
    /// Serialize TLV field to bytes: [Type(1)][Length(4)][Value(Length)]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.field_type as u8);
        buffer.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&self.data);
        buffer
    }
    
    /// Deserialize TLV field from bytes
    pub fn deserialize(data: &[u8], offset: usize) -> Result<(Self, usize), &'static str> {
        if offset + 5 > data.len() {
            return Err("Insufficient data for TLV header");
        }
        
        let field_type = TlvFieldType::from(data[offset]);
        let length = u32::from_le_bytes([
            data[offset + 1],
            data[offset + 2], 
            data[offset + 3],
            data[offset + 4],
        ]) as usize;
        
        let value_start = offset + 5;
        let value_end = value_start + length;
        
        if value_end > data.len() {
            return Err("Insufficient data for TLV value");
        }
        
        let field_data = data[value_start..value_end].to_vec();
        let field = TlvField::new(field_type, field_data);
        
        Ok((field, value_end))
    }
}

pub struct TlvCollection {
    fields: HashMap<TlvFieldType, Vec<u8>>,
}

impl TlvCollection {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }
    
    pub fn add_field(&mut self, field_type: TlvFieldType, data: Vec<u8>) {
        self.fields.insert(field_type, data);
    }
    
    pub fn get_field(&self, field_type: TlvFieldType) -> Option<&Vec<u8>> {
        self.fields.get(&field_type)
    }
    
    /// Serialize all TLV fields
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        // Serialize in deterministic order for consistency
        let mut types: Vec<_> = self.fields.keys().collect();
        types.sort_by_key(|t| **t as u8);
        
        for field_type in types {
            let data = &self.fields[field_type];
            let field = TlvField::new(*field_type, data.clone());
            buffer.extend_from_slice(&field.serialize());
        }
        
        buffer
    }
    
    /// Deserialize TLV fields from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        let mut collection = TlvCollection::new();
        let mut offset = 0;
        
        while offset < data.len() {
            let (field, new_offset) = TlvField::deserialize(data, offset)?;
            collection.add_field(field.field_type, field.data);
            offset = new_offset;
        }
        
        Ok(collection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tlv_field_roundtrip() {
        let original_data = b"test_filename.txt".to_vec();
        let field = TlvField::new(TlvFieldType::OriginalFilename, original_data.clone());
        
        let serialized = field.serialize();
        let (deserialized, _) = TlvField::deserialize(&serialized, 0).unwrap();
        
        assert_eq!(deserialized.field_type, TlvFieldType::OriginalFilename);
        assert_eq!(deserialized.data, original_data);
    }
    
    #[test]
    fn test_tlv_collection_roundtrip() {
        let mut collection = TlvCollection::new();
        collection.add_field(TlvFieldType::OriginalFilename, b"test.txt".to_vec());
        collection.add_field(TlvFieldType::DirectoryPath, b"/home/user".to_vec());
        
        let serialized = collection.serialize();
        let deserialized = TlvCollection::deserialize(&serialized).unwrap();
        
        assert_eq!(
            deserialized.get_field(TlvFieldType::OriginalFilename).unwrap(),
            b"test.txt"
        );
        assert_eq!(
            deserialized.get_field(TlvFieldType::DirectoryPath).unwrap(),
            b"/home/user"
        );
    }
    
    #[test]
    fn test_extensibility() {
        // Test unknown field type handling
        let unknown_type = 0x42;
        let data = [unknown_type, 4, 0, 0, 0, b't', b'e', b's', b't'];
        
        let (field, _) = TlvField::deserialize(&data, 0).unwrap();
        assert_eq!(field.field_type, TlvFieldType::ExtensionMarker);
        assert_eq!(field.data, b"test");
    }
}