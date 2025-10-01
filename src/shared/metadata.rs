//! File metadata handling and serialization
//! 
//! This module handles file metadata structures and their serialization/deserialization
//! for secure storage within encrypted file headers.

use crate::shared::errors::CryptoError;
use std::collections::HashMap;
use std::time::SystemTime;

/// Compression types supported by the file format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionType {
    None = 0x00,
    Zstd = 0x01,        // Zstandard compression
    Lz4 = 0x02,         // LZ4 fast compression
    Brotli = 0x03,      // Brotli compression
}

impl From<u8> for CompressionType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => CompressionType::Zstd,
            0x02 => CompressionType::Lz4,
            0x03 => CompressionType::Brotli,
            _ => CompressionType::None,
        }
    }
}

/// File metadata structure for serialization
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub permissions: u32,                                    // File permissions
    pub created: SystemTime,                                 // Creation timestamp
    pub modified: SystemTime,                                // Modification timestamp
    pub accessed: SystemTime,                                // Access timestamp
    pub file_hash: [u8; 32],                                // SHA-256 of original content
    pub compression: Option<CompressionType>,                // Optional compression
    pub created_by: String,                                  // Software version
    pub custom_attributes: HashMap<String, Vec<u8>>,         // Extensible attributes
}

impl Default for FileMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl FileMetadata {
    /// Create new metadata from file system attributes
    pub fn new() -> Self {
        let now = SystemTime::now();
        Self {
            permissions: 0o644,  // Default permissions
            created: now,
            modified: now,
            accessed: now,
            file_hash: [0u8; 32],  // Will be filled during encryption
            compression: None,
            created_by: format!("shadow-v{}", env!("CARGO_PKG_VERSION")),
            custom_attributes: HashMap::new(),
        }
    }

    /// Serialize metadata to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        // Permissions (4 bytes)
        buffer.extend_from_slice(&self.permissions.to_le_bytes());
        
        // Timestamps (24 bytes total - 8 bytes each)
        let created_secs = self.created.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        let modified_secs = self.modified.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        let accessed_secs = self.accessed.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        
        buffer.extend_from_slice(&created_secs.to_le_bytes());
        buffer.extend_from_slice(&modified_secs.to_le_bytes());
        buffer.extend_from_slice(&accessed_secs.to_le_bytes());
        
        // File hash (32 bytes)
        buffer.extend_from_slice(&self.file_hash);
        
        // Compression type (1 byte)
        let compression_byte = match self.compression {
            Some(comp) => comp as u8,
            None => CompressionType::None as u8,
        };
        buffer.push(compression_byte);
        
        // Created by string (length + data)
        let created_by_bytes = self.created_by.as_bytes();
        buffer.extend_from_slice(&(created_by_bytes.len() as u16).to_le_bytes());
        buffer.extend_from_slice(created_by_bytes);
        
        // Custom attributes (count + entries)
        buffer.extend_from_slice(&(self.custom_attributes.len() as u16).to_le_bytes());
        for (key, value) in &self.custom_attributes {
            let key_bytes = key.as_bytes();
            buffer.extend_from_slice(&(key_bytes.len() as u16).to_le_bytes());
            buffer.extend_from_slice(key_bytes);
            buffer.extend_from_slice(&(value.len() as u16).to_le_bytes());
            buffer.extend_from_slice(value);
        }
        
        buffer
    }
    
    /// Deserialize metadata from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 65 {  // Minimum size: 4+24+32+1+2+2 = 65 bytes
            return Err(CryptoError::HeaderParsingError("Insufficient metadata data".to_string()));
        }
        
        let mut offset = 0;
        
        // Parse permissions
        let permissions = u32::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3]
        ]);
        offset += 4;
        
        // Parse timestamps
        let created_secs = u64::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7]
        ]);
        offset += 8;
        
        let modified_secs = u64::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7]
        ]);
        offset += 8;
        
        let accessed_secs = u64::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7]
        ]);
        offset += 8;
        
        let created = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_secs);
        let modified = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(modified_secs);
        let accessed = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(accessed_secs);
        
        // Parse file hash
        let mut file_hash = [0u8; 32];
        file_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        // Parse compression type
        let compression = match data[offset] {
            0x00 => None,
            comp_byte => Some(CompressionType::from(comp_byte)),
        };
        offset += 1;
        
        // Parse created_by string
        if offset + 2 > data.len() {
            return Err(CryptoError::HeaderParsingError("Missing created_by length".to_string()));
        }
        let created_by_len = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
        offset += 2;
        
        if offset + created_by_len > data.len() {
            return Err(CryptoError::HeaderParsingError("Invalid created_by length".to_string()));
        }
        let created_by = String::from_utf8(data[offset..offset + created_by_len].to_vec())
            .map_err(|_| CryptoError::HeaderParsingError("Invalid UTF-8 in created_by".to_string()))?;
        offset += created_by_len;
        
        // Parse custom attributes
        if offset + 2 > data.len() {
            return Err(CryptoError::HeaderParsingError("Missing attributes count".to_string()));
        }
        let attr_count = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
        offset += 2;
        
        let mut custom_attributes = HashMap::new();
        for _ in 0..attr_count {
            // Parse key
            if offset + 2 > data.len() {
                return Err(CryptoError::HeaderParsingError("Missing attribute key length".to_string()));
            }
            let key_len = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
            offset += 2;
            
            if offset + key_len > data.len() {
                return Err(CryptoError::HeaderParsingError("Invalid attribute key length".to_string()));
            }
            let key = String::from_utf8(data[offset..offset + key_len].to_vec())
                .map_err(|_| CryptoError::HeaderParsingError("Invalid UTF-8 in attribute key".to_string()))?;
            offset += key_len;
            
            // Parse value
            if offset + 2 > data.len() {
                return Err(CryptoError::HeaderParsingError("Missing attribute value length".to_string()));
            }
            let value_len = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
            offset += 2;
            
            if offset + value_len > data.len() {
                return Err(CryptoError::HeaderParsingError("Invalid attribute value length".to_string()));
            }
            let value = data[offset..offset + value_len].to_vec();
            offset += value_len;
            
            custom_attributes.insert(key, value);
        }
        
        Ok(Self {
            permissions,
            created,
            modified,
            accessed,
            file_hash,
            compression,
            created_by,
            custom_attributes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_serialize_deserialize() {
        let mut metadata = FileMetadata::new();
        metadata.permissions = 0o755;
        metadata.file_hash = [42u8; 32];
        metadata.compression = Some(CompressionType::Zstd);
        metadata.custom_attributes.insert("test_key".to_string(), vec![1, 2, 3]);

        let serialized = metadata.serialize();
        let deserialized = FileMetadata::deserialize(&serialized).unwrap();

        assert_eq!(metadata.permissions, deserialized.permissions);
        assert_eq!(metadata.file_hash, deserialized.file_hash);
        assert_eq!(metadata.compression, deserialized.compression);
        assert_eq!(metadata.custom_attributes, deserialized.custom_attributes);
    }

    #[test]
    fn test_compression_type_conversion() {
        assert_eq!(CompressionType::from(0x00), CompressionType::None);
        assert_eq!(CompressionType::from(0x01), CompressionType::Zstd);
        assert_eq!(CompressionType::from(0x02), CompressionType::Lz4);
        assert_eq!(CompressionType::from(0x03), CompressionType::Brotli);
        assert_eq!(CompressionType::from(0xFF), CompressionType::None); // Unknown defaults to None
    }
}