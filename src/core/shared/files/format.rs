//! TLV header format - migrated from domain/shared.

use std::collections::HashMap;

// ============================================================================
// FIELD TYPES
// ============================================================================

/// TLV field types for header metadata.
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
    /// Get expected field size for fixed-size fields.
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

// ============================================================================
// TLV HEADER
// ============================================================================

/// TLV header containing file metadata.
#[derive(Debug, Clone)]
pub struct TlvHeader {
    fields: HashMap<TlvFieldType, Vec<u8>>,
    version: u16,
}

impl TlvHeader {
    /// Create a new empty header.
    pub fn new(version: u16) -> Self {
        Self {
            fields: HashMap::new(),
            version,
        }
    }
    
    /// Get a field value by type.
    pub fn get_field(&self, field_type: TlvFieldType) -> Option<&[u8]> {
        self.fields.get(&field_type).map(|v| v.as_slice())
    }
    
    /// Set a field value.
    pub fn set_field(&mut self, field_type: TlvFieldType, data: Vec<u8>) {
        self.fields.insert(field_type, data);
    }
    
    /// Get the header version.
    pub fn version(&self) -> u16 {
        self.version
    }
    
    /// Get algorithm ID from header.
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
    
    /// Get original filename from header.
    pub fn original_filename(&self) -> Option<&str> {
        self.get_field(TlvFieldType::OriginalFilename)
            .and_then(|data| std::str::from_utf8(data).ok())
    }
    
    /// Calculate serialized size.
    pub fn serialized_size(&self) -> usize {
        // Header version (2 bytes) + field count (2 bytes)
        let mut size = 4;
        
        // Add size of each field (type + length + data)
        for (_, data) in &self.fields {
            size += 1 + 2 + data.len(); // type (1) + length (2) + data
        }
        
        size
    }
}

// ============================================================================
// BUILDER
// ============================================================================

/// Builder for constructing TLV headers.
pub struct TlvHeaderBuilder {
    header: TlvHeader,
}

impl TlvHeaderBuilder {
    /// Create a new builder with the specified version.
    pub fn new(version: u16) -> Self {
        Self {
            header: TlvHeader::new(version),
        }
    }
    
    /// Set the original filename.
    pub fn with_filename(mut self, filename: &str) -> Self {
        self.header.set_field(TlvFieldType::OriginalFilename, filename.as_bytes().to_vec());
        self
    }
    
    /// Set the algorithm ID.
    pub fn with_algorithm_id(mut self, algorithm_id: u16) -> Self {
        self.header.set_field(TlvFieldType::AlgorithmId, algorithm_id.to_le_bytes().to_vec());
        self
    }
    
    /// Set the nonce.
    pub fn with_nonce(mut self, nonce: &[u8]) -> Self {
        self.header.set_field(TlvFieldType::Nonce, nonce.to_vec());
        self
    }
    
    /// Set the content hash.
    pub fn with_content_hash(mut self, hash: &[u8; 32]) -> Self {
        self.header.set_field(TlvFieldType::ContentHash, hash.to_vec());
        self
    }
    
    /// Build the final header.
    pub fn build(self) -> TlvHeader {
        self.header
    }
}