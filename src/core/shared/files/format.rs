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

    /// Create a new empty header.
    pub fn new(version: u16) -> Self {
        Self {
            fields: HashMap::new(),
            magic_number: Self::MAGIC_NUMBER,
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

    /// Get the magic number.
    pub fn magic_number(&self) -> &[u8; 6] {
        &self.magic_number
    }

    /// Check if this header has the correct magic number.
    pub fn has_valid_magic(&self) -> bool {
        self.magic_number == Self::MAGIC_NUMBER
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
    /// This must stay in sync with the to_bytes() method.
    pub fn serialized_size(&self) -> usize {
        self.calculate_size()
    }

    /// Fast size estimation without full serialization (for performance-critical paths).
    /// Note: This is an estimate and may not be exact. Use serialized_size() for accuracy.
    pub fn estimated_size(&self) -> usize {
        self.calculate_size()
    }

    /// Internal method to calculate header size.
    /// Both serialized_size() and estimated_size() use this to ensure consistency.
    fn calculate_size(&self) -> usize {
        // Magic (6) + header length (4) + version (2) + field count (2)
        let mut size = 14;
        
        // Add size of each field (type + length + data)
        for (_, data) in &self.fields {
            size += 1 + 4 + data.len(); // type (1) + length (4) + data
        }
        
        size
    }

    /// Validate header integrity.
    pub fn validate(&self) -> Result<(), String> {
        if !self.has_valid_magic() {
            return Err("Invalid magic number".to_string());
        }
        
        if self.fields.len() > Self::MAX_FIELD_COUNT {
            return Err(format!("Too many fields: {} > {}", self.fields.len(), Self::MAX_FIELD_COUNT));
        }
        
        if self.serialized_size() > Self::MAX_HEADER_SIZE {
            return Err(format!("Header too large: {} > {}", self.serialized_size(), Self::MAX_HEADER_SIZE));
        }
        
        Ok(())
    }

    /// Validate that all required cryptographic fields are present.
    pub fn validate_for_encryption(&self) -> Result<(), String> {
        self.validate()?;
        
        if self.algorithm_id().is_none() {
            return Err("Missing required field: AlgorithmId".to_string());
        }
        
        Ok(())
    }

    /// Serialize header to bytes.
    /// IMPORTANT: Keep this method in sync with calculate_size() method.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        
        let mut buffer = Vec::with_capacity(self.serialized_size());
        
        // Write magic number (6 bytes)
        buffer.extend_from_slice(&self.magic_number);
        
        // Calculate and write header length (4 bytes) - excluding magic number and length field itself
        let header_content_size = self.serialized_size() - 6 - 4;
        buffer.extend_from_slice(&(header_content_size as u32).to_le_bytes());
        
        // Write version (2 bytes)
        buffer.extend_from_slice(&self.version.to_le_bytes());
        
        // Write field count (2 bytes)
        buffer.extend_from_slice(&(self.fields.len() as u16).to_le_bytes());
        
        // Sort fields by type for deterministic output
        let mut sorted_fields: Vec<_> = self.fields.iter().collect();
        sorted_fields.sort_by_key(|(field_type, _)| **field_type);
        
        // Write each field as Type(1) + Length(4) + Value(n)
        for (field_type, data) in sorted_fields {
            if data.len() > Self::MAX_FIELD_SIZE as usize {
                return Err(format!("Field too large: {} > {}", data.len(), Self::MAX_FIELD_SIZE));
            }
            
            buffer.push(*field_type as u8);
            buffer.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buffer.extend_from_slice(data);
        }
        
        Ok(buffer)
    }

    /// Parse a header from bytes (for reading encrypted files).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 14 {
            return Err("Header too short".to_string());
        }

        // Parse magic number
        let magic_number: [u8; 6] = bytes[0..6].try_into().unwrap();
        if magic_number != Self::MAGIC_NUMBER {
            return Err("Invalid magic number".to_string());
        }

        // Parse header length
        let header_length = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
        if bytes.len() < 10 + header_length {
            return Err("Incomplete header".to_string());
        }

        // Parse version
        let version = u16::from_le_bytes([bytes[10], bytes[11]]);

        // Parse field count
        let field_count = u16::from_le_bytes([bytes[12], bytes[13]]);

        // Parse TLV fields
        let mut fields = HashMap::new();
        let mut offset = 14;

        for _ in 0..field_count {
            if offset + 5 > bytes.len() {
                return Err("Incomplete field header".to_string());
            }

            let field_type = TlvFieldType::from(bytes[offset]);
            offset += 1;

            let field_length = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + field_length > bytes.len() {
                return Err("Incomplete field data".to_string());
            }

            let field_data = bytes[offset..offset + field_length].to_vec();
            offset += field_length;

            fields.insert(field_type, field_data);
        }

        Ok(Self {
            fields,
            magic_number,
            version,
        })
    }

    /// Check if a file has Shadow magic bytes.
    pub fn has_shadow_magic_bytes(path: &std::path::Path) -> bool {
        use std::io::Read;

        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };

        let mut magic_buffer = [0u8; 6];
        match file.read_exact(&mut magic_buffer) {
            Ok(()) => magic_buffer == Self::MAGIC_NUMBER,
            Err(_) => false,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialized_size_matches_actual_bytes() {
        let header = TlvHeaderBuilder::new(1)
            .with_filename("test.txt")
            .with_algorithm_id(1)
            .with_nonce(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
            .with_content_hash(&[0u8; 32])
            .build();

        let bytes = header.to_bytes().expect("Serialization should succeed");
        let calculated_size = header.serialized_size();
        
        assert_eq!(bytes.len(), calculated_size, 
            "Serialized size calculation must match actual serialized bytes length");
    }

    #[test]
    fn test_magic_number_validation() {
        let header = TlvHeader::new(1);
        assert!(header.has_valid_magic());
        
        let mut invalid_header = TlvHeader::new(1);
        invalid_header.magic_number = *b"BADMAG";
        assert!(!invalid_header.has_valid_magic());
    }
}