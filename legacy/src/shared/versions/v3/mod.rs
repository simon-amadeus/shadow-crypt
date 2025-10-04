//! Shadow file format Version 3 implementation
//! 
//! Version 3 represents a complete redesign with:
//! - TLV (Type-Length-Value) extensible fields
//! - Algorithm-agnostic design supporting all AlgorithmId variants
//! - Variable-length nonces for different algorithms
//! - Single authenticated header (no nested auth tags)
//! - Future-proof extensibility mechanism

use crate::shared::errors::CryptoError;
use crate::shared::algorithms::AlgorithmId;
use crate::shared::versioning::VersionedHeader;
use std::collections::HashMap;

pub const MAGIC_NUMBER_V3: &[u8; 6] = b"SHADOW";
pub const VERSION_V3: u16 = 3;
const MAX_HEADER_SIZE: u32 = 65536; // 64KB max header size
const MAX_NONCE_SIZE: u8 = 32; // Support up to 32-byte nonces

/// TLV field types for V3 extensible format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TlvFieldType {
    /// Original filename (encrypted)
    OriginalFilename = 0x01,
    /// Directory path (encrypted) 
    DirectoryPath = 0x02,
    /// File metadata (encrypted)
    FileMetadata = 0x03,
    /// Compression settings
    CompressionSettings = 0x04,
    /// Key derivation parameters
    KeyDerivationParams = 0x05,
    /// Custom user attributes
    CustomAttributes = 0x06,
    /// Content hash for integrity verification
    ContentHash = 0x07,
    /// Creation software info
    CreatedBy = 0x08,
    /// Extension marker for unknown types
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
            0x08 => TlvFieldType::CreatedBy,
            _ => TlvFieldType::ExtensionMarker,
        }
    }
}

/// Individual TLV field
#[derive(Debug, Clone)]
pub struct TlvField {
    pub field_type: TlvFieldType,
    pub data: Vec<u8>,
}

impl TlvField {
    pub fn new(field_type: TlvFieldType, data: Vec<u8>) -> Self {
        Self { field_type, data }
    }
    
    /// Serialize TLV field: [Type(1)][Length(4)][Value(Length)]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.field_type as u8);
        buffer.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&self.data);
        buffer
    }
    
    /// Deserialize TLV field from bytes
    pub fn deserialize(data: &[u8], offset: usize) -> Result<(Self, usize), CryptoError> {
        if offset + 5 > data.len() {
            return Err(CryptoError::HeaderParsingError(
                "Insufficient data for TLV header".to_string()
            ));
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
            return Err(CryptoError::HeaderParsingError(
                format!("Insufficient data for TLV value: need {} bytes, have {}", 
                    value_end - offset, data.len() - offset)
            ));
        }
        
        let field_data = data[value_start..value_end].to_vec();
        let field = TlvField::new(field_type, field_data);
        
        Ok((field, value_end))
    }
}

/// Collection of TLV fields with helper methods
#[derive(Debug, Clone)]
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
    
    pub fn has_field(&self, field_type: TlvFieldType) -> bool {
        self.fields.contains_key(&field_type)
    }
    
    pub fn remove_field(&mut self, field_type: TlvFieldType) -> Option<Vec<u8>> {
        self.fields.remove(&field_type)
    }
    
    /// Serialize all TLV fields in deterministic order
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
    pub fn deserialize(data: &[u8]) -> Result<Self, CryptoError> {
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

/// Shadow file format Version 3 header
#[derive(Debug, Clone)]
pub struct HeaderV3 {
    pub magic: [u8; 6],              // "SHADOW"
    pub version: u16,                // Always 3 for this type
    pub algorithm_id: AlgorithmId,   // Cryptographic algorithm identifier
    pub header_length: u32,          // Total header size for validation
    pub nonce_length: u8,            // Variable nonce length (algorithm-specific)
    pub nonce: Vec<u8>,              // Variable-length nonce
    pub salt: [u8; 32],              // 32-byte salt (future-proof)
    pub tlv_fields: TlvCollection,   // Extensible TLV fields
    pub header_auth_tag: [u8; 16],   // Single auth tag for entire header
}

impl HeaderV3 {
    /// Create a new V3 header
    pub fn new(algorithm_id: AlgorithmId, nonce: Vec<u8>, salt: [u8; 32]) -> Self {
        if nonce.len() > MAX_NONCE_SIZE as usize {
            panic!("Nonce length {} exceeds maximum {}", nonce.len(), MAX_NONCE_SIZE);
        }
        
        let mut header = Self {
            magic: *MAGIC_NUMBER_V3,
            version: VERSION_V3,
            algorithm_id,
            header_length: 0, // Will be calculated below
            nonce_length: nonce.len() as u8,
            nonce,
            salt,
            tlv_fields: TlvCollection::new(),
            header_auth_tag: [0u8; 16], // Will be computed during encryption
        };
        
        // Calculate and set the correct header length
        header.header_length = header.calculate_header_size();
        header
    }
    
    /// Add a TLV field to the header
    pub fn add_tlv_field(&mut self, field_type: TlvFieldType, data: Vec<u8>) {
        self.tlv_fields.add_field(field_type, data);
        // Recalculate header length after adding TLV field
        self.header_length = self.calculate_header_size();
    }
    
    /// Get a TLV field from the header
    pub fn get_tlv_field(&self, field_type: TlvFieldType) -> Option<&Vec<u8>> {
        self.tlv_fields.get_field(field_type)
    }
    
    /// Calculate the total header size
    fn calculate_header_size(&self) -> u32 {
        let fixed_size = 6 + 2 + 2 + 4 + 1 + 32 + 16; // magic + version + algorithm + header_length + nonce_length + salt + auth_tag
        let nonce_size = self.nonce.len() as u32;
        let tlv_size = self.tlv_fields.serialize().len() as u32;
        
        fixed_size + nonce_size + tlv_size
    }
    
    /// Get the nonce based on algorithm requirements
    pub fn get_algorithm_nonce_size(algorithm_id: AlgorithmId) -> usize {
        match algorithm_id {
            AlgorithmId::AesGcm256 => 12,           // AES-GCM standard
            AlgorithmId::ChaCha20Poly1305 => 24,    // XChaCha20 extended nonce  
            AlgorithmId::AesGcmStreaming => 12,     // Same as AES-GCM
            _ => 12, // Default for post-quantum algorithms
        }
    }
}

impl VersionedHeader for HeaderV3 {
    const VERSION: u16 = VERSION_V3;
    
    fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        // Fixed header fields
        buffer.extend_from_slice(&self.magic);
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.extend_from_slice(&(self.algorithm_id as u16).to_le_bytes());
        
        // Calculate and include header length
        let header_length = self.calculate_header_size();
        buffer.extend_from_slice(&header_length.to_le_bytes());
        
        // Variable nonce
        buffer.push(self.nonce_length);
        buffer.extend_from_slice(&self.nonce);
        
        // Salt
        buffer.extend_from_slice(&self.salt);
        
        // TLV fields
        buffer.extend_from_slice(&self.tlv_fields.serialize());
        
        // Authentication tag (placeholder during serialization)
        buffer.extend_from_slice(&self.header_auth_tag);
        
        buffer
    }
    
    fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError> {
        let mut offset = 0;
        
        // Minimum header size check
        if data.len() < 63 { // 6+2+2+4+1+0+32+16 minimum
            return Err(CryptoError::HeaderParsingError(
                format!("Insufficient data: expected at least 63 bytes, got {}", data.len())
            ));
        }
        
        // Parse magic
        if offset + 6 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read magic number".to_string()));
        }
        let magic = [data[offset], data[offset + 1], data[offset + 2], 
                    data[offset + 3], data[offset + 4], data[offset + 5]];
        offset += 6;
        
        // Validate magic
        if magic != *MAGIC_NUMBER_V3 {
            return Err(CryptoError::HeaderParsingError(
                format!("Invalid magic number: expected 'SHADOW', got {:?}", 
                    String::from_utf8_lossy(&magic))
            ));
        }
        
        // Parse version
        if offset + 2 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read version".to_string()));
        }
        let version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        // Validate version
        if version != Self::VERSION {
            return Err(CryptoError::HeaderParsingError(
                format!("Version mismatch: expected {}, got {}", Self::VERSION, version)
            ));
        }
        
        // Parse algorithm ID
        if offset + 2 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read algorithm ID".to_string()));
        }
        let algorithm_id = AlgorithmId::from(u16::from_le_bytes([data[offset], data[offset + 1]]));
        offset += 2;
        
        // Parse header length
        if offset + 4 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read header length".to_string()));
        }
        let header_length = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;
        
        // Validate header length
        if header_length > MAX_HEADER_SIZE {
            return Err(CryptoError::HeaderParsingError(
                format!("Header length {} exceeds maximum {}", header_length, MAX_HEADER_SIZE)
            ));
        }
        
        if (header_length as usize) > data.len() {
            return Err(CryptoError::HeaderParsingError(
                format!("Header length {} exceeds available data {}", header_length, data.len())
            ));
        }
        
        // Parse nonce length
        if offset + 1 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read nonce length".to_string()));
        }
        let nonce_length = data[offset];
        offset += 1;
        
        // Validate nonce length
        if nonce_length > MAX_NONCE_SIZE {
            return Err(CryptoError::HeaderParsingError(
                format!("Nonce length {} exceeds maximum {}", nonce_length, MAX_NONCE_SIZE)
            ));
        }
        
        // Parse nonce
        if offset + nonce_length as usize > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read nonce".to_string()));
        }
        let nonce = data[offset..offset + nonce_length as usize].to_vec();
        offset += nonce_length as usize;
        
        // Parse salt
        if offset + 32 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read salt".to_string()));
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        // Calculate TLV fields size (everything except auth tag)
        let auth_tag_start = header_length as usize - 16;
        if offset > auth_tag_start {
            return Err(CryptoError::HeaderParsingError("Invalid header structure".to_string()));
        }
        
        // Parse TLV fields
        let tlv_data = &data[offset..auth_tag_start];
        let tlv_fields = TlvCollection::deserialize(tlv_data)?;
        offset = auth_tag_start;
        
        // Parse authentication tag
        if offset + 16 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read authentication tag".to_string()));
        }
        let mut header_auth_tag = [0u8; 16];
        header_auth_tag.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        
        let header = HeaderV3 {
            magic,
            version,
            algorithm_id,
            header_length,
            nonce_length,
            nonce,
            salt,
            tlv_fields,
            header_auth_tag,
        };
        
        Ok((header, offset))
    }
    
    fn validate(&self) -> Result<(), CryptoError> {
        // Validate magic
        if self.magic != *MAGIC_NUMBER_V3 {
            return Err(CryptoError::HeaderParsingError(
                format!("Invalid magic number: expected 'SHADOW', got {:?}", 
                    String::from_utf8_lossy(&self.magic))
            ));
        }
        
        // Validate version
        if self.version != Self::VERSION {
            return Err(CryptoError::HeaderParsingError(
                format!("Invalid version: expected {}, got {}", Self::VERSION, self.version)
            ));
        }
        
        // Validate nonce length
        if self.nonce_length > MAX_NONCE_SIZE {
            return Err(CryptoError::HeaderParsingError(
                format!("Nonce length {} exceeds maximum {}", self.nonce_length, MAX_NONCE_SIZE)
            ));
        }
        
        if self.nonce.len() != self.nonce_length as usize {
            return Err(CryptoError::HeaderParsingError(
                format!("Nonce length mismatch: declared {}, actual {}", 
                    self.nonce_length, self.nonce.len())
            ));
        }
        
        // Validate header length
        let calculated_length = self.calculate_header_size();
        if self.header_length != calculated_length {
            return Err(CryptoError::HeaderParsingError(
                format!("Header length mismatch: declared {}, calculated {}", 
                    self.header_length, calculated_length)
            ));
        }
        
        Ok(())
    }
    
    fn magic() -> &'static [u8] {
        MAGIC_NUMBER_V3
    }
    
    fn can_migrate_to(target_version: u16) -> bool {
        // V3 can migrate to future versions 4, 5, etc.
        target_version > Self::VERSION && target_version <= 10
    }
    
    fn can_migrate_from(source_version: u16) -> bool {
        // V3 can be migrated from V1 and V2
        source_version == 1 || source_version == 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_header_v3_creation() {
        let nonce = vec![0u8; 12]; // AES-GCM nonce
        let salt = [1u8; 32];
        let header = HeaderV3::new(AlgorithmId::AesGcm256, nonce, salt);
        
        assert_eq!(header.version, VERSION_V3);
        assert_eq!(header.algorithm_id, AlgorithmId::AesGcm256);
        assert_eq!(header.nonce_length, 12);
        assert_eq!(header.nonce.len(), 12);
    }
    
    #[test]
    fn test_header_v3_with_tlv_fields() {
        let nonce = vec![0u8; 24]; // XChaCha20 nonce
        let salt = [2u8; 32];
        let mut header = HeaderV3::new(AlgorithmId::ChaCha20Poly1305, nonce, salt);
        
        // Add TLV fields
        header.add_tlv_field(TlvFieldType::OriginalFilename, b"test.txt".to_vec());
        header.add_tlv_field(TlvFieldType::DirectoryPath, b"/home/user".to_vec());
        
        assert!(header.tlv_fields.has_field(TlvFieldType::OriginalFilename));
        assert!(header.tlv_fields.has_field(TlvFieldType::DirectoryPath));
        assert_eq!(header.get_tlv_field(TlvFieldType::OriginalFilename).unwrap(), b"test.txt");
    }
    
    #[test]
    fn test_header_v3_roundtrip() {
        let nonce = vec![0u8; 12];
        let salt = [3u8; 32];
        let mut header = HeaderV3::new(AlgorithmId::AesGcm256, nonce, salt);
        
        header.add_tlv_field(TlvFieldType::OriginalFilename, b"document.pdf".to_vec());
        header.add_tlv_field(TlvFieldType::ContentHash, vec![0xAB; 32]);
        
        let serialized = header.serialize();
        let (deserialized, offset) = HeaderV3::deserialize(&serialized).unwrap();
        
        assert_eq!(deserialized.version, VERSION_V3);
        assert_eq!(deserialized.algorithm_id, AlgorithmId::AesGcm256);
        assert_eq!(deserialized.nonce, header.nonce);
        assert_eq!(deserialized.salt, header.salt);
        assert_eq!(deserialized.get_tlv_field(TlvFieldType::OriginalFilename).unwrap(), b"document.pdf");
        assert_eq!(offset, serialized.len());
    }
    
    #[test]
    fn test_algorithm_nonce_sizes() {
        assert_eq!(HeaderV3::get_algorithm_nonce_size(AlgorithmId::AesGcm256), 12);
        assert_eq!(HeaderV3::get_algorithm_nonce_size(AlgorithmId::ChaCha20Poly1305), 24);
        assert_eq!(HeaderV3::get_algorithm_nonce_size(AlgorithmId::AesGcmStreaming), 12);
    }
    
    #[test]
    fn test_header_validation() {
        let nonce = vec![0u8; 12];
        let salt = [4u8; 32];
        let header = HeaderV3::new(AlgorithmId::AesGcm256, nonce, salt);
        
        assert!(header.validate().is_ok());
    }
    
    #[test]
    fn test_migration_capabilities() {
        assert!(HeaderV3::can_migrate_from(1));
        assert!(HeaderV3::can_migrate_from(2));
        assert!(!HeaderV3::can_migrate_from(3)); // Can't migrate from self
        assert!(!HeaderV3::can_migrate_from(4)); // Can't migrate from future versions
        
        assert!(HeaderV3::can_migrate_to(4));
        assert!(HeaderV3::can_migrate_to(5));
        assert!(!HeaderV3::can_migrate_to(3)); // Can't migrate to self
        assert!(!HeaderV3::can_migrate_to(1)); // Can't migrate to past versions
    }
    
    #[test]
    fn test_v3_algorithm_agnostic_design() {
        // Test V3 with different algorithms
        let algorithms = [
            (AlgorithmId::AesGcm256, 12),
            (AlgorithmId::ChaCha20Poly1305, 24),
            (AlgorithmId::KyberAes256, 12),  // Future post-quantum
            (AlgorithmId::AesGcmStreaming, 12), // Streaming variant
        ];
        
        for (algorithm, nonce_len) in algorithms {
            let nonce = vec![0xAA; nonce_len];
            let salt = [0xBB; 32];
            let mut header = HeaderV3::new(algorithm, nonce.clone(), salt);
            
            // Add some TLV fields
            header.add_tlv_field(TlvFieldType::OriginalFilename, b"test.txt".to_vec());
            header.add_tlv_field(TlvFieldType::CreatedBy, b"shadow-crypt v0.33.0".to_vec());
            
            // Test roundtrip
            let serialized = header.serialize();
            let (deserialized, _) = HeaderV3::deserialize(&serialized).unwrap();
            
            assert_eq!(deserialized.algorithm_id, algorithm);
            assert_eq!(deserialized.nonce, nonce);
            assert_eq!(deserialized.salt, salt);
            assert!(deserialized.validate().is_ok());
            
            // Check TLV fields survived roundtrip
            assert_eq!(
                deserialized.get_tlv_field(TlvFieldType::OriginalFilename).unwrap(),
                b"test.txt"
            );
            assert_eq!(
                deserialized.get_tlv_field(TlvFieldType::CreatedBy).unwrap(),
                b"shadow-crypt v0.33.0"
            );
        }
    }
    
    #[test]
    fn test_v3_extensibility_future_fields() {
        let nonce = vec![0xCC; 12];
        let salt = [0xDD; 32];
        let mut header = HeaderV3::new(AlgorithmId::AesGcm256, nonce, salt);
        
        // Add various field types including future extensions
        header.add_tlv_field(TlvFieldType::OriginalFilename, b"document.pdf".to_vec());
        header.add_tlv_field(TlvFieldType::ContentHash, vec![0x1A; 32]);
        header.add_tlv_field(TlvFieldType::CompressionSettings, vec![0x01, 0x05]); // Compression type + level
        header.add_tlv_field(TlvFieldType::ExtensionMarker, b"future_data".to_vec());
        
        // Validate extensibility
        assert_eq!(header.tlv_fields.serialize().len() > 50, true); // Has significant TLV data
        
        // Test roundtrip preserves all fields
        let serialized = header.serialize();
        let (deserialized, _) = HeaderV3::deserialize(&serialized).unwrap();
        
        assert!(deserialized.tlv_fields.has_field(TlvFieldType::OriginalFilename));
        assert!(deserialized.tlv_fields.has_field(TlvFieldType::ContentHash));
        assert!(deserialized.tlv_fields.has_field(TlvFieldType::CompressionSettings));
        assert!(deserialized.tlv_fields.has_field(TlvFieldType::ExtensionMarker));
        
        assert_eq!(
            deserialized.get_tlv_field(TlvFieldType::ExtensionMarker).unwrap(),
            b"future_data"
        );
    }
}