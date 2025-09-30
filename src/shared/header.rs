//! File header format and serialization
//! 
//! This module implements the encrypted file header format as specified in the design:
//! - Magic number and version identification
//! - Algorithm identifiers for cryptographic agility
//! - Encrypted metadata with authentication tags
//! - Serialization/deserialization with proper padding

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

/// Algorithm identifiers for cryptographic agility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AlgorithmId {
    AesGcm256 = 0x0001,
    ChaCha20Poly1305 = 0x0002,  // Future algorithm
    
    // Post-quantum cryptography (reserved range 0x1000-0x1FFF)
    KyberAes256 = 0x1001,       // Future: CRYSTALS-Kyber + AES-256-GCM
    KyberChaCha20 = 0x1002,     // Future: CRYSTALS-Kyber + ChaCha20-Poly1305
    DilithiumAes256 = 0x1003,   // Future: CRYSTALS-Dilithium + AES-256-GCM
    
    // Streaming algorithms (reserved range 0x2000-0x2FFF)
    AesGcmStreaming = 0x2001,   // Future: Chunked AES-GCM for large files
}

impl From<u16> for AlgorithmId {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => AlgorithmId::AesGcm256,
            0x0002 => AlgorithmId::ChaCha20Poly1305,
            0x1001 => AlgorithmId::KyberAes256,
            0x1002 => AlgorithmId::KyberChaCha20,
            0x1003 => AlgorithmId::DilithiumAes256,
            0x2001 => AlgorithmId::AesGcmStreaming,
            _ => AlgorithmId::AesGcm256, // Default fallback
        }
    }
}

/// Padding constants to prevent information leakage
pub const MAX_FILENAME_LENGTH: usize = 512;     // Pad all filenames to this size
pub const MAX_DIRECTORY_PATH_LENGTH: usize = 2048;  // Pad all paths to this size  
pub const MAX_METADATA_LENGTH: usize = 256;     // Pad all metadata to this size

/// File header structure with all encrypted components
#[derive(Debug)]
pub struct Header {
    pub magic: [u8; 6],              // "SHADOW"
    pub version: u16,                // Version 3
    pub algorithm_id: AlgorithmId,   // Cryptographic algorithm identifier
    pub salt: [u8; 16],              // Unique per file
    pub nonce: [u8; 12],             // GCM nonce (96-bit)
    pub directory_path_length: u16,  // Padded length of encrypted directory path
    pub encrypted_directory_path: Vec<u8>,  // Original directory structure (padded)
    pub directory_path_auth_tag: [u8; 16],  // GCM authentication tag
    pub filename_length: u16,        // Padded length of encrypted filename
    pub encrypted_filename: Vec<u8>, // Original filename (encrypted and padded)
    pub filename_auth_tag: [u8; 16], // GCM authentication tag
    pub metadata_length: u16,        // Padded length of encrypted metadata
    pub encrypted_metadata: Vec<u8>, // File permissions, timestamps (padded)
    pub metadata_auth_tag: [u8; 16], // GCM authentication tag
    // Followed by encrypted content and content authentication tag
}

impl Header {
    /// Create a new header with specified parameters
    pub fn new(
        algorithm_id: AlgorithmId,
        salt: [u8; 16],
        nonce: [u8; 12],
    ) -> Self {
        Self {
            magic: *b"SHADOW",
            version: 3,
            algorithm_id,
            salt,
            nonce,
            directory_path_length: 0,
            encrypted_directory_path: Vec::new(),
            directory_path_auth_tag: [0u8; 16],
            filename_length: 0,
            encrypted_filename: Vec::new(),
            filename_auth_tag: [0u8; 16],
            metadata_length: 0,
            encrypted_metadata: Vec::new(),
            metadata_auth_tag: [0u8; 16],
        }
    }

    /// Serialize header to bytes for writing to file
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        // Fixed-size fields
        buffer.extend_from_slice(&self.magic);
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.extend_from_slice(&(self.algorithm_id as u16).to_le_bytes());
        buffer.extend_from_slice(&self.salt);
        buffer.extend_from_slice(&self.nonce);
        
        // Directory path section
        buffer.extend_from_slice(&self.directory_path_length.to_le_bytes());
        buffer.extend_from_slice(&self.encrypted_directory_path);
        buffer.extend_from_slice(&self.directory_path_auth_tag);
        
        // Filename section
        buffer.extend_from_slice(&self.filename_length.to_le_bytes());
        buffer.extend_from_slice(&self.encrypted_filename);
        buffer.extend_from_slice(&self.filename_auth_tag);
        
        // Metadata section
        buffer.extend_from_slice(&self.metadata_length.to_le_bytes());
        buffer.extend_from_slice(&self.encrypted_metadata);
        buffer.extend_from_slice(&self.metadata_auth_tag);
        
        buffer
    }
    
    /// Deserialize header from bytes read from file
    pub fn deserialize(data: &[u8]) -> Result<(Header, usize), CryptoError> {
        const FIXED_HEADER_SIZE: usize = 40; // magic(6) + version(2) + algorithm(2) + salt(16) + nonce(12) + 2 length bytes
        
        if data.len() < FIXED_HEADER_SIZE {
            return Err(CryptoError::HeaderParsingError(
                format!("Insufficient data: expected at least {} bytes, got {}", FIXED_HEADER_SIZE, data.len())
            ));
        }
        
        let mut offset = 0;
        
        // Parse magic with bounds check
        if offset + 6 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read magic number".to_string()));
        }
        let magic = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5]];
        offset += 6;
        
        // Validate magic number early
        if magic != *b"SHADOW" {
            return Err(CryptoError::HeaderParsingError(
                format!("Invalid magic number: expected 'SHADOW', got {:?}", 
                    String::from_utf8_lossy(&magic))
            ));
        }
        
        // Parse version with bounds check
        if offset + 2 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read version".to_string()));
        }
        let version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        // Validate version
        if version > 3 {
            return Err(CryptoError::HeaderParsingError(
                format!("Unsupported version: {}", version)
            ));
        }
        
        // Parse algorithm ID with bounds check
        if offset + 2 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read algorithm ID".to_string()));
        }
        let algorithm_id = AlgorithmId::from(u16::from_le_bytes([data[offset], data[offset + 1]]));
        offset += 2;
        
        // Parse salt with bounds check
        if offset + 16 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read salt".to_string()));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        
        // Parse nonce with bounds check
        if offset + 12 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read nonce".to_string()));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[offset..offset + 12]);
        offset += 12;
        
        // Parse directory path section with comprehensive bounds checking
        if offset + 2 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read directory path length".to_string()));
        }
        let directory_path_length = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        // Validate directory path length
        if directory_path_length as usize > MAX_DIRECTORY_PATH_LENGTH {
            return Err(CryptoError::HeaderParsingError(
                format!("Directory path length {} exceeds maximum {}", 
                    directory_path_length, MAX_DIRECTORY_PATH_LENGTH)
            ));
        }
        
        if offset + directory_path_length as usize > data.len() {
            return Err(CryptoError::HeaderParsingError(
                format!("Cannot read directory path: need {} bytes, have {}", 
                    directory_path_length, data.len() - offset)
            ));
        }
        let encrypted_directory_path = data[offset..offset + directory_path_length as usize].to_vec();
        offset += directory_path_length as usize;
        
        if offset + 16 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read directory path auth tag".to_string()));
        }
        let mut directory_path_auth_tag = [0u8; 16];
        directory_path_auth_tag.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        
        // Parse filename section with comprehensive bounds checking
        if offset + 2 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read filename length".to_string()));
        }
        let filename_length = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        // Validate filename length
        if filename_length as usize > MAX_FILENAME_LENGTH {
            return Err(CryptoError::HeaderParsingError(
                format!("Filename length {} exceeds maximum {}", 
                    filename_length, MAX_FILENAME_LENGTH)
            ));
        }
        
        if offset + filename_length as usize > data.len() {
            return Err(CryptoError::HeaderParsingError(
                format!("Cannot read filename: need {} bytes, have {}", 
                    filename_length, data.len() - offset)
            ));
        }
        let encrypted_filename = data[offset..offset + filename_length as usize].to_vec();
        offset += filename_length as usize;
        
        if offset + 16 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read filename auth tag".to_string()));
        }
        let mut filename_auth_tag = [0u8; 16];
        filename_auth_tag.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        
        // Parse metadata section with comprehensive bounds checking
        if offset + 2 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read metadata length".to_string()));
        }
        let metadata_length = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        // Validate metadata length
        if metadata_length as usize > MAX_METADATA_LENGTH {
            return Err(CryptoError::HeaderParsingError(
                format!("Metadata length {} exceeds maximum {}", 
                    metadata_length, MAX_METADATA_LENGTH)
            ));
        }
        
        if offset + metadata_length as usize > data.len() {
            return Err(CryptoError::HeaderParsingError(
                format!("Cannot read metadata: need {} bytes, have {}", 
                    metadata_length, data.len() - offset)
            ));
        }
        let encrypted_metadata = data[offset..offset + metadata_length as usize].to_vec();
        offset += metadata_length as usize;
        
        if offset + 16 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read metadata auth tag".to_string()));
        }
        let mut metadata_auth_tag = [0u8; 16];
        metadata_auth_tag.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        
        let header = Header {
            magic,
            version,
            algorithm_id,
            salt,
            nonce,
            directory_path_length,
            encrypted_directory_path,
            directory_path_auth_tag,
            filename_length,
            encrypted_filename,
            filename_auth_tag,
            metadata_length,
            encrypted_metadata,
            metadata_auth_tag,
        };
        
        Ok((header, offset))
    }
    
    /// Validate magic number
    pub fn validate_magic(&self) -> bool { 
        self.magic == *b"SHADOW" 
    }
    
    /// Check if algorithm is supported
    pub fn supports_algorithm(&self) -> bool { 
        matches!(self.algorithm_id, AlgorithmId::AesGcm256 | AlgorithmId::ChaCha20Poly1305)
    }
    
    /// Validate version compatibility
    pub fn is_version_compatible(&self) -> bool {
        self.version <= 3 && self.version > 0
    }
    
    /// Check if header is structurally valid
    pub fn is_valid(&self) -> Result<(), CryptoError> {
        // Validate magic number
        if !self.validate_magic() {
            return Err(CryptoError::HeaderParsingError(
                format!("Invalid magic number: {:?}", String::from_utf8_lossy(&self.magic))
            ));
        }
        
        // Validate version
        if !self.is_version_compatible() {
            return Err(CryptoError::HeaderParsingError(
                format!("Unsupported version: {}", self.version)
            ));
        }
        
        // Validate algorithm support
        if !self.supports_algorithm() {
            return Err(CryptoError::HeaderParsingError(
                format!("Unsupported algorithm: {:?}", self.algorithm_id)
            ));
        }
        
        // Validate length constraints
        if self.directory_path_length as usize > MAX_DIRECTORY_PATH_LENGTH {
            return Err(CryptoError::HeaderParsingError(
                format!("Directory path length {} exceeds maximum {}", 
                    self.directory_path_length, MAX_DIRECTORY_PATH_LENGTH)
            ));
        }
        
        if self.filename_length as usize > MAX_FILENAME_LENGTH {
            return Err(CryptoError::HeaderParsingError(
                format!("Filename length {} exceeds maximum {}", 
                    self.filename_length, MAX_FILENAME_LENGTH)
            ));
        }
        
        if self.metadata_length as usize > MAX_METADATA_LENGTH {
            return Err(CryptoError::HeaderParsingError(
                format!("Metadata length {} exceeds maximum {}", 
                    self.metadata_length, MAX_METADATA_LENGTH)
            ));
        }
        
        // Validate data consistency
        if self.encrypted_directory_path.len() != self.directory_path_length as usize {
            return Err(CryptoError::HeaderParsingError(
                "Directory path data length mismatch".to_string()
            ));
        }
        
        if self.encrypted_filename.len() != self.filename_length as usize {
            return Err(CryptoError::HeaderParsingError(
                "Filename data length mismatch".to_string()
            ));
        }
        
        if self.encrypted_metadata.len() != self.metadata_length as usize {
            return Err(CryptoError::HeaderParsingError(
                "Metadata data length mismatch".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Get the minimum header size for this version
    pub fn minimum_size() -> usize {
        40 + 18 + 18 + 18  // Fixed fields + 3 sections (each: 2 bytes length + 16 bytes auth tag)
    }
    
    /// Calculate the total size of this header when serialized
    pub fn serialized_size(&self) -> usize {
        40  // Fixed fields: magic(6) + version(2) + algorithm(2) + salt(16) + nonce(12) + 2 bytes
            + 2 + self.directory_path_length as usize + 16  // Directory path section
            + 2 + self.filename_length as usize + 16       // Filename section  
            + 2 + self.metadata_length as usize + 16       // Metadata section
    }
    
    /// Get algorithm-specific parameters
    pub fn get_key_size(&self) -> usize {
        match self.algorithm_id {
            AlgorithmId::AesGcm256 => 32,           // 256 bits
            AlgorithmId::ChaCha20Poly1305 => 32,    // 256 bits
            _ => 32,  // Default to 256 bits
        }
    }
    
    /// Get algorithm-specific nonce size
    pub fn get_nonce_size(&self) -> usize {
        match self.algorithm_id {
            AlgorithmId::AesGcm256 => 12,           // 96 bits for GCM
            AlgorithmId::ChaCha20Poly1305 => 12,    // 96 bits
            _ => 12,  // Default to 96 bits
        }
    }
    
    /// Get algorithm-specific authentication tag size
    pub fn get_tag_size(&self) -> usize {
        match self.algorithm_id {
            AlgorithmId::AesGcm256 => 16,           // 128 bits
            AlgorithmId::ChaCha20Poly1305 => 16,    // 128 bits
            _ => 16,  // Default to 128 bits
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    
    fn create_test_header() -> Header {
        Header::new(
            AlgorithmId::AesGcm256,
            [1u8; 16],  // Test salt
            [2u8; 12],  // Test nonce
        )
    }
    
    fn create_test_metadata() -> FileMetadata {
        let mut metadata = FileMetadata::new();
        metadata.permissions = 0o755;
        metadata.file_hash = [42u8; 32];
        metadata.compression = Some(CompressionType::Zstd);
        metadata.created_by = "crypto-test-v1.0".to_string();
        metadata.custom_attributes.insert("test_key".to_string(), vec![1, 2, 3]);
        metadata
    }
    
    #[test]
    fn test_algorithm_id_conversion() {
        assert_eq!(AlgorithmId::from(0x0001), AlgorithmId::AesGcm256);
        assert_eq!(AlgorithmId::from(0x0002), AlgorithmId::ChaCha20Poly1305);
        assert_eq!(AlgorithmId::from(0x1001), AlgorithmId::KyberAes256);
        assert_eq!(AlgorithmId::from(0x9999), AlgorithmId::AesGcm256); // Unknown defaults to AES
    }
    
    #[test]
    fn test_compression_type_conversion() {
        assert_eq!(CompressionType::from(0x00), CompressionType::None);
        assert_eq!(CompressionType::from(0x01), CompressionType::Zstd);
        assert_eq!(CompressionType::from(0x02), CompressionType::Lz4);
        assert_eq!(CompressionType::from(0x03), CompressionType::Brotli);
        assert_eq!(CompressionType::from(0xFF), CompressionType::None); // Unknown defaults to None
    }
    
    #[test]
    fn test_file_metadata_creation() {
        let metadata = FileMetadata::new();
        assert_eq!(metadata.permissions, 0o644);
        assert_eq!(metadata.compression, None);
        assert!(metadata.created_by.starts_with("shadow-v"));
        assert!(metadata.custom_attributes.is_empty());
    }
    
    #[test]
    fn test_file_metadata_serialization_roundtrip() {
        let original = create_test_metadata();
        let serialized = original.serialize();
        let deserialized = FileMetadata::deserialize(&serialized).expect("Failed to deserialize");
        
        assert_eq!(original.permissions, deserialized.permissions);
        assert_eq!(original.file_hash, deserialized.file_hash);
        assert_eq!(original.compression, deserialized.compression);
        assert_eq!(original.created_by, deserialized.created_by);
        assert_eq!(original.custom_attributes, deserialized.custom_attributes);
    }
    
    #[test]
    fn test_file_metadata_deserialization_insufficient_data() {
        let small_data = vec![0u8; 64]; // Less than minimum 65 bytes
        let result = FileMetadata::deserialize(&small_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Insufficient metadata data"));
    }
    
    #[test]
    fn test_file_metadata_deserialization_invalid_utf8() {
        // Create properly structured metadata with invalid UTF-8 in created_by field
        let mut data = Vec::new();
        
        // Permissions (4 bytes)
        data.extend_from_slice(&0o644u32.to_le_bytes());
        
        // Timestamps (24 bytes - 8 bytes each)
        let now_secs = 1234567890u64;
        data.extend_from_slice(&now_secs.to_le_bytes());
        data.extend_from_slice(&now_secs.to_le_bytes());
        data.extend_from_slice(&now_secs.to_le_bytes());
        
        // File hash (32 bytes)
        data.extend_from_slice(&[0u8; 32]);
        
        // Compression type (1 byte)
        data.push(0x00);
        
        // Created by string with invalid UTF-8 (length + invalid data)
        data.extend_from_slice(&5u16.to_le_bytes()); // Length = 5
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC, 0xFB]); // Invalid UTF-8
        
        // Custom attributes (empty - just count)
        data.extend_from_slice(&0u16.to_le_bytes()); // Count = 0
        
        let result = FileMetadata::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid UTF-8"));
    }
    
    #[test]
    fn test_header_creation() {
        let header = create_test_header();
        assert_eq!(header.magic, *b"SHADOW");
        assert_eq!(header.version, 3);
        assert_eq!(header.algorithm_id, AlgorithmId::AesGcm256);
        assert_eq!(header.salt, [1u8; 16]);
        assert_eq!(header.nonce, [2u8; 12]);
    }
    
    #[test]
    fn test_header_serialization_roundtrip() {
        let mut header = create_test_header();
        
        // Add some test data to make it realistic
        header.directory_path_length = 10;
        header.encrypted_directory_path = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        header.directory_path_auth_tag = [3u8; 16];
        
        header.filename_length = 8;
        header.encrypted_filename = vec![11, 12, 13, 14, 15, 16, 17, 18];
        header.filename_auth_tag = [4u8; 16];
        
        header.metadata_length = 6;
        header.encrypted_metadata = vec![21, 22, 23, 24, 25, 26];
        header.metadata_auth_tag = [5u8; 16];
        
        let serialized = header.serialize();
        let (deserialized, offset) = Header::deserialize(&serialized).expect("Failed to deserialize");
        
        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.version, deserialized.version);
        assert_eq!(header.algorithm_id, deserialized.algorithm_id);
        assert_eq!(header.salt, deserialized.salt);
        assert_eq!(header.nonce, deserialized.nonce);
        assert_eq!(header.directory_path_length, deserialized.directory_path_length);
        assert_eq!(header.encrypted_directory_path, deserialized.encrypted_directory_path);
        assert_eq!(header.directory_path_auth_tag, deserialized.directory_path_auth_tag);
        assert_eq!(header.filename_length, deserialized.filename_length);
        assert_eq!(header.encrypted_filename, deserialized.encrypted_filename);
        assert_eq!(header.filename_auth_tag, deserialized.filename_auth_tag);
        assert_eq!(header.metadata_length, deserialized.metadata_length);
        assert_eq!(header.encrypted_metadata, deserialized.encrypted_metadata);
        assert_eq!(header.metadata_auth_tag, deserialized.metadata_auth_tag);
        assert_eq!(offset, serialized.len());
    }
    
    #[test]
    fn test_header_deserialization_insufficient_data() {
        let small_data = vec![0u8; 30]; // Less than minimum 38 bytes
        let result = Header::deserialize(&small_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Insufficient data"));
    }
    
    #[test]
    fn test_header_deserialization_invalid_magic() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(b"BAAD"); // Wrong magic
        let result = Header::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid magic number"));
    }
    
    #[test]
    fn test_header_deserialization_unsupported_version() {
        let mut data = vec![0u8; 100];
        data[0..6].copy_from_slice(b"SHADOW"); // Correct magic
        data[6] = 99; // Version 99 (unsupported)
        data[7] = 0;
        let result = Header::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported version"));
    }
    
    #[test]
    fn test_header_deserialization_length_overflow() {
        let mut data = vec![0u8; 100];
        data[0..6].copy_from_slice(b"SHADOW");
        data[6] = 3; // Version 3
        data[7] = 0;
        data[8] = 1; // Algorithm AES-256-GCM
        data[9] = 0;
        // Salt (16 bytes at offset 10-25) and nonce (12 bytes at offset 26-37) - all zeros are fine
        data[38] = 0xFF; // Directory path length = 65535 (too large for remaining data)
        data[39] = 0xFF;
        
        let result = Header::deserialize(&data);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        // Should fail with bounds check error when trying to read directory path data
        assert!(error_msg.contains("Cannot read directory path") || error_msg.contains("Directory path length"));
    }
    
    #[test]
    fn test_header_validation() {
        let header = create_test_header();
        
        assert!(header.validate_magic());
        assert!(header.supports_algorithm());
        assert!(header.is_version_compatible());
        assert!(header.is_valid().is_ok());
    }
    
    #[test]
    fn test_header_validation_invalid_magic() {
        let mut header = create_test_header();
        header.magic = *b"BADMAG";
        
        assert!(!header.validate_magic());
        assert!(header.is_valid().is_err());
    }
    
    #[test]
    fn test_header_validation_unsupported_algorithm() {
        let mut header = create_test_header();
        header.algorithm_id = AlgorithmId::KyberAes256; // Future algorithm
        
        assert!(!header.supports_algorithm());
        assert!(header.is_valid().is_err());
    }
    
    #[test]
    fn test_header_validation_length_mismatch() {
        let mut header = create_test_header();
        header.filename_length = 10;
        header.encrypted_filename = vec![1, 2, 3]; // Only 3 bytes, not 10
        
        let result = header.is_valid();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length mismatch"));
    }
    
    #[test]
    fn test_header_size_calculations() {
        let header = create_test_header();
        
        assert_eq!(Header::minimum_size(), 94); // 40 + 18 + 18 + 18
        assert_eq!(header.serialized_size(), 94); // Empty sections: 40 + (2+0+16)*3
        
        let mut header_with_data = header;
        header_with_data.filename_length = 10;
        header_with_data.encrypted_filename = vec![0u8; 10];
        assert_eq!(header_with_data.serialized_size(), 104); // 94 + 10
    }
    
    #[test]
    fn test_algorithm_parameters() {
        let header = create_test_header();
        
        assert_eq!(header.get_key_size(), 32);   // 256 bits
        assert_eq!(header.get_nonce_size(), 12); // 96 bits
        assert_eq!(header.get_tag_size(), 16);   // 128 bits
    }
    
    #[test]
    fn test_header_with_maximum_lengths() {
        let mut header = create_test_header();
        
        // Set maximum allowed lengths
        header.directory_path_length = MAX_DIRECTORY_PATH_LENGTH as u16;
        header.encrypted_directory_path = vec![0u8; MAX_DIRECTORY_PATH_LENGTH];
        header.filename_length = MAX_FILENAME_LENGTH as u16;
        header.encrypted_filename = vec![0u8; MAX_FILENAME_LENGTH];
        header.metadata_length = MAX_METADATA_LENGTH as u16;
        header.encrypted_metadata = vec![0u8; MAX_METADATA_LENGTH];
        
        assert!(header.is_valid().is_ok());
    }
    
    #[test]
    fn test_header_with_excessive_lengths() {
        let mut header = create_test_header();
        
        // Set length that exceeds maximum
        header.directory_path_length = (MAX_DIRECTORY_PATH_LENGTH + 1) as u16;
        header.encrypted_directory_path = vec![0u8; MAX_DIRECTORY_PATH_LENGTH + 1];
        
        assert!(header.is_valid().is_err());
    }
    
    #[test]
    fn test_metadata_with_empty_attributes() {
        let metadata = FileMetadata {
            permissions: 0o644,
            created: SystemTime::now(),
            modified: SystemTime::now(),
            accessed: SystemTime::now(),
            file_hash: [0u8; 32],
            compression: None,
            created_by: "test".to_string(),
            custom_attributes: HashMap::new(),
        };
        
        let serialized = metadata.serialize();
        let deserialized = FileMetadata::deserialize(&serialized).expect("Failed to deserialize");
        assert!(deserialized.custom_attributes.is_empty());
    }
    
    #[test]
    fn test_metadata_with_multiple_attributes() {
        let mut metadata = create_test_metadata();
        metadata.custom_attributes.insert("key1".to_string(), vec![1, 2, 3]);
        metadata.custom_attributes.insert("key2".to_string(), vec![4, 5, 6, 7]);
        metadata.custom_attributes.insert("key3".to_string(), vec![]);
        
        let serialized = metadata.serialize();
        let deserialized = FileMetadata::deserialize(&serialized).expect("Failed to deserialize");
        
        assert_eq!(deserialized.custom_attributes.len(), 4); // Including original test_key
        assert_eq!(deserialized.custom_attributes.get("key1"), Some(&vec![1, 2, 3]));
        assert_eq!(deserialized.custom_attributes.get("key2"), Some(&vec![4, 5, 6, 7]));
        assert_eq!(deserialized.custom_attributes.get("key3"), Some(&vec![]));
    }
}