//! Versioning system for Shadow file format
//! 
//! This module implements proper versioned types and migration chains
//! to enable robust migration between different Shadow file format versions.

use crate::shared::errors::CryptoError;
use crate::shared::algorithms::AlgorithmId;

// Re-export V3 header from versions module
pub use crate::shared::versions::v3::HeaderV3;

/// Trait for version-specific header implementations
pub trait VersionedHeader: Sized {
    /// The version number this header represents
    const VERSION: u16;
    
    /// Serialize this header to bytes
    fn serialize(&self) -> Vec<u8>;
    
    /// Deserialize from bytes
    fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError>;
    
    /// Validate this header's format
    fn validate(&self) -> Result<(), CryptoError>;
    
    /// Get the magic bytes for this version
    fn magic() -> &'static [u8];
    
    /// Check if this version can migrate to another version
    fn can_migrate_to(target_version: u16) -> bool;
    
    /// Check if this version can migrate from another version
    fn can_migrate_from(source_version: u16) -> bool;
}

/// Shadow file format version 1 header
#[derive(Debug)]
pub struct HeaderV1 {
    pub magic: [u8; 6],              // "SHADOW"
    pub version: u16,                // Always 1 for this type
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

impl HeaderV1 {
    /// Create a new version 1 header
    pub fn new(
        algorithm_id: AlgorithmId,
        salt: [u8; 16],
        nonce: [u8; 12],
    ) -> Self {
        Self {
            magic: *b"SHADOW",
            version: 1,
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
}

impl VersionedHeader for HeaderV1 {
    const VERSION: u16 = 1;
    
    fn serialize(&self) -> Vec<u8> {
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
    
    fn deserialize(data: &[u8]) -> Result<(Self, usize), CryptoError> {
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
        
        // Validate version for V1
        if version != Self::VERSION {
            return Err(CryptoError::HeaderParsingError(
                format!("Version mismatch: expected {}, got {}", Self::VERSION, version)
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
        
        // Parse variable-length sections
        let (directory_path_length, encrypted_directory_path, directory_path_auth_tag, new_offset) = 
            parse_encrypted_section_v1(data, offset, 2048, "directory path")?;
        offset = new_offset;
        
        let (filename_length, encrypted_filename, filename_auth_tag, new_offset) = 
            parse_encrypted_section_v1(data, offset, 512, "filename")?;
        offset = new_offset;
        
        let (metadata_length, encrypted_metadata, metadata_auth_tag, new_offset) = 
            parse_encrypted_section_v1(data, offset, 256, "metadata")?;
        offset = new_offset;
        
        let header = HeaderV1 {
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
    
    fn validate(&self) -> Result<(), CryptoError> {
        // Validate magic
        if self.magic != *b"SHADOW" {
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
        
        // Validate algorithm
        if !matches!(self.algorithm_id, AlgorithmId::AesGcm256) {
            return Err(CryptoError::HeaderParsingError(
                format!("Unsupported algorithm for version 1: {:?}", self.algorithm_id)
            ));
        }
        
        // Validate lengths
        if self.directory_path_length as usize > 2048 {
            return Err(CryptoError::HeaderParsingError(
                "Directory path length exceeds maximum for version 1".to_string()
            ));
        }
        
        if self.filename_length as usize > 512 {
            return Err(CryptoError::HeaderParsingError(
                "Filename length exceeds maximum for version 1".to_string()
            ));
        }
        
        if self.metadata_length as usize > 256 {
            return Err(CryptoError::HeaderParsingError(
                "Metadata length exceeds maximum for version 1".to_string()
            ));
        }
        
        Ok(())
    }
    
    fn magic() -> &'static [u8] {
        b"SHADOW"
    }
    
    fn can_migrate_to(target_version: u16) -> bool {
        // Version 1 can migrate to future versions 2, 3, etc.
        target_version > Self::VERSION && target_version <= 10 // arbitrary reasonable limit
    }
    
    fn can_migrate_from(_source_version: u16) -> bool {
        // Version 1 is the first version, so it can't migrate from anything
        false
    }
}

/// Helper function for parsing encrypted sections in version 1 format
fn parse_encrypted_section_v1(
    data: &[u8], 
    offset: usize, 
    max_length: usize, 
    section_name: &str
) -> Result<(u16, Vec<u8>, [u8; 16], usize), CryptoError> {
    let mut current_offset = offset;
    
    // Parse length
    if current_offset + 2 > data.len() {
        return Err(CryptoError::HeaderParsingError(
            format!("Cannot read {} length", section_name)
        ));
    }
    let length = u16::from_le_bytes([data[current_offset], data[current_offset + 1]]);
    current_offset += 2;
    
    // Validate length
    if length as usize > max_length {
        return Err(CryptoError::HeaderParsingError(
            format!("{} length {} exceeds maximum {}", section_name, length, max_length)
        ));
    }
    
    // Parse encrypted data
    if current_offset + length as usize > data.len() {
        return Err(CryptoError::HeaderParsingError(
            format!("Cannot read {} data", section_name)
        ));
    }
    let encrypted_data = data[current_offset..current_offset + length as usize].to_vec();
    current_offset += length as usize;
    
    // Parse auth tag
    if current_offset + 16 > data.len() {
        return Err(CryptoError::HeaderParsingError(
            format!("Cannot read {} auth tag", section_name)
        ));
    }
    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(&data[current_offset..current_offset + 16]);
    current_offset += 16;
    
    Ok((length, encrypted_data, auth_tag, current_offset))
}

/// Version detection from raw header data
pub fn detect_version(data: &[u8]) -> Result<u16, CryptoError> {
    if data.len() < 8 {
        return Err(CryptoError::HeaderParsingError(
            "Insufficient data to detect version".to_string()
        ));
    }
    
    // Check magic first
    let magic = &data[0..6];
    if magic != b"SHADOW" {
        return Err(CryptoError::HeaderParsingError(
            format!("Invalid magic number: expected 'SHADOW', got {:?}", 
                String::from_utf8_lossy(magic))
        ));
    }
    
    // Extract version
    let version = u16::from_le_bytes([data[6], data[7]]);
    Ok(version)
}

/// Compatibility matrix for version migration
pub struct CompatibilityMatrix;

impl CompatibilityMatrix {
    /// Check if source version can migrate to target version
    pub fn can_migrate(source_version: u16, target_version: u16) -> bool {
        match source_version {
            1 => HeaderV1::can_migrate_to(target_version),
            3 => HeaderV3::can_migrate_to(target_version),
            // Future versions will add their logic here
            _ => false,
        }
    }
    
    /// Get supported migration paths from a version
    pub fn migration_paths(source_version: u16) -> Vec<u16> {
        match source_version {
            1 => (2..=10).filter(|&v| HeaderV1::can_migrate_to(v)).collect(),
            3 => (4..=10).filter(|&v| HeaderV3::can_migrate_to(v)).collect(),
            // Future versions will add their paths here
            _ => vec![],
        }
    }
    
    /// Check if a version is supported for reading
    pub fn can_read(version: u16) -> bool {
        match version {
            1 => true,
            3 => true,
            // Future versions will add support here
            _ => false,
        }
    }
    
    /// Check if a version is supported for writing
    pub fn can_write(version: u16) -> bool {
        match version {
            1 => true,
            3 => true,
            // Future versions will add support here
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version_detection() {
        let mut data = vec![0u8; 100];
        data[0..6].copy_from_slice(b"SHADOW");
        data[6..8].copy_from_slice(&1u16.to_le_bytes());
        
        assert_eq!(detect_version(&data).unwrap(), 1);
    }
    
    #[test]
    fn test_header_v1_constants() {
        assert_eq!(HeaderV1::VERSION, 1);
        assert_eq!(HeaderV1::magic(), b"SHADOW");
    }
    
    #[test]
    fn test_migration_capabilities() {
        assert!(!HeaderV1::can_migrate_from(0));
        assert!(HeaderV1::can_migrate_to(2));
        assert!(!HeaderV1::can_migrate_to(100));
    }
    
    #[test]
    fn test_compatibility_matrix() {
        assert!(CompatibilityMatrix::can_read(1));
        assert!(CompatibilityMatrix::can_write(1));
        assert!(!CompatibilityMatrix::can_read(0));
        assert!(!CompatibilityMatrix::can_read(100));
        
        assert!(CompatibilityMatrix::can_migrate(1, 2));
        assert!(!CompatibilityMatrix::can_migrate(1, 100));
        
        let paths = CompatibilityMatrix::migration_paths(1);
        assert!(!paths.is_empty());
        assert!(paths.contains(&2));
    }
}