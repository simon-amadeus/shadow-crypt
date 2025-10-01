//! File header structure and serialization
//! 
//! This module provides the main Header struct that coordinates
//! metadata, algorithms, and version information for encrypted files.

use crate::shared::errors::CryptoError;
use crate::shared::algorithms::{AlgorithmId, VersionInfo, CURRENT_VERSION, MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION, MAX_FILENAME_LENGTH, MAX_DIRECTORY_PATH_LENGTH, MAX_METADATA_LENGTH};

/// File header structure with all encrypted components
#[derive(Debug)]
pub struct Header {
    pub magic: [u8; 6],              // "SHADOW"
    pub version: u16,                // Current version: 1 (Shadow format)
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
    pub obfuscated_filename_auth_tag: [u8; 16], // HMAC of obfuscated filename (prevents substitution attacks)
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
            version: CURRENT_VERSION,
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
            obfuscated_filename_auth_tag: [0u8; 16],
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
        
        // Obfuscated filename authentication
        buffer.extend_from_slice(&self.obfuscated_filename_auth_tag);
        
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
        if version > MAX_SUPPORTED_VERSION {
            return Err(CryptoError::HeaderParsingError(
                format!("Unsupported version: {} (maximum supported: {})", 
                       version, MAX_SUPPORTED_VERSION)
            ));
        }
        
        if version < MIN_SUPPORTED_VERSION {
            return Err(CryptoError::HeaderParsingError(
                format!("Unsupported version: {} (minimum supported: {})", 
                       version, MIN_SUPPORTED_VERSION)
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
            parse_encrypted_section(data, offset, MAX_DIRECTORY_PATH_LENGTH, "directory path")?;
        offset = new_offset;
        
        let (filename_length, encrypted_filename, filename_auth_tag, new_offset) = 
            parse_encrypted_section(data, offset, MAX_FILENAME_LENGTH, "filename")?;
        offset = new_offset;
        
        let (metadata_length, encrypted_metadata, metadata_auth_tag, new_offset) = 
            parse_encrypted_section(data, offset, MAX_METADATA_LENGTH, "metadata")?;
        offset = new_offset;
        
        // Parse obfuscated filename authentication tag
        if offset + 16 > data.len() {
            return Err(CryptoError::HeaderParsingError("Cannot read obfuscated filename auth tag".to_string()));
        }
        let mut obfuscated_filename_auth_tag = [0u8; 16];
        obfuscated_filename_auth_tag.copy_from_slice(&data[offset..offset + 16]);
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
            obfuscated_filename_auth_tag,
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
        self.version >= MIN_SUPPORTED_VERSION && self.version <= MAX_SUPPORTED_VERSION
    }
    
    /// Get version information for migration decisions
    pub fn get_version_info(&self) -> VersionInfo {
        VersionInfo::for_version(self.version)
    }
    
    /// Check if file can be migrated to current version
    pub fn can_be_migrated(&self) -> bool {
        self.get_version_info().is_supported(self.version)
    }
    
    /// Check if file needs migration to current version
    pub fn needs_migration(&self) -> bool {
        self.version < CURRENT_VERSION
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
        validate_section_length(self.directory_path_length, MAX_DIRECTORY_PATH_LENGTH, "directory path")?;
        validate_section_length(self.filename_length, MAX_FILENAME_LENGTH, "filename")?;
        validate_section_length(self.metadata_length, MAX_METADATA_LENGTH, "metadata")?;
        
        // Validate data consistency
        validate_data_consistency(
            &self.encrypted_directory_path, 
            self.directory_path_length, 
            "directory path"
        )?;
        validate_data_consistency(
            &self.encrypted_filename, 
            self.filename_length, 
            "filename"
        )?;
        validate_data_consistency(
            &self.encrypted_metadata, 
            self.metadata_length, 
            "metadata"
        )?;
        
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

/// Helper function to parse an encrypted section (length + data + auth_tag)
fn parse_encrypted_section(
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
            format!("Cannot read {}: need {} bytes, have {}", 
                section_name, length, data.len() - current_offset)
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

/// Helper function to validate section length constraints
fn validate_section_length(
    length: u16, 
    max_length: usize, 
    section_name: &str
) -> Result<(), CryptoError> {
    if length as usize > max_length {
        return Err(CryptoError::HeaderParsingError(
            format!("{} length {} exceeds maximum {}", section_name, length, max_length)
        ));
    }
    Ok(())
}

/// Helper function to validate data consistency
fn validate_data_consistency(
    data: &[u8], 
    expected_length: u16, 
    section_name: &str
) -> Result<(), CryptoError> {
    if data.len() != expected_length as usize {
        return Err(CryptoError::HeaderParsingError(
            format!("{} data length mismatch: expected {}, got {}", 
                section_name, expected_length, data.len())
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_creation() {
        let salt = [1u8; 16];
        let nonce = [2u8; 12];
        let header = Header::new(AlgorithmId::AesGcm256, salt, nonce);
        
        assert_eq!(header.magic, *b"SHADOW");
        assert_eq!(header.version, CURRENT_VERSION);
        assert_eq!(header.algorithm_id, AlgorithmId::AesGcm256);
        assert_eq!(header.salt, salt);
        assert_eq!(header.nonce, nonce);
    }

    #[test]
    fn test_header_serialization() {
        let salt = [1u8; 16];
        let nonce = [2u8; 12];
        let header = Header::new(AlgorithmId::AesGcm256, salt, nonce);
        
        let serialized = header.serialize();
        let (deserialized, _) = Header::deserialize(&serialized).unwrap();
        
        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.version, deserialized.version);
        assert_eq!(header.algorithm_id, deserialized.algorithm_id);
        assert_eq!(header.salt, deserialized.salt);
        assert_eq!(header.nonce, deserialized.nonce);
    }

    #[test]
    fn test_invalid_magic_number() {
        let mut data = vec![0u8; 100];
        data[0..6].copy_from_slice(b"BADMAG");
        
        let result = Header::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid magic number"));
    }

    #[test]
    fn test_version_validation() {
        let header = Header::new(AlgorithmId::AesGcm256, [0u8; 16], [0u8; 12]);
        assert!(header.is_version_compatible());
        assert!(header.validate_magic());
        assert!(header.supports_algorithm());
    }
}