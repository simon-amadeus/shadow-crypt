//! File header format and serialization
//! 
//! This module implements the encrypted file header format as specified in the design:
//! - Magic number and version identification
//! - Algorithm identifiers for cryptographic agility
//! - Encrypted metadata with authentication tags
//! - Serialization/deserialization with proper padding

use crate::shared::errors::CryptoError;

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
pub struct Header {
    pub magic: [u8; 4],              // "ENC3"
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
            magic: *b"ENC3",
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
        if data.len() < 32 {  // Minimum header size
            return Err(CryptoError::HeaderParsingError("Insufficient data".to_string()));
        }
        
        let mut offset = 0;
        
        // Parse magic
        let magic = [data[0], data[1], data[2], data[3]];
        offset += 4;
        
        // Parse version
        let version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        // Parse algorithm ID
        let algorithm_id = AlgorithmId::from(u16::from_le_bytes([data[offset], data[offset + 1]]));
        offset += 2;
        
        // Parse salt
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        
        // Parse nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[offset..offset + 12]);
        offset += 12;
        
        // Parse directory path section
        let directory_path_length = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        let encrypted_directory_path = data[offset..offset + directory_path_length as usize].to_vec();
        offset += directory_path_length as usize;
        
        let mut directory_path_auth_tag = [0u8; 16];
        directory_path_auth_tag.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        
        // Parse filename section
        let filename_length = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        let encrypted_filename = data[offset..offset + filename_length as usize].to_vec();
        offset += filename_length as usize;
        
        let mut filename_auth_tag = [0u8; 16];
        filename_auth_tag.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        
        // Parse metadata section
        let metadata_length = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        let encrypted_metadata = data[offset..offset + metadata_length as usize].to_vec();
        offset += metadata_length as usize;
        
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
        self.magic == *b"ENC3" 
    }
    
    /// Check if algorithm is supported
    pub fn supports_algorithm(&self) -> bool { 
        matches!(self.algorithm_id, AlgorithmId::AesGcm256 | AlgorithmId::ChaCha20Poly1305)
    }
}