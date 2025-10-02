//! Shadow file format version 2 header
//! 
//! V2 header format supports:
//! - Variable-length nonces for different algorithms
//! - Enhanced metadata structure
//! - XChaCha20-Poly1305 with 24-byte nonces
//! - Backward compatibility detection

use crate::shared::errors::CryptoError;
use crate::shared::algorithms::{AlgorithmId, Algorithm};
use std::io::Read;

pub const MAGIC_NUMBER_V2: [u8; 8] = *b"SHADOW2\0";
pub const VERSION_V2: u16 = 2;

/// Shadow file format version 2 header
/// 
/// This header supports variable-length nonces and enhanced algorithm support.
/// Layout:
/// - Magic number (8 bytes): "SHADOW2\0"  
/// - Version (2 bytes): 0x0002
/// - Algorithm ID (2 bytes)
/// - Salt (32 bytes): Extended to 256-bit for enhanced security
/// - Nonce length (1 byte): Allows 1-255 byte nonces
/// - Nonce (variable length): Algorithm-specific nonce
/// - Metadata length (2 bytes)
/// - Encrypted metadata (variable length)
/// - Filename length (2 bytes)
/// - Encrypted filename (variable length)
#[derive(Debug, Clone)]
pub struct HeaderV2 {
    pub magic: [u8; 8],
    pub version: u16,
    pub algorithm_id: u16,
    pub salt: [u8; 32],           // Extended to 256-bit
    pub nonce_length: u8,         // Variable nonce length
    pub nonce: Vec<u8>,           // Variable-length nonce
    pub metadata_length: u16,
    pub encrypted_metadata: Vec<u8>,
    pub filename_length: u16,
    pub encrypted_filename: Vec<u8>,
}

impl HeaderV2 {
    /// Create a new V2 header
    pub fn new(algorithm_id: AlgorithmId, salt: [u8; 32], nonce: Vec<u8>) -> Self {
        Self {
            magic: MAGIC_NUMBER_V2,
            version: VERSION_V2,
            algorithm_id: algorithm_id as u16,
            salt,
            nonce_length: nonce.len() as u8,
            nonce,
            metadata_length: 0,
            encrypted_metadata: Vec::new(),
            filename_length: 0,
            encrypted_filename: Vec::new(),
        }
    }

    /// Get the algorithm from the header
    pub fn algorithm(&self) -> Algorithm {
        match AlgorithmId::from(self.algorithm_id) {
            AlgorithmId::AesGcm256 => Algorithm::AES256GCM,
            AlgorithmId::ChaCha20Poly1305 => Algorithm::XChaCha20Poly1305,
            _ => Algorithm::AES256GCM, // Default fallback
        }
    }

    /// Validate header format and algorithm support
    pub fn validate(&self) -> Result<(), CryptoError> {
        // Check magic number
        if self.magic != MAGIC_NUMBER_V2 {
            return Err(CryptoError::HeaderParsingError("Invalid magic number for V2".to_string()));
        }

        // Check version
        if self.version != VERSION_V2 {
            return Err(CryptoError::HeaderParsingError(format!("Unsupported version: {}", self.version)));
        }

        // Validate algorithm-specific constraints
        match AlgorithmId::from(self.algorithm_id) {
            AlgorithmId::AesGcm256 => {
                if self.nonce.len() != 12 {
                    return Err(CryptoError::HeaderParsingError(
                        format!("AES-GCM requires 12-byte nonce, got {}", self.nonce.len())
                    ));
                }
            }
            AlgorithmId::ChaCha20Poly1305 => {
                if self.nonce.len() != 24 {
                    return Err(CryptoError::HeaderParsingError(
                        format!("XChaCha20-Poly1305 requires 24-byte nonce, got {}", self.nonce.len())
                    ));
                }
            }
            _ => {
                return Err(CryptoError::HeaderParsingError(
                    format!("Unsupported algorithm ID: {}", self.algorithm_id)
                ));
            }
        }

        // Validate nonce length consistency
        if self.nonce.len() != self.nonce_length as usize {
            return Err(CryptoError::HeaderParsingError("Nonce length mismatch".to_string()));
        }

        // Validate field lengths
        if self.encrypted_metadata.len() != self.metadata_length as usize {
            return Err(CryptoError::HeaderParsingError("Metadata length mismatch".to_string()));
        }

        if self.encrypted_filename.len() != self.filename_length as usize {
            return Err(CryptoError::HeaderParsingError("Filename length mismatch".to_string()));
        }

        Ok(())
    }

    /// Calculate the total header size in bytes
    pub fn size(&self) -> usize {
        8 +                              // magic
        2 +                              // version  
        2 +                              // algorithm_id
        32 +                             // salt
        1 +                              // nonce_length
        self.nonce.len() +               // nonce (variable)
        2 +                              // metadata_length
        self.encrypted_metadata.len() +  // encrypted_metadata (variable)
        2 +                              // filename_length
        self.encrypted_filename.len()    // encrypted_filename (variable)
    }

    /// Serialize header to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.size());
        
        buffer.extend_from_slice(&self.magic);
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.extend_from_slice(&self.algorithm_id.to_le_bytes());
        buffer.extend_from_slice(&self.salt);
        buffer.push(self.nonce_length);
        buffer.extend_from_slice(&self.nonce);
        buffer.extend_from_slice(&self.metadata_length.to_le_bytes());
        buffer.extend_from_slice(&self.encrypted_metadata);
        buffer.extend_from_slice(&self.filename_length.to_le_bytes());
        buffer.extend_from_slice(&self.encrypted_filename);
        
        buffer
    }

    /// Deserialize header from bytes
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, CryptoError> {
        // Read magic number
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)
            .map_err(|e| CryptoError::HeaderParsingError(format!("Failed to read magic: {}", e)))?;

        if magic != MAGIC_NUMBER_V2 {
            return Err(CryptoError::HeaderParsingError("Invalid V2 magic number".to_string()));
        }

        // Read version
        let mut version_bytes = [0u8; 2];
        reader.read_exact(&mut version_bytes)
            .map_err(|e| CryptoError::HeaderParsingError(format!("Failed to read version: {}", e)))?;
        let version = u16::from_le_bytes(version_bytes);

        // Read algorithm ID
        let mut algorithm_bytes = [0u8; 2];
        reader.read_exact(&mut algorithm_bytes)
            .map_err(|e| CryptoError::HeaderParsingError(format!("Failed to read algorithm: {}", e)))?;
        let algorithm_id = u16::from_le_bytes(algorithm_bytes);

        // Read salt
        let mut salt = [0u8; 32];
        reader.read_exact(&mut salt)
            .map_err(|e| CryptoError::HeaderParsingError(format!("Failed to read salt: {}", e)))?;

        // Read nonce length
        let mut nonce_length_byte = [0u8; 1];
        reader.read_exact(&mut nonce_length_byte)
            .map_err(|e| CryptoError::HeaderParsingError(format!("Failed to read nonce length: {}", e)))?;
        let nonce_length = nonce_length_byte[0];

        // Read variable-length nonce
        let mut nonce = vec![0u8; nonce_length as usize];
        reader.read_exact(&mut nonce)
            .map_err(|e| CryptoError::HeaderParsingError(format!("Failed to read nonce: {}", e)))?;

        // Read metadata length
        let mut metadata_length_bytes = [0u8; 2];
        reader.read_exact(&mut metadata_length_bytes)
            .map_err(|e| CryptoError::HeaderParsingError(format!("Failed to read metadata length: {}", e)))?;
        let metadata_length = u16::from_le_bytes(metadata_length_bytes);

        // Read encrypted metadata
        let mut encrypted_metadata = vec![0u8; metadata_length as usize];
        reader.read_exact(&mut encrypted_metadata)
            .map_err(|e| CryptoError::HeaderParsingError(format!("Failed to read metadata: {}", e)))?;

        // Read filename length
        let mut filename_length_bytes = [0u8; 2];
        reader.read_exact(&mut filename_length_bytes)
            .map_err(|e| CryptoError::HeaderParsingError(format!("Failed to read filename length: {}", e)))?;
        let filename_length = u16::from_le_bytes(filename_length_bytes);

        // Read encrypted filename
        let mut encrypted_filename = vec![0u8; filename_length as usize];
        reader.read_exact(&mut encrypted_filename)
            .map_err(|e| CryptoError::HeaderParsingError(format!("Failed to read filename: {}", e)))?;

        let header = Self {
            magic,
            version,
            algorithm_id,
            salt,
            nonce_length,
            nonce,
            metadata_length,
            encrypted_metadata,
            filename_length,
            encrypted_filename,
        };

        // Validate the constructed header
        header.validate()?;

        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::algorithms::AlgorithmId;

    #[test]
    fn test_v2_header_creation_aes_gcm() {
        let salt = [1u8; 32];
        let nonce = vec![2u8; 12]; // AES-GCM nonce
        let header = HeaderV2::new(AlgorithmId::AesGcm256, salt, nonce);
        
        assert_eq!(header.magic, MAGIC_NUMBER_V2);
        assert_eq!(header.version, VERSION_V2);
        assert_eq!(header.algorithm_id, AlgorithmId::AesGcm256 as u16);
        assert_eq!(header.salt, salt);
        assert_eq!(header.nonce_length, 12);
        assert_eq!(header.nonce.len(), 12);
    }

    #[test]
    fn test_v2_header_creation_xchacha20() {
        let salt = [1u8; 32];
        let nonce = vec![2u8; 24]; // XChaCha20-Poly1305 nonce
        let header = HeaderV2::new(AlgorithmId::ChaCha20Poly1305, salt, nonce);
        
        assert_eq!(header.magic, MAGIC_NUMBER_V2);
        assert_eq!(header.version, VERSION_V2);
        assert_eq!(header.algorithm_id, AlgorithmId::ChaCha20Poly1305 as u16);
        assert_eq!(header.salt, salt);
        assert_eq!(header.nonce_length, 24);
        assert_eq!(header.nonce.len(), 24);
    }

    #[test]
    fn test_v2_header_serialization_roundtrip() {
        let salt = [42u8; 32];
        let nonce = vec![99u8; 24];
        let mut header = HeaderV2::new(AlgorithmId::ChaCha20Poly1305, salt, nonce);
        
        // Add some metadata and filename
        header.encrypted_metadata = vec![1, 2, 3, 4];
        header.metadata_length = 4;
        header.encrypted_filename = vec![5, 6, 7];
        header.filename_length = 3;
        
        // Serialize
        let serialized = header.serialize();
        
        // Deserialize
        let mut cursor = std::io::Cursor::new(serialized);
        let deserialized = HeaderV2::deserialize(&mut cursor).unwrap();
        
        // Verify all fields match
        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.version, deserialized.version);
        assert_eq!(header.algorithm_id, deserialized.algorithm_id);
        assert_eq!(header.salt, deserialized.salt);
        assert_eq!(header.nonce_length, deserialized.nonce_length);
        assert_eq!(header.nonce, deserialized.nonce);
        assert_eq!(header.metadata_length, deserialized.metadata_length);
        assert_eq!(header.encrypted_metadata, deserialized.encrypted_metadata);
        assert_eq!(header.filename_length, deserialized.filename_length);
        assert_eq!(header.encrypted_filename, deserialized.encrypted_filename);
    }

    #[test]
    fn test_v2_header_validation_aes_gcm() {
        let salt = [1u8; 32];
        let nonce = vec![2u8; 12]; // Correct for AES-GCM
        let header = HeaderV2::new(AlgorithmId::AesGcm256, salt, nonce);
        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_v2_header_validation_xchacha20() {
        let salt = [1u8; 32];
        let nonce = vec![2u8; 24]; // Correct for XChaCha20-Poly1305
        let header = HeaderV2::new(AlgorithmId::ChaCha20Poly1305, salt, nonce);
        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_v2_header_validation_wrong_nonce_size() {
        let salt = [1u8; 32];
        let nonce = vec![2u8; 16]; // Wrong size for both algorithms
        let header = HeaderV2::new(AlgorithmId::AesGcm256, salt, nonce);
        assert!(header.validate().is_err());
    }

    #[test]
    fn test_v2_header_algorithm_detection() {
        let salt = [1u8; 32];
        
        // Test AES-GCM detection
        let nonce_aes = vec![2u8; 12];
        let header_aes = HeaderV2::new(AlgorithmId::AesGcm256, salt, nonce_aes);
        assert_eq!(header_aes.algorithm(), Algorithm::AES256GCM);
        
        // Test XChaCha20-Poly1305 detection
        let nonce_chacha = vec![2u8; 24];
        let header_chacha = HeaderV2::new(AlgorithmId::ChaCha20Poly1305, salt, nonce_chacha);
        assert_eq!(header_chacha.algorithm(), Algorithm::XChaCha20Poly1305);
    }
}