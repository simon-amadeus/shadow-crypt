// shadow-core/src/file_format.rs
// Pure file format serialization/deserialization functions
// Implements the Shadow file format as defined in SHADOW_SPECIFICATION_v1.0.md

use crate::types::{FileHeader, FilenameData, EncryptedFile};
use crate::errors::SerializationError;
use crate::constants::{
    OBFUSCATION_FLAG_DISABLED, OBFUSCATION_FLAG_ENABLED,
    MAX_FILENAME_LENGTH
};

#[cfg(test)]
use crate::constants::{MAGIC_BYTES, ALGORITHM_ID_XCHACHA20_POLY1305};

/// Serialize a file header to bytes
/// Pure function - deterministic with same inputs
pub fn serialize_header(header: &FileHeader) -> Result<Vec<u8>, SerializationError> {
    let mut buffer = Vec::new();
    
    // Magic bytes (8 bytes)
    buffer.extend_from_slice(&header.magic);
    
    // Algorithm ID (1 byte)
    buffer.push(header.algorithm_id);
    
    // Obfuscation flag (1 byte)
    buffer.push(header.obfuscation_flag);
    
    // Content hash (32 bytes)
    buffer.extend_from_slice(&header.content_hash);
    
    // Filename data (variable length)
    serialize_filename_data(&header.filename_data, &mut buffer)?;
    
    // Salt (16 bytes)
    buffer.extend_from_slice(&header.salt);
    
    // Content nonce (24 bytes)
    buffer.extend_from_slice(&header.content_nonce);
    
    Ok(buffer)
}

/// Deserialize a file header from bytes
/// Pure function - deterministic with same inputs
pub fn deserialize_header(data: &[u8]) -> Result<FileHeader, SerializationError> {
    if data.len() < 8 {
        return Err(SerializationError::BufferUnderflow {
            requested: 8,
            available: data.len(),
        });
    }
    
    let mut offset = 0;
    
    // Magic bytes (8 bytes)
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&data[offset..offset + 8]);
    offset += 8;
    
    // Algorithm ID (1 byte)
    if offset >= data.len() {
        return Err(SerializationError::BufferUnderflow {
            requested: 1,
            available: data.len() - offset,
        });
    }
    let algorithm_id = data[offset];
    offset += 1;
    
    // Obfuscation flag (1 byte)
    if offset >= data.len() {
        return Err(SerializationError::BufferUnderflow {
            requested: 1,
            available: data.len() - offset,
        });
    }
    let obfuscation_flag = data[offset];
    offset += 1;
    
    // Content hash (32 bytes)
    if data.len() < offset + 32 {
        return Err(SerializationError::BufferUnderflow {
            requested: 32,
            available: data.len() - offset,
        });
    }
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    
    // Filename data (variable length)
    let (filename_data, filename_data_size) = deserialize_filename_data(&data[offset..], obfuscation_flag)?;
    offset += filename_data_size;
    
    // Salt (16 bytes)
    if data.len() < offset + 16 {
        return Err(SerializationError::BufferUnderflow {
            requested: 16,
            available: data.len() - offset,
        });
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[offset..offset + 16]);
    offset += 16;
    
    // Content nonce (24 bytes)
    if data.len() < offset + 24 {
        return Err(SerializationError::BufferUnderflow {
            requested: 24,
            available: data.len() - offset,
        });
    }
    let mut content_nonce = [0u8; 24];
    content_nonce.copy_from_slice(&data[offset..offset + 24]);
    
    Ok(FileHeader {
        magic,
        algorithm_id,
        obfuscation_flag,
        content_hash,
        filename_data,
        salt,
        content_nonce,
    })
}

/// Serialize filename data based on obfuscation flag
/// Pure function - deterministic with same inputs
fn serialize_filename_data(
    filename_data: &FilenameData,
    buffer: &mut Vec<u8>,
) -> Result<(), SerializationError> {
    match filename_data {
        FilenameData::Plaintext(filename) => {
            let filename_bytes = filename.as_bytes();
            if filename_bytes.len() > MAX_FILENAME_LENGTH {
                return Err(SerializationError::FilenameTooLong {
                    length: filename_bytes.len(),
                    max: MAX_FILENAME_LENGTH,
                });
            }
            
            // Length prefix (1 byte)
            buffer.push(filename_bytes.len() as u8);
            
            // Filename bytes
            buffer.extend_from_slice(filename_bytes);
        }
        FilenameData::Encrypted { ciphertext, nonce } => {
            if ciphertext.len() > MAX_FILENAME_LENGTH {
                return Err(SerializationError::FilenameTooLong {
                    length: ciphertext.len(),
                    max: MAX_FILENAME_LENGTH,
                });
            }
            
            // Length prefix (1 byte)
            buffer.push(ciphertext.len() as u8);
            
            // Ciphertext
            buffer.extend_from_slice(ciphertext);
            
            // Nonce (24 bytes)
            buffer.extend_from_slice(nonce);
        }
    }
    Ok(())
}

/// Deserialize filename data based on obfuscation flag
/// Returns (FilenameData, size consumed)
/// Pure function - deterministic with same inputs
fn deserialize_filename_data(
    data: &[u8],
    obfuscation_flag: u8,
) -> Result<(FilenameData, usize), SerializationError> {
    if data.is_empty() {
        return Err(SerializationError::BufferUnderflow {
            requested: 1,
            available: 0,
        });
    }
    
    let filename_length = data[0] as usize;
    let mut offset = 1;
    
    if filename_length > MAX_FILENAME_LENGTH {
        return Err(SerializationError::FilenameTooLong {
            length: filename_length,
            max: MAX_FILENAME_LENGTH,
        });
    }
    
    match obfuscation_flag {
        OBFUSCATION_FLAG_DISABLED => {
            // Plaintext filename
            if data.len() < offset + filename_length {
                return Err(SerializationError::BufferUnderflow {
                    requested: filename_length,
                    available: data.len() - offset,
                });
            }
            
            let filename_bytes = &data[offset..offset + filename_length];
            let filename = String::from_utf8(filename_bytes.to_vec())
                .map_err(|_| SerializationError::InvalidUtf8)?;
            offset += filename_length;
            
            Ok((FilenameData::Plaintext(filename), offset))
        }
        OBFUSCATION_FLAG_ENABLED => {
            // Encrypted filename
            if data.len() < offset + filename_length + 24 {
                return Err(SerializationError::BufferUnderflow {
                    requested: filename_length + 24,
                    available: data.len() - offset,
                });
            }
            
            let ciphertext = data[offset..offset + filename_length].to_vec();
            offset += filename_length;
            
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&data[offset..offset + 24]);
            offset += 24;
            
            Ok((FilenameData::Encrypted { ciphertext, nonce }, offset))
        }
        _ => Err(SerializationError::InvalidLength {
            expected: 0,
            actual: obfuscation_flag as usize,
        }),
    }
}

/// Serialize a complete encrypted file (header + ciphertext)
/// Pure function - deterministic with same inputs
pub fn serialize_encrypted_file(file: &EncryptedFile) -> Result<Vec<u8>, SerializationError> {
    let mut result = serialize_header(&file.header)?;
    result.extend_from_slice(&file.ciphertext);
    Ok(result)
}

/// Deserialize a complete encrypted file (header + ciphertext)
/// Returns (header, ciphertext)
/// Pure function - deterministic with same inputs
pub fn deserialize_encrypted_file(data: &[u8]) -> Result<(FileHeader, Vec<u8>), SerializationError> {
    // First, deserialize just enough to get the header size
    let header = deserialize_header(data)?;
    let header_size = calculate_header_size(&header)?;
    
    if data.len() < header_size {
        return Err(SerializationError::BufferUnderflow {
            requested: header_size,
            available: data.len(),
        });
    }
    
    // Extract ciphertext (everything after the header)
    let ciphertext = data[header_size..].to_vec();
    
    Ok((header, ciphertext))
}

/// Calculate the total size of a serialized header
/// Pure function - deterministic with same inputs
fn calculate_header_size(header: &FileHeader) -> Result<usize, SerializationError> {
    let mut size = 0;
    
    // Magic bytes (8) + Algorithm ID (1) + Obfuscation flag (1) + Content hash (32)
    size += 8 + 1 + 1 + 32;
    
    // Filename data size
    match &header.filename_data {
        FilenameData::Plaintext(filename) => {
            size += 1; // length prefix
            size += filename.as_bytes().len();
        }
        FilenameData::Encrypted { ciphertext, nonce: _ } => {
            size += 1; // length prefix
            size += ciphertext.len();
            size += 24; // nonce
        }
    }
    
    // Salt (16) + Content nonce (24)
    size += 16 + 24;
    
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileHeader;

    fn create_test_header(obfuscated: bool) -> FileHeader {
        let filename_data = if obfuscated {
            FilenameData::Encrypted {
                ciphertext: vec![1, 2, 3, 4],
                nonce: [5u8; 24],
            }
        } else {
            FilenameData::Plaintext("test.txt".to_string())
        };
        
        FileHeader {
            magic: *MAGIC_BYTES,
            algorithm_id: ALGORITHM_ID_XCHACHA20_POLY1305,
            obfuscation_flag: if obfuscated { OBFUSCATION_FLAG_ENABLED } else { OBFUSCATION_FLAG_DISABLED },
            content_hash: [42u8; 32],
            filename_data,
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        }
    }

    #[test]
    fn test_serialize_deserialize_header_plaintext() {
        let header = create_test_header(false);
        
        let serialized = serialize_header(&header).unwrap();
        let deserialized = deserialize_header(&serialized).unwrap();
        
        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.algorithm_id, deserialized.algorithm_id);
        assert_eq!(header.obfuscation_flag, deserialized.obfuscation_flag);
        assert_eq!(header.content_hash, deserialized.content_hash);
        assert_eq!(header.salt, deserialized.salt);
        assert_eq!(header.content_nonce, deserialized.content_nonce);
        
        match (&header.filename_data, &deserialized.filename_data) {
            (FilenameData::Plaintext(orig), FilenameData::Plaintext(deser)) => {
                assert_eq!(orig, deser);
            }
            _ => panic!("Filename data type mismatch"),
        }
    }

    #[test]
    fn test_serialize_deserialize_header_encrypted() {
        let header = create_test_header(true);
        
        let serialized = serialize_header(&header).unwrap();
        let deserialized = deserialize_header(&serialized).unwrap();
        
        assert_eq!(header.magic, deserialized.magic);
        assert_eq!(header.algorithm_id, deserialized.algorithm_id);
        assert_eq!(header.obfuscation_flag, deserialized.obfuscation_flag);
        assert_eq!(header.content_hash, deserialized.content_hash);
        assert_eq!(header.salt, deserialized.salt);
        assert_eq!(header.content_nonce, deserialized.content_nonce);
        
        match (&header.filename_data, &deserialized.filename_data) {
            (
                FilenameData::Encrypted { ciphertext: orig_ct, nonce: orig_nonce },
                FilenameData::Encrypted { ciphertext: deser_ct, nonce: deser_nonce }
            ) => {
                assert_eq!(orig_ct, deser_ct);
                assert_eq!(orig_nonce, deser_nonce);
            }
            _ => panic!("Filename data type mismatch"),
        }
    }

    #[test]
    fn test_serialize_deserialize_encrypted_file() {
        let header = create_test_header(false);
        let ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let suggested_filename = "test.txt.shadow".to_string();
        
        let encrypted_file = EncryptedFile {
            header,
            ciphertext: ciphertext.clone(),
            suggested_filename,
        };
        
        let serialized = serialize_encrypted_file(&encrypted_file).unwrap();
        let (deserialized_header, deserialized_ciphertext) = deserialize_encrypted_file(&serialized).unwrap();
        
        assert_eq!(encrypted_file.header.magic, deserialized_header.magic);
        assert_eq!(ciphertext, deserialized_ciphertext);
    }

    #[test]
    fn test_filename_too_long() {
        let long_filename = "a".repeat(256);
        let filename_data = FilenameData::Plaintext(long_filename);
        let mut buffer = Vec::new();
        
        let result = serialize_filename_data(&filename_data, &mut buffer);
        assert!(matches!(result, Err(SerializationError::FilenameTooLong { .. })));
    }

    #[test]
    fn test_deserialize_header_insufficient_data() {
        let data = vec![1, 2, 3]; // Too short
        let result = deserialize_header(&data);
        assert!(matches!(result, Err(SerializationError::BufferUnderflow { .. })));
    }

    #[test]
    fn test_calculate_header_size() {
        let header = create_test_header(false);
        let size = calculate_header_size(&header).unwrap();
        
        let serialized = serialize_header(&header).unwrap();
        assert_eq!(size, serialized.len());
    }

    #[test]
    fn test_calculate_header_size_encrypted() {
        let header = create_test_header(true);
        let size = calculate_header_size(&header).unwrap();
        
        let serialized = serialize_header(&header).unwrap();
        assert_eq!(size, serialized.len());
    }

    #[test]
    fn test_invalid_utf8_filename() {
        let mut data = vec![
            // Magic
            b'S', b'H', b'A', b'D', b'O', b'W', b'0', b'1',
            // Algorithm ID
            0x01,
            // Obfuscation flag (disabled)
            0x00,
        ];
        // Content hash (32 bytes)
        data.extend_from_slice(&[0u8; 32]);
        
        // Invalid UTF-8 filename
        data.push(4); // length
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]); // Invalid UTF-8
        
        // Salt and nonce
        data.extend_from_slice(&[0u8; 16]); // salt
        data.extend_from_slice(&[0u8; 24]); // nonce
        
        let result = deserialize_header(&data);
        assert!(matches!(result, Err(SerializationError::InvalidUtf8)));
    }
}