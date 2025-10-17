// shadow-core/src/v1/serialization.rs
// Version 1.0 format serialization/deserialization functions
// Pure functions implementing the Shadow v1.0 file format specification

use super::constants::*;
use super::types::{EncryptedFile, FileHeader, FilenameData};
use crate::errors::SerializationError;

/// Serialize a v1 file header to bytes
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

/// Deserialize a v1 file header from bytes
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
    let magic: [u8; 8] = data[offset..offset + 8]
        .try_into()
        .map_err(|_| SerializationError::InvalidMagicBytes)?;
    offset += 8;

    if data.len() < offset + 2 {
        return Err(SerializationError::BufferUnderflow {
            requested: offset + 2,
            available: data.len(),
        });
    }

    // Algorithm ID (1 byte)
    let algorithm_id = data[offset];
    offset += 1;

    // Obfuscation flag (1 byte)
    let obfuscation_flag = data[offset];
    offset += 1;

    if data.len() < offset + 32 {
        return Err(SerializationError::BufferUnderflow {
            requested: offset + 32,
            available: data.len(),
        });
    }

    // Content hash (32 bytes)
    let content_hash: [u8; 32] =
        data[offset..offset + 32]
            .try_into()
            .map_err(|_| SerializationError::InvalidLength {
                field: "content_hash".to_string(),
                expected: 32,
                actual: data.len() - offset,
            })?;
    offset += 32;

    // Filename data (variable length)
    let (filename_data, filename_size) =
        deserialize_filename_data(&data[offset..], obfuscation_flag)?;
    offset += filename_size;

    if data.len() < offset + 40 {
        return Err(SerializationError::BufferUnderflow {
            requested: offset + 40,
            available: data.len(),
        });
    }

    // Salt (16 bytes)
    let salt: [u8; 16] =
        data[offset..offset + 16]
            .try_into()
            .map_err(|_| SerializationError::InvalidLength {
                field: "salt".to_string(),
                expected: 16,
                actual: data.len() - offset,
            })?;
    offset += 16;

    // Content nonce (24 bytes)
    let content_nonce: [u8; 24] =
        data[offset..offset + 24]
            .try_into()
            .map_err(|_| SerializationError::InvalidLength {
                field: "content_nonce".to_string(),
                expected: 24,
                actual: data.len() - offset,
            })?;

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

/// Serialize filename data into the buffer
fn serialize_filename_data(
    filename_data: &FilenameData,
    buffer: &mut Vec<u8>,
) -> Result<(), SerializationError> {
    match filename_data {
        FilenameData::Plaintext(filename) => {
            let filename_bytes = filename.as_bytes();
            if filename_bytes.len() > MAX_FILENAME_LENGTH {
                return Err(SerializationError::InvalidLength {
                    field: "filename".to_string(),
                    expected: MAX_FILENAME_LENGTH,
                    actual: filename_bytes.len(),
                });
            }

            // Length (1 byte) + filename bytes
            buffer.push(filename_bytes.len() as u8);
            buffer.extend_from_slice(filename_bytes);
        }
        FilenameData::Encrypted { ciphertext, nonce } => {
            if ciphertext.len() > 255 {
                return Err(SerializationError::InvalidLength {
                    field: "encrypted_filename".to_string(),
                    expected: 255,
                    actual: ciphertext.len(),
                });
            }

            // Length (1 byte) + ciphertext + nonce (24 bytes)
            buffer.push(ciphertext.len() as u8);
            buffer.extend_from_slice(ciphertext);
            buffer.extend_from_slice(nonce);
        }
    }
    Ok(())
}

/// Deserialize filename data from bytes
/// Returns (FilenameData, size consumed)
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

    match obfuscation_flag {
        FILENAME_PLAINTEXT => {
            if data.len() < offset + filename_length {
                return Err(SerializationError::BufferUnderflow {
                    requested: offset + filename_length,
                    available: data.len(),
                });
            }

            let filename_bytes = &data[offset..offset + filename_length];
            let filename = String::from_utf8(filename_bytes.to_vec())
                .map_err(|_| SerializationError::InvalidUtf8)?;
            offset += filename_length;

            Ok((FilenameData::Plaintext(filename), offset))
        }
        FILENAME_ENCRYPTED => {
            if data.len() < offset + filename_length + 24 {
                return Err(SerializationError::BufferUnderflow {
                    requested: offset + filename_length + 24,
                    available: data.len(),
                });
            }

            let ciphertext = data[offset..offset + filename_length].to_vec();
            offset += filename_length;

            let nonce: [u8; 24] = data[offset..offset + 24].try_into().map_err(|_| {
                SerializationError::InvalidLength {
                    field: "filename_nonce".to_string(),
                    expected: 24,
                    actual: data.len() - offset,
                }
            })?;
            offset += 24;

            Ok((FilenameData::Encrypted { ciphertext, nonce }, offset))
        }
        _ => Err(SerializationError::InvalidObfuscationFlag(obfuscation_flag)),
    }
}

/// Serialize a complete v1 encrypted file to bytes
pub fn serialize_encrypted_file(file: &EncryptedFile) -> Result<Vec<u8>, SerializationError> {
    let mut result = serialize_header(&file.header)?;
    result.extend_from_slice(&file.ciphertext);
    Ok(result)
}

/// Deserialize a complete v1 encrypted file from bytes
pub fn deserialize_encrypted_file(
    data: &[u8],
) -> Result<(FileHeader, Vec<u8>), SerializationError> {
    let header = deserialize_header(data)?;
    let header_size = calculate_header_size(&header)?;

    if data.len() < header_size {
        return Err(SerializationError::BufferUnderflow {
            requested: header_size,
            available: data.len(),
        });
    }

    let ciphertext = data[header_size..].to_vec();
    Ok((header, ciphertext))
}

/// Calculate the total size of a serialized header
fn calculate_header_size(header: &FileHeader) -> Result<usize, SerializationError> {
    let mut size = 8 + 1 + 1 + 32; // magic + algorithm + flag + hash

    // Filename data size
    size += 1; // length byte
    match &header.filename_data {
        FilenameData::Plaintext(filename) => {
            size += filename.len();
        }
        FilenameData::Encrypted { ciphertext, .. } => {
            size += ciphertext.len() + 24; // ciphertext + nonce
        }
    }

    size += 16 + 24; // salt + content_nonce
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_header_plaintext() {
        let original_header = FileHeader {
            magic: *MAGIC,
            algorithm_id: ALGORITHM_XCHACHA20_POLY1305,
            obfuscation_flag: FILENAME_PLAINTEXT,
            content_hash: [42u8; 32],
            filename_data: FilenameData::Plaintext("test.txt".to_string()),
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        };

        let serialized = serialize_header(&original_header).unwrap();
        let deserialized = deserialize_header(&serialized).unwrap();

        assert_eq!(original_header.magic, deserialized.magic);
        assert_eq!(original_header.algorithm_id, deserialized.algorithm_id);
        assert_eq!(
            original_header.obfuscation_flag,
            deserialized.obfuscation_flag
        );
        assert_eq!(original_header.content_hash, deserialized.content_hash);
        assert_eq!(original_header.salt, deserialized.salt);
        assert_eq!(original_header.content_nonce, deserialized.content_nonce);

        match (&original_header.filename_data, &deserialized.filename_data) {
            (FilenameData::Plaintext(orig), FilenameData::Plaintext(deser)) => {
                assert_eq!(orig, deser);
            }
            _ => panic!("Filename data mismatch"),
        }
    }

    #[test]
    fn test_serialize_deserialize_header_encrypted() {
        let original_header = FileHeader {
            magic: *MAGIC,
            algorithm_id: ALGORITHM_XCHACHA20_POLY1305,
            obfuscation_flag: FILENAME_ENCRYPTED,
            content_hash: [42u8; 32],
            filename_data: FilenameData::Encrypted {
                ciphertext: vec![1, 2, 3, 4, 5],
                nonce: [99u8; 24],
            },
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        };

        let serialized = serialize_header(&original_header).unwrap();
        let deserialized = deserialize_header(&serialized).unwrap();

        assert_eq!(original_header.magic, deserialized.magic);
        assert_eq!(original_header.algorithm_id, deserialized.algorithm_id);
        assert_eq!(
            original_header.obfuscation_flag,
            deserialized.obfuscation_flag
        );

        match (&original_header.filename_data, &deserialized.filename_data) {
            (
                FilenameData::Encrypted {
                    ciphertext: orig_ct,
                    nonce: orig_nonce,
                },
                FilenameData::Encrypted {
                    ciphertext: deser_ct,
                    nonce: deser_nonce,
                },
            ) => {
                assert_eq!(orig_ct, deser_ct);
                assert_eq!(orig_nonce, deser_nonce);
            }
            _ => panic!("Filename data mismatch"),
        }
    }

    #[test]
    fn test_serialize_deserialize_encrypted_file() {
        let header = FileHeader {
            magic: *MAGIC,
            algorithm_id: ALGORITHM_XCHACHA20_POLY1305,
            obfuscation_flag: FILENAME_PLAINTEXT,
            content_hash: [42u8; 32],
            filename_data: FilenameData::Plaintext("test.txt".to_string()),
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        };

        let original_file = EncryptedFile {
            header,
            ciphertext: vec![10, 20, 30, 40, 50],
            suggested_filename: "test.shadow".to_string(),
        };

        let serialized = serialize_encrypted_file(&original_file).unwrap();
        let (deserialized_header, deserialized_ciphertext) =
            deserialize_encrypted_file(&serialized).unwrap();

        assert_eq!(original_file.header.magic, deserialized_header.magic);
        assert_eq!(original_file.ciphertext, deserialized_ciphertext);
    }

    #[test]
    fn test_calculate_header_size() {
        let header = FileHeader {
            magic: *MAGIC,
            algorithm_id: ALGORITHM_XCHACHA20_POLY1305,
            obfuscation_flag: FILENAME_PLAINTEXT,
            content_hash: [42u8; 32],
            filename_data: FilenameData::Plaintext("test.txt".to_string()),
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        };

        let calculated_size = calculate_header_size(&header).unwrap();
        let serialized = serialize_header(&header).unwrap();

        assert_eq!(calculated_size, serialized.len());
    }

    #[test]
    fn test_calculate_header_size_encrypted() {
        let header = FileHeader {
            magic: *MAGIC,
            algorithm_id: ALGORITHM_XCHACHA20_POLY1305,
            obfuscation_flag: FILENAME_ENCRYPTED,
            content_hash: [42u8; 32],
            filename_data: FilenameData::Encrypted {
                ciphertext: vec![1, 2, 3, 4, 5],
                nonce: [99u8; 24],
            },
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        };

        let calculated_size = calculate_header_size(&header).unwrap();
        let serialized = serialize_header(&header).unwrap();

        assert_eq!(calculated_size, serialized.len());
    }

    #[test]
    fn test_deserialize_header_insufficient_data() {
        let data = vec![1, 2, 3]; // Way too short
        let result = deserialize_header(&data);
        assert!(matches!(
            result,
            Err(SerializationError::BufferUnderflow { .. })
        ));
    }

    #[test]
    fn test_filename_too_long() {
        let long_filename = "a".repeat(300); // Over the 255 limit
        let header = FileHeader {
            magic: *MAGIC,
            algorithm_id: ALGORITHM_XCHACHA20_POLY1305,
            obfuscation_flag: FILENAME_PLAINTEXT,
            content_hash: [42u8; 32],
            filename_data: FilenameData::Plaintext(long_filename),
            salt: [1u8; 16],
            content_nonce: [2u8; 24],
        };

        let result = serialize_header(&header);
        assert!(matches!(
            result,
            Err(SerializationError::InvalidLength { .. })
        ));
    }

    #[test]
    fn test_invalid_utf8_filename() {
        // Create invalid UTF-8 data manually
        let mut invalid_data = vec![
            // Magic bytes
            b'S',
            b'H',
            b'A',
            b'D',
            b'O',
            b'W',
            b'0',
            b'1',
            // Algorithm ID
            ALGORITHM_XCHACHA20_POLY1305,
            // Obfuscation flag
            FILENAME_PLAINTEXT,
        ];
        // Content hash (32 bytes)
        invalid_data.extend_from_slice(&[42u8; 32]);
        // Filename length
        invalid_data.push(4);
        // Invalid UTF-8 sequence
        invalid_data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
        // Salt and nonce
        invalid_data.extend_from_slice(&[1u8; 16]); // salt
        invalid_data.extend_from_slice(&[2u8; 24]); // nonce

        let result = deserialize_header(&invalid_data);
        assert!(matches!(result, Err(SerializationError::InvalidUtf8)));
    }
}
