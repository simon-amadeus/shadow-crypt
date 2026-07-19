use crate::{errors::HeaderError, v1::key::KeyDerivationParams};

use super::header::FileHeader;

pub fn serialize(header: &FileHeader) -> Vec<u8> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(header.magic.as_slice());
    bytes.push(header.version);
    bytes.extend_from_slice(header.header_length.to_le_bytes().as_slice());
    bytes.extend_from_slice(header.salt.as_slice());
    bytes.extend_from_slice(header.kdf_memory.to_le_bytes().as_slice());
    bytes.extend_from_slice(header.kdf_iterations.to_le_bytes().as_slice());
    bytes.extend_from_slice(header.kdf_parallelism.to_le_bytes().as_slice());
    bytes.push(header.kdf_key_length);
    bytes.extend_from_slice(header.content_nonce.as_slice());
    bytes.extend_from_slice(header.filename_nonce.as_slice());
    bytes.extend_from_slice(header.filename_ciphertext_length.to_le_bytes().as_slice());
    bytes.extend_from_slice(header.filename_ciphertext.as_slice());

    bytes
}

pub fn get_length_from_bytes(bytes: &[u8]) -> Result<u32, HeaderError> {
    if bytes.len() < 11 {
        return Err(HeaderError::InsufficientBytes);
    }
    let length_bytes = &bytes[7..11];
    let length = u32::from_le_bytes(
        length_bytes
            .try_into()
            .map_err(|_| HeaderError::InvalidData)?,
    );
    Ok(length)
}

pub fn get_kdf_params(header: &FileHeader) -> KeyDerivationParams {
    KeyDerivationParams {
        memory_cost: header.kdf_memory,
        time_cost: header.kdf_iterations,
        parallelism: header.kdf_parallelism,
        key_size: header.kdf_key_length,
    }
}

pub fn try_deserialize(bytes: &[u8]) -> Result<FileHeader, HeaderError> {
    if bytes.len() < FileHeader::min_length() {
        return Err(HeaderError::InsufficientBytes);
    }

    let length: u32 = get_length_from_bytes(bytes)?;

    if bytes.len() < length as usize {
        return Err(HeaderError::InsufficientBytes);
    }

    match deserialize(bytes) {
        Some(header) => Ok(header),
        None => Err(HeaderError::InvalidData),
    }
}

fn deserialize(bytes: &[u8]) -> Option<FileHeader> {
    if bytes.len() < FileHeader::min_length() {
        return None;
    }
    let magic = bytes[0..6].try_into().ok()?;
    let version = bytes[6];
    let header_length = u32::from_le_bytes(bytes[7..11].try_into().ok()?);
    let salt = bytes[11..27].try_into().ok()?;
    let kdf_memory = u32::from_le_bytes(bytes[27..31].try_into().ok()?);
    let kdf_iterations = u32::from_le_bytes(bytes[31..35].try_into().ok()?);
    let kdf_parallelism = u32::from_le_bytes(bytes[35..39].try_into().ok()?);
    let kdf_key_length = bytes[39];
    let content_nonce = bytes[40..64].try_into().ok()?;
    let filename_nonce = bytes[64..88].try_into().ok()?;
    let filename_ciphertext_length = u16::from_le_bytes(bytes[88..90].try_into().ok()?);

    let expected_length: usize = FileHeader::min_length() + filename_ciphertext_length as usize;

    if header_length != expected_length as u32 {
        return None;
    }

    if bytes.len() < expected_length {
        return None;
    }

    let filename_ciphertext = bytes[FileHeader::min_length()
        ..(FileHeader::min_length() + filename_ciphertext_length as usize)]
        .to_vec();

    Some(FileHeader {
        magic,
        version,
        header_length,
        salt,
        kdf_memory,
        kdf_iterations,
        kdf_parallelism,
        kdf_key_length,
        content_nonce,
        filename_nonce,
        filename_ciphertext_length,
        filename_ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile;
    use crate::v1::key::KeyDerivationParams;

    fn create_test_header() -> FileHeader {
        let salt = [1u8; 16];
        let kdf_params = KeyDerivationParams::from(profile::SecurityProfile::Test);
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let filename_ciphertext = vec![4, 5, 6, 7, 8];

        FileHeader::new(
            salt,
            kdf_params,
            content_nonce,
            filename_nonce,
            filename_ciphertext,
        )
    }

    #[test]
    fn test_serialize() {
        let header = create_test_header();
        let serialized = serialize(&header);

        // Check that the serialized data has the correct length
        assert_eq!(serialized.len(), header.header_length as usize);

        // Check magic bytes
        assert_eq!(&serialized[0..6], b"SHADOW");

        // Check version
        assert_eq!(serialized[6], 1);

        // Check header length (little endian)
        let header_len_bytes = &serialized[7..11];
        let header_len = u32::from_le_bytes(header_len_bytes.try_into().unwrap());
        assert_eq!(header_len, header.header_length);

        // Check salt
        assert_eq!(&serialized[11..27], &header.salt);

        // Check KDF parameters
        let kdf_memory_bytes = &serialized[27..31];
        let kdf_memory = u32::from_le_bytes(kdf_memory_bytes.try_into().unwrap());
        assert_eq!(kdf_memory, header.kdf_memory);

        let kdf_iterations_bytes = &serialized[31..35];
        let kdf_iterations = u32::from_le_bytes(kdf_iterations_bytes.try_into().unwrap());
        assert_eq!(kdf_iterations, header.kdf_iterations);

        let kdf_parallelism_bytes = &serialized[35..39];
        let kdf_parallelism = u32::from_le_bytes(kdf_parallelism_bytes.try_into().unwrap());
        assert_eq!(kdf_parallelism, header.kdf_parallelism);

        // Check key length
        assert_eq!(serialized[39], header.kdf_key_length);

        // Check nonces
        assert_eq!(&serialized[40..64], &header.content_nonce);
        assert_eq!(&serialized[64..88], &header.filename_nonce);

        // Check filename ciphertext length
        let filename_len_bytes = &serialized[88..90];
        let filename_len = u16::from_le_bytes(filename_len_bytes.try_into().unwrap());
        assert_eq!(filename_len, header.filename_ciphertext_length);

        // Check filename ciphertext
        let filename_start = FileHeader::min_length();
        let filename_end = filename_start + header.filename_ciphertext.len();
        assert_eq!(
            &serialized[filename_start..filename_end],
            &header.filename_ciphertext[..]
        );
    }

    #[test]
    fn test_try_deserialize_valid() {
        let original_header = create_test_header();
        let serialized = serialize(&original_header);

        let result = try_deserialize(&serialized);
        assert!(result.is_ok());

        let deserialized_header = result.unwrap();
        assert_eq!(deserialized_header.magic, original_header.magic);
        assert_eq!(deserialized_header.version, original_header.version);
        assert_eq!(
            deserialized_header.header_length,
            original_header.header_length
        );
        assert_eq!(deserialized_header.salt, original_header.salt);
        assert_eq!(deserialized_header.kdf_memory, original_header.kdf_memory);
        assert_eq!(
            deserialized_header.kdf_iterations,
            original_header.kdf_iterations
        );
        assert_eq!(
            deserialized_header.kdf_parallelism,
            original_header.kdf_parallelism
        );
        assert_eq!(
            deserialized_header.kdf_key_length,
            original_header.kdf_key_length
        );
        assert_eq!(
            deserialized_header.content_nonce,
            original_header.content_nonce
        );
        assert_eq!(
            deserialized_header.filename_nonce,
            original_header.filename_nonce
        );
        assert_eq!(
            deserialized_header.filename_ciphertext_length,
            original_header.filename_ciphertext_length
        );
        assert_eq!(
            deserialized_header.filename_ciphertext,
            original_header.filename_ciphertext
        );
    }

    #[test]
    fn test_try_deserialize_insufficient_bytes() {
        let bytes = vec![0u8; 50]; // Less than min_length

        let result = try_deserialize(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HeaderError::InsufficientBytes
        ));
    }

    #[test]
    fn test_try_deserialize_invalid_data() {
        let mut bytes = vec![0u8; 100];
        // Set invalid header length (too small)
        bytes[7..11].copy_from_slice(&(50u32.to_le_bytes())); // Header length smaller than min

        let result = try_deserialize(&bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HeaderError::InvalidData));
    }

    #[test]
    fn test_try_deserialize_insufficient_bytes_for_filename() {
        let mut bytes = vec![0u8; 95]; // FileHeader::min_length() is 90, but we need more for filename
        // Set up a valid header but with filename_ciphertext_length > 0
        bytes[0..6].copy_from_slice(b"SHADOW");
        bytes[6] = 1; // version
        bytes[7..11].copy_from_slice(&(100u32.to_le_bytes())); // header_length = 100 (90 + 10)
        // salt, kdf params, nonces, etc. - keep as zeros for simplicity
        bytes[88..90].copy_from_slice(&(10u16.to_le_bytes())); // filename_ciphertext_length = 10
        // But we only have 95 bytes total, and we need 100, so insufficient

        let result = try_deserialize(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HeaderError::InsufficientBytes
        ));
    }

    #[test]
    fn test_round_trip_serialization() {
        let original_header = create_test_header();
        let serialized = serialize(&original_header);
        let deserialized_result = try_deserialize(&serialized);

        assert!(deserialized_result.is_ok());
        let deserialized_header = deserialized_result.unwrap();

        // Ensure all fields match
        assert_eq!(original_header.magic, deserialized_header.magic);
        assert_eq!(original_header.version, deserialized_header.version);
        assert_eq!(
            original_header.header_length,
            deserialized_header.header_length
        );
        assert_eq!(original_header.salt, deserialized_header.salt);
        assert_eq!(original_header.kdf_memory, deserialized_header.kdf_memory);
        assert_eq!(
            original_header.kdf_iterations,
            deserialized_header.kdf_iterations
        );
        assert_eq!(
            original_header.kdf_parallelism,
            deserialized_header.kdf_parallelism
        );
        assert_eq!(
            original_header.kdf_key_length,
            deserialized_header.kdf_key_length
        );
        assert_eq!(
            original_header.content_nonce,
            deserialized_header.content_nonce
        );
        assert_eq!(
            original_header.filename_nonce,
            deserialized_header.filename_nonce
        );
        assert_eq!(
            original_header.filename_ciphertext_length,
            deserialized_header.filename_ciphertext_length
        );
        assert_eq!(
            original_header.filename_ciphertext,
            deserialized_header.filename_ciphertext
        );
    }

    #[test]
    fn test_empty_filename_ciphertext() {
        let salt = [1u8; 16];
        let kdf_params = KeyDerivationParams::from(profile::SecurityProfile::Test);
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let filename_ciphertext = vec![]; // Empty filename

        let header = FileHeader::new(
            salt,
            kdf_params,
            content_nonce,
            filename_nonce,
            filename_ciphertext,
        );

        let serialized = serialize(&header);
        let deserialized_result = try_deserialize(&serialized);

        assert!(deserialized_result.is_ok());
        let deserialized_header = deserialized_result.unwrap();
        assert_eq!(header.magic, deserialized_header.magic);
        assert_eq!(header.version, deserialized_header.version);
        assert_eq!(header.header_length, deserialized_header.header_length);
        assert_eq!(header.salt, deserialized_header.salt);
        assert_eq!(header.kdf_memory, deserialized_header.kdf_memory);
        assert_eq!(header.kdf_iterations, deserialized_header.kdf_iterations);
        assert_eq!(header.kdf_parallelism, deserialized_header.kdf_parallelism);
        assert_eq!(header.kdf_key_length, deserialized_header.kdf_key_length);
        assert_eq!(header.content_nonce, deserialized_header.content_nonce);
        assert_eq!(header.filename_nonce, deserialized_header.filename_nonce);
        assert_eq!(
            header.filename_ciphertext_length,
            deserialized_header.filename_ciphertext_length
        );
        assert_eq!(
            header.filename_ciphertext,
            deserialized_header.filename_ciphertext
        );
    }

    #[test]
    fn test_large_filename_ciphertext() {
        let salt = [1u8; 16];
        let kdf_params = KeyDerivationParams::from(profile::SecurityProfile::Test);
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let filename_ciphertext = vec![4u8; 1000]; // Large filename

        let header = FileHeader::new(
            salt,
            kdf_params,
            content_nonce,
            filename_nonce,
            filename_ciphertext,
        );

        let serialized = serialize(&header);
        let deserialized_result = try_deserialize(&serialized);

        assert!(deserialized_result.is_ok());
        let deserialized_header = deserialized_result.unwrap();
        assert_eq!(header.magic, deserialized_header.magic);
        assert_eq!(header.version, deserialized_header.version);
        assert_eq!(header.header_length, deserialized_header.header_length);
        assert_eq!(header.salt, deserialized_header.salt);
        assert_eq!(header.kdf_memory, deserialized_header.kdf_memory);
        assert_eq!(header.kdf_iterations, deserialized_header.kdf_iterations);
        assert_eq!(header.kdf_parallelism, deserialized_header.kdf_parallelism);
        assert_eq!(header.kdf_key_length, deserialized_header.kdf_key_length);
        assert_eq!(header.content_nonce, deserialized_header.content_nonce);
        assert_eq!(header.filename_nonce, deserialized_header.filename_nonce);
        assert_eq!(
            header.filename_ciphertext_length,
            deserialized_header.filename_ciphertext_length
        );
        assert_eq!(
            header.filename_ciphertext,
            deserialized_header.filename_ciphertext
        );
    }
}
