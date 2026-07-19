use crate::{errors::HeaderError, v2::key::KeyDerivationParams};

use super::header::{FileHeader, MAGIC, VERSION};

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
    let magic: [u8; 6] = bytes[0..6].try_into().ok()?;
    let version = bytes[6];

    // Unlike v1, v2 rejects a wrong magic or version byte at parse time.
    if magic != MAGIC || version != VERSION {
        return None;
    }

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
    use crate::v2::key::KeyDerivationParams;

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
        .unwrap()
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = create_test_header();
        let serialized = serialize(&original);
        assert_eq!(serialized.len(), original.header_length as usize);
        assert_eq!(&serialized[0..6], b"SHADOW");
        assert_eq!(serialized[6], 2);

        let deserialized = try_deserialize(&serialized).unwrap();
        assert_eq!(deserialized.magic, original.magic);
        assert_eq!(deserialized.version, original.version);
        assert_eq!(deserialized.header_length, original.header_length);
        assert_eq!(deserialized.salt, original.salt);
        assert_eq!(deserialized.kdf_memory, original.kdf_memory);
        assert_eq!(deserialized.kdf_iterations, original.kdf_iterations);
        assert_eq!(deserialized.kdf_parallelism, original.kdf_parallelism);
        assert_eq!(deserialized.kdf_key_length, original.kdf_key_length);
        assert_eq!(deserialized.content_nonce, original.content_nonce);
        assert_eq!(deserialized.filename_nonce, original.filename_nonce);
        assert_eq!(
            deserialized.filename_ciphertext_length,
            original.filename_ciphertext_length
        );
        assert_eq!(deserialized.filename_ciphertext, original.filename_ciphertext);
    }

    #[test]
    fn test_try_deserialize_rejects_wrong_version() {
        let header = create_test_header();
        let mut serialized = serialize(&header);
        serialized[6] = 1; // claim v1

        assert!(try_deserialize(&serialized).is_err());
    }

    #[test]
    fn test_try_deserialize_rejects_wrong_magic() {
        let header = create_test_header();
        let mut serialized = serialize(&header);
        serialized[0..6].copy_from_slice(b"NOTSHD");

        assert!(try_deserialize(&serialized).is_err());
    }

    #[test]
    fn test_try_deserialize_insufficient_bytes() {
        let bytes = vec![0u8; 50];
        assert!(matches!(
            try_deserialize(&bytes),
            Err(HeaderError::InsufficientBytes)
        ));
    }

    #[test]
    fn test_try_deserialize_inconsistent_lengths() {
        let header = create_test_header();
        let mut serialized = serialize(&header);
        // header_length no longer matches min_length + filename_ciphertext_length
        serialized[7..11].copy_from_slice(&(200u32.to_le_bytes()));

        assert!(try_deserialize(&serialized).is_err());
    }

    #[test]
    fn test_empty_filename_ciphertext_round_trip() {
        let header = FileHeader::new(
            [1u8; 16],
            KeyDerivationParams::from(profile::SecurityProfile::Test),
            [2u8; 24],
            [3u8; 24],
            vec![],
        )
        .unwrap();

        let deserialized = try_deserialize(&serialize(&header)).unwrap();
        assert_eq!(deserialized.filename_ciphertext_length, 0);
        assert!(deserialized.filename_ciphertext.is_empty());
    }
}
