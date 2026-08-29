use crate::{
    errors::{FileError, HeaderError},
    memory::{SecureKey, SecureString},
    v1::{crypt, key::KeyDerivationParams},
};

/// Complete v1 file header.
///
/// The struct holds only the header's actual information content; the layout
/// artifacts of the serialized form (magic, version byte, length fields) are
/// computed during (de)serialization and never stored.
///
/// Serialized layout:
///
/// | field                      | size     |
/// |----------------------------|----------|
/// | magic ("SHADOW")           | 6 bytes  |
/// | version (1)                | 1 byte   |
/// | header_length              | 4 bytes  |
/// | salt                       | 16 bytes |
/// | kdf_memory                 | 4 bytes  |
/// | kdf_iterations             | 4 bytes  |
/// | kdf_parallelism            | 4 bytes  |
/// | kdf_key_length             | 1 byte   |
/// | content_nonce              | 24 bytes |
/// | filename_nonce             | 24 bytes |
/// | filename_ciphertext_length | 2 bytes  |
/// | filename_ciphertext        | variable |
#[derive(Debug, Clone)]
pub struct FileHeader {
    salt: [u8; 16],
    kdf_params: KeyDerivationParams,
    content_nonce: [u8; 24],
    filename_nonce: [u8; 24],
    filename_ciphertext: Vec<u8>,
}

const MAGIC: [u8; 6] = *b"SHADOW";
const VERSION: u8 = 1;

impl FileHeader {
    pub fn new(
        salt: [u8; 16],
        kdf_params: KeyDerivationParams,
        content_nonce: [u8; 24],
        filename_nonce: [u8; 24],
        filename_ciphertext: Vec<u8>,
    ) -> Self {
        FileHeader {
            salt,
            kdf_params,
            content_nonce,
            filename_nonce,
            filename_ciphertext,
        }
    }

    /// Minimum length of the serialized header without the variable-length
    /// filename ciphertext. Changing the layout requires updating this value.
    pub(crate) const fn min_length() -> usize {
        6  // magic ("SHADOW")
        + 1  // version (u8)
        + 4  // header_length (u32)
        + 16 // salt ([u8; 16])
        + 4  // kdf_memory (u32)
        + 4  // kdf_iterations (u32)
        + 4  // kdf_parallelism (u32)
        + 1  // kdf_key_length (u8)
        + 24 // content_nonce ([u8; 24])
        + 24 // filename_nonce ([u8; 24])
        + 2 // filename_ciphertext_length (u16)
    }

    /// Total length of this header's serialized form.
    pub fn header_length(&self) -> usize {
        Self::min_length() + self.filename_ciphertext.len()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header_length());

        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&(self.header_length() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.kdf_params.memory_cost.to_le_bytes());
        bytes.extend_from_slice(&self.kdf_params.time_cost.to_le_bytes());
        bytes.extend_from_slice(&self.kdf_params.parallelism.to_le_bytes());
        bytes.push(self.kdf_params.key_size);
        bytes.extend_from_slice(&self.content_nonce);
        bytes.extend_from_slice(&self.filename_nonce);
        bytes.extend_from_slice(&(self.filename_ciphertext.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.filename_ciphertext);

        bytes
    }

    pub fn try_deserialize(bytes: &[u8]) -> Result<FileHeader, HeaderError> {
        if bytes.len() < FileHeader::min_length() {
            return Err(HeaderError::InsufficientBytes);
        }

        let length = read_header_length(bytes)?;

        if bytes.len() < length as usize {
            return Err(HeaderError::InsufficientBytes);
        }

        match Self::deserialize(bytes) {
            Some(header) => Ok(header),
            None => Err(HeaderError::InvalidData),
        }
    }

    fn deserialize(bytes: &[u8]) -> Option<FileHeader> {
        if bytes.len() < FileHeader::min_length() {
            return None;
        }
        // v1 historically accepts any magic and version bytes here; the
        // dispatcher validates them before selecting this module.
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

        let filename_ciphertext = bytes[FileHeader::min_length()..expected_length].to_vec();

        Some(FileHeader {
            salt,
            kdf_params: KeyDerivationParams::new(
                kdf_memory,
                kdf_iterations,
                kdf_parallelism,
                kdf_key_length,
            ),
            content_nonce,
            filename_nonce,
            filename_ciphertext,
        })
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// The key derivation parameters recorded in this header.
    pub fn kdf_params(&self) -> &KeyDerivationParams {
        &self.kdf_params
    }

    pub fn content_nonce(&self) -> &[u8; 24] {
        &self.content_nonce
    }

    pub fn filename_nonce(&self) -> &[u8; 24] {
        &self.filename_nonce
    }

    pub fn filename_ciphertext(&self) -> &[u8] {
        &self.filename_ciphertext
    }

    /// Decrypts a content ciphertext under this header's content nonce.
    pub fn decrypt_content(
        &self,
        ciphertext: &[u8],
        key: &SecureKey,
    ) -> Result<crate::memory::SecureBytes, FileError> {
        let (content, _) = crypt::decrypt_bytes(ciphertext, key.as_bytes(), &self.content_nonce)?;
        Ok(content)
    }

    /// Decrypts the original filename stored in this header.
    pub fn decrypt_filename(&self, key: &SecureKey) -> Result<SecureString, FileError> {
        let (filename_bytes, _) = crypt::decrypt_bytes(
            &self.filename_ciphertext,
            key.as_bytes(),
            &self.filename_nonce,
        )?;
        let filename = String::from_utf8(filename_bytes.as_slice().to_vec())
            .map_err(|_| FileError::InvalidFilename)?;
        Ok(SecureString::new(filename))
    }
}

/// Reads the total header length out of the fixed header fields.
fn read_header_length(bytes: &[u8]) -> Result<u32, HeaderError> {
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

#[cfg(test)]
mod tests {
    use crate::profile;

    use super::*;

    fn get_test_params() -> KeyDerivationParams {
        let profile = profile::SecurityProfile::Test;
        KeyDerivationParams::from(profile)
    }

    fn create_test_header() -> FileHeader {
        FileHeader::new(
            [1u8; 16],
            get_test_params(),
            [2u8; 24],
            [3u8; 24],
            vec![4, 5, 6, 7, 8],
        )
    }

    #[test]
    fn serialized_magic_and_version_are_correct() {
        let serialized = create_test_header().serialize();
        assert_eq!(&serialized[0..6], b"SHADOW");
        assert_eq!(serialized[6], 1);
    }

    #[test]
    fn header_size_is_calculated_correctly() {
        let filename_ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let header = FileHeader::new(
            [0u8; 16],
            get_test_params(),
            [0u8; 24],
            [0u8; 24],
            filename_ciphertext.clone(),
        );

        assert_eq!(header.header_length(), 90 + filename_ciphertext.len());
        assert_eq!(header.serialize().len(), header.header_length());
    }

    #[test]
    fn kdf_params_round_trip_through_header() {
        let params = get_test_params();
        let header = FileHeader::new(
            [0u8; 16],
            params.clone(),
            [0u8; 24],
            [0u8; 24],
            vec![1, 2, 3],
        );
        assert_eq!(header.kdf_params(), &params);
    }

    #[test]
    fn test_serialize_field_offsets() {
        let header = create_test_header();
        let serialized = header.serialize();
        let params = header.kdf_params();

        assert_eq!(serialized.len(), header.header_length());
        assert_eq!(&serialized[0..6], b"SHADOW");
        assert_eq!(serialized[6], 1);
        assert_eq!(
            u32::from_le_bytes(serialized[7..11].try_into().unwrap()) as usize,
            header.header_length()
        );
        assert_eq!(&serialized[11..27], header.salt());
        assert_eq!(
            u32::from_le_bytes(serialized[27..31].try_into().unwrap()),
            params.memory_cost
        );
        assert_eq!(
            u32::from_le_bytes(serialized[31..35].try_into().unwrap()),
            params.time_cost
        );
        assert_eq!(
            u32::from_le_bytes(serialized[35..39].try_into().unwrap()),
            params.parallelism
        );
        assert_eq!(serialized[39], params.key_size);
        assert_eq!(&serialized[40..64], header.content_nonce());
        assert_eq!(&serialized[64..88], header.filename_nonce());
        assert_eq!(
            u16::from_le_bytes(serialized[88..90].try_into().unwrap()) as usize,
            header.filename_ciphertext().len()
        );
        assert_eq!(
            &serialized[FileHeader::min_length()..],
            header.filename_ciphertext()
        );
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = create_test_header();
        let serialized = original.serialize();

        let deserialized = FileHeader::try_deserialize(&serialized).unwrap();
        assert_eq!(deserialized.salt(), original.salt());
        assert_eq!(deserialized.kdf_params(), original.kdf_params());
        assert_eq!(deserialized.content_nonce(), original.content_nonce());
        assert_eq!(deserialized.filename_nonce(), original.filename_nonce());
        assert_eq!(
            deserialized.filename_ciphertext(),
            original.filename_ciphertext()
        );
    }

    #[test]
    fn test_try_deserialize_insufficient_bytes() {
        let bytes = vec![0u8; 50];
        assert!(matches!(
            FileHeader::try_deserialize(&bytes),
            Err(HeaderError::InsufficientBytes)
        ));
    }

    #[test]
    fn test_try_deserialize_invalid_data() {
        let mut bytes = vec![0u8; 100];
        // Set invalid header length (smaller than min_length)
        bytes[7..11].copy_from_slice(&(50u32.to_le_bytes()));

        let result = FileHeader::try_deserialize(&bytes);
        assert!(matches!(result.unwrap_err(), HeaderError::InvalidData));
    }

    #[test]
    fn test_try_deserialize_inconsistent_lengths() {
        let mut serialized = create_test_header().serialize();
        // header_length no longer matches min_length + filename_ciphertext_length
        serialized[7..11].copy_from_slice(&(200u32.to_le_bytes()));

        assert!(FileHeader::try_deserialize(&serialized).is_err());
    }

    #[test]
    fn test_try_deserialize_insufficient_bytes_for_filename() {
        // A header claiming a 10-byte filename ciphertext (total length 100)
        // backed by only 95 bytes must be rejected.
        let mut bytes = vec![0u8; 95];
        bytes[0..6].copy_from_slice(b"SHADOW");
        bytes[6] = 1; // version
        bytes[7..11].copy_from_slice(&(100u32.to_le_bytes()));
        bytes[88..90].copy_from_slice(&(10u16.to_le_bytes()));

        let result = FileHeader::try_deserialize(&bytes);
        assert!(matches!(
            result.unwrap_err(),
            HeaderError::InsufficientBytes
        ));
    }

    #[test]
    fn test_empty_filename_ciphertext_round_trip() {
        let header = FileHeader::new([1u8; 16], get_test_params(), [2u8; 24], [3u8; 24], vec![]);

        let deserialized = FileHeader::try_deserialize(&header.serialize()).unwrap();
        assert!(deserialized.filename_ciphertext().is_empty());
    }

    #[test]
    fn test_large_filename_ciphertext_round_trip() {
        let header = FileHeader::new(
            [1u8; 16],
            get_test_params(),
            [2u8; 24],
            [3u8; 24],
            vec![4u8; 1000],
        );

        let deserialized = FileHeader::try_deserialize(&header.serialize()).unwrap();
        assert_eq!(deserialized.filename_ciphertext(), &[4u8; 1000][..]);
    }
}
