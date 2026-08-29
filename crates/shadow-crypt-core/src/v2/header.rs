use crate::{
    errors::{FileError, HeaderError},
    memory::{SecureKey, SecureString},
    v2::{crypt, key::KeyDerivationParams},
};

/// Complete v2 file header.
///
/// The layout matches v1 byte for byte, but the version byte is 2 and the
/// fixed fields are authenticated: they are bound as associated data to both
/// AEAD operations via [`HeaderBinding`].
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub magic: [u8; 6],                  // 6 bytes: "SHADOW"
    pub version: u8,                     // 1 byte: Version number (2)
    pub header_length: u32,              // 4 byte: Total header size
    pub salt: [u8; 16],                  // 16 bytes: Argon2id salt
    pub kdf_memory: u32,                 // 4 bytes: Argon2id memory parameter
    pub kdf_iterations: u32,             // 4 bytes: Argon2id iterations parameter
    pub kdf_parallelism: u32,            // 4 bytes: Argon2id parallelism parameter
    pub kdf_key_length: u8,              // 1 byte: XChaCha20 key length
    pub content_nonce: [u8; 24],         // 24 bytes: XChaCha20 nonce
    pub filename_nonce: [u8; 24],        // 24 bytes: XChaCha20 nonce for filename
    pub filename_ciphertext_length: u16, // 2 bytes: Length of encrypted filename ciphertext
    pub filename_ciphertext: Vec<u8>,    // Encrypted filename ciphertext (variable length)
}

pub const MAGIC: [u8; 6] = *b"SHADOW";
pub const VERSION: u8 = 2;

impl FileHeader {
    /// Builds a v2 header. Fails with [`HeaderError::FilenameTooLong`] if the
    /// filename ciphertext does not fit the u16 length field, instead of
    /// silently truncating.
    pub fn new(
        salt: [u8; 16],
        kdf_params: KeyDerivationParams,
        content_nonce: [u8; 24],
        filename_nonce: [u8; 24],
        filename_ciphertext: Vec<u8>,
    ) -> Result<Self, HeaderError> {
        let filename_ciphertext_length: u16 = filename_ciphertext
            .len()
            .try_into()
            .map_err(|_| HeaderError::FilenameTooLong)?;
        let size = Self::min_length() + filename_ciphertext.len();

        Ok(FileHeader {
            magic: MAGIC,
            version: VERSION,
            header_length: size as u32,
            salt,
            kdf_memory: kdf_params.memory_cost,
            kdf_iterations: kdf_params.time_cost,
            kdf_parallelism: kdf_params.parallelism,
            kdf_key_length: kdf_params.key_size,
            content_nonce,
            filename_nonce,
            filename_ciphertext_length,
            filename_ciphertext,
        })
    }

    /// Minimum length of the header without the variable-length filename ciphertext.
    /// Changing the fixed fields above requires updating this value.
    pub const fn min_length() -> usize {
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

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(self.magic.as_slice());
        bytes.push(self.version);
        bytes.extend_from_slice(self.header_length.to_le_bytes().as_slice());
        bytes.extend_from_slice(self.salt.as_slice());
        bytes.extend_from_slice(self.kdf_memory.to_le_bytes().as_slice());
        bytes.extend_from_slice(self.kdf_iterations.to_le_bytes().as_slice());
        bytes.extend_from_slice(self.kdf_parallelism.to_le_bytes().as_slice());
        bytes.push(self.kdf_key_length);
        bytes.extend_from_slice(self.content_nonce.as_slice());
        bytes.extend_from_slice(self.filename_nonce.as_slice());
        bytes.extend_from_slice(self.filename_ciphertext_length.to_le_bytes().as_slice());
        bytes.extend_from_slice(self.filename_ciphertext.as_slice());

        bytes
    }

    /// Reads the total header length out of the fixed header fields, so a
    /// caller can learn how many bytes to feed to [`FileHeader::try_deserialize`]
    /// without knowing the header layout.
    pub fn read_header_length(bytes: &[u8]) -> Result<u32, HeaderError> {
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

    pub fn try_deserialize(bytes: &[u8]) -> Result<FileHeader, HeaderError> {
        if bytes.len() < FileHeader::min_length() {
            return Err(HeaderError::InsufficientBytes);
        }

        let length: u32 = Self::read_header_length(bytes)?;

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

    /// The key derivation parameters recorded in this header.
    pub fn kdf_params(&self) -> KeyDerivationParams {
        KeyDerivationParams {
            memory_cost: self.kdf_memory,
            time_cost: self.kdf_iterations,
            parallelism: self.kdf_parallelism,
            key_size: self.kdf_key_length,
        }
    }

    /// Decrypts the original filename stored in this header, verifying the
    /// header binding under the filename domain.
    pub fn decrypt_filename(&self, key: &SecureKey) -> Result<SecureString, FileError> {
        let (filename_bytes, _) = crypt::decrypt_bytes(
            &self.filename_ciphertext,
            key.as_bytes(),
            &self.filename_nonce,
            &self.binding().aad(AadPurpose::Filename),
        )?;
        let filename = String::from_utf8(filename_bytes.as_slice().to_vec())
            .map_err(|_| FileError::InvalidFilename)?;
        Ok(SecureString::new(filename))
    }

    /// The header binding used as associated data for this header's AEAD
    /// operations.
    pub fn binding(&self) -> HeaderBinding<'_> {
        HeaderBinding {
            salt: &self.salt,
            kdf_memory: self.kdf_memory,
            kdf_iterations: self.kdf_iterations,
            kdf_parallelism: self.kdf_parallelism,
            kdf_key_length: self.kdf_key_length,
            content_nonce: &self.content_nonce,
            filename_nonce: &self.filename_nonce,
        }
    }
}

/// Which ciphertext an AEAD operation belongs to.
///
/// The purpose is mixed into the associated data, giving the filename and
/// content ciphertexts distinct domains: a ciphertext produced for one
/// purpose can never authenticate for the other, even under the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AadPurpose {
    Filename,
    Content,
}

impl AadPurpose {
    fn domain_tag(self) -> &'static [u8] {
        match self {
            AadPurpose::Filename => b"shadow-crypt/v2/filename",
            AadPurpose::Content => b"shadow-crypt/v2/content",
        }
    }
}

/// The fixed header fields bound as associated data to every v2 AEAD
/// operation.
///
/// This exists separately from [`FileHeader`] because on encryption the
/// associated data is needed *before* the header can be built (the header
/// contains the filename ciphertext, which is itself AEAD-encrypted under
/// this binding).
///
/// The variable-length fields (`header_length`, `filename_ciphertext_length`,
/// and the filename ciphertext itself) are deliberately excluded: they depend
/// on the filename encryption output, and tampering with them is already
/// detected — a shifted length changes which bytes are interpreted as
/// ciphertext, which fails authentication.
#[derive(Debug, Clone, Copy)]
pub struct HeaderBinding<'a> {
    pub salt: &'a [u8; 16],
    pub kdf_memory: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub kdf_key_length: u8,
    pub content_nonce: &'a [u8; 24],
    pub filename_nonce: &'a [u8; 24],
}

impl<'a> HeaderBinding<'a> {
    pub fn new(
        salt: &'a [u8; 16],
        kdf_params: &KeyDerivationParams,
        content_nonce: &'a [u8; 24],
        filename_nonce: &'a [u8; 24],
    ) -> Self {
        Self {
            salt,
            kdf_memory: kdf_params.memory_cost,
            kdf_iterations: kdf_params.time_cost,
            kdf_parallelism: kdf_params.parallelism,
            kdf_key_length: kdf_params.key_size,
            content_nonce,
            filename_nonce,
        }
    }

    /// Serializes the binding into the associated data for one AEAD
    /// operation. Field order mirrors the header serialization.
    pub fn aad(&self, purpose: AadPurpose) -> Vec<u8> {
        let mut aad = Vec::with_capacity(FileHeader::min_length() + 24);
        aad.extend_from_slice(&MAGIC);
        aad.push(VERSION);
        aad.extend_from_slice(self.salt);
        aad.extend_from_slice(&self.kdf_memory.to_le_bytes());
        aad.extend_from_slice(&self.kdf_iterations.to_le_bytes());
        aad.extend_from_slice(&self.kdf_parallelism.to_le_bytes());
        aad.push(self.kdf_key_length);
        aad.extend_from_slice(self.content_nonce);
        aad.extend_from_slice(self.filename_nonce);
        aad.extend_from_slice(purpose.domain_tag());
        aad
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile;

    fn get_test_params() -> KeyDerivationParams {
        KeyDerivationParams::from(profile::SecurityProfile::Test)
    }

    fn create_test_header() -> FileHeader {
        FileHeader::new(
            [1u8; 16],
            get_test_params(),
            [2u8; 24],
            [3u8; 24],
            vec![4, 5, 6, 7, 8],
        )
        .unwrap()
    }

    #[test]
    fn default_values_are_correct() {
        let header = FileHeader::new(
            [0u8; 16],
            get_test_params(),
            [0u8; 24],
            [0u8; 24],
            vec![1, 2, 3, 4],
        )
        .unwrap();

        assert_eq!(&header.magic, b"SHADOW");
        assert_eq!(header.version, 2);
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
        )
        .unwrap();

        let expected_size: u32 = 90 + filename_ciphertext.len() as u32;
        assert_eq!(header.header_length, expected_size);
    }

    #[test]
    fn oversized_filename_ciphertext_is_rejected() {
        let filename_ciphertext = vec![0u8; u16::MAX as usize + 1];
        let result = FileHeader::new(
            [0u8; 16],
            get_test_params(),
            [0u8; 24],
            [0u8; 24],
            filename_ciphertext,
        );
        assert!(matches!(result, Err(HeaderError::FilenameTooLong)));
    }

    #[test]
    fn max_length_filename_ciphertext_is_accepted() {
        let filename_ciphertext = vec![0u8; u16::MAX as usize];
        let header = FileHeader::new(
            [0u8; 16],
            get_test_params(),
            [0u8; 24],
            [0u8; 24],
            filename_ciphertext,
        )
        .unwrap();
        assert_eq!(header.filename_ciphertext_length, u16::MAX);
    }

    #[test]
    fn aad_differs_by_purpose() {
        let salt = [1u8; 16];
        let params = get_test_params();
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let binding = HeaderBinding::new(&salt, &params, &content_nonce, &filename_nonce);

        assert_ne!(
            binding.aad(AadPurpose::Filename),
            binding.aad(AadPurpose::Content)
        );
    }

    #[test]
    fn header_binding_matches_standalone_binding() {
        let salt = [1u8; 16];
        let params = get_test_params();
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];

        let standalone = HeaderBinding::new(&salt, &params, &content_nonce, &filename_nonce);
        let header =
            FileHeader::new(salt, params, content_nonce, filename_nonce, vec![1, 2, 3]).unwrap();

        assert_eq!(
            standalone.aad(AadPurpose::Content),
            header.binding().aad(AadPurpose::Content)
        );
        assert_eq!(
            standalone.aad(AadPurpose::Filename),
            header.binding().aad(AadPurpose::Filename)
        );
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
        )
        .unwrap();
        assert_eq!(header.kdf_params(), params);
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = create_test_header();
        let serialized = original.serialize();
        assert_eq!(serialized.len(), original.header_length as usize);
        assert_eq!(&serialized[0..6], b"SHADOW");
        assert_eq!(serialized[6], 2);

        let deserialized = FileHeader::try_deserialize(&serialized).unwrap();
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
        assert_eq!(
            deserialized.filename_ciphertext,
            original.filename_ciphertext
        );
    }

    #[test]
    fn test_try_deserialize_rejects_wrong_version() {
        let mut serialized = create_test_header().serialize();
        serialized[6] = 1; // claim v1

        assert!(FileHeader::try_deserialize(&serialized).is_err());
    }

    #[test]
    fn test_try_deserialize_rejects_wrong_magic() {
        let mut serialized = create_test_header().serialize();
        serialized[0..6].copy_from_slice(b"NOTSHD");

        assert!(FileHeader::try_deserialize(&serialized).is_err());
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
    fn test_try_deserialize_inconsistent_lengths() {
        let mut serialized = create_test_header().serialize();
        // header_length no longer matches min_length + filename_ciphertext_length
        serialized[7..11].copy_from_slice(&(200u32.to_le_bytes()));

        assert!(FileHeader::try_deserialize(&serialized).is_err());
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

        let deserialized = FileHeader::try_deserialize(&header.serialize()).unwrap();
        assert_eq!(deserialized.filename_ciphertext_length, 0);
        assert!(deserialized.filename_ciphertext.is_empty());
    }
}
