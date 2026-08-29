use crate::{
    errors::{FileError, HeaderError},
    file::FileMetadata,
    memory::SecureKey,
    v3::{crypt, key::KeyDerivationParams, metadata},
};

/// Complete v3 file header.
///
/// Differences from v2: the content is encrypted as a sequence of AEAD
/// chunks (see [`crate::v3::stream`]) using a 16-byte nonce prefix stored
/// here, and the bare filename ciphertext is replaced by an encrypted
/// metadata envelope carrying the filename plus optional mtime and Unix
/// mode. All fixed fields are authenticated as associated data via
/// [`HeaderBinding`], with distinct domains for metadata and content.
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
/// | version (3)                | 1 byte   |
/// | header_length              | 4 bytes  |
/// | salt                       | 16 bytes |
/// | kdf_memory                 | 4 bytes  |
/// | kdf_iterations             | 4 bytes  |
/// | kdf_parallelism            | 4 bytes  |
/// | kdf_key_length             | 1 byte   |
/// | nonce_prefix               | 16 bytes |
/// | chunk_size                 | 4 bytes  |
/// | metadata_nonce             | 24 bytes |
/// | metadata_ciphertext_length | 2 bytes  |
/// | metadata_ciphertext        | variable |
#[derive(Debug, Clone)]
pub struct FileHeader {
    salt: [u8; 16],
    kdf_params: KeyDerivationParams,
    nonce_prefix: [u8; 16],
    chunk_size: u32,
    metadata_nonce: [u8; 24],
    metadata_ciphertext: Vec<u8>,
}

pub const MAGIC: [u8; 6] = *b"SHADOW";
pub const VERSION: u8 = 3;

/// Largest chunk size accepted when parsing a header. Bounds the per-chunk
/// allocation a crafted file can request.
pub const MAX_ACCEPTED_CHUNK_SIZE: u32 = 64 * 1024 * 1024; // 64 MiB

impl FileHeader {
    /// Builds a v3 header. Fails with [`HeaderError::MetadataTooLong`] if the
    /// metadata ciphertext does not fit the u16 length field, and with
    /// [`HeaderError::InvalidData`] for a chunk size outside
    /// `1..=MAX_ACCEPTED_CHUNK_SIZE`.
    pub fn new(
        salt: [u8; 16],
        kdf_params: KeyDerivationParams,
        nonce_prefix: [u8; 16],
        chunk_size: u32,
        metadata_nonce: [u8; 24],
        metadata_ciphertext: Vec<u8>,
    ) -> Result<Self, HeaderError> {
        if u16::try_from(metadata_ciphertext.len()).is_err() {
            return Err(HeaderError::MetadataTooLong);
        }
        if chunk_size == 0 || chunk_size > MAX_ACCEPTED_CHUNK_SIZE {
            return Err(HeaderError::InvalidData);
        }

        Ok(FileHeader {
            salt,
            kdf_params,
            nonce_prefix,
            chunk_size,
            metadata_nonce,
            metadata_ciphertext,
        })
    }

    /// Minimum length of the serialized header without the variable-length
    /// metadata ciphertext. Changing the layout requires updating this value.
    pub(crate) const fn min_length() -> usize {
        6  // magic ("SHADOW")
        + 1  // version (u8)
        + 4  // header_length (u32)
        + 16 // salt ([u8; 16])
        + 4  // kdf_memory (u32)
        + 4  // kdf_iterations (u32)
        + 4  // kdf_parallelism (u32)
        + 1  // kdf_key_length (u8)
        + 16 // nonce_prefix ([u8; 16])
        + 4  // chunk_size (u32)
        + 24 // metadata_nonce ([u8; 24])
        + 2 // metadata_ciphertext_length (u16)
    }

    /// Total length of this header's serialized form.
    pub fn header_length(&self) -> usize {
        Self::min_length() + self.metadata_ciphertext.len()
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
        bytes.extend_from_slice(&self.nonce_prefix);
        bytes.extend_from_slice(&self.chunk_size.to_le_bytes());
        bytes.extend_from_slice(&self.metadata_nonce);
        bytes.extend_from_slice(&(self.metadata_ciphertext.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.metadata_ciphertext);

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
        let magic: [u8; 6] = bytes[0..6].try_into().ok()?;
        let version = bytes[6];

        if magic != MAGIC || version != VERSION {
            return None;
        }

        let header_length = u32::from_le_bytes(bytes[7..11].try_into().ok()?);
        let salt = bytes[11..27].try_into().ok()?;
        let kdf_memory = u32::from_le_bytes(bytes[27..31].try_into().ok()?);
        let kdf_iterations = u32::from_le_bytes(bytes[31..35].try_into().ok()?);
        let kdf_parallelism = u32::from_le_bytes(bytes[35..39].try_into().ok()?);
        let kdf_key_length = bytes[39];
        let nonce_prefix = bytes[40..56].try_into().ok()?;
        let chunk_size = u32::from_le_bytes(bytes[56..60].try_into().ok()?);
        let metadata_nonce = bytes[60..84].try_into().ok()?;
        let metadata_ciphertext_length = u16::from_le_bytes(bytes[84..86].try_into().ok()?);

        if chunk_size == 0 || chunk_size > MAX_ACCEPTED_CHUNK_SIZE {
            return None;
        }

        let expected_length: usize = FileHeader::min_length() + metadata_ciphertext_length as usize;

        if header_length != expected_length as u32 {
            return None;
        }

        if bytes.len() < expected_length {
            return None;
        }

        let metadata_ciphertext = bytes[FileHeader::min_length()..expected_length].to_vec();

        Some(FileHeader {
            salt,
            kdf_params: KeyDerivationParams::new(
                kdf_memory,
                kdf_iterations,
                kdf_parallelism,
                kdf_key_length,
            ),
            nonce_prefix,
            chunk_size,
            metadata_nonce,
            metadata_ciphertext,
        })
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// The key derivation parameters recorded in this header.
    pub fn kdf_params(&self) -> &KeyDerivationParams {
        &self.kdf_params
    }

    pub fn nonce_prefix(&self) -> &[u8; 16] {
        &self.nonce_prefix
    }

    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub fn metadata_nonce(&self) -> &[u8; 24] {
        &self.metadata_nonce
    }

    pub fn metadata_ciphertext(&self) -> &[u8] {
        &self.metadata_ciphertext
    }

    /// Decrypts and parses the metadata envelope stored in this header,
    /// verifying the header binding under the metadata domain.
    pub fn decrypt_metadata(&self, key: &SecureKey) -> Result<FileMetadata, FileError> {
        let (envelope, _) = crypt::decrypt_bytes(
            &self.metadata_ciphertext,
            key.as_bytes(),
            &self.metadata_nonce,
            &self.binding().aad(AadPurpose::Metadata),
        )?;
        metadata::parse(envelope.as_slice())
    }

    /// The header binding used as associated data for this header's AEAD
    /// operations.
    pub fn binding(&self) -> HeaderBinding<'_> {
        HeaderBinding {
            salt: &self.salt,
            kdf_params: &self.kdf_params,
            nonce_prefix: &self.nonce_prefix,
            chunk_size: self.chunk_size,
            metadata_nonce: &self.metadata_nonce,
        }
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

/// Which ciphertext an AEAD operation belongs to.
///
/// The purpose is mixed into the associated data, giving the metadata
/// envelope and the content chunks distinct domains: a ciphertext produced
/// for one purpose can never authenticate for the other, even under the
/// same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AadPurpose {
    Metadata,
    Content,
}

impl AadPurpose {
    fn domain_tag(self) -> &'static [u8] {
        match self {
            AadPurpose::Metadata => b"shadow-crypt/v3/metadata",
            AadPurpose::Content => b"shadow-crypt/v3/content",
        }
    }
}

/// The fixed header fields bound as associated data to every v3 AEAD
/// operation.
///
/// This exists separately from [`FileHeader`] because on encryption the
/// associated data is needed *before* the header can be built (the header
/// contains the metadata ciphertext, which is itself AEAD-encrypted under
/// this binding).
///
/// The variable-length fields (`header_length`, `metadata_ciphertext_length`,
/// and the metadata ciphertext itself) are deliberately excluded: they depend
/// on the metadata encryption output, and tampering with them is already
/// detected — a shifted length changes which bytes are interpreted as
/// ciphertext, which fails authentication.
#[derive(Debug, Clone, Copy)]
pub struct HeaderBinding<'a> {
    salt: &'a [u8; 16],
    kdf_params: &'a KeyDerivationParams,
    nonce_prefix: &'a [u8; 16],
    chunk_size: u32,
    metadata_nonce: &'a [u8; 24],
}

impl<'a> HeaderBinding<'a> {
    pub fn new(
        salt: &'a [u8; 16],
        kdf_params: &'a KeyDerivationParams,
        nonce_prefix: &'a [u8; 16],
        chunk_size: u32,
        metadata_nonce: &'a [u8; 24],
    ) -> Self {
        Self {
            salt,
            kdf_params,
            nonce_prefix,
            chunk_size,
            metadata_nonce,
        }
    }

    /// Serializes the binding into the associated data for one AEAD
    /// operation. Field order mirrors the header serialization.
    pub fn aad(&self, purpose: AadPurpose) -> Vec<u8> {
        let mut aad = Vec::with_capacity(FileHeader::min_length() + 24);
        aad.extend_from_slice(&MAGIC);
        aad.push(VERSION);
        aad.extend_from_slice(self.salt);
        aad.extend_from_slice(&self.kdf_params.memory_cost.to_le_bytes());
        aad.extend_from_slice(&self.kdf_params.time_cost.to_le_bytes());
        aad.extend_from_slice(&self.kdf_params.parallelism.to_le_bytes());
        aad.push(self.kdf_params.key_size);
        aad.extend_from_slice(self.nonce_prefix);
        aad.extend_from_slice(&self.chunk_size.to_le_bytes());
        aad.extend_from_slice(self.metadata_nonce);
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
            [2u8; 16],
            1024,
            [3u8; 24],
            vec![4, 5, 6, 7, 8],
        )
        .unwrap()
    }

    #[test]
    fn serialized_magic_and_version_are_correct() {
        let serialized = create_test_header().serialize();
        assert_eq!(&serialized[0..6], b"SHADOW");
        assert_eq!(serialized[6], 3);
    }

    #[test]
    fn header_size_is_calculated_correctly() {
        let header = create_test_header();
        assert_eq!(header.header_length(), 86 + 5);
        assert_eq!(header.serialize().len(), header.header_length());
    }

    #[test]
    fn oversized_metadata_ciphertext_is_rejected() {
        let result = FileHeader::new(
            [0u8; 16],
            get_test_params(),
            [0u8; 16],
            1024,
            [0u8; 24],
            vec![0u8; u16::MAX as usize + 1],
        );
        assert!(matches!(result, Err(HeaderError::MetadataTooLong)));
    }

    #[test]
    fn invalid_chunk_sizes_are_rejected() {
        for chunk_size in [0, MAX_ACCEPTED_CHUNK_SIZE + 1] {
            let result = FileHeader::new(
                [0u8; 16],
                get_test_params(),
                [0u8; 16],
                chunk_size,
                [0u8; 24],
                vec![1, 2, 3],
            );
            assert!(matches!(result, Err(HeaderError::InvalidData)));
        }
    }

    #[test]
    fn oversized_chunk_size_is_rejected_at_parse_time() {
        let mut serialized = create_test_header().serialize();
        serialized[56..60].copy_from_slice(&(MAX_ACCEPTED_CHUNK_SIZE + 1).to_le_bytes());
        assert!(FileHeader::try_deserialize(&serialized).is_err());
    }

    #[test]
    fn aad_differs_by_purpose() {
        let salt = [1u8; 16];
        let params = get_test_params();
        let nonce_prefix = [2u8; 16];
        let metadata_nonce = [3u8; 24];
        let binding = HeaderBinding::new(&salt, &params, &nonce_prefix, 1024, &metadata_nonce);

        assert_ne!(
            binding.aad(AadPurpose::Metadata),
            binding.aad(AadPurpose::Content)
        );
    }

    #[test]
    fn header_binding_matches_standalone_binding() {
        let salt = [1u8; 16];
        let params = get_test_params();
        let nonce_prefix = [2u8; 16];
        let metadata_nonce = [3u8; 24];

        let standalone = HeaderBinding::new(&salt, &params, &nonce_prefix, 1024, &metadata_nonce);
        let header = FileHeader::new(
            salt,
            params.clone(),
            nonce_prefix,
            1024,
            metadata_nonce,
            vec![1, 2, 3],
        )
        .unwrap();

        assert_eq!(
            standalone.aad(AadPurpose::Content),
            header.binding().aad(AadPurpose::Content)
        );
        assert_eq!(
            standalone.aad(AadPurpose::Metadata),
            header.binding().aad(AadPurpose::Metadata)
        );
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = create_test_header();
        let serialized = original.serialize();
        assert_eq!(serialized.len(), original.header_length());

        let deserialized = FileHeader::try_deserialize(&serialized).unwrap();
        assert_eq!(deserialized.salt(), original.salt());
        assert_eq!(deserialized.kdf_params(), original.kdf_params());
        assert_eq!(deserialized.nonce_prefix(), original.nonce_prefix());
        assert_eq!(deserialized.chunk_size(), original.chunk_size());
        assert_eq!(deserialized.metadata_nonce(), original.metadata_nonce());
        assert_eq!(
            deserialized.metadata_ciphertext(),
            original.metadata_ciphertext()
        );
    }

    #[test]
    fn test_try_deserialize_rejects_wrong_version() {
        let mut serialized = create_test_header().serialize();
        serialized[6] = 2; // claim v2

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
        // header_length no longer matches min_length + metadata_ciphertext_length
        serialized[7..11].copy_from_slice(&(200u32.to_le_bytes()));

        assert!(FileHeader::try_deserialize(&serialized).is_err());
    }
}
