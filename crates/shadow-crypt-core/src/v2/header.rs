use crate::{errors::HeaderError, v2::key::KeyDerivationParams};

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
    pub fn min_length() -> usize {
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
        let header = FileHeader::new(salt, params, content_nonce, filename_nonce, vec![1, 2, 3])
            .unwrap();

        assert_eq!(
            standalone.aad(AadPurpose::Content),
            header.binding().aad(AadPurpose::Content)
        );
        assert_eq!(
            standalone.aad(AadPurpose::Filename),
            header.binding().aad(AadPurpose::Filename)
        );
    }
}
