use crate::{
    errors::{CryptError, FileError, HeaderError},
    file::{FileMetadata, PlaintextFile},
    memory::{SecureBytes, SecureKey},
    v3::{
        key::KeyDerivationParams,
        stream::{StreamOpener, StreamSealer},
    },
};

use super::header::FileHeader;

/// Represents a complete encrypted file with header and content.
///
/// This is the whole-bytes convenience over the streaming API in
/// [`crate::v3::stream`]; callers that cannot hold the content in memory
/// should drive [`StreamSealer`]/[`StreamOpener`] directly.
#[derive(Debug)]
pub struct EncryptedFile {
    header: FileHeader,
    ciphertext: Vec<u8>,
}

impl EncryptedFile {
    pub fn new(header: FileHeader, ciphertext: Vec<u8>) -> Self {
        Self { header, ciphertext }
    }

    /// Encrypts metadata and content into a complete v3 encrypted file.
    ///
    /// The caller supplies the key (derived from `kdf_params` and `salt`) and
    /// fresh random salt/nonces, keeping this function deterministic.
    pub fn seal(
        metadata: &FileMetadata,
        content: &[u8],
        key: &SecureKey,
        kdf_params: KeyDerivationParams,
        salt: [u8; 16],
        nonce_prefix: [u8; 16],
        metadata_nonce: [u8; 24],
    ) -> Result<Self, FileError> {
        let (header, mut sealer) = StreamSealer::begin(
            metadata,
            key,
            kdf_params,
            salt,
            nonce_prefix,
            metadata_nonce,
        )?;

        let chunk_size = sealer.chunk_plaintext_len();
        let pieces: Vec<&[u8]> = if content.is_empty() {
            vec![&[][..]]
        } else {
            content.chunks(chunk_size).collect()
        };

        let mut ciphertext = Vec::with_capacity(content.len() + pieces.len() * 16);
        for (i, piece) in pieces.iter().enumerate() {
            ciphertext.extend_from_slice(&sealer.seal_chunk(piece, i == pieces.len() - 1)?);
        }

        Ok(Self::new(header, ciphertext))
    }

    /// Parses a serialized v3 file into its header and content ciphertext.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderError> {
        let header = FileHeader::try_deserialize(bytes)?;
        let ciphertext = bytes[header.header_length()..].to_vec();

        Ok(Self::new(header, ciphertext))
    }

    /// Serializes the complete file (header followed by content ciphertext).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.serialize();
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Decrypts the metadata and the full content stream. The inverse of
    /// [`EncryptedFile::seal`].
    pub fn decrypt(&self, key: &SecureKey) -> Result<PlaintextFile, FileError> {
        let metadata = self.header.decrypt_metadata(key)?;

        let mut opener = StreamOpener::new(&self.header, key);
        let piece_len = opener.chunk_ciphertext_len();
        if self.ciphertext.is_empty() {
            return Err(FileError::Crypt(CryptError::DecryptionError(
                "invalid content stream: missing final chunk".to_string(),
            )));
        }

        let pieces: Vec<&[u8]> = self.ciphertext.chunks(piece_len).collect();
        let mut content = Vec::with_capacity(self.ciphertext.len());
        for (i, piece) in pieces.iter().enumerate() {
            let plaintext = opener.open_chunk(piece, i == pieces.len() - 1)?;
            content.extend_from_slice(plaintext.as_slice());
        }

        Ok(PlaintextFile::new(
            metadata.filename().clone(),
            SecureBytes::new(content),
        ))
    }

    pub fn header(&self) -> &FileHeader {
        &self.header
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}
