use crate::{
    errors::{FileError, HeaderError},
    file::PlaintextFile,
    memory::SecureKey,
    v2::crypt,
};

use super::header::{AadPurpose, FileHeader, HeaderBinding};

/// Represents a complete encrypted file with header and content
#[derive(Debug)]
pub struct EncryptedFile {
    header: FileHeader,
    ciphertext: Vec<u8>,
}

impl EncryptedFile {
    pub fn new(header: FileHeader, ciphertext: Vec<u8>) -> Self {
        Self { header, ciphertext }
    }

    /// Encrypts a plaintext file into a complete v2 encrypted file.
    ///
    /// This owns the v2 AEAD choreography: the fixed header fields are bound
    /// as associated data to both ciphertexts, with distinct domains for
    /// filename and content, so neither the header nor the pairing of the two
    /// ciphertexts can be tampered with undetected.
    ///
    /// The caller supplies the key (derived from `kdf_params` and `salt`) and
    /// fresh random salt/nonces, keeping this function deterministic.
    pub fn seal(
        plaintext_file: &PlaintextFile,
        key: &SecureKey,
        kdf_params: super::key::KeyDerivationParams,
        salt: [u8; 16],
        content_nonce: [u8; 24],
        filename_nonce: [u8; 24],
    ) -> Result<Self, FileError> {
        let binding = HeaderBinding::new(&salt, &kdf_params, &content_nonce, &filename_nonce);

        let (filename_ciphertext, _) = crypt::encrypt_bytes(
            plaintext_file.filename().as_str().as_bytes(),
            key.as_bytes(),
            &filename_nonce,
            &binding.aad(AadPurpose::Filename),
        )?;

        let (content_ciphertext, _) = crypt::encrypt_bytes(
            plaintext_file.content().as_slice(),
            key.as_bytes(),
            &content_nonce,
            &binding.aad(AadPurpose::Content),
        )?;

        let header = FileHeader::new(
            salt,
            kdf_params,
            content_nonce,
            filename_nonce,
            filename_ciphertext,
        )?;

        Ok(Self::new(header, content_ciphertext))
    }

    /// Parses a serialized v2 file into its header and content ciphertext.
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

    /// Decrypts the filename and content, verifying the header binding under
    /// each ciphertext's own domain. The inverse of [`EncryptedFile::seal`].
    pub fn decrypt(&self, key: &SecureKey) -> Result<PlaintextFile, FileError> {
        let filename = self.header.decrypt_filename(key)?;

        let (content, _) = crypt::decrypt_bytes(
            &self.ciphertext,
            key.as_bytes(),
            self.header.content_nonce(),
            &self.header.binding().aad(AadPurpose::Content),
        )?;

        Ok(PlaintextFile::new(filename, content))
    }

    pub fn header(&self) -> &FileHeader {
        &self.header
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}
