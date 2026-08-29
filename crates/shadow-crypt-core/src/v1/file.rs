use crate::{
    errors::{FileError, HeaderError},
    memory::{SecureBytes, SecureKey, SecureString},
    v1::crypt,
};

use super::header::FileHeader;

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

    /// Parses a serialized v1 file into its header and content ciphertext.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderError> {
        let header = FileHeader::try_deserialize(bytes)?;
        let header_length = header.header_length as usize;

        let ciphertext = bytes[header_length..].to_vec();

        Ok(Self::new(header, ciphertext))
    }

    /// Serializes the complete file (header followed by content ciphertext).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.serialize();
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Decrypts the filename and content. v1 has no header authentication,
    /// so only the AEAD tags of the two ciphertexts are verified.
    pub fn decrypt(&self, key: &SecureKey) -> Result<PlaintextFile, FileError> {
        let filename = self.header.decrypt_filename(key)?;

        let (content, _) =
            crypt::decrypt_bytes(&self.ciphertext, key.as_bytes(), &self.header.content_nonce)?;

        Ok(PlaintextFile::new(filename, content))
    }

    pub fn header(&self) -> &FileHeader {
        &self.header
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Represents a plaintext file with filename and content
#[derive(Debug)]
pub struct PlaintextFile {
    filename: SecureString, // Decrypted filename
    content: SecureBytes,   // Decrypted file content
}

impl PlaintextFile {
    pub fn new(filename: SecureString, content: SecureBytes) -> Self {
        Self { filename, content }
    }
    pub fn filename(&self) -> &SecureString {
        &self.filename
    }
    pub fn content(&self) -> &SecureBytes {
        &self.content
    }
}
