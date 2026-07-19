use crate::memory::{SecureBytes, SecureString};

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
    pub fn header(&self) -> &FileHeader {
        &self.header
    }
    pub fn ciphertext(&self) -> &Vec<u8> {
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
