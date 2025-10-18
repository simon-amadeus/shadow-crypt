use crate::memory::SecureBytes;

use super::header::FileHeader;

/// Represents a complete encrypted file with header and content
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    filename: String,
    header: FileHeader,
    ciphertext: Vec<u8>,
}

impl EncryptedFile {
    pub fn new(filename: String, header: FileHeader, ciphertext: Vec<u8>) -> Self {
        Self {
            filename,
            header,
            ciphertext,
        }
    }
    pub fn filename(&self) -> &String {
        &self.filename
    }
    pub fn header(&self) -> &FileHeader {
        &self.header
    }
    pub fn ciphertext(&self) -> &Vec<u8> {
        &self.ciphertext
    }
}

/// Represents a plaintext file with filename and content
#[derive(Debug, Clone)]
pub struct PlaintextFile {
    filename: String,     // Decrypted filename
    content: SecureBytes, // Decrypted file content
}

impl PlaintextFile {
    pub fn new(filename: String, content: SecureBytes) -> Self {
        Self { filename, content }
    }

    pub fn filename(&self) -> &String {
        &self.filename
    }

    pub fn content(&self) -> &SecureBytes {
        &self.content
    }
}
