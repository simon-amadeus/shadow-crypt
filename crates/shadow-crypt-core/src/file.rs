//! Version-independent file types.
//!
//! [`PlaintextFile`] is the decrypted *output* shape shared by every format
//! version. It carries no format-specific information, so sharing it does not
//! couple the version modules to each other (unlike format-defining code,
//! which is duplicated per version on purpose).

use crate::memory::{SecureBytes, SecureString};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_file_accessors() {
        let file = PlaintextFile::new(
            SecureString::new("a.txt".to_string()),
            SecureBytes::new(vec![1, 2, 3]),
        );
        assert_eq!(file.filename().as_str(), "a.txt");
        assert_eq!(file.content().as_slice(), &[1, 2, 3]);
    }
}
