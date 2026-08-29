//! Version-independent file types.
//!
//! [`PlaintextFile`] is the decrypted *output* shape shared by every format
//! version. It carries no format-specific information, so sharing it does not
//! couple the version modules to each other (unlike format-defining code,
//! which is duplicated per version on purpose).

use std::time::SystemTime;

use crate::memory::{SecureBytes, SecureString};

/// What an encrypted file's content stream contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    /// The content is the bytes of a single file.
    File,
    /// The content is a [`crate::archive`] stream holding a directory tree.
    Archive,
}

/// Metadata of a plaintext file, stored encrypted alongside the content.
///
/// Which fields a format version actually preserves varies: v1/v2 store only
/// the filename, v3 stores everything. Absent fields are `None`.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    filename: SecureString,
    mtime: Option<SystemTime>,
    mode: Option<u32>, // Unix permission bits
    kind: ContentKind,
}

impl FileMetadata {
    pub fn new(filename: SecureString, mtime: Option<SystemTime>, mode: Option<u32>) -> Self {
        Self {
            filename,
            mtime,
            mode,
            kind: ContentKind::File,
        }
    }

    /// Marks this metadata as describing an archive (directory tree) rather
    /// than a single file. For archives, `filename` is the directory name.
    pub fn into_archive(mut self) -> Self {
        self.kind = ContentKind::Archive;
        self
    }

    pub fn filename(&self) -> &SecureString {
        &self.filename
    }
    pub fn mtime(&self) -> Option<SystemTime> {
        self.mtime
    }
    pub fn mode(&self) -> Option<u32> {
        self.mode
    }
    pub fn kind(&self) -> ContentKind {
        self.kind
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
