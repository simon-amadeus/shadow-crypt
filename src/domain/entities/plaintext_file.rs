//! PlaintextFile Entity
//!
//! Immutable representation of plaintext file data ready for encryption.
//! Performs no I/O operations and has no side effects.

use std::path::{Path, PathBuf};
use crate::domain::entities::metadata::FileMetadata;
use sha2::{Sha256, Digest};

/// Immutable plaintext file entity for encryption workflows
#[derive(Debug, Clone)]
pub struct PlaintextFile {
    path: PathBuf,
    content: Vec<u8>,
    metadata: FileMetadata,
    content_hash: [u8; 32],
}

impl PlaintextFile {
    /// Creates a new PlaintextFile from loaded data
    pub fn new(path: PathBuf, content: Vec<u8>, metadata: FileMetadata) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let content_hash: [u8; 32] = hasher.finalize().into();

        Self {
            path,
            content,
            metadata,
            content_hash,
        }
    }

    /// Returns the content hash
    pub fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }

    /// Returns the file size in bytes
    pub fn size(&self) -> usize {
        self.content.len()
    }

    /// Returns the original file path
    pub fn original_path(&self) -> &Path {
        &self.path
    }

    /// Returns the file metadata
    pub fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }

    /// Returns the file content
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// Returns true if the file content is empty
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Returns the filename without path
    pub fn filename(&self) -> Option<&str> {
        self.path.file_name()?.to_str()
    }

    /// Returns the file extension
    pub fn extension(&self) -> Option<&str> {
        self.path.extension()?.to_str()
    }

    /// Verifies content integrity against stored hash
    pub fn verify_integrity(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.content);
        let computed_hash: [u8; 32] = hasher.finalize().into();
        computed_hash == self.content_hash
    }

    /// Returns content hash as hex string
    pub fn content_hash_hex(&self) -> String {
        self.content_hash
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }

    /// Compares content equality via hash
    pub fn content_equals(&self, other: &Self) -> bool {
        self.content_hash == other.content_hash
    }
}