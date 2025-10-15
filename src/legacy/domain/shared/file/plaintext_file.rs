//! Plaintext file entity.
//!
//! Immutable representation of plaintext file data ready for encryption.

use std::path::{Path, PathBuf};
use super::metadata::{FileMetadata, FileType};
use crate::domain::shared::crypto::memory::SecureBox;
use crate::domain::shared::crypto::hash::{ContentHash, ContentHasher};
use crate::domain::errors::{DomainError, InputValidationError};

/// Plaintext file entity for encryption workflows.
#[derive(Debug)]
pub struct PlaintextFile {
    path: PathBuf,
    content: SecureBox<Vec<u8>>,
    metadata: FileMetadata,
    content_hash: ContentHash,
}

impl PlaintextFile {
    /// Create new PlaintextFile from loaded data.
    /// 
    /// Returns an error if the file type is not suitable for encryption.
    /// Only regular files can be encrypted for security and functionality reasons.
    pub fn new(path: PathBuf, content: SecureBox<Vec<u8>>, metadata: FileMetadata) -> Result<Self, DomainError> {
        // Validate that only regular files can be encrypted
        if !matches!(metadata.file_type, FileType::Regular) {
            let file_type_name = match metadata.file_type {
                FileType::Directory => "directory",
                FileType::Symlink => "symbolic link", 
                FileType::Other => "special file",
                FileType::EncryptedShadow => "encrypted file", 
                FileType::Regular => unreachable!(), // We already checked this
            };
            
            return Err(DomainError::InputValidationError(
                InputValidationError::InvalidPath {
                    path: path.display().to_string(),
                    reason: format!(
                        "Cannot encrypt {} - only regular files are supported for encryption", 
                        file_type_name
                    ),
                }
            ));
        }

        let content_hash = ContentHasher::hash(content.expose_secret());

        Ok(Self {
            path,
            content,
            metadata,
            content_hash,
        })
    }

    /// Get the content hash.
    pub fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }

    /// Get the file size in bytes.
    pub fn size(&self) -> usize {
        self.content.expose_secret().len()
    }

    /// Get the original file path.
    pub fn original_path(&self) -> &Path {
        &self.path
    }

    /// Get the file metadata.
    pub fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }

    /// Get the file content.
    /// 
    /// Exposes sensitive plaintext content - handle carefully.
    pub fn content(&self) -> &[u8] {
        self.content.expose_secret()
    }

    /// Check if the file content is empty.
    pub fn is_empty(&self) -> bool {
        self.content.expose_secret().is_empty()
    }

    /// Get the filename without path.
    pub fn filename(&self) -> Option<&str> {
        self.path.file_name()?.to_str()
    }

    /// Get the file extension.
    pub fn extension(&self) -> Option<&str> {
        self.path.extension()?.to_str()
    }

    /// Verify content integrity against stored hash.
    pub fn verify_integrity(&self) -> bool {
        let computed_hash = ContentHasher::hash(self.content.expose_secret());
        computed_hash == self.content_hash
    }

    /// Get content hash as hex string.
    pub fn content_hash_hex(&self) -> String {
        ContentHasher::to_hex(&self.content_hash)
    }

    /// Compare content equality via hash.
    pub fn content_equals(&self, other: &Self) -> bool {
        self.content_hash == other.content_hash
    }
}

impl Clone for PlaintextFile {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            content: self.content.clone(),
            metadata: self.metadata.clone(),
            content_hash: self.content_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn create_test_metadata(file_type: FileType) -> FileMetadata {
        FileMetadata {
            filename: "test.txt".to_string(),
            file_size: 100,
            modified_time: SystemTime::now(),
            created_time: Some(SystemTime::now()),
            file_type,
        }
    }

    #[test]
    fn creates_plaintext_file_for_regular_file() {
        let path = PathBuf::from("test.txt");
        let content = SecureBox::new(b"Hello, world!".to_vec());
        let metadata = create_test_metadata(FileType::Regular);

        let result = PlaintextFile::new(path, content, metadata);
        assert!(result.is_ok());
        
        let file = result.unwrap();
        assert_eq!(file.size(), 13);
        assert!(!file.is_empty());
        assert_eq!(file.filename(), Some("test.txt"));
    }

    #[test]
    fn rejects_directory() {
        let path = PathBuf::from("test_dir");
        let content = SecureBox::new(Vec::new());
        let metadata = create_test_metadata(FileType::Directory);

        let result = PlaintextFile::new(path, content, metadata);
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(matches!(error, DomainError::InputValidationError(_)));
        assert!(error.user_friendly_message().contains("directory"));
        assert!(error.user_friendly_message().contains("only regular files"));
    }

    #[test]
    fn rejects_symlink() {
        let path = PathBuf::from("test_link");
        let content = SecureBox::new(Vec::new());
        let metadata = create_test_metadata(FileType::Symlink);

        let result = PlaintextFile::new(path, content, metadata);
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(matches!(error, DomainError::InputValidationError(_)));
        assert!(error.user_friendly_message().contains("symbolic link"));
    }

    #[test]
    fn rejects_special_file() {
        let path = PathBuf::from("device");
        let content = SecureBox::new(Vec::new());
        let metadata = create_test_metadata(FileType::Other);

        let result = PlaintextFile::new(path, content, metadata);
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(matches!(error, DomainError::InputValidationError(_)));
        assert!(error.user_friendly_message().contains("special file"));
    }

    #[test]
    fn verifies_content_integrity() {
        let path = PathBuf::from("test.txt");
        let content = SecureBox::new(b"test content".to_vec());
        let metadata = create_test_metadata(FileType::Regular);

        let file = PlaintextFile::new(path, content, metadata).unwrap();
        assert!(file.verify_integrity());
    }

    #[test]
    fn compares_content_equality() {
        let path1 = PathBuf::from("test1.txt");
        let path2 = PathBuf::from("test2.txt");
        let content1 = SecureBox::new(b"same content".to_vec());
        let content2 = SecureBox::new(b"same content".to_vec());
        let content3 = SecureBox::new(b"different content".to_vec());
        let metadata = create_test_metadata(FileType::Regular);

        let file1 = PlaintextFile::new(path1, content1, metadata.clone()).unwrap();
        let file2 = PlaintextFile::new(path2, content2, metadata.clone()).unwrap();
        let file3 = PlaintextFile::new(PathBuf::from("test3.txt"), content3, metadata).unwrap();

        assert!(file1.content_equals(&file2));
        assert!(!file1.content_equals(&file3));
    }
}