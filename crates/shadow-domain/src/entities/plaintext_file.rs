//! # PlaintextFile Entity
//!
//! Represents a plaintext file ready for encryption.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::{Path, PathBuf};
use std::fs;
use crate::errors::{DomainError, DomainResult};
use crate::entities::file_metadata::FileMetadata;
use sha2::{Sha256, Digest};

/// Represents a plaintext file ready for encryption
#[derive(Debug)]
pub struct PlaintextFile {
    path: PathBuf,
    content: Vec<u8>,
    metadata: FileMetadata,
    content_hash: [u8; 32],
}

impl PlaintextFile {
    /// Create PlaintextFile from a file path, loading content and metadata
    pub fn from_path(path: &Path) -> DomainResult<Self> {
        // Validate path points to a regular file
        let fs_metadata = fs::metadata(path)
            .map_err(|e| DomainError::file_access_denied(
                path.display().to_string(), 
                &format!("Cannot read file metadata: {}", e)
            ))?;

        if !fs_metadata.is_file() {
            return Err(DomainError::InputValidationError(
                crate::errors::InputValidationError::InvalidPath { 
                    path: path.display().to_string(),
                    reason: "Path must point to a regular file".to_string() 
                }
            ));
        }

        // Load file content
        let content = fs::read(path)
            .map_err(|e| DomainError::file_access_denied(
                path.display().to_string(),
                &format!("Cannot read file content: {}", e)
            ))?;

        // Extract metadata
        let metadata = FileMetadata::from_path(path)
            .map_err(|e| DomainError::file_access_denied(
                path.display().to_string(),
                &format!("Cannot extract file metadata: {}", e)
            ))?;

        // Calculate content hash
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let content_hash: [u8; 32] = hasher.finalize().into();

        Ok(Self {
            path: path.to_path_buf(),
            content,
            metadata,
            content_hash,
        })
    }

    /// Get the content hash
    pub fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }

    /// Get the file size
    pub fn size(&self) -> usize {
        self.content.len()
    }

    /// Get the original file path
    pub fn original_path(&self) -> &Path {
        &self.path
    }

    /// Get the file metadata
    pub fn metadata(&self) -> &FileMetadata {
        &self.metadata
    }

    /// Get the file content
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}