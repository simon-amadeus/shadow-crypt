//! # PlaintextFile Entity
//!
//! Represents a plaintext file ready for encryption.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::{Path, PathBuf};
use std::fs;
use crate::domain::errors::{DomainError, DomainResult};

/// Represents a plaintext file ready for encryption
#[derive(Debug, Clone)]
pub struct PlaintextFile {
    path: PathBuf,
    size: Option<u64>,
}

impl PlaintextFile {
    /// Create a new PlaintextFile instance from a path
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            size: None,
        }
    }

    /// Create PlaintextFile with metadata loaded
    pub fn from_path(path: &Path) -> DomainResult<Self> {
        let metadata = fs::metadata(path)
            .map_err(|e| DomainError::file_access_denied(
                path.display().to_string(), 
                &format!("Cannot read file metadata: {}", e)
            ))?;

        if !metadata.is_file() {
            return Err(DomainError::InputValidationError(
                crate::domain::errors::InputValidationError::InvalidPath { 
                    path: path.display().to_string(),
                    reason: "Path must point to a regular file".to_string() 
                }
            ));
        }

        Ok(Self {
            path: path.to_path_buf(),
            size: Some(metadata.len()),
        })
    }

    /// Get the file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the file size (if loaded)
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Load file size from filesystem
    pub fn load_size(&mut self) -> DomainResult<u64> {
        let metadata = fs::metadata(&self.path)
            .map_err(|e| DomainError::file_access_denied(
                self.path.display().to_string(), 
                &format!("Cannot read file metadata: {}", e)
            ))?;

        let size = metadata.len();
        self.size = Some(size);
        Ok(size)
    }
}