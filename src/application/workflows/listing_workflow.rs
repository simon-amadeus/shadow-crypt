//! # ListingWorkflow
//!
//! Directory scanning and information display coordination.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use crate::domain::repositories::{
    file_repository::{FileRepository, FileType},
    password_repository::{PasswordRepository, PasswordInputError},
};
use crate::application::workflows::results::{WorkflowResult, DirectoryListing, EncryptedFileInfo};
use std::path::{Path, PathBuf};
use std::time::Instant;
use crate::domain::entities::AlgorithmId;

/// Result type for listing workflow operations
pub type ListingWorkflowResult<T> = Result<T, ListingWorkflowError>;

/// Errors that can occur during listing workflow
#[derive(Debug)]
pub enum ListingWorkflowError {
    /// Password input failed
    PasswordInput(PasswordInputError),
    /// File operation error
    FileError(String),
    /// Directory scanning error
    ScanError(String),
    /// Validation error
    ValidationError(String),
}

impl std::fmt::Display for ListingWorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListingWorkflowError::PasswordInput(err) => {
                write!(f, "Password input failed: {}", err)
            }
            ListingWorkflowError::FileError(msg) => {
                write!(f, "File operation error: {}", msg)
            }
            ListingWorkflowError::ScanError(msg) => {
                write!(f, "Directory scanning error: {}", msg)
            }
            ListingWorkflowError::ValidationError(msg) => {
                write!(f, "Validation error: {}", msg)
            }
        }
    }
}

impl std::error::Error for ListingWorkflowError {}

impl From<PasswordInputError> for ListingWorkflowError {
    fn from(err: PasswordInputError) -> Self {
        ListingWorkflowError::PasswordInput(err)
    }
}

/// Directory scanning and information display coordination
pub struct ListingWorkflow {
    file_repo: Box<dyn FileRepository>,
    password_repo: Box<dyn PasswordRepository>,
}

impl ListingWorkflow {
    /// Create a new ListingWorkflow instance
    pub fn new(
        file_repo: Box<dyn FileRepository>,
        password_repo: Box<dyn PasswordRepository>,
    ) -> Self {
        Self {
            file_repo,
            password_repo,
        }
    }

    /// Execute directory listing workflow
    pub fn execute(
        &mut self,
        directory: &Path,
        password: Option<String>,
    ) -> ListingWorkflowResult<WorkflowResult> {
        let start_time = Instant::now();

        // Step 1: Validate directory exists
        if !self.file_repo.file_exists(directory) {
            return Err(ListingWorkflowError::ValidationError(
                format!("Directory does not exist: {}", directory.display())
            ));
        }

        let metadata = self.file_repo.file_metadata(directory)
            .map_err(|e| ListingWorkflowError::FileError(
                format!("Cannot access directory {}: {}", directory.display(), e)
            ))?;

        if metadata.file_type != FileType::Directory {
            return Err(ListingWorkflowError::ValidationError(
                format!("Path is not a directory: {}", directory.display())
            ));
        }

        // Step 2: Get password if not provided
        let password = if let Some(pwd) = password {
            pwd
        } else {
            self.password_repo.prompt_password(
                "Enter password to reveal original filenames (or Ctrl+C to skip): "
            )?
        };

        // Step 3: Scan directory for encrypted files
        let files = self.scan_directory_for_encrypted_files(directory, &password)?;

        let scan_duration = start_time.elapsed();
        let listing = DirectoryListing {
            directory: directory.to_path_buf(),
            files,
            scan_duration,
        };

        Ok(WorkflowResult::Listing(listing))
    }

    /// List encrypted files in directory without password
    pub fn list_directory_basic(&self, directory: &Path) -> ListingWorkflowResult<Vec<PathBuf>> {
        // TODO: Implement directory scanning to find .shadow files
        // For now, return placeholder
        if !self.file_repo.file_exists(directory) {
            return Err(ListingWorkflowError::ValidationError(
                format!("Directory does not exist: {}", directory.display())
            ));
        }

        // This would scan for files with .shadow extension or TLV headers
        Ok(vec![directory.join("example.shadow")])
    }

    /// Scan directory for encrypted files and extract metadata
    fn scan_directory_for_encrypted_files(
        &self,
        directory: &Path,
        password: &str,
    ) -> ListingWorkflowResult<Vec<EncryptedFileInfo>> {
        // TODO: Implement actual directory scanning
        // This would:
        // 1. Find all files with .shadow extension or TLV headers
        // 2. Parse headers to extract metadata
        // 3. Attempt to decrypt original filename with password
        // 4. Collect file information

        let example_file = directory.join("example.shadow");
        if self.file_repo.file_exists(&example_file) {
            let metadata = self.file_repo.file_metadata(&example_file)
                .map_err(|e| ListingWorkflowError::FileError(
                    format!("Cannot read file metadata: {}", e)
                ))?;

            let file_info = EncryptedFileInfo {
                path: example_file,
                original_filename: if !password.is_empty() {
                    Some("original_document.txt".to_string()) // Would be decrypted from header
                } else {
                    None
                },
                algorithm: AlgorithmId::XChaCha20Poly1305, // Would be read from header
                version: 1, // Would be read from header
                size: metadata.file_size,
                password_valid: !password.is_empty(), // Would be validated by attempting decryption
            };

            Ok(vec![file_info])
        } else {
            Ok(vec![])
        }
    }
}