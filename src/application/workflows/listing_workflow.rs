//! # ListingWorkflow
//!
//! Directory scanning and information display coordination.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use crate::domain::repositories::{
    file_repository::{FileRepository, FileType},
    password_repository::{PasswordRepository, PasswordInputError},
};
use crate::domain::services::listing_service::ListingService;
use crate::application::workflows::results::{WorkflowResult, DirectoryListing, EncryptedFileInfo};
use std::path::Path;

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
    listing_service: ListingService,
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
            listing_service: ListingService::new(),
        }
    }

    /// Execute directory listing workflow
    pub fn execute(
        &mut self,
        directory: &Path,
        password: Option<String>,
    ) -> ListingWorkflowResult<WorkflowResult> {
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

        // Step 3: Use domain service to scan directory
        let domain_listing = self.listing_service.scan_directory(directory, &password)
            .map_err(|e| ListingWorkflowError::ScanError(e.to_string()))?;

        // Step 4: Convert from domain types to application types
        let files: Vec<EncryptedFileInfo> = domain_listing.files
            .into_iter()
            .map(|domain_file| EncryptedFileInfo {
                path: domain_file.path,
                original_filename: domain_file.original_filename,
                algorithm: domain_file.algorithm,
                version: domain_file.version,
                size: domain_file.size,
                password_valid: domain_file.password_valid,
            })
            .collect();

        let listing = DirectoryListing {
            directory: domain_listing.directory,
            files,
            scan_duration: domain_listing.scan_duration,
        };

        Ok(WorkflowResult::Listing(listing))
    }
}