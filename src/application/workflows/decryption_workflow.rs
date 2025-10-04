//! # DecryptionWorkflow
//!
//! Coordinates decryption with filename restoration (stateless).
//! Based on specs/DOMAIN_ARCHITECTURE.md

use crate::domain::repositories::{
    file_repository::FileRepository,
    password_repository::{PasswordRepository, PasswordInputError},
};
use crate::application::workflows::results::{WorkflowResult, BatchResult, DecryptionResult};
use std::path::{Path, PathBuf};
use std::time::Instant;
use crate::domain::entities::AlgorithmId;

/// Result type for decryption workflow operations
pub type DecryptionWorkflowResult<T> = Result<T, DecryptionWorkflowError>;

/// Errors that can occur during decryption workflow
#[derive(Debug)]
pub enum DecryptionWorkflowError {
    /// Password input failed
    PasswordInput(PasswordInputError),
    /// File operation error
    FileError(String),
    /// Decryption error
    DecryptionError(String),
    /// Validation error
    ValidationError(String),
}

impl std::fmt::Display for DecryptionWorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptionWorkflowError::PasswordInput(err) => {
                write!(f, "Password input failed: {}", err)
            }
            DecryptionWorkflowError::FileError(msg) => {
                write!(f, "File operation error: {}", msg)
            }
            DecryptionWorkflowError::DecryptionError(msg) => {
                write!(f, "Decryption error: {}", msg)
            }
            DecryptionWorkflowError::ValidationError(msg) => {
                write!(f, "Validation error: {}", msg)
            }
        }
    }
}

impl std::error::Error for DecryptionWorkflowError {}

impl From<PasswordInputError> for DecryptionWorkflowError {
    fn from(err: PasswordInputError) -> Self {
        DecryptionWorkflowError::PasswordInput(err)
    }
}

/// Options for decryption operations
#[derive(Debug, Clone)]
pub struct DecryptionOptions {
    pub force_overwrite: bool,
    pub remove_source: bool,
    pub verify_integrity: bool,
}

impl Default for DecryptionOptions {
    fn default() -> Self {
        Self {
            force_overwrite: false,
            remove_source: true,   // Default behavior from specs
            verify_integrity: true,
        }
    }
}

/// Coordinates decryption with filename restoration
pub struct DecryptionWorkflow {
    file_repo: Box<dyn FileRepository>,
    password_repo: Box<dyn PasswordRepository>,
}

impl DecryptionWorkflow {
    /// Create a new DecryptionWorkflow instance
    pub fn new(
        file_repo: Box<dyn FileRepository>,
        password_repo: Box<dyn PasswordRepository>,
    ) -> Self {
        Self {
            file_repo,
            password_repo,
        }
    }

    /// Execute complete decryption workflow for multiple files
    pub fn execute(
        &mut self,
        input_patterns: Vec<String>,
        options: DecryptionOptions,
    ) -> DecryptionWorkflowResult<WorkflowResult> {
        let start_time = Instant::now();

        // Step 1: Expand patterns and validate files
        let file_paths = self.expand_patterns(input_patterns)?;
        self.validate_encrypted_files(&file_paths)?;

        // Step 2: Get password (single prompt for decryption)
        let password = self.password_repo.prompt_password("Enter password for decryption: ")?;

        // Step 3: Execute batch decryption
        let mut successful = Vec::new();
        let mut failed = Vec::new();

        for input_path in file_paths {
            match self.decrypt_single_file(&input_path, &password, &options) {
                Ok(result) => successful.push(result),
                Err(err) => failed.push((input_path, err.to_string())),
            }
        }

        let total_duration = start_time.elapsed();
        let batch_result = BatchResult {
            successful,
            failed,
            total_duration,
        };

        Ok(WorkflowResult::Decryption(batch_result))
    }

    /// Decrypt a single file with automatic filename restoration
    pub fn decrypt_file(
        &self,
        input_path: &Path,
        output_path: Option<&Path>,
    ) -> DecryptionWorkflowResult<String> {
        // Step 1: Validate input file
        if !self.file_repo.file_exists(input_path) {
            return Err(DecryptionWorkflowError::FileError(
                format!("Input file does not exist: {}", input_path.display())
            ));
        }

        // Step 2: Get password
        let password = self.password_repo.prompt_password("Enter password for decryption: ")?;

        // Step 3: TODO - Implement actual decryption
        let output_display = if let Some(path) = output_path {
            path.display().to_string()
        } else {
            "auto-detected from header".to_string()
        };

        Ok(format!(
            "Decryption would proceed with password (length: {}) for file: {} -> {}",
            password.len(),
            input_path.display(),
            output_display
        ))
    }

    /// Expand glob patterns into file paths
    fn expand_patterns(&self, patterns: Vec<String>) -> DecryptionWorkflowResult<Vec<PathBuf>> {
        let mut file_paths = Vec::new();
        
        for pattern in patterns {
            // TODO: Implement actual glob expansion
            // For now, treat as direct file paths
            let path = PathBuf::from(pattern);
            if self.file_repo.file_exists(&path) {
                file_paths.push(path);
            } else {
                return Err(DecryptionWorkflowError::FileError(
                    format!("File not found: {}", path.display())
                ));
            }
        }

        if file_paths.is_empty() {
            return Err(DecryptionWorkflowError::ValidationError(
                "No files to decrypt".to_string()
            ));
        }

        Ok(file_paths)
    }

    /// Validate all input files are encrypted files
    fn validate_encrypted_files(&self, file_paths: &[PathBuf]) -> DecryptionWorkflowResult<()> {
        for path in file_paths {
            if !self.file_repo.file_exists(path) {
                return Err(DecryptionWorkflowError::FileError(
                    format!("Input file does not exist: {}", path.display())
                ));
            }

            // TODO: Validate file has proper TLV header structure
            // For now, just check accessibility
            self.file_repo.file_metadata(path)
                .map_err(|e| DecryptionWorkflowError::FileError(
                    format!("Cannot access file {}: {}", path.display(), e)
                ))?;
        }
        Ok(())
    }

    /// Decrypt a single file
    fn decrypt_single_file(
        &self,
        input_path: &PathBuf,
        _password: &str,
        _options: &DecryptionOptions,
    ) -> DecryptionWorkflowResult<DecryptionResult> {
        let start_time = Instant::now();

        // TODO: Implement actual decryption using domain services
        // For now, create a placeholder result
        
        // Auto-detect output path (remove .shadow extension or use original filename from header)
        let output_path = if let Some(stem) = input_path.file_stem() {
            input_path.with_file_name(stem)
        } else {
            input_path.with_extension("")
        };

        let duration = start_time.elapsed();

        Ok(DecryptionResult {
            input_path: input_path.clone(),
            output_path,
            original_filename: Some("original_file.txt".to_string()), // Placeholder
            algorithm: AlgorithmId::XChaCha20Poly1305, // Placeholder - would be detected from header
            duration,
        })
    }
}