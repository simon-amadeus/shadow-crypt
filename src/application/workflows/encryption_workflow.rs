//! # EncryptionWorkflow
//!
//! Coordinates encryption with all features and validations (stateless).
//! Based on specs/DOMAIN_ARCHITECTURE.md

use crate::domain::services::password_service::{PasswordVerificationService, PasswordVerificationError};
use crate::domain::services::EncryptionService;
use crate::domain::repositories::{
    password_repository::PasswordRepository,
    file_repository::FileRepository,
};
use crate::domain::entities::AlgorithmId;
use crate::domain::utilities::filename_obfuscation::FilenameObfuscator;
use crate::infrastructure::crypto::factory::Algorithm;
use crate::application::workflows::results::{WorkflowResult, BatchResult, EncryptionResult};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Result type for encryption workflow operations
pub type EncryptionWorkflowResult<T> = Result<T, EncryptionWorkflowError>;

/// Errors that can occur during encryption workflow
#[derive(Debug)]
pub enum EncryptionWorkflowError {
    /// Password verification failed
    PasswordVerification(PasswordVerificationError),
    /// File operation error
    FileError(String),
    /// Encryption error
    EncryptionError(String),
    /// Validation error
    ValidationError(String),
}

impl std::fmt::Display for EncryptionWorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionWorkflowError::PasswordVerification(err) => {
                write!(f, "Password verification failed: {}", err)
            }
            EncryptionWorkflowError::FileError(msg) => {
                write!(f, "File operation error: {}", msg)
            }
            EncryptionWorkflowError::EncryptionError(msg) => {
                write!(f, "Encryption error: {}", msg)
            }
            EncryptionWorkflowError::ValidationError(msg) => {
                write!(f, "Validation error: {}", msg)
            }
        }
    }
}

impl std::error::Error for EncryptionWorkflowError {}

impl From<PasswordVerificationError> for EncryptionWorkflowError {
    fn from(err: PasswordVerificationError) -> Self {
        EncryptionWorkflowError::PasswordVerification(err)
    }
}

/// Options for encryption operations
#[derive(Debug, Clone)]
pub struct EncryptionOptions {
    pub obfuscate_filename: bool,
    pub force_overwrite: bool,
    pub remove_source: bool,
    pub check_duplicates: bool,
}

impl Default for EncryptionOptions {
    fn default() -> Self {
        Self {
            obfuscate_filename: false,
            force_overwrite: false,
            remove_source: true,   // Default behavior from specs
            check_duplicates: true,
        }
    }
}

/// Coordinates encryption with all features and validations
pub struct EncryptionWorkflow {
    password_service: PasswordVerificationService,
    file_repo: Box<dyn FileRepository>,
    algorithm: AlgorithmId,
    quiet_mode: bool,
}

impl EncryptionWorkflow {
    /// Create a new EncryptionWorkflow instance
    pub fn new(
        file_repo: Box<dyn FileRepository>,
        password_repository: Box<dyn PasswordRepository>,
        algorithm: AlgorithmId,
    ) -> Self {
        Self {
            password_service: PasswordVerificationService::new(password_repository),
            file_repo,
            algorithm,
            quiet_mode: false,
        }
    }

    /// Enable or disable quiet mode (affects progress reporting)
    pub fn with_quiet_mode(mut self, quiet: bool) -> Self {
        self.quiet_mode = quiet;
        self
    }

    /// Execute complete encryption workflow for multiple files
    pub fn execute(
        &mut self,
        input_patterns: Vec<String>,
        options: EncryptionOptions,
    ) -> EncryptionWorkflowResult<WorkflowResult> {
        let start_time = Instant::now();

        // Step 1: Expand glob patterns and validate files
        let file_paths = self.expand_patterns(input_patterns)?;
        self.validate_input_files(&file_paths)?;

        // Step 2: Check for already encrypted files (double-encryption prevention)
        self.check_already_encrypted(&file_paths)?;

        // Step 3: Get password with confirmation for encryption
        let password = self.password_service.verify_password_for_encryption()?;

        // Step 4: Prepare file pairs (input -> output paths)
        let file_pairs = self.prepare_file_pairs(&file_paths, &options)?;

        // Step 5: Execute batch encryption
        let mut successful = Vec::new();
        let mut failed = Vec::new();

        for (input_path, output_path) in file_pairs {
            match self.encrypt_single_file(&input_path, &output_path, &password, &options) {
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

        Ok(WorkflowResult::Encryption(batch_result))
    }

    /// Execute encryption workflow for a single file
    pub fn encrypt_file(&self, input_path: &Path) -> EncryptionWorkflowResult<String> {
        // Step 1: Verify password with double confirmation
        let password = self.password_service.verify_password_for_encryption()?;
        
        // Step 2: Basic file validation
        if !self.file_repo.file_exists(input_path) {
            return Err(EncryptionWorkflowError::FileError(
                format!("Input file does not exist: {}", input_path.display())
            ));
        }

        // Step 3: Generate output path
        let output_path = {
            let mut output = input_path.to_path_buf();
            if let Some(current_ext) = output.extension() {
                let new_ext = format!("{}.shadow", current_ext.to_string_lossy());
                output.set_extension(new_ext);
            } else {
                output.set_extension("shadow");
            }
            output
        };

        // Step 4: Execute encryption using real crypto
        let options = EncryptionOptions::default();
        match self.encrypt_single_file(
            input_path,
            &output_path,
            &password,
            &options,
        ) {
            Ok(result) => {
                Ok(format!(
                    "Successfully encrypted '{}' to '{}' using {} (took {:?})",
                    result.input_path.display(),
                    result.output_path.display(),
                    result.algorithm.name(),
                    result.duration
                ))
            }
            Err(err) => Err(err),
        }
    }

    /// Expand glob patterns into file paths
    fn expand_patterns(&self, patterns: Vec<String>) -> EncryptionWorkflowResult<Vec<PathBuf>> {
        let mut file_paths = Vec::new();
        
        for pattern in patterns {
            // Use glob pattern matching for multi-file support
            match glob::glob(&pattern) {
                Ok(entries) => {
                    let mut found_files = false;
                    for entry in entries {
                        match entry {
                            Ok(path) => {
                                // Only include files (not directories)
                                if self.file_repo.file_exists(&path) && path.is_file() {
                                    file_paths.push(path);
                                    found_files = true;
                                }
                            }
                            Err(e) => {
                                return Err(EncryptionWorkflowError::FileError(
                                    format!("Error processing glob pattern '{}': {}", pattern, e)
                                ));
                            }
                        }
                    }
                    
                    // If no files found for this pattern, check if it's a direct file path
                    if !found_files {
                        let direct_path = PathBuf::from(&pattern);
                        if self.file_repo.file_exists(&direct_path) {
                            file_paths.push(direct_path);
                        } else {
                            return Err(EncryptionWorkflowError::FileError(
                                format!("No files found matching pattern: {}", pattern)
                            ));
                        }
                    }
                }
                Err(e) => {
                    return Err(EncryptionWorkflowError::FileError(
                        format!("Invalid glob pattern '{}': {}", pattern, e)
                    ));
                }
            }
        }

        if file_paths.is_empty() {
            return Err(EncryptionWorkflowError::ValidationError(
                "No files to encrypt".to_string()
            ));
        }

        // Remove duplicates and sort for consistent ordering
        file_paths.sort();
        file_paths.dedup();

        Ok(file_paths)
    }

    /// Validate all input files exist and are readable
    fn validate_input_files(&self, file_paths: &[PathBuf]) -> EncryptionWorkflowResult<()> {
        for path in file_paths {
            if !self.file_repo.file_exists(path) {
                return Err(EncryptionWorkflowError::FileError(
                    format!("Input file does not exist: {}", path.display())
                ));
            }

            // Try to read metadata to verify accessibility
            self.file_repo.file_metadata(path)
                .map_err(|e| EncryptionWorkflowError::FileError(
                    format!("Cannot access file {}: {}", path.display(), e)
                ))?;
        }
        Ok(())
    }

    /// Check for already encrypted files to prevent double encryption
    fn check_already_encrypted(&self, file_paths: &[PathBuf]) -> EncryptionWorkflowResult<()> {
        use crate::domain::services::FileDetector;
        
        let file_detector = FileDetector::new();
        for path in file_paths {
            // Use FileDetector to check if file is already encrypted
            match file_detector.is_encrypted_file(path) {
                Ok(true) => {
                    return Err(EncryptionWorkflowError::ValidationError(
                        format!("File is already encrypted: {}", path.display())
                    ));
                }
                Ok(false) => {
                    // File is not encrypted, continue
                }
                Err(e) => {
                    // File check failed, treat as validation error
                    return Err(EncryptionWorkflowError::ValidationError(
                        format!("Cannot validate encryption status of {}: {}", path.display(), e)
                    ));
                }
            }
        }
        Ok(())
    }

    /// Prepare input -> output file path pairs
    fn prepare_file_pairs(
        &self,
        file_paths: &[PathBuf],
        options: &EncryptionOptions,
    ) -> EncryptionWorkflowResult<Vec<(PathBuf, PathBuf)>> {
        let mut pairs = Vec::new();

        for input_path in file_paths {
            let output_path = if options.obfuscate_filename {
                // Generate obfuscated filename for enhanced privacy
                let (obfuscated_path, _obfuscated_info) = FilenameObfuscator::create_obfuscated_output_path(
                    input_path, 
                    false // Don't preserve extension for obfuscation
                ).map_err(|e| EncryptionWorkflowError::ValidationError(
                    format!("Failed to generate obfuscated filename for {}: {}", 
                           input_path.display(), e)
                ))?;
                obfuscated_path
            } else {
                // Append .shadow extension
                let mut output = input_path.clone();
                if let Some(current_ext) = output.extension() {
                    let new_ext = format!("{}.shadow", current_ext.to_string_lossy());
                    output.set_extension(new_ext);
                } else {
                    output.set_extension("shadow");
                }
                output
            };

            // Check for overwrite protection
            if !options.force_overwrite && self.file_repo.file_exists(&output_path) {
                return Err(EncryptionWorkflowError::ValidationError(
                    format!("Output file already exists: {} (use --force to overwrite)", 
                           output_path.display())
                ));
            }

            pairs.push((input_path.clone(), output_path));
        }

        Ok(pairs)
    }

    /// Encrypt a single file
    fn encrypt_single_file(
        &self,
        input_path: &Path,
        output_path: &Path,
        password: &str,
        options: &EncryptionOptions,
    ) -> EncryptionWorkflowResult<EncryptionResult> {
        // Create algorithm instance from stored ID
        let algorithm = Algorithm::from_id(self.algorithm);

        // Create encryption service with progress reporting based on quiet mode
        let mut encryption_service = EncryptionService::new()
            .with_progress_reporting(!self.quiet_mode);

        // Convert options
        let service_options = crate::domain::services::EncryptionOptions {
            obfuscate_filename: options.obfuscate_filename,
            force_overwrite: options.force_overwrite,
            remove_source: options.remove_source,
            check_duplicates: options.check_duplicates,
        };

        // Execute encryption through domain service
        match encryption_service.encrypt_file(
            input_path,
            output_path,
            &algorithm,
            password,
            service_options,
        ) {
            Ok(service_result) => {
                // Convert domain service result to workflow result
                Ok(EncryptionResult {
                    input_path: service_result.input_path,
                    output_path: service_result.output_path,
                    content_hash: service_result.content_hash,
                    algorithm: service_result.algorithm,
                    duration: service_result.duration,
                })
            }
            Err(domain_error) => {
                Err(EncryptionWorkflowError::EncryptionError(domain_error.to_string()))
            }
        }
    }
}