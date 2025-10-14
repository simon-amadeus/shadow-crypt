//! # MigrationWorkflow
//!
//! Version upgrade planning and execution management.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use crate::domain::repositories::{
    file_handler::FileHandler,
    password_repository::{PasswordRepository, PasswordInputError},
};
use crate::application::workflows::results::{WorkflowResult, MigrationPlan, MigrationStep};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Result type for migration workflow operations
pub type MigrationWorkflowResult<T> = Result<T, MigrationWorkflowError>;

/// Errors that can occur during migration workflow
#[derive(Debug)]
pub enum MigrationWorkflowError {
    /// Password input failed
    PasswordInput(PasswordInputError),
    /// File operation error
    FileError(String),
    /// Migration error
    MigrationError(String),
    /// Validation error
    ValidationError(String),
    /// Version compatibility error
    VersionCompatibilityError(String),
}

impl std::fmt::Display for MigrationWorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationWorkflowError::PasswordInput(err) => {
                write!(f, "Password input failed: {}", err)
            }
            MigrationWorkflowError::FileError(msg) => {
                write!(f, "File operation error: {}", msg)
            }
            MigrationWorkflowError::MigrationError(msg) => {
                write!(f, "Migration error: {}", msg)
            }
            MigrationWorkflowError::ValidationError(msg) => {
                write!(f, "Validation error: {}", msg)
            }
            MigrationWorkflowError::VersionCompatibilityError(msg) => {
                write!(f, "Version compatibility error: {}", msg)
            }
        }
    }
}

impl std::error::Error for MigrationWorkflowError {}

impl From<PasswordInputError> for MigrationWorkflowError {
    fn from(err: PasswordInputError) -> Self {
        MigrationWorkflowError::PasswordInput(err)
    }
}

/// Migration analysis result for a single file
#[derive(Debug)]
pub struct MigrationAnalysis {
    pub current_version: u16,
    pub target_version: u16,
    pub migration_path: Vec<u16>,
    pub is_required: bool,
    pub is_possible: bool,
}

/// Version upgrade planning and execution management
pub struct MigrationWorkflow {
    file_repo: Box<dyn FileHandler>,
    password_repo: Box<dyn PasswordRepository>,
}

impl MigrationWorkflow {
    /// Create a new MigrationWorkflow instance
    pub fn new(
        file_repo: Box<dyn FileHandler>,
        password_repo: Box<dyn PasswordRepository>,
    ) -> Self {
        Self {
            file_repo,
            password_repo,
        }
    }

    /// Execute migration planning and analysis
    pub fn execute(
        &mut self,
        input_patterns: Vec<String>,
        target_version: u16,
    ) -> MigrationWorkflowResult<WorkflowResult> {
        let start_time = Instant::now();

        // Step 1: Expand patterns and validate files
        let file_paths = self.expand_patterns(input_patterns)?;
        self.validate_encrypted_files(&file_paths)?;

        // Step 2: Analyze each file's migration requirements
        let migration_steps = self.analyze_migration_requirements(&file_paths, target_version)?;

        // Step 3: Create migration plan
        let planning_duration = start_time.elapsed();
        let estimated_duration = Duration::from_secs(migration_steps.len() as u64 * 5) + planning_duration;
        let plan = MigrationPlan {
            files_to_migrate: file_paths,
            migration_steps,
            estimated_duration,
        };

        Ok(WorkflowResult::Migration(plan))
    }

    /// Analyze a single file's migration requirements
    pub fn analyze_file(&self, path: &Path) -> MigrationWorkflowResult<MigrationAnalysis> {
        if !self.file_repo.file_exists(path) {
            return Err(MigrationWorkflowError::FileError(
                format!("File does not exist: {}", path.display())
            ));
        }

        // Read actual file version from TLV header
        use crate::infrastructure::file_system::FileSystemService;
        use crate::domain::shared::version_matrix::{VersionMatrix, VersionCompatibility};
        
        let header = FileSystemService::read_header_only(path)
            .map_err(|e| MigrationWorkflowError::FileError(
                format!("Failed to read header from {}: {}", path.display(), e)
            ))?;
            
        let current_version = header.version();
        let version_matrix = VersionMatrix::new_shadow_rewrite();
        let target_version = version_matrix.current_baseline();
        
        // Check compatibility and migration requirements
        let compatibility = version_matrix.is_compatible(current_version, target_version);
        let is_required = matches!(compatibility, VersionCompatibility::RequiresMigration);
        let is_possible = version_matrix.can_migrate(current_version, target_version);
        
        // Build migration path
        let migration_path = if is_required && is_possible {
            // Use version matrix to get proper migration path
            if let Some(path) = version_matrix.get_migration_path(current_version, target_version) {
                vec![path.from_version, path.to_version]
            } else {
                vec![current_version, target_version]
            }
        } else {
            vec![current_version]
        };

        let analysis = MigrationAnalysis {
            current_version,
            target_version,
            migration_path,
            is_required,
            is_possible,
        };

        Ok(analysis)
    }

    /// Execute migration for a single file
    pub fn migrate_file(
        &self,
        path: &Path,
        target_version: u16,
    ) -> MigrationWorkflowResult<String> {
        // Step 1: Analyze file requirements
        let analysis = self.analyze_file(path)?;

        if !analysis.is_required {
            return Ok(format!(
                "File {} is already at version {} (target: {})",
                path.display(),
                analysis.current_version,
                target_version
            ));
        }

        if !analysis.is_possible {
            return Err(MigrationWorkflowError::VersionCompatibilityError(
                format!(
                    "Cannot migrate {} from version {} to {}",
                    path.display(),
                    analysis.current_version,
                    target_version
                )
            ));
        }

        // Step 2: Get password for file access
        let password = self.password_repo.prompt_password(
            "Enter password for migration: "
        )?;

        // Step 3: Execute actual migration using domain service
        use crate::domain::services::migration_service::{MigrationService, MigrationOptions};
        
        let migration_service = MigrationService::new();
        let options = MigrationOptions::default(); // Use safe defaults (backup enabled, etc.)
        
        match migration_service.migrate_file(path, target_version, Some(&password), &options) {
            Ok(result) => {
                Ok(format!(
                    "Successfully migrated {} from version {} to version {} ({} bytes processed in {:?})",
                    path.display(),
                    result.original_version,
                    result.target_version,
                    result.bytes_processed,
                    result.duration
                ))
            }
            Err(e) => {
                Err(MigrationWorkflowError::MigrationError(format!(
                    "Failed to migrate {}: {}",
                    path.display(),
                    e
                )))
            }
        }
    }

    /// Expand glob patterns into file paths
    fn expand_patterns(&self, patterns: Vec<String>) -> MigrationWorkflowResult<Vec<PathBuf>> {
        let mut file_paths = Vec::new();
        
        for pattern in patterns {
            let path = PathBuf::from(pattern);
            
            if path.is_dir() {
                // Scan directory for .shadow files
                let dir_files = self.scan_directory_for_shadow_files(&path)?;
                file_paths.extend(dir_files);
            } else if self.file_repo.file_exists(&path) {
                file_paths.push(path);
            } else {
                // Try as a potential glob pattern or missing file
                return Err(MigrationWorkflowError::FileError(
                    format!("File or directory not found: {}", path.display())
                ));
            }
        }

        if file_paths.is_empty() {
            return Err(MigrationWorkflowError::ValidationError(
                "No encrypted files found to migrate".to_string()
            ));
        }

        Ok(file_paths)
    }
    
    /// Scan directory for .shadow files recursively
    fn scan_directory_for_shadow_files(&self, dir: &Path) -> MigrationWorkflowResult<Vec<PathBuf>> {
        use std::fs;
        
        let mut shadow_files = Vec::new();
        
        let entries = fs::read_dir(dir)
            .map_err(|e| MigrationWorkflowError::FileError(
                format!("Cannot read directory {}: {}", dir.display(), e)
            ))?;
            
        for entry in entries {
            let entry = entry.map_err(|e| MigrationWorkflowError::FileError(
                format!("Error reading directory entry in {}: {}", dir.display(), e)
            ))?;
            
            let path = entry.path();
            
            if path.is_dir() {
                // Recursive directory scanning
                let nested_files = self.scan_directory_for_shadow_files(&path)?;
                shadow_files.extend(nested_files);
            } else if path.extension().and_then(|s| s.to_str()) == Some("shadow") {
                shadow_files.push(path);
            }
        }
        
        Ok(shadow_files)
    }

    /// Validate all input files are encrypted files
    fn validate_encrypted_files(&self, file_paths: &[PathBuf]) -> MigrationWorkflowResult<()> {
        use crate::infrastructure::file_system::FileSystemService;
        
        for path in file_paths {
            if !self.file_repo.file_exists(path) {
                return Err(MigrationWorkflowError::FileError(
                    format!("Input file does not exist: {}", path.display())
                ));
            }

            // Validate file has proper TLV header structure by attempting to read it
            FileSystemService::read_header_only(path)
                .map_err(|e| MigrationWorkflowError::ValidationError(
                    format!("File {} is not a valid encrypted file: {}", path.display(), e)
                ))?;
        }
        Ok(())
    }

    /// Analyze migration requirements for multiple files
    fn analyze_migration_requirements(
        &self,
        file_paths: &[PathBuf],
        target_version: u16,
    ) -> MigrationWorkflowResult<Vec<MigrationStep>> {
        let mut steps = Vec::new();

        for path in file_paths {
            let analysis = self.analyze_file(path)?;
            
            if analysis.is_required {
                let step = MigrationStep {
                    file_path: path.clone(),
                    from_version: analysis.current_version,
                    to_version: target_version,
                    required: analysis.is_required,
                };
                steps.push(step);
            }
        }

        Ok(steps)
    }
}