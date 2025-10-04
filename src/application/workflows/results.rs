//! # Workflow Result Types
//!
//! Unified result types for all workflow operations

use std::path::PathBuf;
use std::time::Duration;
use crate::domain::entities::AlgorithmId;
use crate::domain::utilities::content_hash::ContentHash;

/// Unified result type for all workflow operations
#[derive(Debug)]
pub enum WorkflowResult {
    /// Encryption workflow result
    Encryption(BatchResult<EncryptionResult>),
    /// Decryption workflow result  
    Decryption(BatchResult<DecryptionResult>),
    /// Listing workflow result
    Listing(DirectoryListing),
    /// Migration workflow result
    Migration(MigrationPlan),
}

/// Batch operation result with success/failure tracking
#[derive(Debug)]
pub struct BatchResult<T> {
    pub successful: Vec<T>,
    pub failed: Vec<(PathBuf, String)>, // Simplified error for PoC
    pub total_duration: Duration,
}

/// Individual encryption operation result
#[derive(Debug)]
pub struct EncryptionResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub content_hash: ContentHash,
    pub algorithm: AlgorithmId,
    pub duration: Duration,
}

/// Individual decryption operation result
#[derive(Debug)]
pub struct DecryptionResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub original_filename: Option<String>,
    pub algorithm: AlgorithmId,
    pub duration: Duration,
}

/// Directory listing result
#[derive(Debug)]
pub struct DirectoryListing {
    pub directory: PathBuf,
    pub files: Vec<EncryptedFileInfo>,
    pub scan_duration: Duration,
}

/// Information about an encrypted file in a directory
#[derive(Debug, Clone)]
pub struct EncryptedFileInfo {
    pub path: PathBuf,
    pub original_filename: Option<String>,
    pub algorithm: AlgorithmId,
    pub version: u16,
    pub size: u64,
    pub password_valid: bool,
}

/// Migration planning result
#[derive(Debug)]
pub struct MigrationPlan {
    pub files_to_migrate: Vec<PathBuf>,
    pub migration_steps: Vec<MigrationStep>,
    pub estimated_duration: Duration,
}

/// Individual migration step
#[derive(Debug)]
pub struct MigrationStep {
    pub file_path: PathBuf,
    pub from_version: u16,
    pub to_version: u16,
    pub required: bool,
}