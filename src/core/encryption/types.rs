//! Encryption-specific types for the functional pipeline.

use std::path::PathBuf;
use std::time::Duration;
use crate::core::shared::crypto::{AlgorithmId};
use crate::core::shared::files::{ContentHash, EncryptedData};

// ============================================================================
// CONFIGURATION
// ============================================================================

/// Options for encryption operations.
#[derive(Debug, Clone)]
pub struct EncryptionOptions {
    pub algorithm: AlgorithmId,
    pub obfuscate_filename: bool,
    pub force_overwrite: bool,
    pub remove_source: bool,
    pub check_duplicates: bool,
}

impl Default for EncryptionOptions {
    fn default() -> Self {
        Self {
            algorithm: AlgorithmId::recommended(),
            obfuscate_filename: false,
            force_overwrite: false,
            remove_source: true,
            check_duplicates: true,
        }
    }
}

// ============================================================================
// PIPELINE DATA
// ============================================================================

/// An encryption job representing a source -> target transformation.
#[derive(Debug, Clone)]
pub struct EncryptionJob {
    pub source_path: PathBuf,
    pub target_path: PathBuf,
    pub content_hash: ContentHash,
    pub source_size: u64,
}

impl EncryptionJob {
    pub fn new(
        source_path: PathBuf,
        target_path: PathBuf,
        content_hash: ContentHash,
        source_size: u64,
    ) -> Self {
        Self {
            source_path,
            target_path,
            content_hash,
            source_size,
        }
    }
}

/// Result of a successful encryption operation.
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub job: EncryptionJob,
    pub algorithm: AlgorithmId,
    pub duration: Duration,
    pub output_size: u64,
    pub encrypted_data: EncryptedData,
}

impl EncryptionResult {
    pub fn new(
        job: EncryptionJob,
        algorithm: AlgorithmId,
        duration: Duration,
        encrypted_data: EncryptedData,
    ) -> Self {
        let output_size = encrypted_data.total_size() as u64;
        Self {
            job,
            algorithm,
            duration,
            output_size,
            encrypted_data,
        }
    }
}

/// Failed encryption operation.
#[derive(Debug, Clone)]
pub struct EncryptionFailure {
    pub job: EncryptionJob,
    pub error: String,
    pub duration: Duration,
}

impl EncryptionFailure {
    pub fn new(job: EncryptionJob, error: String, duration: Duration) -> Self {
        Self {
            job,
            error,
            duration,
        }
    }
}

// ============================================================================
// REPORTING
// ============================================================================

/// Final report of encryption pipeline execution.
#[derive(Debug)]
pub struct EncryptionReport {
    pub successful: Vec<EncryptionResult>,
    pub failed: Vec<EncryptionFailure>,
    pub total_duration: Duration,
    pub total_bytes_processed: u64,
    pub total_files_processed: usize,
}

impl EncryptionReport {
    pub fn new(
        successful: Vec<EncryptionResult>,
        failed: Vec<EncryptionFailure>,
        total_duration: Duration,
    ) -> Self {
        let total_bytes_processed = successful
            .iter()
            .map(|r| r.job.source_size)
            .sum();
        
        let total_files_processed = successful.len() + failed.len();

        Self {
            successful,
            failed,
            total_duration,
            total_bytes_processed,
            total_files_processed,
        }
    }
    
    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }
    
    pub fn success_count(&self) -> usize {
        self.successful.len()
    }
    
    pub fn failure_count(&self) -> usize {
        self.failed.len()
    }
    
    pub fn compression_ratio(&self) -> f64 {
        if self.total_bytes_processed == 0 {
            return 0.0;
        }
        
        let total_output_bytes: u64 = self.successful
            .iter()
            .map(|r| r.output_size)
            .sum();
            
        total_output_bytes as f64 / self.total_bytes_processed as f64
    }
}