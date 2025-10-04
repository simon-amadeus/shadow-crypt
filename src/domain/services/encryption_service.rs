//! # EncryptionService
//!
//! Orchestrates file encryption with all features.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use crate::domain::entities::{duplicate_detector::DuplicateDetector, tlv_header::{TlvHeader, TlvFieldType}, AlgorithmId};
use crate::domain::errors::{DomainError, DomainResult, FileSystemError};
use crate::domain::services::{FileDetector, CryptographicAlgorithm};
use crate::domain::utilities::content_hash::{ContentHash, calculate_content_hash};
use crate::infrastructure::tlv_serialization::TlvSerializer;

/// Orchestrates file encryption with duplicate detection and progress reporting
pub struct EncryptionService {
    duplicate_detector: Option<DuplicateDetector>,
    file_detector: FileDetector,
    progress_reporter: ProgressReporter,
}

#[derive(Debug, Clone)]
pub struct EncryptionOptions {
    pub obfuscate_filename: bool,
    pub force_overwrite: bool,
    pub remove_source: bool,
    pub check_duplicates: bool,
}

#[derive(Debug)]
pub struct EncryptionResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub content_hash: ContentHash,
    pub algorithm: AlgorithmId,
    pub duration: Duration,
}

#[derive(Debug)]
pub struct BatchResult<T> {
    pub successful: Vec<T>,
    pub failed: Vec<(PathBuf, DomainError)>,
    pub total_duration: Duration,
}

/// Progress reporting functionality
pub struct ProgressReporter {
    enabled: bool,
    callback: Option<Box<dyn Fn(&str) + Send + Sync>>,
}

impl ProgressReporter {
    pub fn new(enabled: bool) -> Self {
        Self { 
            enabled,
            callback: None,
        }
    }

    /// Create a progress reporter with a custom callback
    pub fn with_callback<F>(callback: F) -> Self 
    where 
        F: Fn(&str) + Send + Sync + 'static,
    {
        Self {
            enabled: true,
            callback: Some(Box::new(callback)),
        }
    }

    pub fn report_progress(&self, message: &str) {
        if self.enabled {
            if let Some(callback) = &self.callback {
                callback(message);
            } else {
                // Default progress reporting for testing/development
                eprintln!("[PROGRESS] {}", message);
            }
        }
    }
}

impl EncryptionService {
    /// Create a new EncryptionService instance
    pub fn new() -> Self {
        Self {
            duplicate_detector: None,
            file_detector: FileDetector::new(),
            progress_reporter: ProgressReporter::new(false),
        }
    }

    /// Enable duplicate detection with given search paths
    pub fn with_duplicate_detection(mut self, search_paths: Vec<PathBuf>) -> Self {
        self.duplicate_detector = Some(DuplicateDetector::new(search_paths));
        self
    }

    /// Enable or disable progress reporting
    pub fn with_progress_reporting(mut self, enabled: bool) -> Self {
        self.progress_reporter = ProgressReporter::new(enabled);
        self
    }

    /// Set custom progress reporting callback
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self 
    where 
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.progress_reporter = ProgressReporter::with_callback(callback);
        self
    }

    /// Encrypt a single file with double-encryption prevention
    pub fn encrypt_file<T: CryptographicAlgorithm>(
        &mut self,
        input_path: &Path,
        output_path: &Path,
        algorithm: &T,
        password: &str,
        options: EncryptionOptions,
    ) -> DomainResult<EncryptionResult> {
        let start_time = Instant::now();

        // Phase 1: File detection and double-encryption prevention
        self.progress_reporter.report_progress("Checking file format and encryption safety...");
        
        // Prevent double-encryption (the core integration with FileDetector)
        self.file_detector.validate_encryption_safety(input_path, options.force_overwrite)?;

        // Phase 2: Read file contents and calculate content hash
        self.progress_reporter.report_progress("Reading file contents...");
        let content = std::fs::read(input_path)
            .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed { 
                operation: format!("read file {}", input_path.display()),
                reason: e.to_string(),
            }))?;

        // Calculate content hash for fingerprinting and duplicate detection
        let content_hash = calculate_content_hash(&content);

        // Phase 3: Duplicate detection (if enabled)
        if options.check_duplicates {
            if let Some(detector) = &self.duplicate_detector {
                self.progress_reporter.report_progress("Checking for duplicates...");
                
                // Check if this content hash already exists
                if let Some(duplicate_paths) = detector.check_duplicate(&content_hash) {
                    // For now, log the duplicates - user prompt will be added in Phase 4
                    self.progress_reporter.report_progress(&format!(
                        "Warning: Found {} files with identical content", 
                        duplicate_paths.len()
                    ));
                    for path in duplicate_paths {
                        self.progress_reporter.report_progress(&format!(
                            "  Duplicate: {}", 
                            path.display()
                        ));
                    }
                    // TODO: Implement user prompt for duplicate handling decision
                }
            }
        }

        // Phase 4: Generate key material
        self.progress_reporter.report_progress("Deriving encryption keys...");
        let salt = algorithm.generate_salt()?;
        let key_material = algorithm.derive_key_material(password, &salt)?;

        // Phase 5: Encrypt content
        self.progress_reporter.report_progress("Encrypting file...");
        let encryption_result = algorithm.encrypt(&content, &key_material)?;

        // Phase 6: Create TLV header with content hash
        self.progress_reporter.report_progress("Creating TLV header...");
        let mut header = TlvHeader::new();
        
        // Add algorithm ID field
        header.add_field(TlvFieldType::AlgorithmId, vec![algorithm.algorithm_id() as u8]);
        
        // Add nonce field  
        header.add_field(TlvFieldType::Nonce, encryption_result.nonce);
        
        // Add salt field (using key derivation params)
        header.add_field(TlvFieldType::KeyDerivationParams, salt);

        // Add content hash for duplicate detection and integrity
        header.set_content_hash(content_hash);

        // Phase 7: Serialize header and write encrypted file
        let header_bytes = TlvSerializer::serialize(&header)
            .map_err(|e| DomainError::FormatError(crate::domain::errors::FormatError::HeaderParsingFailed { 
                field: "TLV header".to_string(),
                reason: e.to_string() 
            }))?;

        let mut output_data = Vec::new();
        output_data.extend_from_slice(&header_bytes);
        output_data.extend_from_slice(&encryption_result.ciphertext);

        self.progress_reporter.report_progress("Writing encrypted file...");
        std::fs::write(output_path, &output_data)
            .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed { 
                operation: format!("write encrypted file {}", output_path.display()),
                reason: e.to_string(),
            }))?;

        // Phase 8: Track encrypted file in duplicate database (if duplicate detection enabled)
        if options.check_duplicates {
            if let Some(detector) = &mut self.duplicate_detector {
                detector.add_encrypted_file(output_path.to_path_buf(), content_hash);
            }
        }

        // Phase 9: Source removal (if requested)
        if options.remove_source {
            self.progress_reporter.report_progress("Removing source file...");
            std::fs::remove_file(input_path)
                .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed { 
                    operation: format!("remove source file {}", input_path.display()),
                    reason: e.to_string(),
                }))?;
        }

        let duration = start_time.elapsed();
        self.progress_reporter.report_progress("Encryption complete!");

        Ok(EncryptionResult {
            input_path: input_path.to_path_buf(),
            output_path: output_path.to_path_buf(),
            content_hash,
            algorithm: algorithm.algorithm_id(),
            duration,
        })
    }

    /// Encrypt multiple files in batch
    pub fn encrypt_multiple_files<T: CryptographicAlgorithm>(
        &mut self,
        file_pairs: Vec<(PathBuf, PathBuf)>,
        algorithm: &T,
        password: &str,
        options: EncryptionOptions,
    ) -> DomainResult<BatchResult<EncryptionResult>> {
        let start_time = Instant::now();
        let mut successful = Vec::new();
        let mut failed = Vec::new();

        for (input_path, output_path) in file_pairs {
            match self.encrypt_file(&input_path, &output_path, algorithm, password, options.clone()) {
                Ok(result) => successful.push(result),
                Err(error) => failed.push((input_path, error)),
            }
        }

        Ok(BatchResult {
            successful,
            failed,
            total_duration: start_time.elapsed(),
        })
    }
}