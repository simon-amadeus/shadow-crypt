//! # EncryptionService
//!
//! Orchestrates file encryption with all features.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use crate::domain::entities::{duplicate_detector::DuplicateDetector, header::{TlvHeader, TlvFieldType}, AlgorithmId};
use crate::domain::errors::{DomainError, DomainResult, FileSystemError};
use crate::domain::services::{FileDetector, CryptographicAlgorithm};
use crate::domain::utilities::content_hash::{ContentHash, calculate_content_hash};
use crate::infrastructure::tlv_serialization::TlvSerializer;
use crate::infrastructure::{ProgressReporter, ProgressContext, ProgressStyle};

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

impl Default for EncryptionService {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptionService {
    /// Create a new EncryptionService instance
    pub fn new() -> Self {
        Self {
            duplicate_detector: None,
            file_detector: FileDetector::new(),
            progress_reporter: ProgressReporter::from_quiet_mode(true), // Default to quiet
        }
    }

    /// Enable duplicate detection with given search paths
    pub fn with_duplicate_detection(mut self, search_paths: Vec<PathBuf>) -> Self {
        self.duplicate_detector = Some(DuplicateDetector::new(search_paths));
        self
    }

    /// Enable or disable progress reporting
    pub fn with_progress_reporting(mut self, enabled: bool) -> Self {
        self.progress_reporter = ProgressReporter::from_quiet_mode(!enabled);
        self
    }

    /// Set progress style
    pub fn with_progress_style(mut self, style: ProgressStyle) -> Self {
        self.progress_reporter = ProgressReporter::new(style);
        self
    }

    /// Encrypt a single file with automatic filename obfuscation when enabled
    /// 
    /// This is a convenience method that automatically generates the output path
    /// based on the filename obfuscation settings in the options.
    pub fn encrypt_file_with_obfuscation<T: CryptographicAlgorithm>(
        &mut self,
        input_path: &Path,
        algorithm: &T,
        password: &str,
        options: EncryptionOptions,
    ) -> DomainResult<EncryptionResult> {
        let (output_path, _obfuscated_info) = if options.obfuscate_filename {
            // Generate obfuscated output path
            FilenameObfuscator::create_obfuscated_output_path(input_path, false)?
        } else {
            // Use standard .shadow extension
            let output_path = input_path.with_extension("shadow");
            (output_path, ObfuscatedFilename {
                obfuscated_name: input_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                original_name: input_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                extension: input_path.extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext.to_string()),
            })
        };

        self.encrypt_file(input_path, &output_path, algorithm, password, options)
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
        let context = ProgressContext::new("Encrypting file".to_string())
            .with_file(input_path.display().to_string())
            .with_phase("Checking encryption safety".to_string())
            .with_elapsed(start_time.elapsed());
        self.progress_reporter.report_with_context(context);
        
        // Prevent double-encryption (the core integration with FileDetector)
        self.file_detector.validate_encryption_safety(input_path, options.force_overwrite)?;

        // Phase 2: Read file contents and calculate content hash
        let context = ProgressContext::new("Encrypting file".to_string())
            .with_file(input_path.display().to_string())
            .with_phase("Reading content".to_string())
            .with_elapsed(start_time.elapsed());
        self.progress_reporter.report_with_context(context);
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
                self.progress_reporter.report_simple("Checking for duplicates...");
                
                // Check if this content hash already exists
                if let Some(duplicate_paths) = detector.check_duplicate(&content_hash) {
                    // For now, log the duplicates - user prompt will be added in Phase 4
                    self.progress_reporter.report_simple(&format!(
                        "Warning: Found {} files with identical content", 
                        duplicate_paths.len()
                    ));
                    for path in duplicate_paths {
                        self.progress_reporter.report_simple(&format!(
                            "  Duplicate: {}", 
                            path.display()
                        ));
                    }
                    // Future enhancement: Interactive duplicate handling.
                    // Currently duplicates are detected and logged for user awareness.
                    // Future versions could prompt for action (skip, encrypt anyway, view diff).
                }
            }
        }

        // Phase 4: Generate key material
        self.progress_reporter.report_simple("Deriving encryption keys...");
        let salt = algorithm.generate_salt()?;
        let key_material = algorithm.derive_key_material(password, &salt)?;

        // Phase 5: Encrypt content
        self.progress_reporter.report_simple("Encrypting file...");
        let encryption_result = algorithm.encrypt(&content, &key_material)?;

        // Phase 6: Create TLV header with content hash
        self.progress_reporter.report_simple("Creating TLV header...");
        let mut header = TlvHeader::new();
        
        // Add original filename
        if let Some(filename) = input_path.file_name().and_then(|n| n.to_str()) {
            header.set_original_filename(filename);
        }
        
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

        self.progress_reporter.report_simple("Writing encrypted file...");
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
            self.progress_reporter.report_simple("Removing source file...");
            std::fs::remove_file(input_path)
                .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed { 
                    operation: format!("remove source file {}", input_path.display()),
                    reason: e.to_string(),
                }))?;
        }

        let duration = start_time.elapsed();
        self.progress_reporter.complete_operation("Encryption complete!");

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