//! # DecryptionService
//!
//! Orchestrates file decryption with filename restoration.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use crate::domain::entities::{AlgorithmId, header::TlvFieldType};
use crate::domain::errors::{DomainResult, DomainError, FileSystemError};
use crate::domain::services::{FileDetector, CryptographicAlgorithm};
use crate::domain::services::crypto_service::KeyDerivationConfig;
use crate::domain::services::encryption_service::BatchResult;
use crate::infrastructure::{ProgressReporter, ProgressStyle};

use crate::infrastructure::crypto::factory::Algorithm;
use crate::infrastructure::tlv_serialization::TlvSerializer;

/// Orchestrates file decryption with filename restoration
pub struct DecryptionService {
    file_detector: FileDetector,
    progress_reporter: ProgressReporter,
}

#[derive(Debug, Clone)]
pub struct DecryptionOptions {
    pub force_overwrite: bool,
    pub remove_source: bool,
    pub verify_integrity: bool,
}

#[derive(Debug)]
pub struct DecryptionResult {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub original_filename: Option<String>,
    pub algorithm: AlgorithmId,
    pub duration: Duration,
}

impl Default for DecryptionService {
    fn default() -> Self {
        Self::new()
    }
}

impl DecryptionService {
    /// Create a new DecryptionService instance
    pub fn new() -> Self {
        Self {
            file_detector: FileDetector::new(),
            progress_reporter: ProgressReporter::from_quiet_mode(true), // Default to quiet
        }
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

    /// Decrypt a single file with automatic filename restoration and validation
    /// 
    /// This is a convenience method that automatically restores the original filename
    /// from the TLV header and validates it for security.
    pub fn decrypt_file_with_validation(
        &mut self,
        input_path: &Path,
        password: &str,
        options: DecryptionOptions,
    ) -> DomainResult<DecryptionResult> {
        // First decrypt to get the original filename
        let temp_result = self.decrypt_file(input_path, None, password, options.clone())?;
        
        // Validate the original filename if it was restored from obfuscation
        if let Some(ref original_filename) = temp_result.original_filename {
            FilenameObfuscator::validate_filename_safety(original_filename)?;
        }
        
        Ok(temp_result)
    }

    /// Decrypt a single file with automatic filename restoration
    pub fn decrypt_file(
        &mut self,
        input_path: &Path,
        output_path: Option<&Path>, // None = auto-detect from header
        password: &str,
        options: DecryptionOptions,
    ) -> DomainResult<DecryptionResult> {
        let start_time = Instant::now();

        // Phase 1: File detection and validation
        self.progress_reporter.report_simple("Detecting file format...");
        
        if !self.file_detector.is_encrypted_file(input_path)? {
            return Err(DomainError::InputValidationError(
                crate::domain::errors::InputValidationError::InvalidPath {
                    path: input_path.display().to_string(),
                    reason: "File is not a valid encrypted Shadow file".to_string(),
                }
            ));
        }

        // Phase 2: Read and parse encrypted file
        self.progress_reporter.report_simple("Reading encrypted file...");
        let encrypted_data = std::fs::read(input_path)
            .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed { 
                operation: format!("read encrypted file {}", input_path.display()),
                reason: e.to_string(),
            }))?;

        // Phase 3: Parse TLV header and extract ciphertext
        self.progress_reporter.report_simple("Parsing file header...");
        let (header, ciphertext) = TlvSerializer::deserialize_with_remainder(&encrypted_data)
            .map_err(|e| DomainError::FormatError(
                crate::domain::errors::FormatError::HeaderParsingFailed { 
                    field: "TLV header".to_string(),
                    reason: e.to_string() 
                }
            ))?;

        // Phase 4: Extract algorithm and configuration
        let algorithm_id = header.get_field(TlvFieldType::AlgorithmId)
            .and_then(|data| data.first().copied())
            .and_then(|id_byte| match id_byte {
                1 => Some(AlgorithmId::XChaCha20Poly1305),
                2 => Some(AlgorithmId::AesGcm256),
                _ => None,
            })
            .ok_or_else(|| DomainError::FormatError(
                crate::domain::errors::FormatError::HeaderParsingFailed { 
                    field: "AlgorithmId".to_string(),
                    reason: "Invalid or missing algorithm ID".to_string() 
                }
            ))?;

        let algorithm = Algorithm::from_id(algorithm_id);

        // Phase 5: Extract cryptographic parameters
        let nonce = header.get_field(TlvFieldType::Nonce)
            .ok_or_else(|| DomainError::FormatError(
                crate::domain::errors::FormatError::HeaderParsingFailed { 
                    field: "Nonce".to_string(),
                    reason: "Missing nonce field".to_string() 
                }
            ))?;

        let salt = header.get_field(TlvFieldType::KeyDerivationParams)
            .ok_or_else(|| DomainError::FormatError(
                crate::domain::errors::FormatError::HeaderParsingFailed { 
                    field: "KeyDerivationParams".to_string(),
                    reason: "Missing salt field".to_string() 
                }
            ))?;

        // Phase 6: Derive key material
        self.progress_reporter.report_simple("Deriving decryption keys...");
        let key_material = algorithm.derive_key_material(password, salt)?;

        // Phase 7: Decrypt content  
        self.progress_reporter.report_simple("Decrypting file content...");
        let plaintext = algorithm.decrypt(ciphertext, nonce, &key_material)?;

        // Phase 8: Determine output path
        let original_filename = header.original_filename();
        let final_output_path = match output_path {
            Some(path) => path.to_path_buf(),
            None => {
                // Auto-detect from original filename or use input name without encryption extension
                if let Some(orig_name) = &original_filename {
                    input_path.parent()
                        .map(|parent| parent.join(orig_name))
                        .unwrap_or_else(|| PathBuf::from(orig_name))
                } else {
                    // Remove .shadow extension if present, otherwise add .decrypted
                    let stem = input_path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("decrypted");
                    input_path.parent()
                        .map(|parent| parent.join(stem))
                        .unwrap_or_else(|| PathBuf::from(stem))
                }
            }
        };

        // Phase 9: Check for overwrite conflicts
        if final_output_path.exists() && !options.force_overwrite {
            return Err(DomainError::InputValidationError(
                crate::domain::errors::InputValidationError::InvalidPath {
                    path: final_output_path.display().to_string(),
                    reason: "Output file already exists. Use --force to overwrite".to_string(),
                }
            ));
        }

        // Phase 10: Write decrypted file
        self.progress_reporter.report_simple("Writing decrypted file...");
        std::fs::write(&final_output_path, &plaintext)
            .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed { 
                operation: format!("write decrypted file {}", final_output_path.display()),
                reason: e.to_string(),
            }))?;

        // Phase 11: Remove source file if requested
        if options.remove_source {
            self.progress_reporter.report_simple("Removing encrypted source file...");
            std::fs::remove_file(input_path)
                .map_err(|e| DomainError::FileSystemError(FileSystemError::IoOperationFailed { 
                    operation: format!("remove source file {}", input_path.display()),
                    reason: e.to_string(),
                }))?;
        }

        let duration = start_time.elapsed();
        self.progress_reporter.complete_operation("Decryption complete!");

        Ok(DecryptionResult {
            input_path: input_path.to_path_buf(),
            output_path: final_output_path,
            original_filename,
            algorithm: algorithm_id,
            duration,
        })
    }

    /// Decrypt multiple files in batch
    pub fn decrypt_multiple_files(
        &mut self,
        input_paths: Vec<PathBuf>,
        password: &str,
        options: DecryptionOptions,
    ) -> DomainResult<BatchResult<DecryptionResult>> {
        let start_time = Instant::now();
        let mut successful = Vec::new();
        let mut failed = Vec::new();

        for input_path in input_paths {
            match self.decrypt_file(&input_path, None, password, options.clone()) {
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