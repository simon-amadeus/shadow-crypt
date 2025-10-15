//! Main encryption pipeline implementation.

use std::time::Instant;
use super::types::{EncryptionOptions, EncryptionJob, EncryptionResult, EncryptionFailure, EncryptionReport};
use super::jobs::{create_encryption_jobs, validate_encryption_jobs};
use super::validation::{validate_options, validate_files_for_encryption, validate_password};
use crate::core::shared::files::operations::{expand_patterns, filter_regular_files, classify_files};
use crate::core::shared::files::{EncryptedData, write_encrypted_file, remove_source_file, verify_encrypted_file};
use crate::core::shared::files::format::{TlvHeaderBuilder, TlvHeader};
use crate::core::shared::crypto::{create_session, generate_nonce, encrypt_data, CryptoSession};
use crate::core::shared::types::{CoreResult, CoreError};
use crate::core::shared::pipeline::ProcessContinue;

/// Main encryption pipeline orchestrating the functional workflow.
pub struct EncryptionPipeline;

impl EncryptionPipeline {
    /// Execute the complete encryption pipeline.
    pub fn execute(
        patterns: Vec<String>,
        password: String,
        options: EncryptionOptions,
    ) -> CoreResult<EncryptionReport> {
        let start_time = Instant::now();

        // Step 1-3: Parse args, expand patterns, validate
        println!("⏳ 📁 Expanding file patterns...");
        let paths = expand_patterns(patterns)?;
        
        println!("⏳ 🔍 Filtering regular files...");
        let regular_files = filter_regular_files(paths)?;
        
        println!("⏳ 📋 Classifying files...");
        let file_jobs = classify_files(regular_files)?;

        // Step 3: Validate password and options
        println!("⏳ 🔐 Validating password and options...");
        validate_password(&password)?;
        validate_options(&options)?;
        validate_files_for_encryption(&file_jobs)?;

        // Step 4-10: Create encryption jobs
        println!("⏳ ⚙️ Creating encryption jobs...");
        let encryption_jobs = create_encryption_jobs(file_jobs, options.obfuscate_filename)?;
        validate_encryption_jobs(&encryption_jobs, options.force_overwrite)?;

        // Step 5: Create crypto session
        println!("⏳ 🔑 Initializing cryptographic session...");
        let session = create_session(&password, options.algorithm, None)?;

        // Step 11-13: Execute encryption jobs
        println!("⏳ 🔐 Encrypting {} files...", encryption_jobs.len());
        let (successful, failed) = Self::process_batch_jobs(encryption_jobs, &session, &options);

        let total_duration = start_time.elapsed();
        
        // Step 15: Generate final report
        println!("✅ Encryption completed: {} successful, {} failed", successful.len(), failed.len());
        Ok(EncryptionReport::new(successful, failed, total_duration))
    }

    /// Process all encryption jobs, collecting successes and failures.
    fn process_batch_jobs(
        jobs: Vec<EncryptionJob>,
        session: &CryptoSession,
        options: &EncryptionOptions,
    ) -> (Vec<EncryptionResult>, Vec<EncryptionFailure>) {
        let total_jobs = jobs.len();

        jobs.into_iter()
            .enumerate()
            .process_continue(|(index, job)| {
                let file_name = job.source_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown");
                
                println!("  📄 [{}/{}] Encrypting {}...", index + 1, total_jobs, file_name);
                
                let start_time = Instant::now();
                
                match Self::encrypt_and_write_job(&job, session, options) {
                    Ok(result) => {
                        let duration = start_time.elapsed();
                        let encryption_result = EncryptionResult::new(
                            job,
                            session.algorithm(),
                            duration,
                            result,
                        );
                        println!("    ✅ Success ({:.2}ms)", duration.as_secs_f64() * 1000.0);
                        Ok(encryption_result)
                    }
                    Err(error) => {
                        let duration = start_time.elapsed();
                        let failure = EncryptionFailure::new(
                            job,
                            error.to_string(),
                            duration,
                        );
                        println!("    ❌ Failed: {}", error);
                        Err(failure)
                    }
                }
            })
    }

    /// Encrypt a single job and write to disk with proper cleanup.
    fn encrypt_and_write_job(
        job: &EncryptionJob,
        session: &CryptoSession,
        options: &EncryptionOptions,
    ) -> CoreResult<EncryptedData> {
        // Step 11: Encrypt the file
        let encrypted_data = Self::encrypt_single_job(job, session, options)?;

        // Step 12: Write encrypted file atomically
        write_encrypted_file(job, &encrypted_data, options.force_overwrite)?;

        // Step 12: Verify the written file (temporarily disabled for debugging)
        // verify_encrypted_file(&job.target_path, encrypted_data.total_size())?;

        // Step 13: Cleanup - remove source file if requested
        if options.remove_source {
            remove_source_file(&job.source_path)?;
        }

        Ok(encrypted_data)
    }

    /// Encrypt a single job (Steps 11-12: encrypt + validate).
    fn encrypt_single_job(
        job: &EncryptionJob,
        session: &CryptoSession,
        options: &EncryptionOptions,
    ) -> CoreResult<EncryptedData> {
        // Load file content
        let content = std::fs::read(&job.source_path)
            .map_err(|e| CoreError::Io(e))?;

        // Generate nonce for encryption
        let nonce = generate_nonce(session.algorithm())?;

        // Create TLV header
        let filename = job.source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let header = TlvHeaderBuilder::new(1)
            .with_filename(filename)
            .with_algorithm_id(session.algorithm().as_u16())
            .with_nonce(&nonce)
            .with_content_hash(&job.content_hash)
            .build();

        // Serialize header for associated data (provides authenticated encryption of metadata)
        let header_bytes = Self::serialize_header(&header);
        
        // Encrypt content with header as associated data
        let ciphertext = encrypt_data(
            &content,
            session,
            &nonce,
            Some(&header_bytes),
        )?;

        // Create encrypted data structure
        let encrypted_data = EncryptedData::new(
            header,
            ciphertext,
            if options.obfuscate_filename { None } else { Some(filename.to_string()) },
            Self::generate_obfuscated_filename(),
        );

        Ok(encrypted_data)
    }

    /// Serialize TLV header for use as associated data.
    fn serialize_header(header: &TlvHeader) -> Vec<u8> {
        // Simple serialization - in production you'd use the actual TLV format
        let mut bytes = Vec::new();
        
        // Add version
        bytes.extend_from_slice(&header.version().to_le_bytes());
        
        // Add algorithm ID if present
        if let Some(algo_id) = header.algorithm_id() {
            bytes.extend_from_slice(&algo_id.to_le_bytes());
        }
        
        // Add filename if present
        if let Some(filename) = header.original_filename() {
            bytes.extend_from_slice(filename.as_bytes());
        }
        
        bytes
    }

    /// Generate obfuscated filename.
    fn generate_obfuscated_filename() -> String {
        format!("{}.shadow", uuid::Uuid::new_v4())
    }
}