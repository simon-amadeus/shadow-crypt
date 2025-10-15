//! Main encryption pipeline implementation.

use std::time::Instant;
use super::types::{EncryptionOptions, EncryptionJob, EncryptionResult, EncryptionFailure, EncryptionReport};
use super::jobs::{create_encryption_jobs, validate_encryption_jobs};
use super::validation::{validate_options, validate_files_for_encryption, validate_password};
use crate::core::files::operations::{expand_patterns, filter_regular_files, classify_files};
use crate::core::files::EncryptedData;
use crate::core::files::format::TlvHeaderBuilder;
use crate::core::crypto::operations::create_session;
use crate::core::types::{CoreResult, CoreError};
use crate::{pipeline};

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
        let file_jobs = pipeline!(
            patterns
            => expand_patterns                    // Step 2: expand patterns
            => filter_regular_files              // Step 6: filter regular files  
            => classify_files                    // Step 7-8: classify and hash
        )?;

        // Step 3: Validate password and options
        validate_password(&password)?;
        validate_options(&options)?;
        validate_files_for_encryption(&file_jobs)?;

        // Step 4-10: Create encryption jobs
        let encryption_jobs = create_encryption_jobs(file_jobs, options.obfuscate_filename)?;
        validate_encryption_jobs(&encryption_jobs, options.force_overwrite)?;

        // Step 5: Create crypto session
        let session = create_session(&password, options.algorithm, None)?;

        // Step 11-13: Execute encryption jobs
        let (successful, failed) = Self::process_encryption_jobs(encryption_jobs, &session, &options);

        let total_duration = start_time.elapsed();
        
        // Step 15: Generate final report
        Ok(EncryptionReport::new(successful, failed, total_duration))
    }

    /// Process all encryption jobs, collecting successes and failures.
    fn process_encryption_jobs(
        jobs: Vec<EncryptionJob>,
        session: &crate::core::crypto::CryptoSession,
        options: &EncryptionOptions,
    ) -> (Vec<EncryptionResult>, Vec<EncryptionFailure>) {
        let mut successful = Vec::new();
        let mut failed = Vec::new();

        for job in jobs {
            let start_time = Instant::now();
            
            match Self::encrypt_single_job(&job, session, options) {
                Ok(result) => {
                    let duration = start_time.elapsed();
                    let encryption_result = EncryptionResult::new(
                        job,
                        session.algorithm(),
                        duration,
                        result,
                    );
                    successful.push(encryption_result);
                }
                Err(error) => {
                    let duration = start_time.elapsed();
                    let failure = EncryptionFailure::new(
                        job,
                        error.to_string(),
                        duration,
                    );
                    failed.push(failure);
                }
            }
        }

        (successful, failed)
    }

    /// Encrypt a single job (Steps 11-12: encrypt + validate).
    fn encrypt_single_job(
        job: &EncryptionJob,
        session: &crate::core::crypto::CryptoSession,
        options: &EncryptionOptions,
    ) -> CoreResult<EncryptedData> {
        // Load file content
        let content = std::fs::read(&job.source_path)
            .map_err(|e| CoreError::Io(e))?;

        // Create TLV header
        let filename = job.source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let header = TlvHeaderBuilder::new(1)
            .with_filename(filename)
            .with_algorithm_id(session.algorithm().as_u16())
            .with_content_hash(&job.content_hash)
            .build();

        // For now, create a simplified encrypted data structure
        // In a real implementation, this would use the actual crypto infrastructure
        let encrypted_data = EncryptedData::new(
            header,
            Self::mock_encrypt(&content, session)?,
            if options.obfuscate_filename { None } else { Some(filename.to_string()) },
            Self::generate_obfuscated_filename(),
        );

        Ok(encrypted_data)
    }

    /// Mock encryption function - replace with real crypto.
    fn mock_encrypt(
        content: &[u8],
        session: &crate::core::crypto::CryptoSession,
    ) -> CoreResult<Vec<u8>> {
        // This is a placeholder - in reality you'd use the actual crypto infrastructure
        // from the infrastructure layer
        let mut encrypted = content.to_vec();
        
        // Simple XOR with first byte of key (just for demo)
        let key_byte = session.encryption_key()[0];
        for byte in &mut encrypted {
            *byte ^= key_byte;
        }
        
        Ok(encrypted)
    }

    /// Generate obfuscated filename.
    fn generate_obfuscated_filename() -> String {
        format!("{}.shadow", uuid::Uuid::new_v4())
    }
}