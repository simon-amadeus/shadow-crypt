//! Encryption job creation and management.

use std::path::{Path, PathBuf};
use uuid::Uuid;
use super::types::EncryptionJob;
use crate::core::files::{FileJob, PlaintextData};
use crate::core::types::{CoreResult, FileError};

/// Create encryption jobs from classified file jobs.
pub fn create_encryption_jobs(
    file_jobs: Vec<FileJob>,
    obfuscate_filenames: bool,
) -> CoreResult<Vec<EncryptionJob>> {
    let mut encryption_jobs = Vec::new();

    for file_job in file_jobs {
        match file_job {
            FileJob::Plaintext { path, info, hash } => {
                let target_path = generate_target_path(&path, obfuscate_filenames)?;
                
                let job = EncryptionJob::new(
                    path,
                    target_path,
                    hash,
                    info.size,
                );
                
                encryption_jobs.push(job);
            }
            FileJob::Encrypted { path, .. } => {
                // Skip encrypted files or return error
                return Err(FileError::AlreadyEncrypted {
                    path: path.display().to_string(),
                }.into());
            }
        }
    }

    Ok(encryption_jobs)
}

/// Generate target path for encryption output.
fn generate_target_path(source_path: &Path, obfuscate: bool) -> CoreResult<PathBuf> {
    let parent = source_path.parent()
        .ok_or_else(|| FileError::Format {
            reason: "Source path has no parent directory".to_string(),
        })?;

    if obfuscate {
        // Generate UUID-based filename
        let uuid = Uuid::new_v4();
        let obfuscated_name = format!("{}.shadow", uuid);
        Ok(parent.join(obfuscated_name))
    } else {
        // Use original filename with .shadow extension
        let mut target = source_path.to_path_buf();
        
        if let Some(current_ext) = target.extension() {
            let new_ext = format!("{}.shadow", current_ext.to_string_lossy());
            target.set_extension(new_ext);
        } else {
            target.set_extension("shadow");
        }
        
        Ok(target)
    }
}

/// Check if target path already exists.
pub fn check_target_exists(job: &EncryptionJob, force_overwrite: bool) -> CoreResult<()> {
    if job.target_path.exists() && !force_overwrite {
        return Err(FileError::Format {
            reason: format!(
                "Target file already exists: {} (use --force to overwrite)",
                job.target_path.display()
            ),
        }.into());
    }
    Ok(())
}

/// Validate encryption jobs before processing.
pub fn validate_encryption_jobs(
    jobs: &[EncryptionJob],
    force_overwrite: bool,
) -> CoreResult<()> {
    for job in jobs {
        // Check source exists
        if !job.source_path.exists() {
            return Err(FileError::NotFound {
                path: job.source_path.display().to_string(),
            }.into());
        }

        // Check target doesn't exist (unless force)
        check_target_exists(job, force_overwrite)?;
    }

    Ok(())
}