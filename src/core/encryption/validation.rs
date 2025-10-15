//! Validation functions for encryption pipeline.

use std::path::Path;
use super::types::EncryptionOptions;
use crate::core::shared::files::FileJob;
use crate::core::shared::types::{CoreResult, ValidationError, FileError};

/// Validate encryption options.
pub fn validate_options(options: &EncryptionOptions) -> CoreResult<()> {
    // Basic validation - could be extended
    Ok(())
}

/// Validate that files are suitable for encryption.
pub fn validate_files_for_encryption(file_jobs: &[FileJob]) -> CoreResult<()> {
    if file_jobs.is_empty() {
        return Err(ValidationError::EmptyFileList.into());
    }

    for job in file_jobs {
        match job {
            FileJob::Plaintext { .. } => {
                // Plaintext files are good for encryption
                continue;
            }
            FileJob::Encrypted { path, .. } => {
                // Encrypted files should not be encrypted again
                return Err(FileError::AlreadyEncrypted {
                    path: path.display().to_string(),
                }.into());
            }
        }
    }

    Ok(())
}

/// Validate that password meets requirements.
pub fn validate_password(password: &str) -> CoreResult<()> {
    if password.is_empty() {
        return Err(ValidationError::InvalidPassword {
            reason: "Password cannot be empty".to_string(),
        }.into());
    }

    if password.len() < 8 {
        return Err(ValidationError::InvalidPassword {
            reason: "Password must be at least 8 characters".to_string(),
        }.into());
    }

    // Could add more sophisticated password validation here
    Ok(())
}

/// Validate password confirmation matches.
pub fn validate_password_confirmation(password: &str, confirmation: &str) -> CoreResult<()> {
    if password != confirmation {
        return Err(ValidationError::InvalidPassword {
            reason: "Password confirmation does not match".to_string(),
        }.into());
    }

    Ok(())
}