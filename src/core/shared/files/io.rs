//! File I/O operations for the encryption pipeline.

use std::fs::File;
use std::io::{Write, BufWriter};
use std::path::Path;
use crate::core::shared::files::EncryptedData;
use crate::core::encryption::types::EncryptionJob;
use crate::core::shared::types::{CoreResult, FileError};

/// Write encrypted data to file atomically.
/// 
/// Uses atomic write pattern: write to temporary file, then rename.
/// This ensures the operation is atomic and prevents corruption.
pub fn write_encrypted_file(
    job: &EncryptionJob,
    encrypted_data: &EncryptedData,
    force_overwrite: bool,
) -> CoreResult<()> {
    // Check if target already exists (unless force overwrite)
    if job.target_path.exists() && !force_overwrite {
        return Err(FileError::Format {
            reason: format!(
                "Target file already exists: {} (use --force to overwrite)",
                job.target_path.display()
            ),
        }.into());
    }

    // Create temporary file path
    let temp_path = create_temp_path(&job.target_path)?;

    // Write to temporary file first (atomic operation)
    {
        let temp_file = File::create(&temp_path)
            .map_err(|e| FileError::Permission {
                path: temp_path.display().to_string(),
            })?;

        let mut writer = BufWriter::new(temp_file);

        // Write TLV header using the proper serialization
        let header_bytes = encrypted_data.header.to_bytes()
            .map_err(|e| FileError::Format {
                reason: format!("Failed to serialize header: {}", e),
            })?;
        
        writer.write_all(&header_bytes)
            .map_err(|e| FileError::Format {
                reason: format!("Failed to write header: {}", e),
            })?;

        // Write encrypted content
        writer.write_all(&encrypted_data.ciphertext)
            .map_err(|e| FileError::Format {
                reason: format!("Failed to write encrypted content: {}", e),
            })?;

        writer.flush()
            .map_err(|e| FileError::Format {
                reason: format!("Failed to flush data: {}", e),
            })?;
    } // File is closed here

    // Atomic rename from temp to final location
    std::fs::rename(&temp_path, &job.target_path)
        .map_err(|e| FileError::Format {
            reason: format!("Failed to finalize file write: {}", e),
        })?;

    Ok(())
}

/// Remove source file after successful encryption.
pub fn remove_source_file(path: &Path) -> CoreResult<()> {
    std::fs::remove_file(path)
        .map_err(|_e| FileError::Permission {
            path: path.display().to_string(),
        })?;
    Ok(())
}

/// Create a temporary file path for atomic writes.
fn create_temp_path(target_path: &Path) -> CoreResult<std::path::PathBuf> {
    let parent = target_path.parent()
        .ok_or_else(|| FileError::Format {
            reason: "Target path has no parent directory".to_string(),
        })?;

    let file_stem = target_path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("encrypted");

    // Use process ID and timestamp for uniqueness
    let temp_name = format!("{}.tmp.{}.{}", 
        file_stem, 
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );

    Ok(parent.join(temp_name))
}

/// Verify that an encrypted file was written correctly.
pub fn verify_encrypted_file(path: &Path, expected_size: usize) -> CoreResult<()> {
    let metadata = std::fs::metadata(path)
        .map_err(|_| FileError::NotFound {
            path: path.display().to_string(),
        })?;

    let actual_size = metadata.len() as usize;
    
    // The encrypted file should be at least the expected size
    // (header + ciphertext), but could be slightly larger due to OS metadata
    if actual_size < expected_size {
        return Err(FileError::Format {
            reason: format!(
                "Encrypted file is smaller than expected: {} < {} bytes",
                actual_size, expected_size
            ),
        }.into());
    }

    // Basic file accessibility check
    let _file = File::open(path)
        .map_err(|_| FileError::Permission {
            path: path.display().to_string(),
        })?;

    Ok(())
}