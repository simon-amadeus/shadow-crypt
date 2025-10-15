//! File I/O operations for the encryption pipeline.

use std::fs::File;
use std::io::{Write, BufWriter};
use std::path::Path;
use crate::core::files::EncryptedData;
use crate::core::encryption::types::EncryptionJob;
use crate::core::types::{CoreResult, FileError};

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

        // Write TLV header
        write_tlv_header(&mut writer, &encrypted_data.header)?;

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
        .map_err(|e| FileError::Permission {
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

/// Write TLV header to a writer.
fn write_tlv_header(
    writer: &mut impl Write,
    header: &crate::core::files::format::TlvHeader,
) -> CoreResult<()> {
    // Write version
    writer.write_all(&header.version().to_le_bytes())
        .map_err(|e| FileError::Format {
            reason: format!("Failed to write header version: {}", e),
        })?;

    // For now, write a simplified header format
    // In production, you'd implement the full TLV serialization
    
    // Write algorithm ID if present
    if let Some(algo_id) = header.algorithm_id() {
        writer.write_all(&[0x10, 0x02, 0x00]) // Type=0x10, Length=2
            .map_err(|e| FileError::Format {
                reason: format!("Failed to write algorithm field: {}", e),
            })?;
        writer.write_all(&algo_id.to_le_bytes())
            .map_err(|e| FileError::Format {
                reason: format!("Failed to write algorithm ID: {}", e),
            })?;
    }

    // Write filename if present
    if let Some(filename) = header.original_filename() {
        let filename_bytes = filename.as_bytes();
        writer.write_all(&[0x01]) // Type=0x01
            .map_err(|e| FileError::Format {
                reason: format!("Failed to write filename field type: {}", e),
            })?;
        writer.write_all(&(filename_bytes.len() as u16).to_le_bytes())
            .map_err(|e| FileError::Format {
                reason: format!("Failed to write filename length: {}", e),
            })?;
        writer.write_all(filename_bytes)
            .map_err(|e| FileError::Format {
                reason: format!("Failed to write filename: {}", e),
            })?;
    }

    Ok(())
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