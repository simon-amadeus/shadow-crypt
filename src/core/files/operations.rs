//! Pure file operations for the functional pipeline.

use std::path::{Path, PathBuf};
use std::fs;
use std::io::Read;
use glob::glob;
use super::types::{FileJob, FileInfo, FileType, PlaintextData};
use super::detection::detect_file_type;
use super::format::TlvHeader;
use crate::core::crypto::{SecureBox, ContentHasher};
use crate::core::types::{CoreResult, FileError, ValidationError};

/// Expand glob patterns into individual file paths.
pub fn expand_patterns(patterns: Vec<String>) -> CoreResult<Vec<PathBuf>> {
    if patterns.is_empty() {
        return Err(ValidationError::EmptyFileList.into());
    }

    let mut file_paths = Vec::new();

    for pattern in patterns {
        match glob(&pattern) {
            Ok(entries) => {
                let mut found_any = false;
                for entry in entries {
                    match entry {
                        Ok(path) => {
                            if path.is_file() {
                                file_paths.push(path);
                                found_any = true;
                            }
                        }
                        Err(e) => {
                            return Err(FileError::Format {
                                reason: format!("Error processing glob pattern '{}': {}", pattern, e)
                            }.into());
                        }
                    }
                }

                // If no files found, try as direct path
                if !found_any {
                    let direct_path = PathBuf::from(&pattern);
                    if direct_path.is_file() {
                        file_paths.push(direct_path);
                    } else {
                        return Err(FileError::NotFound {
                            path: pattern,
                        }.into());
                    }
                }
            }
            Err(e) => {
                return Err(ValidationError::InvalidPattern {
                    pattern: pattern.clone(),
                }.into());
            }
        }
    }

    if file_paths.is_empty() {
        return Err(ValidationError::EmptyFileList.into());
    }

    // Remove duplicates and sort
    file_paths.sort();
    file_paths.dedup();

    Ok(file_paths)
}

/// Filter paths to only include regular files.
pub fn filter_regular_files(paths: Vec<PathBuf>) -> CoreResult<Vec<PathBuf>> {
    let mut regular_files = Vec::new();

    for path in paths {
        let file_type = detect_file_type(&path)?;
        if file_type == FileType::Regular {
            regular_files.push(path);
        }
    }

    if regular_files.is_empty() {
        return Err(ValidationError::EmptyFileList.into());
    }

    Ok(regular_files)
}

/// Read file information from a path.
pub fn read_file_info(path: &Path) -> CoreResult<FileInfo> {
    let metadata = fs::metadata(path)
        .map_err(|_| FileError::NotFound {
            path: path.display().to_string()
        })?;

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let file_type = detect_file_type(path)?;

    Ok(FileInfo::new(
        filename,
        metadata.len(),
        metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
        metadata.created().ok(),
        file_type,
    ))
}

/// Classify files into jobs based on their type.
pub fn classify_files(paths: Vec<PathBuf>) -> CoreResult<Vec<FileJob>> {
    let mut jobs = Vec::new();

    for path in paths {
        let info = read_file_info(&path)?;

        match info.file_type {
            FileType::Regular => {
                // Calculate content hash for plaintext files
                let content = read_file_content(&path)?;
                let hash = ContentHasher::hash(content.expose_secret());

                jobs.push(FileJob::Plaintext { path, info, hash });
            }
            FileType::EncryptedShadow => {
                // Read TLV header for encrypted files
                let header = read_tlv_header(&path)?;
                jobs.push(FileJob::Encrypted { path, info, header });
            }
            _ => {
                // Skip non-regular files
                continue;
            }
        }
    }

    Ok(jobs)
}

/// Load plaintext file data.
pub fn load_plaintext_file(path: &Path) -> CoreResult<PlaintextData> {
    let info = read_file_info(path)?;

    if !info.file_type.is_encryptable() {
        return Err(FileError::InvalidType {
            path: path.display().to_string(),
            file_type: format!("{:?}", info.file_type),
        }.into());
    }

    let content = read_file_content(path)?;
    let hash = ContentHasher::hash(content.expose_secret());

    Ok(PlaintextData::new(path.to_path_buf(), content, hash, info))
}

/// Read file content into secure memory.
fn read_file_content(path: &Path) -> CoreResult<SecureBox<Vec<u8>>> {
    let mut file = fs::File::open(path)
        .map_err(|_| FileError::NotFound {
            path: path.display().to_string()
        })?;

    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .map_err(|e| FileError::Format {
            reason: format!("Failed to read file content: {}", e)
        })?;

    Ok(SecureBox::new(content))
}

/// Read TLV header from an encrypted file.
fn read_tlv_header(path: &Path) -> CoreResult<TlvHeader> {
    // This is a simplified implementation
    // In reality, you'd parse the actual TLV format
    let mut file = fs::File::open(path)
        .map_err(|_| FileError::NotFound {
            path: path.display().to_string()
        })?;

    let mut buffer = vec![0u8; 1024]; // Read first 1KB
    let bytes_read = file.read(&mut buffer)
        .map_err(|e| FileError::Format {
            reason: format!("Failed to read header: {}", e)
        })?;

    // For now, create a minimal header
    // In a real implementation, you'd parse the TLV data
    Ok(TlvHeader::new(1)) // Version 1
}

/// Check if any files are already encrypted to prevent double encryption.
pub fn check_not_encrypted(jobs: &[FileJob]) -> CoreResult<()> {
    for job in jobs {
        if job.is_encrypted() {
            return Err(FileError::AlreadyEncrypted {
                path: job.path().display().to_string(),
            }.into());
        }
    }
    Ok(())
}