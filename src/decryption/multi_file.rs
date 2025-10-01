//! Multi-file decryption functionality
//! 
//! This module provides support for decrypting multiple files in a single operation,
//! with progress reporting and graceful error handling.

use crate::shared::errors::CryptoError;
use crate::shared::secure_delete::{secure_delete_file, confirm_destructive_operation};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Results from a multi-file decryption operation
#[derive(Debug)]
pub struct MultiFileResults {
    pub successful: Vec<PathBuf>,
    pub failed: Vec<(PathBuf, String)>,
    pub total_files: usize,
    pub total_time: std::time::Duration,
}

impl MultiFileResults {
    pub fn success_rate(&self) -> f64 {
        if self.total_files == 0 {
            return 0.0;
        }
        self.successful.len() as f64 / self.total_files as f64
    }

    pub fn has_failures(&self) -> bool {
        !self.failed.is_empty()
    }
}

/// Decrypt multiple files with progress reporting and error collection
pub fn decrypt_multiple_files(
    file_paths: &[PathBuf],
    password: &str,
    force_overwrite: bool,
    remove_source: bool,
) -> Result<MultiFileResults, CryptoError> {
    use crate::shared::algorithms::aes_gcm::Argon2Params;
    decrypt_multiple_files_with_params(
        file_paths,
        password,
        force_overwrite,
        remove_source,
        &Argon2Params::default()
    )
}

/// Decrypt multiple files with custom Argon2 parameters (for testing)
pub fn decrypt_multiple_files_with_params(
    file_paths: &[PathBuf],
    password: &str,
    force_overwrite: bool,
    remove_source: bool,
    argon2_params: &crate::shared::algorithms::aes_gcm::Argon2Params,
) -> Result<MultiFileResults, CryptoError> {
    let start_time = Instant::now();
    let total_files = file_paths.len();
    
    if total_files == 0 {
        return Err(CryptoError::InvalidFileFormat); // No files to process
    }

    println!("🔓 Starting decryption of {} files...", total_files);
    println!("🔑 Using password-based decryption with AES-256-GCM");
    println!();

    let mut successful = Vec::new();
    let mut failed = Vec::new();

    // Process each file individually with progress reporting
    for (index, input_path) in file_paths.iter().enumerate() {
        let progress = index + 1;
        println!("🔄 [{}/{}] Decrypting: {}", progress, total_files, input_path.display());

        // Generate output path with automatic filename restoration
        let output_path = match generate_output_path_with_params(input_path, password, argon2_params) {
            Ok(path) => path,
            Err(e) => {
                let error_msg = format!("Failed to determine output path: {}", e);
                println!("❌ Failed: {}", error_msg);
                failed.push((input_path.clone(), error_msg));
                continue;
            }
        };

        // Check for file overwrite protection
        if output_path.exists() && !force_overwrite {
            let error_msg = format!("Output file '{}' already exists (use --force to overwrite)", output_path.display());
            println!("❌ Skipped: {}", error_msg);
            failed.push((input_path.clone(), error_msg));
            continue;
        }

        // Attempt decryption with custom parameters
        match crate::decryption::decrypt_single_file_with_params(input_path, &output_path, password, argon2_params) {
            Ok(()) => {
                println!("✅ Success: {} → {}", input_path.display(), output_path.display());
                successful.push(input_path.clone());
            }
            Err(e) => {
                let error_msg = format!("Decryption failed: {}", e);
                println!("❌ Failed: {}", error_msg);
                failed.push((input_path.clone(), error_msg));
            }
        }
    }

    // Handle source file removal for successful files (if requested)
    if remove_source && !successful.is_empty() {
        println!();
        println!("🗑️  Processing source file removal for {} successful decryptions...", successful.len());
        
        for input_path in &successful {
            if confirm_destructive_operation("Source file removal", input_path) {
                match secure_delete_file(input_path) {
                    Ok(()) => {
                        println!("🗑️  Source file securely deleted: {}", input_path.display());
                    }
                    Err(e) => {
                        println!("⚠️  Warning: Failed to delete source file {}: {}", input_path.display(), e);
                    }
                }
            } else {
                println!("🔄 Source file removal cancelled for: {}", input_path.display());
            }
        }
    }

    let total_time = start_time.elapsed();

    Ok(MultiFileResults {
        successful,
        failed,
        total_files,
        total_time,
    })
}

/// Generate output path for a decrypted file with automatic filename restoration
/// 
/// Attempts to restore the original filename from the encrypted file header.
/// Falls back to extension-based naming if restoration fails.
/// 
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `password` - Password for decryption
/// 
/// # Returns
/// * `Ok(PathBuf)` - Determined output path
/// * `Err(CryptoError)` - Failed to determine path
pub fn generate_output_path(input_path: &Path, password: &str) -> Result<PathBuf, CryptoError> {
    use crate::shared::algorithms::aes_gcm::Argon2Params;
    generate_output_path_with_params(input_path, password, &Argon2Params::default())
}

/// Generate output path with custom Argon2 parameters (for testing)
pub fn generate_output_path_with_params(
    input_path: &Path, 
    password: &str,
    argon2_params: &crate::shared::algorithms::aes_gcm::Argon2Params
) -> Result<PathBuf, CryptoError> {
    // Try to restore original filename from header
    match try_restore_filename_from_header_with_params(input_path, password, argon2_params) {
        Ok(original_name) => {
            // Use the directory of input file + restored filename
            let input_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
            Ok(input_dir.join(original_name))
        }
        Err(_) => {
            // Fall back to extension-based naming
            if let Some(stem) = input_path.file_stem() {
                if input_path.to_string_lossy().ends_with(".shadow") {
                    Ok(input_path.with_file_name(stem))
                } else {
                    Ok(input_path.with_extension("dec"))
                }
            } else {
                Ok(input_path.with_extension("dec"))
            }
        }
    }
}

/// Try to restore filename from header without full decryption
/// 
/// Reads just the header from the encrypted file and attempts to restore
/// the original filename. This is used for smart output path determination.
/// 
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `password` - Password for decryption
/// 
/// # Returns
/// * `Ok(String)` - Restored original filename
/// * `Err(CryptoError)` - Restoration failed
fn try_restore_filename_from_header(
    input_path: &Path,
    password: &str
) -> Result<String, CryptoError> {
    use crate::shared::algorithms::aes_gcm::Argon2Params;
    try_restore_filename_from_header_with_params(input_path, password, &Argon2Params::default())
}

/// Try to restore filename from header with custom Argon2 parameters
fn try_restore_filename_from_header_with_params(
    input_path: &Path,
    password: &str,
    argon2_params: &crate::shared::algorithms::aes_gcm::Argon2Params
) -> Result<String, CryptoError> {
    use crate::decryption::filename_restoration::restore_original_filename;
    use crate::shared::header::Header;
    use crate::shared::algorithms::aes_gcm::derive_master_key;
    use std::fs::File;
    use std::io::Read;

    // Read encrypted file
    let mut input_file = File::open(input_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    let mut encrypted_data = Vec::new();
    input_file.read_to_end(&mut encrypted_data)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    // Parse header from encrypted file
    let (header, _) = Header::deserialize(&encrypted_data)?;
    
    // Derive master key from password and salt
    let key_material = derive_master_key(password, &header.salt, argon2_params)?;
    
    // Restore original filename
    restore_original_filename(&header, &key_material)
}

/// Expand glob patterns into file paths for decryption
/// 
/// Supports wildcard patterns like *.shadow, **/*.shadow, etc.
/// Filters to only include readable files.
/// 
/// # Arguments
/// * `patterns` - Array of file patterns/paths
/// 
/// # Returns
/// * `Ok(Vec<PathBuf>)` - List of expanded file paths
/// * `Err(CryptoError)` - Failed to expand patterns
pub fn expand_glob_patterns(patterns: &[String]) -> Result<Vec<PathBuf>, CryptoError> {
    let mut file_paths = Vec::new();
    
    for pattern in patterns {
        let pattern_path = Path::new(pattern);
        
        // If it's a direct file path (no wildcards), add it directly
        if !pattern.contains('*') && !pattern.contains('?') {
            if pattern_path.exists() && pattern_path.is_file() {
                file_paths.push(pattern_path.to_path_buf());
            } else if pattern_path.exists() {
                return Err(CryptoError::FileSystemError(
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, 
                        format!("'{}' is not a regular file", pattern))
                ));
            } else {
                return Err(CryptoError::FileSystemError(
                    std::io::Error::new(std::io::ErrorKind::NotFound, 
                        format!("File '{}' does not exist", pattern))
                ));
            }
        } else {
            // Use glob pattern matching
            match glob::glob(pattern) {
                Ok(entries) => {
                    let mut pattern_matches = 0;
                    for entry in entries {
                        match entry {
                            Ok(path) => {
                                if path.is_file() {
                                    file_paths.push(path);
                                    pattern_matches += 1;
                                }
                            }
                            Err(e) => {
                                return Err(CryptoError::FileSystemError(
                                    std::io::Error::new(std::io::ErrorKind::Other, 
                                        format!("Glob error: {}", e))
                                ));
                            }
                        }
                    }
                    
                    if pattern_matches == 0 {
                        return Err(CryptoError::FileSystemError(
                            std::io::Error::new(std::io::ErrorKind::NotFound, 
                                format!("No files found matching pattern '{}'", pattern))
                        ));
                    }
                }
                Err(e) => {
                    return Err(CryptoError::FileSystemError(
                        std::io::Error::new(std::io::ErrorKind::Other, 
                            format!("Invalid glob pattern '{}': {}", pattern, e))
                    ));
                }
            }
        }
    }
    
    // Remove duplicates while preserving order
    let mut unique_paths = Vec::new();
    for path in file_paths {
        if !unique_paths.contains(&path) {
            unique_paths.push(path);
        }
    }
    
    Ok(unique_paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multifile_results_success_rate() {
        let results = MultiFileResults {
            successful: vec![PathBuf::from("file1"), PathBuf::from("file2")],
            failed: vec![(PathBuf::from("file3"), "error".to_string())],
            total_files: 3,
            total_time: std::time::Duration::from_secs(1),
        };
        
        assert!((results.success_rate() - 0.666).abs() < 0.01);
        assert!(results.has_failures());
    }

    #[test]
    fn test_expand_glob_patterns_no_glob() {
        // Test with non-existent file should return error
        let patterns = vec!["nonexistent.shadow".to_string()];
        let result = expand_glob_patterns(&patterns);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_output_path_fallback() {
        // Test fallback behavior when filename restoration fails
        let input_path = Path::new("test.shadow");
        
        // This should fall back to extension-based naming since the file doesn't exist
        // We can't easily test the header restoration without setting up encrypted files
        let result = generate_output_path(input_path, "password");
        
        // Should either succeed with fallback naming or fail gracefully
        // We're mainly testing that the function doesn't panic
        match result {
            Ok(path) => {
                // Should be "test" (stem of "test.shadow")
                assert_eq!(path.file_name().unwrap(), "test");
            }
            Err(_) => {
                // Also acceptable if file doesn't exist
            }
        }
    }
}