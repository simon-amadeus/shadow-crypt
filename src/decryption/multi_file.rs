//! Multi-file decryption functionality
//! 
//! This module provides support for decrypting multiple files in a single operation,
//! with progress reporting and graceful error handling. Uses parallel processing
//! for improved performance when decrypting multiple files.

use crate::shared::errors::CryptoError;
use crate::shared::progress::{show_minimal_multifile_progress, report_minimal_multifile_completion};
use crate::shared::secure_delete::{secure_delete_file, confirm_destructive_operation};
use std::path::{Path, PathBuf};
use std::time::Instant;
use rayon::prelude::*;

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
    use crate::shared::algorithms::{AesGcmConfig, DefaultConfigProvider};
    let provider = DefaultConfigProvider::<AesGcmConfig>::test();
    decrypt_multiple_files_with_provider(
        file_paths,
        password,
        force_overwrite,
        remove_source,
        &provider,
        true // show_progress = true for backward compatibility
    )
}

/// Decrypt multiple files using a configuration provider (trait-based approach)
pub fn decrypt_multiple_files_with_provider<P: crate::shared::algorithms::ConfigProvider + Sync>(
    file_paths: &[PathBuf],
    password: &str,
    force_overwrite: bool,
    remove_source: bool,
    provider: &P,
    show_progress: bool,
) -> Result<MultiFileResults, CryptoError> {
    use crate::decryption::decrypt_file::decrypt_single_file_with_config;
    
    let start_time = Instant::now();
    let total_files = file_paths.len();
    
    if total_files == 0 {
        return Err(CryptoError::InvalidFileFormat); // No files to process
    }

    let results: Vec<Result<PathBuf, CryptoError>> = show_minimal_multifile_progress(
        "Decrypting",
        total_files,
        show_progress,
        || {
            // Use parallel processing for multiple files to improve performance
            file_paths
                .par_iter()
                .map(|input_path| {
                    let config = provider.config();
                    
                    // Generate output path with automatic filename restoration
                    let output_path = match generate_output_path_with_config(input_path, password, config) {
                        Ok(path) => path,
                        Err(e) => return Err(e),
                    };

                    // Check for overwrite permission
                    if output_path.exists() && !force_overwrite {
                        return Err(CryptoError::FileSystemError(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            format!("Output file already exists: {}", output_path.display())
                        )));
                    }

                    // Decrypt the file
                    decrypt_single_file_with_config(input_path, &output_path, password, config)?;

                    // Remove source file if requested
                    if remove_source
                        && let Err(e) = secure_delete_file(input_path) {
                            // Don't fail the entire operation if we can't delete the source
                            eprintln!("Warning: Failed to securely delete source file {}: {}", input_path.display(), e);
                        }

                    Ok(output_path)
                })
                .collect()
        },
    );

    let mut successful = Vec::new();
    let mut failed = Vec::new();
    
    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(output_path) => successful.push(output_path),
            Err(e) => failed.push((file_paths[i].clone(), e.to_string())),
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

/// Decrypt multiple files with custom Argon2 parameters (for testing)
pub fn decrypt_multiple_files_with_params(
    file_paths: &[PathBuf],
    password: &str,
    force_overwrite: bool,
    remove_source: bool,
    argon2_params: &crate::shared::algorithms::aes_gcm::Argon2Params,
) -> Result<MultiFileResults, CryptoError> {
    decrypt_multiple_files_with_params_and_progress(
        file_paths,
        password,
        force_overwrite,
        remove_source,
        argon2_params,
        true // show_progress = true for backward compatibility
    )
}

/// Decrypt multiple files with progress reporting control
pub fn decrypt_multiple_files_with_params_and_progress(
    file_paths: &[PathBuf],
    password: &str,
    force_overwrite: bool,
    remove_source: bool,
    argon2_params: &crate::shared::algorithms::aes_gcm::Argon2Params,
    show_progress: bool,
) -> Result<MultiFileResults, CryptoError> {
    let start_time = Instant::now();
    let total_files = file_paths.len();
    
    if total_files == 0 {
        return Err(CryptoError::InvalidFileFormat); // No files to process
    }

    let results = show_minimal_multifile_progress(
        "Decrypting",
        total_files,
        show_progress,
        || {
            // Use parallel processing for multiple files to improve performance
            file_paths
                .par_iter()
                .map(|input_path| {
                    // Generate output path with automatic filename restoration
                    let output_path = match generate_output_path_with_params(input_path, password, argon2_params) {
                        Ok(path) => path,
                        Err(e) => {
                            let error_msg = format!("Failed to determine output path: {}", e);
                            return (input_path.clone(), Err(error_msg));
                        }
                    };

                    // Check for file overwrite protection
                    if output_path.exists() && !force_overwrite {
                        let error_msg = format!("Output file '{}' already exists (use --force to overwrite)", output_path.display());
                        return (input_path.clone(), Err(error_msg));
                    }

                    // Attempt decryption with custom parameters
                    match crate::decryption::decrypt_single_file_with_params(input_path, &output_path, password, argon2_params) {
                        Ok(()) => {
                            (input_path.clone(), Ok(output_path))
                        }
                        Err(e) => {
                            let error_msg = format!("Decryption failed: {}", e);
                            (input_path.clone(), Err(error_msg))
                        }
                    }
                })
                .collect::<Vec<(PathBuf, Result<PathBuf, String>)>>()
        }
    );

    // Collect results from parallel processing
    let mut successful = Vec::new();
    let mut failed = Vec::new();

    for (input_path, result) in results {
        match result {
            Ok(_output_path) => successful.push(input_path),
            Err(error_msg) => failed.push((input_path, error_msg)),
        }
    }

    let total_time = start_time.elapsed();

    // Report completion with minimal output
    report_minimal_multifile_completion(
        "Decrypted",
        total_files,
        successful.len(),
        failed.len(),
        total_time,
        show_progress,
    );

    // Show failed files if any (this is essential information)
    if !failed.is_empty() && show_progress {
        println!();
        println!("❌ Failed files:");
        for (path, error) in &failed {
            println!("   {} - {}", path.display(), error);
        }
    }

    // Handle source file removal for successful files (if requested)
    // This stays visible even in minimal mode because it's a critical safety operation
    if remove_source && !successful.is_empty() && show_progress {
        println!();
        println!("🗑️  Processing source file removal for {} successful decryption{}...", 
                successful.len(),
                if successful.len() == 1 { "" } else { "s" });
        
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
/// Try to restore the original filename from the encrypted file header
/// 
/// This function attempts to read the header and extract the original filename.
/// Used for automatic output path generation during decryption.
/// 
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `password` - User password for header decryption
/// 
/// # Returns
/// * `Ok(String)` - Restored original filename
/// * `Err(CryptoError)` - Restoration failed
pub fn try_restore_filename_from_header(
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
        .map_err(CryptoError::FileSystemError)?;
    
    let mut encrypted_data = Vec::new();
    input_file.read_to_end(&mut encrypted_data)
        .map_err(CryptoError::FileSystemError)?;
    
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
                                    std::io::Error::other(format!("Glob error: {}", e))
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
                        std::io::Error::other(format!("Invalid glob pattern '{}': {}", pattern, e))
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

/// Generate output path using trait-based configuration
pub fn generate_output_path_with_config<C: crate::shared::algorithms::CryptoConfig>(
    input_path: &Path, 
    password: &str,
    config: &C
) -> Result<PathBuf, CryptoError> {
    // Try to restore original filename from header
    match try_restore_filename_from_header_with_config(input_path, password, config) {
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

/// Try to restore filename from header using trait-based configuration
fn try_restore_filename_from_header_with_config<C: crate::shared::algorithms::CryptoConfig>(
    input_path: &Path,
    password: &str,
    config: &C
) -> Result<String, CryptoError> {
    use crate::decryption::filename_restoration::restore_original_filename;
    use crate::shared::header::Header;
    use std::fs::File;
    use std::io::Read;

    // Read encrypted file
    let mut input_file = File::open(input_path)
        .map_err(CryptoError::FileSystemError)?;
    
    let mut encrypted_data = Vec::new();
    input_file.read_to_end(&mut encrypted_data)
        .map_err(CryptoError::FileSystemError)?;
    
    // Parse header from encrypted file
    let (header, _) = Header::deserialize(&encrypted_data)?;
    
    // Use trait-based key derivation
    let key_material = config.derive_key_material(password, &header.salt)?;
    
    // Restore original filename
    restore_original_filename(&header, &key_material)
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