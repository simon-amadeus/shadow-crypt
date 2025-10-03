//! Multi-file encryption functionality
//! 
//! This module provides support for encrypting multiple files in a single operation,
//! with progress reporting and graceful error handling. Uses parallel processing
//! for improved performance when encrypting multiple files.

use crate::shared::errors::CryptoError;
use crate::shared::progress::{show_minimal_multifile_progress, report_minimal_multifile_completion};
use crate::encryption::encrypt_single_file_with_config;
use crate::shared::algorithms::{Algorithm, AesGcmConfig, DefaultConfigProvider, ConfigProvider};
use std::path::{Path, PathBuf};
use std::time::Instant;
use rayon::prelude::*;

/// Results from a multi-file encryption operation
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

/// Encrypt multiple files with progress reporting and error collection
/// Uses parallel processing for improved performance
pub fn encrypt_multiple_files(
    file_paths: &[PathBuf],
    password: &str,
    obfuscate_filename: bool,
    force_overwrite: bool,
    remove_source: bool,
) -> Result<MultiFileResults, CryptoError> {
    let provider = DefaultConfigProvider::<AesGcmConfig>::production();
    encrypt_multiple_files_with_provider(
        file_paths,
        password,
        obfuscate_filename,
        force_overwrite,
        remove_source,
        &provider,
    )
}

/// Encrypt multiple files with trait-based configuration provider
/// Uses parallel processing for improved performance
pub fn encrypt_multiple_files_with_provider<P: ConfigProvider + Sync>(
    file_paths: &[PathBuf],
    password: &str,
    obfuscate_filename: bool,
    force_overwrite: bool,
    remove_source: bool,
    provider: &P,
) -> Result<MultiFileResults, CryptoError> {
    encrypt_multiple_files_with_provider_and_progress(
        file_paths,
        password,
        obfuscate_filename,
        force_overwrite,
        remove_source,
        true, // show_progress = true for backward compatibility
        provider,
    )
}

/// Encrypt multiple files with trait-based configuration provider and progress control
pub fn encrypt_multiple_files_with_provider_and_progress<P: ConfigProvider + Sync>(
    file_paths: &[PathBuf],
    password: &str,
    obfuscate_filename: bool,
    force_overwrite: bool,
    remove_source: bool,
    show_progress: bool,
    provider: &P,
) -> Result<MultiFileResults, CryptoError> {
    let start_time = Instant::now();
    let total_files = file_paths.len();
    
    if total_files == 0 {
        return Err(CryptoError::InvalidFileFormat); // No files to process
    }

    let config = provider.config();

    let results = show_minimal_multifile_progress(
        "Encrypting",
        total_files,
        show_progress,
        || {
            // Use parallel processing for multiple files to improve performance
            file_paths
                .par_iter()
                .map(|file_path| {
                    // Validate file before processing
                    if !file_path.exists() {
                        let error_msg = "File does not exist".to_string();
                        return (file_path.clone(), Err(error_msg));
                    }

                    if !file_path.is_file() {
                        let error_msg = "Not a regular file (directories not supported)".to_string();
                        return (file_path.clone(), Err(error_msg));
                    }

                    // Check if file is already encrypted (prevent double-encryption)
                    match crate::shared::file_detection::is_encrypted_file(file_path) {
                        Ok(true) => {
                            let error_msg = "File is already encrypted (skipped)".to_string();
                            return (file_path.clone(), Err(error_msg));
                        }
                        Ok(false) => {
                            // File is not encrypted, proceed with encryption
                        }
                        Err(_e) => {
                            // Could not check if encrypted - proceed with encryption (fail-safe)
                        }
                    }

                    // Determine output path
                    let output_path = generate_output_path(file_path, obfuscate_filename);

                    // Check for overwrite protection
                    if output_path.exists() && !force_overwrite {
                        let error_msg = format!("Output file '{}' already exists (use --force to overwrite)", output_path.display());
                        return (file_path.clone(), Err(error_msg));
                    }

                    // Attempt encryption with trait-based configuration
                    match encrypt_single_file_with_config(file_path, &output_path, password, obfuscate_filename, config) {
                        Ok(()) => {
                            // Handle source file removal if requested
                            if remove_source {
                                match crate::shared::secure_delete::secure_delete_file(file_path) {
                                    Ok(()) => {
                                        // Source deleted successfully - this is logged for single files but not multi-files to keep output minimal
                                    }
                                    Err(_e) => {
                                        // Don't treat this as a failure of the encryption itself for minimal UI
                                        // The encryption succeeded, source deletion is a warning at most
                                    }
                                }
                            }
                            (file_path.clone(), Ok(()))
                        }
                        Err(e) => {
                            let error_msg = format!("Encryption failed: {}", e);
                            (file_path.clone(), Err(error_msg))
                        }
                    }
                })
                .collect::<Vec<(PathBuf, Result<(), String>)>>()
        }
    );

    // Collect results from parallel processing
    let mut successful = Vec::new();
    let mut failed = Vec::new();

    for (file_path, result) in results {
        match result {
            Ok(()) => successful.push(file_path),
            Err(error_msg) => failed.push((file_path, error_msg)),
        }
    }

    let total_time = start_time.elapsed();
    report_minimal_multifile_completion("Encrypted", total_files, successful.len(), failed.len(), total_time, show_progress);

    Ok(MultiFileResults {
        successful,
        failed,
        total_files,
        total_time,
    })
}

/// Encrypt multiple files with algorithm selection and progress reporting control
/// Uses parallel processing for improved performance
pub fn encrypt_multiple_files_with_algorithm(
    file_paths: &[PathBuf],
    password: &str,
    obfuscate_filename: bool,
    force_overwrite: bool,
    remove_source: bool,
    show_progress: bool,
    algorithm: Algorithm,
) -> Result<MultiFileResults, CryptoError> {
    let start_time = Instant::now();
    let total_files = file_paths.len();
    
    if total_files == 0 {
        return Err(CryptoError::InvalidFileFormat); // No files to process
    }

    let results = show_minimal_multifile_progress(
        "Encrypting",
        total_files,
        show_progress,
        || {
            // Use parallel processing for multiple files to improve performance
            file_paths
                .par_iter()
                .map(|file_path| {
                    // Validate file before processing
                    if !file_path.exists() {
                        let error_msg = "File does not exist".to_string();
                        return (file_path.clone(), Err(error_msg));
                    }

                    if !file_path.is_file() {
                        let error_msg = "Not a regular file (directories not supported)".to_string();
                        return (file_path.clone(), Err(error_msg));
                    }

                    // Check if file is already encrypted (prevent double-encryption)
                    match crate::shared::file_detection::is_encrypted_file(file_path) {
                        Ok(true) => {
                            let error_msg = "File is already encrypted (skipped)".to_string();
                            return (file_path.clone(), Err(error_msg));
                        }
                        Ok(false) => {
                            // File is not encrypted, proceed with encryption
                        }
                        Err(_e) => {
                            // Could not check if encrypted - proceed with encryption (fail-safe)
                        }
                    }

                    // Determine output path
                    let output_path = generate_output_path(file_path, obfuscate_filename);

                    // Check for overwrite protection
                    if output_path.exists() && !force_overwrite {
                        let error_msg = format!("Output file '{}' already exists (use --force to overwrite)", output_path.display());
                        return (file_path.clone(), Err(error_msg));
                    }

                    // Attempt encryption with algorithm selection
                    let encryption_result = match algorithm {
                        Algorithm::AES256GCM => {
                            use crate::shared::algorithms::aes_gcm_config::AesGcmConfig;
                            use crate::shared::algorithms::config::CryptoConfig;
                            let config = AesGcmConfig::production_config();
                            encrypt_single_file_with_config(file_path, &output_path, password, obfuscate_filename, &config)
                        }
                        Algorithm::XChaCha20Poly1305 => {
                            use crate::shared::algorithms::xchacha20_config::XChaCha20Config;
                            use crate::shared::algorithms::config::CryptoConfig;
                            let config = XChaCha20Config::production_config();
                            encrypt_single_file_with_config(file_path, &output_path, password, obfuscate_filename, &config)
                        }
                    };
                    
                    match encryption_result {
                        Ok(()) => {
                            // Handle source file removal if requested
                            if remove_source {
                                match crate::shared::secure_delete::secure_delete_file(file_path) {
                                    Ok(()) => {
                                        // Source deleted successfully - this is logged for single files but not multi-files to keep output minimal
                                    }
                                    Err(_e) => {
                                        // Don't treat this as a failure of the encryption itself for minimal UI
                                        // The encryption succeeded, source deletion is a warning at most
                                    }
                                }
                            }
                            (file_path.clone(), Ok(()))
                        }
                        Err(e) => {
                            let error_msg = format!("Encryption failed: {}", e);
                            (file_path.clone(), Err(error_msg))
                        }
                    }
                })
                .collect::<Vec<(PathBuf, Result<(), String>)>>()
        }
    );

    // Collect results from parallel processing
    let mut successful = Vec::new();
    let mut failed = Vec::new();

    for (file_path, result) in results {
        match result {
            Ok(()) => successful.push(file_path),
            Err(error_msg) => failed.push((file_path, error_msg)),
        }
    }

    let total_time = start_time.elapsed();

    // Report completion with minimal output
    report_minimal_multifile_completion(
        "Encrypted",
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

    Ok(MultiFileResults {
        successful,
        failed,
        total_files,
        total_time,
    })
}

/// Encrypt multiple files with progress reporting control
/// Uses parallel processing for improved performance
pub fn encrypt_multiple_files_with_progress(
    file_paths: &[PathBuf],
    password: &str,
    obfuscate_filename: bool,
    force_overwrite: bool,
    remove_source: bool,
    show_progress: bool,
) -> Result<MultiFileResults, CryptoError> {
    let start_time = Instant::now();
    let total_files = file_paths.len();
    
    if total_files == 0 {
        return Err(CryptoError::InvalidFileFormat); // No files to process
    }

    let results = show_minimal_multifile_progress(
        "Encrypting",
        total_files,
        show_progress,
        || {
            // Use parallel processing for multiple files to improve performance
            file_paths
                .par_iter()
                .map(|file_path| {
                    // Validate file before processing
                    if !file_path.exists() {
                        let error_msg = "File does not exist".to_string();
                        return (file_path.clone(), Err(error_msg));
                    }

                    if !file_path.is_file() {
                        let error_msg = "Not a regular file (directories not supported)".to_string();
                        return (file_path.clone(), Err(error_msg));
                    }

                    // Check if file is already encrypted (prevent double-encryption)
                    match crate::shared::file_detection::is_encrypted_file(file_path) {
                        Ok(true) => {
                            let error_msg = "File is already encrypted (skipped)".to_string();
                            return (file_path.clone(), Err(error_msg));
                        }
                        Ok(false) => {
                            // File is not encrypted, proceed with encryption
                        }
                        Err(_e) => {
                            // Could not check if encrypted - proceed with encryption (fail-safe)
                        }
                    }

                    // Determine output path
                    let output_path = generate_output_path(file_path, obfuscate_filename);

                    // Check for overwrite protection
                    if output_path.exists() && !force_overwrite {
                        let error_msg = format!("Output file '{}' already exists (use --force to overwrite)", output_path.display());
                        return (file_path.clone(), Err(error_msg));
                    }

                    // Attempt encryption using AES-256-GCM (default algorithm)
                    use crate::shared::algorithms::aes_gcm_config::AesGcmConfig;
                    use crate::shared::algorithms::config::CryptoConfig;
                    let config = AesGcmConfig::production_config();
                    match encrypt_single_file_with_config(file_path, &output_path, password, obfuscate_filename, &config) {
                        Ok(()) => {
                            // Handle source file removal if requested
                            if remove_source {
                                match crate::shared::secure_delete::secure_delete_file(file_path) {
                                    Ok(()) => {
                                        // Source deleted successfully - this is logged for single files but not multi-files to keep output minimal
                                    }
                                    Err(_e) => {
                                        // Don't treat this as a failure of the encryption itself for minimal UI
                                        // The encryption succeeded, source deletion is a warning at most
                                    }
                                }
                            }
                            (file_path.clone(), Ok(()))
                        }
                        Err(e) => {
                            let error_msg = format!("Encryption failed: {}", e);
                            (file_path.clone(), Err(error_msg))
                        }
                    }
                })
                .collect::<Vec<(PathBuf, Result<(), String>)>>()
        }
    );

    // Collect results from parallel processing
    let mut successful = Vec::new();
    let mut failed = Vec::new();

    for (file_path, result) in results {
        match result {
            Ok(()) => successful.push(file_path),
            Err(error_msg) => failed.push((file_path, error_msg)),
        }
    }

    let total_time = start_time.elapsed();

    // Report completion with minimal output
    report_minimal_multifile_completion(
        "Encrypted",
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

    Ok(MultiFileResults {
        successful,
        failed,
        total_files,
        total_time,
    })
}

/// Generate output path for a given input file
fn generate_output_path(input_path: &Path, obfuscate_filename: bool) -> PathBuf {
    if obfuscate_filename {
        // When obfuscating, use input file directory with .shadow extension
        let parent_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = input_path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown");
        parent_dir.join(format!("{}.shadow", file_name))
    } else {
        // Simple case: add .shadow extension to the full filename
        format!("{}.shadow", input_path.to_string_lossy()).into()
    }
}

/// Expand glob patterns into concrete file paths
pub fn expand_glob_patterns(patterns: &[String]) -> Result<Vec<PathBuf>, CryptoError> {
    let mut all_files = Vec::new();
    
    for pattern in patterns {
        // Check if this looks like a glob pattern
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            // Handle glob expansion
            match glob::glob(pattern) {
                Ok(paths) => {
                    for path_result in paths {
                        match path_result {
                            Ok(path) => {
                                if path.is_file() {
                                    all_files.push(path);
                                }
                            }
                            Err(e) => {
                                eprintln!("Warning: Glob expansion error for '{}': {}", pattern, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(CryptoError::FileSystemError(
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("Invalid glob pattern '{}': {}", pattern, e)
                        )
                    ));
                }
            }
        } else {
            // Regular file path
            all_files.push(PathBuf::from(pattern));
        }
    }

    // Remove duplicates while preserving order
    let mut unique_files = Vec::new();
    for file in all_files {
        if !unique_files.contains(&file) {
            unique_files.push(file);
        }
    }

    Ok(unique_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::algorithms::Algorithm;

    #[test]
    fn test_generate_output_path_normal() {
        let input = Path::new("/tmp/test.txt");
        let output = generate_output_path(input, false);
        assert_eq!(output, Path::new("/tmp/test.txt.shadow"));
    }

    #[test]
    fn test_generate_output_path_obfuscated() {
        let input = Path::new("/tmp/test.txt");
        let output = generate_output_path(input, true);
        assert_eq!(output, Path::new("/tmp/test.txt.shadow"));
    }

    #[test]
    fn test_expand_glob_patterns_no_glob() {
        let patterns = vec!["file1.txt".to_string(), "file2.txt".to_string()];
        let result = expand_glob_patterns(&patterns).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], PathBuf::from("file1.txt"));
        assert_eq!(result[1], PathBuf::from("file2.txt"));
    }

    #[test]
    fn test_multifile_results_success_rate() {
        let results = MultiFileResults {
            successful: vec![PathBuf::from("a"), PathBuf::from("b")],
            failed: vec![(PathBuf::from("c"), "error".to_string())],
            total_files: 3,
            total_time: std::time::Duration::from_secs(1),
        };

        assert!((results.success_rate() - 0.6666666666666666).abs() < 0.0001);
        assert!(results.has_failures());
    }

    #[test]
    fn test_multifile_algorithm_support() {
        // Test that the new function supports algorithm selection
        let file_paths = vec![PathBuf::from("nonexistent1.txt"), PathBuf::from("nonexistent2.txt")];
        
        // Test with XChaCha20-Poly1305 (default)
        let result_xchacha = encrypt_multiple_files_with_algorithm(
            &file_paths,
            "password123",
            false, // obfuscate_filename
            false, // force_overwrite  
            false, // remove_source
            false, // show_progress
            Algorithm::XChaCha20Poly1305,
        );
        
        // Should return error because files don't exist, but validates algorithm parameter is accepted
        assert!(result_xchacha.is_ok()); // Function returns Ok with failed files in results
        let res = result_xchacha.unwrap();
        assert_eq!(res.total_files, 2);
        assert_eq!(res.successful.len(), 0);
        assert_eq!(res.failed.len(), 2);
        
        // Test with AES256GCM
        let result_aes = encrypt_multiple_files_with_algorithm(
            &file_paths,
            "password123",
            false, // obfuscate_filename
            false, // force_overwrite
            false, // remove_source
            false, // show_progress
            Algorithm::AES256GCM,
        );
        
        // Should also return error because files don't exist, but validates algorithm parameter is accepted
        assert!(result_aes.is_ok()); // Function returns Ok with failed files in results
        let res = result_aes.unwrap();
        assert_eq!(res.total_files, 2);
        assert_eq!(res.successful.len(), 0);
        assert_eq!(res.failed.len(), 2);
    }

    #[test]
    fn test_multifile_algorithm_error_handling() {
        // Test empty file list
        let empty_files: Vec<PathBuf> = vec![];
        let result = encrypt_multiple_files_with_algorithm(
            &empty_files,
            "password123",
            false,
            false,
            false,
            false,
            Algorithm::XChaCha20Poly1305,
        );
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidFileFormat));
    }
}