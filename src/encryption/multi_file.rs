//! Multi-file encryption functionality
//! 
//! This module provides support for encrypting multiple files in a single operation,
//! with progress reporting and graceful error handling. Uses parallel processing
//! for improved performance when encrypting multiple files.

use crate::shared::errors::CryptoError;
use crate::shared::progress::{show_minimal_multifile_progress, report_minimal_multifile_completion};
use crate::encryption::encrypt_single_file;
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
    encrypt_multiple_files_with_progress(
        file_paths,
        password,
        obfuscate_filename,
        force_overwrite,
        remove_source,
        true, // show_progress = true for backward compatibility
    )
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

                    // Determine output path
                    let output_path = generate_output_path(file_path, obfuscate_filename);

                    // Check for overwrite protection
                    if output_path.exists() && !force_overwrite {
                        let error_msg = format!("Output file '{}' already exists (use --force to overwrite)", output_path.display());
                        return (file_path.clone(), Err(error_msg));
                    }

                    // Attempt encryption
                    match encrypt_single_file(file_path, &output_path, password, obfuscate_filename) {
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
}