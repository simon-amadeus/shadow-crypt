//! Demonstration of monadic pipeline usage for encryption operations.
//!
//! This example shows how to convert the traditional discrete-step encryption
//! pipeline into a true monadic composition using the new monadic combinators.

use crate::core::shared::{Pipeline, PipelineItem, CoreResult, CoreError, FileError};
use crate::core::encryption::types::EncryptionOptions;
use std::path::{Path, PathBuf};

/// Example demonstrating monadic pipeline vs discrete steps.
#[allow(dead_code)]
pub fn demonstrate_monadic_pipeline() {
    println!("=== Monadic Pipeline Demonstration ===\n");
    
    // Sample input patterns
    let patterns = vec![
        "*.txt".to_string(),
        "docs/*.md".to_string(),
        "src/**/*.rs".to_string(),
    ];
    
    // Traditional discrete steps approach (current implementation)
    println!("Traditional Discrete Steps:");
    let _traditional_result = traditional_encrypt_pipeline(patterns.clone());
    
    println!("\n{}\n", "=".repeat(50));
    
    // New monadic approach 
    println!("Monadic Pipeline:");
    let _monadic_result = monadic_encrypt_pipeline(patterns);
}

/// Traditional discrete-step pipeline (current implementation).
#[allow(dead_code)]
fn traditional_encrypt_pipeline(patterns: Vec<String>) -> CoreResult<(Vec<String>, Vec<String>)> {
    println!("Step 1: Expanding patterns...");
    let paths = expand_patterns_traditional(patterns)?;
    println!("  → Found {} paths", paths.len());
    
    println!("Step 2: Filtering regular files...");
    let regular_files = filter_regular_files_traditional(paths)?;
    println!("  → {} regular files", regular_files.len());
    
    println!("Step 3: Validating files...");
    let validated_files = validate_files_traditional(regular_files)?;
    println!("  → {} validated files", validated_files.len());
    
    println!("Step 4: Creating jobs...");
    let jobs = create_jobs_traditional(validated_files)?;
    println!("  → {} jobs created", jobs.len());
    
    Ok((jobs, vec![]))
}

/// New monadic pipeline (target implementation).
#[allow(dead_code)]
fn monadic_encrypt_pipeline(patterns: Vec<String>) -> (Vec<String>, Vec<String>) {
    println!("Starting monadic pipeline...");
    
    let (successes, failures) = patterns
        .into_iter()
        .pipeline::<String>()
        .progress_step("Pattern processing")
        .flat_map_continue(|pattern| expand_pattern_monadic(&pattern))
        .progress_step("Pattern expansion complete")
        .filter_continue(|path| is_regular_file_monadic(path))
        .progress_step("File filtering complete")
        .filter_continue(|path| validate_file_monadic(path))
        .progress_step("File validation complete")
        .map_continue(|path| create_job_monadic(&path))
        .progress_step("Job creation complete")
        .collect_results();
    
    println!("Pipeline complete: {} successes, {} failures", successes.len(), failures.len());
    (successes, failures)
}

// ============================================================================
// TRADITIONAL DISCRETE STEP FUNCTIONS
// ============================================================================

fn expand_patterns_traditional(patterns: Vec<String>) -> CoreResult<Vec<PathBuf>> {
    let mut all_paths = Vec::new();
    for pattern in patterns {
        // Simulate pattern expansion
        match pattern.as_str() {
            "*.txt" => {
                all_paths.extend(vec![
                    PathBuf::from("file1.txt"),
                    PathBuf::from("file2.txt"),
                ]);
            }
            "docs/*.md" => {
                all_paths.extend(vec![
                    PathBuf::from("docs/README.md"),
                    PathBuf::from("docs/GUIDE.md"),
                ]);
            }
            "src/**/*.rs" => {
                all_paths.extend(vec![
                    PathBuf::from("src/main.rs"),
                    PathBuf::from("src/lib.rs"),
                ]);
            }
            _ => {
                return Err(CoreError::Validation(
                    crate::core::shared::ValidationError::InvalidPattern { 
                        pattern: pattern.clone() 
                    }
                ));
            }
        }
    }
    Ok(all_paths)
}

fn filter_regular_files_traditional(paths: Vec<PathBuf>) -> CoreResult<Vec<PathBuf>> {
    // In real implementation, this would check file types
    // For demo, we'll simulate some files being filtered out
    let filtered: Vec<PathBuf> = paths
        .into_iter()
        .filter(|path| !path.to_string_lossy().contains("directory"))
        .collect();
    Ok(filtered)
}

fn validate_files_traditional(paths: Vec<PathBuf>) -> CoreResult<Vec<PathBuf>> {
    // In real implementation, this would validate file accessibility, permissions, etc.
    // For demo, we'll simulate some validation failures
    for path in &paths {
        if path.to_string_lossy().contains("forbidden") {
            return Err(CoreError::File(FileError::Permission { 
                path: path.to_string_lossy().to_string() 
            }));
        }
    }
    Ok(paths)
}

fn create_jobs_traditional(paths: Vec<PathBuf>) -> CoreResult<Vec<String>> {
    // Convert paths to job descriptions
    let jobs: Vec<String> = paths
        .into_iter()
        .map(|path| format!("Encrypt: {}", path.to_string_lossy()))
        .collect();
    Ok(jobs)
}

// ============================================================================
// MONADIC STEP FUNCTIONS
// ============================================================================

fn expand_pattern_monadic(pattern: &str) -> Vec<Result<PathBuf, String>> {
    match pattern {
        "*.txt" => vec![
            Ok(PathBuf::from("file1.txt")),
            Ok(PathBuf::from("file2.txt")),
        ],
        "docs/*.md" => vec![
            Ok(PathBuf::from("docs/README.md")),
            Ok(PathBuf::from("docs/GUIDE.md")),
        ],
        "src/**/*.rs" => vec![
            Ok(PathBuf::from("src/main.rs")),
            Ok(PathBuf::from("src/lib.rs")),
        ],
        _ => vec![Err(format!("Invalid pattern: {}", pattern))],
    }
}

fn is_regular_file_monadic(path: &PathBuf) -> Result<bool, String> {
    // Simulate file type checking
    if path.to_string_lossy().contains("directory") {
        Ok(false) // Filter out directories
    } else {
        Ok(true) // Keep regular files
    }
}

fn validate_file_monadic(path: &PathBuf) -> Result<bool, String> {
    // Simulate file validation
    if path.to_string_lossy().contains("forbidden") {
        Err(format!("Permission denied: {}", path.to_string_lossy()))
    } else {
        Ok(true) // File is valid
    }
}

fn create_job_monadic(path: &PathBuf) -> Result<String, String> {
    // Create job description
    Ok(format!("Encrypt: {}", path.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monadic_pipeline_demo() {
        let patterns = vec![
            "*.txt".to_string(),
            "docs/*.md".to_string(),
        ];
        
        let (successes, failures) = monadic_encrypt_pipeline(patterns);
        
        assert!(successes.len() > 0);
        assert_eq!(failures.len(), 0);
        
        // Verify job format
        assert!(successes.iter().all(|job| job.starts_with("Encrypt:")));
    }
    
    #[test]
    fn test_error_handling_in_monadic_pipeline() {
        let patterns = vec![
            "*.txt".to_string(),
            "invalid_pattern".to_string(), // This will cause an error
        ];
        
        let (successes, failures) = monadic_encrypt_pipeline(patterns);
        
        // Should have successes from *.txt and failures from invalid_pattern
        assert!(successes.len() > 0);
        assert!(failures.len() > 0);
        assert!(failures.iter().any(|err| err.contains("Invalid pattern")));
    }
}