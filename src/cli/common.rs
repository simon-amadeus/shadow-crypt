//! # CLI Common Module
//!
//! Shared CLI patterns and utilities for all binaries.
//! Supports upcoming critical security features like --keep flag behavior fixes.

use std::path::PathBuf;

/// Common CLI validation patterns
pub struct CLIValidator;

impl CLIValidator {
    /// Validate that input patterns are provided
    pub fn validate_input_patterns(patterns: &[String]) -> Result<(), String> {
        if patterns.is_empty() {
            return Err("At least one input file or pattern is required".to_string());
        }
        Ok(())
    }
    
    /// Validate that a directory exists and is accessible
    pub fn validate_directory(path: &PathBuf) -> Result<(), String> {
        if !path.exists() {
            return Err(format!("Directory does not exist: {}", path.display()));
        }
        
        if !path.is_dir() {
            return Err(format!("Path is not a directory: {}", path.display()));
        }
        
        Ok(())
    }
    
    /// Validate that an input path exists (file or directory)
    pub fn validate_input_path(path: &PathBuf) -> Result<(), String> {
        if !path.exists() {
            return Err(format!("Path does not exist: {}", path.display()));
        }
        Ok(())
    }
    
    /// Validate algorithm choice
    pub fn validate_algorithm(algorithm: &str) -> Result<(), String> {
        match algorithm {
            "xchacha20" | "aes-gcm" => Ok(()),
            _ => Err(format!(
                "Unsupported algorithm '{}'. Supported: xchacha20, aes-gcm", 
                algorithm
            )),
        }
    }
}

/// Common CLI output formatting
pub struct CLIFormatter;

impl CLIFormatter {
    /// Print standardized error message and exit
    pub fn print_error_and_exit(message: &str) -> ! {
        eprintln!("Error: {}", message);
        std::process::exit(1);
    }
    
    /// Print operation cancelled message and exit gracefully
    pub fn print_cancelled_and_exit() -> ! {
        println!("\nOperation cancelled by user");
        std::process::exit(0);
    }
}

/// Common source file handling logic for --keep flag support
/// This will be expanded in the next cycle for correct --keep behavior
pub struct SourceFileHandler;

impl SourceFileHandler {
    /// Print status information about source file handling
    /// Prepares for upcoming --keep flag behavior fix
    pub fn print_source_file_status(keep: bool) {
        if keep {
            println!("✅ Source files will be preserved");
        } else {
            println!("✅ Source files will be removed after successful operation");
        }
    }
}