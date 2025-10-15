//! # Shared CLI Components
//!
//! Common CLI argument patterns and utilities shared across all shadow binaries.

use clap::Parser;

/// Common flags shared across shadow binaries that modify files
#[derive(Parser, Debug, Clone)]
pub struct CommonModifyFlags {
    /// Overwrite existing output files without prompting
    #[arg(short = 'f', long)]
    pub force: bool,
    
    /// Keep source files after successful operation (default: remove)
    #[arg(short = 'k', long)]
    pub keep: bool,
    
    /// Minimal output (no progress indicators)
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

/// Common flags for listing operations (read-only)
#[derive(Parser, Debug, Clone)]
pub struct CommonListFlags {
    /// Minimal output (no headers or formatting)
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

impl CommonModifyFlags {
    /// Print status information about flag settings (unless quiet)
    pub fn print_status(&self, operation: &str) {
        if !self.quiet {
            println!("Keep source files: {}", if self.keep { "Yes" } else { "No (will remove)" });
            
            if self.force {
                println!("Force overwrite: Enabled");
            }
            
            println!("✅ CLI parsing complete");
            
            let removal_message = format!("removed after {}", operation);
            println!("✅ Source files will be {}", 
                if self.keep { "preserved" } else { &removal_message });
        }
    }
}

impl CommonListFlags {
    /// Check if output should be minimal
    pub fn is_quiet(&self) -> bool {
        self.quiet
    }
}

/// Validate that input patterns are provided
pub fn validate_input_patterns(patterns: &[String], file_type: &str) -> Result<(), String> {
    if patterns.is_empty() {
        return Err(format!("At least one input {} is required", file_type));
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