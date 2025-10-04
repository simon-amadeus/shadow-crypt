//! # Shadows CLI Binary
//!
//! Directory scanning and listing tool for encrypted files with original filename display.

use clap::Parser;
use std::path::PathBuf;
use std::process;

// Import from the shadow-crypt library
use shadow_crypt::application::workflows::listing_workflow::{ListingWorkflow, ListingWorkflowError};
use shadow_crypt::application::workflows::WorkflowResult;
use shadow_crypt::infrastructure::{StandardFileRepository, StandardPasswordRepository};
use shadow_crypt::cli::common::{CLIValidator, CLIFormatter};

/// Shadows File Listing Tool
#[derive(Parser, Debug)]
#[command(name = "shadows")]
#[command(about = "Directory scanning and listing tool for encrypted files")]
#[command(long_about = "Scan directories for .shadow files and display original filenames with metadata")]
struct ShadowsArgs {
    /// Directory to scan for encrypted files (default: current directory)
    directory: Option<PathBuf>,
}

impl ShadowsArgs {
    /// Get the directory to scan, defaulting to current directory
    fn get_directory(&self) -> PathBuf {
        self.directory.clone().unwrap_or_else(|| PathBuf::from("."))
    }
    
    /// Validate that the directory exists and is accessible
    fn validate_directory(&self) -> Result<(), String> {
        CLIValidator::validate_directory(&self.get_directory())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ShadowsArgs::parse();
    
    // Validate arguments
    if let Err(msg) = args.validate_directory() {
        CLIFormatter::print_error_and_exit(&msg);
    }
    
    let directory = args.get_directory();
    
    println!("Shadows File Listing Tool");
    println!("Scanning directory: {}", directory.display());
    
    // Create repository instances
    let file_repo = Box::new(StandardFileRepository::new());
    let password_repo = Box::new(StandardPasswordRepository::new());
    
    // Create listing workflow
    let mut workflow = ListingWorkflow::new(file_repo, password_repo);
    
    // Execute listing workflow
    // Note: Password prompt will be handled by the workflow when needed
    match workflow.execute(&directory, None) {
        Ok(WorkflowResult::Listing(listing_result)) => {
            // Print user-friendly results
            if listing_result.files.is_empty() {
                println!("\n📁 No encrypted files found in directory");
                println!("   Directory appears to be empty or contains no .shadow files");
            } else {
                println!("\n📋 Encrypted Files Found:");
                println!("✅ Found {} encrypted files", listing_result.files.len());
                
                // Count successful vs failed password validations
                let successful_count = listing_result.files.iter().filter(|f| f.password_valid).count();
                let failed_count = listing_result.files.len() - successful_count;
                
                if failed_count > 0 {
                    println!("❌ Failed to decrypt {} file names (wrong password)", failed_count);
                }
                
                println!("⏱️  Scan time: {:?}", listing_result.scan_duration);
                
                // Print file details
                for file_info in &listing_result.files {
                    let status = if file_info.password_valid { "✓" } else { "✗" };
                    println!("   {} {} → {}",
                        status,
                        file_info.path.file_name().unwrap_or_default().to_string_lossy(),
                        file_info.original_filename.as_deref().unwrap_or("[Unable to decrypt]")
                    );
                    println!("      Algorithm: {:?}, Version: {}, Size: {} bytes",
                        file_info.algorithm,
                        file_info.version,
                        file_info.size
                    );
                }
            }
        }
        Ok(_other_result) => {
            eprintln!("Error: Unexpected workflow result type");
            process::exit(1);
        }
        Err(ListingWorkflowError::PasswordInput(_)) => {
            // User cancelled password input
            CLIFormatter::print_cancelled_and_exit();
        }
        Err(e) => {
            eprintln!("Listing failed: {}", e);
            process::exit(1);
        }
    }
    
    Ok(())
}