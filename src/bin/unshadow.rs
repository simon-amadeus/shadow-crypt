//! # Unshadow CLI Binary
//!
//! File decryption binary implementation with automatic filename restoration.

use clap::Parser;
use std::process;

// Import from the shadow-crypt library
use shadow_crypt::application::workflows::decryption_workflow::{DecryptionWorkflow, DecryptionOptions};
use shadow_crypt::application::workflows::WorkflowResult;
use shadow_crypt::infrastructure::{StandardFileRepository, StandardPasswordRepository};

/// Unshadow File Decryption Tool
#[derive(Parser, Debug)]
#[command(name = "unshadow")]
#[command(about = "File decryption with automatic filename restoration")]
#[command(long_about = "Decrypt .shadow files and restore original filenames")]
struct UnshadowArgs {
    /// Input .shadow files or glob patterns to decrypt
    input_patterns: Vec<String>,
    
    /// Overwrite existing output files without prompting
    #[arg(short = 'f', long)]
    force: bool,
    
    /// Keep source files after successful decryption (default: remove)
    #[arg(short = 'k', long)]
    keep: bool,
    
    /// Minimal output (no progress indicators)
    #[arg(short = 'q', long)]
    quiet: bool,
}

impl UnshadowArgs {
    /// Validate input patterns are provided
    fn validate_input(&self) -> Result<(), String> {
        if self.input_patterns.is_empty() {
            return Err("At least one input .shadow file or pattern is required".to_string());
        }
        Ok(())
    }
    
    /// Print status information about flag settings
    fn print_status(&self) {
        println!("✅ CLI parsing complete");
        println!("✅ Encrypted files will be {}", 
            if self.keep { "preserved" } else { "removed after decryption" });
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = UnshadowArgs::parse();
    
    // Validate arguments
    if let Err(msg) = args.validate_input() {
        eprintln!("Error: {}", msg);
        process::exit(1);
    }
    
    if !args.quiet {
        println!("Unshadow File Decryption Tool");
        println!("Input patterns: {:?}", args.input_patterns);
    }
    
    // Print status information
    args.print_status();
    
    // Create repository instances
    let file_repo = Box::new(StandardFileRepository::new());
    let password_repo = Box::new(StandardPasswordRepository::new());
    
    // Create decryption workflow
    let mut workflow = DecryptionWorkflow::new(
        file_repo,
        password_repo,
    );
    
    // Prepare decryption options
    let options = DecryptionOptions {
        force_overwrite: args.force,
        remove_source: !args.keep,  // Inverted: keep=true means remove_source=false
        verify_integrity: true,     // Always verify integrity
    };
    
    // Execute decryption workflow
    match workflow.execute(args.input_patterns, options) {
        Ok(WorkflowResult::Decryption(batch_result)) => {
            if !args.quiet {
                // Print user-friendly results
                println!("\n🔓 Decryption Complete!");
                println!("✅ Successfully decrypted {} files", batch_result.successful.len());
                
                if !batch_result.failed.is_empty() {
                    println!("❌ Failed to decrypt {} files", batch_result.failed.len());
                    for (path, error) in &batch_result.failed {
                        eprintln!("   Error: {} - {}", path.display(), error);
                    }
                }
                
                println!("⏱️  Total time: {:?}", batch_result.total_duration);
                
                // Print details for successful decryptions
                for result in &batch_result.successful {
                    println!("   {} → {} ({:?})",
                        result.input_path.display(),
                        result.output_path.display(),
                        result.duration
                    );
                }
            }
            
            // Exit with error code if any files failed
            if !batch_result.failed.is_empty() {
                process::exit(1);
            }
        }
        Ok(_other_result) => {
            eprintln!("Error: Unexpected workflow result type");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("Decryption failed: {}", e);
            process::exit(1);
        }
    }
    
    Ok(())
}