//! # Shadow CLI Binary
//!
//! File encryption binary implementation with correct --keep flag behavior.

use clap::Parser;
use std::process;

// Import from the shadow-crypt library
use shadow_crypt::application::workflows::encryption_workflow::{EncryptionWorkflow, EncryptionOptions};
use shadow_crypt::application::workflows::WorkflowResult;
use shadow_crypt::domain::entities::AlgorithmId;
use shadow_crypt::infrastructure::{StandardFileRepository, StandardPasswordRepository};

/// Shadow File Encryption Tool
#[derive(Parser, Debug)]
#[command(name = "shadow")]
#[command(about = "File encryption with modern cryptography")]
#[command(long_about = "Encrypt files with XChaCha20-Poly1305 or AES-256-GCM algorithms")]
struct ShadowArgs {
    /// Input files or glob patterns to encrypt
    input_patterns: Vec<String>,
    
    /// Encryption algorithm: xchacha20 (default), aes-gcm
    #[arg(short = 'a', long, default_value = "xchacha20")]
    algorithm: String,
    
    /// Obfuscate the original filename for privacy
    #[arg(short = 'o', long)]
    obfuscate: bool,
    
    /// Overwrite existing output files without prompting
    #[arg(short = 'f', long)]
    force: bool,
    
    /// Keep source files after successful encryption (default: remove)
    #[arg(short = 'k', long)]
    keep: bool,
    
    /// Minimal output (no progress indicators)
    #[arg(short = 'q', long)]
    quiet: bool,
}

impl ShadowArgs {
    /// Validate input patterns are provided
    fn validate_input(&self) -> Result<(), String> {
        if self.input_patterns.is_empty() {
            return Err("At least one input file or pattern is required".to_string());
        }
        Ok(())
    }
    
    /// Validate algorithm choice
    fn validate_algorithm(&self) -> Result<(), String> {
        match self.algorithm.as_str() {
            "xchacha20" | "aes-gcm" => Ok(()),
            _ => Err(format!(
                "Unsupported algorithm '{}'. Supported: xchacha20, aes-gcm", 
                self.algorithm
            )),
        }
    }
    
    /// Print status information about flag settings
    fn print_status(&self) {
        println!("✅ CLI parsing complete");
        println!("✅ Source files will be {}", 
            if self.keep { "preserved" } else { "removed after encryption" });
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = ShadowArgs::parse();
    
    // Validate arguments
    if let Err(msg) = args.validate_input() {
        eprintln!("Error: {}", msg);
        process::exit(1);
    }
    
    if let Err(msg) = args.validate_algorithm() {
        eprintln!("Error: {}", msg);
        process::exit(1);
    }
    
    if !args.quiet {
        println!("Shadow File Encryption Tool");
        println!("Algorithm: {}", args.algorithm);
        println!("Input patterns: {:?}", args.input_patterns);
        
        if args.obfuscate {
            println!("Filename obfuscation: Enabled");
        }
    }
    
    // Print status information
    args.print_status();
    
    // Parse algorithm ID
    let algorithm_id = match args.algorithm.as_str() {
        "xchacha20" => AlgorithmId::XChaCha20Poly1305,
        "aes-gcm" => AlgorithmId::AesGcm256,
        _ => unreachable!(), // Already validated above
    };
    
    // Create repository instances
    let file_repo = Box::new(StandardFileRepository::new());
    let password_repo = Box::new(StandardPasswordRepository::new());
    
    // Create encryption workflow
    let mut workflow = EncryptionWorkflow::new(
        file_repo,
        password_repo,
        algorithm_id,
    ).with_quiet_mode(args.quiet);
    
    // Prepare encryption options
    let options = EncryptionOptions {
        obfuscate_filename: args.obfuscate,
        force_overwrite: args.force,
        remove_source: !args.keep,  // Inverted: keep=true means remove_source=false
        check_duplicates: true,     // Always check for duplicates
    };
    
    // Execute encryption workflow
    match workflow.execute(args.input_patterns, options) {
        Ok(WorkflowResult::Encryption(batch_result)) => {
            if !args.quiet {
                // Print user-friendly results
                println!("\n🔒 Encryption Complete!");
                println!("✅ Successfully encrypted {} files", batch_result.successful.len());
                
                if !batch_result.failed.is_empty() {
                    println!("❌ Failed to encrypt {} files", batch_result.failed.len());
                    for (path, error) in &batch_result.failed {
                        eprintln!("   Error: {} - {}", path.display(), error);
                    }
                }
                
                println!("⏱️  Total time: {:?}", batch_result.total_duration);
                
                // Print details for successful encryptions
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
            eprintln!("Encryption failed: {}", e);
            process::exit(1);
        }
    }
    
    Ok(())
}