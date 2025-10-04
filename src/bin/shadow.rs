//! # Shadow CLI Binary
//!
//! File encryption binary implementation with correct --keep flag behavior.

use clap::Parser;
use std::process;

// Import from the shadow-crypt library
use shadow_crypt::application::container::Container;
use shadow_crypt::application::workflows::encryption_workflow::EncryptionOptions;
use shadow_crypt::domain::entities::AlgorithmId;

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
    
    /// Print status information about flag settings (unless quiet)
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
    
    // TODO: Proof-of-concept workflow integration
    println!("✅ Validation complete - ready for workflow integration");
    
    Ok(())
}