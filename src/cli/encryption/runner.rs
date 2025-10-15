//! Command execution runner for the functional pipeline.

use std::io::{self, Write};
use crate::cli::encryption::commands::EncryptCommand;
use crate::core::{EncryptionPipeline, EncryptionReport};

/// Run the encrypt command using the functional pipeline.
pub fn run_encrypt_command(command: EncryptCommand) -> Result<(), Box<dyn std::error::Error>> {
    if !command.quiet {
        println!("🔒 Shadow File Encryption");
        println!("Algorithm: {}", command.algorithm.name());
        println!("Files: {:?}", command.input_patterns);
    }

    // Get password from user
    let password = prompt_password()?;
    
    // Convert command to options
    let options = command.to_options();
    
    // Execute the functional pipeline
    match EncryptionPipeline::execute(command.input_patterns, password, options) {
        Ok(report) => {
            print_encryption_report(&report, command.quiet);
            
            if !report.is_success() {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("❌ Encryption failed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Print the encryption report.
fn print_encryption_report(report: &EncryptionReport, quiet: bool) {
    if quiet {
        // In quiet mode, only print essential information
        if !report.is_success() {
            eprintln!("Failed: {}/{} files", 
                report.failure_count(), 
                report.total_files_processed
            );
        }
        return;
    }

    println!("\n🔒 Encryption Complete!");
    
    if report.success_count() > 0 {
        println!("✅ Successfully encrypted {} files", report.success_count());
    }
    
    if report.failure_count() > 0 {
        println!("❌ Failed to encrypt {} files", report.failure_count());
        for failure in &report.failed {
            eprintln!("   Error: {} - {}", 
                failure.job.source_path.display(), 
                failure.error
            );
        }
    }
    
    println!("⏱️  Total time: {:?}", report.total_duration);
    println!("📊 Processed {} bytes across {} files", 
        report.total_bytes_processed, 
        report.total_files_processed
    );
    
    if report.success_count() > 0 {
        println!("\nDetails:");
        for result in &report.successful {
            println!("   {} → {} ({:?})",
                result.job.source_path.display(),
                result.job.target_path.display(),
                result.duration
            );
        }
    }
}

/// Prompt user for password.
fn prompt_password() -> Result<String, Box<dyn std::error::Error>> {
    print!("Enter password: ");
    io::stdout().flush()?;
    
    // For this example, we'll use simple stdin reading
    // In production, you'd use a proper password input library
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    
    // Remove trailing newline
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    
    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }
    
    Ok(password)
}