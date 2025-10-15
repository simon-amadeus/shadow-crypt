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
                println!();

                // Smart ordering: successful decryptions first (alphabetically), then failed attempts
                let mut files = listing_result.files.clone();
                files.sort_by(|a, b| {
                    match (a.password_valid, b.password_valid) {
                        (true, false) => std::cmp::Ordering::Less,    // successful first
                        (false, true) => std::cmp::Ordering::Greater, // failed last
                        _ => {
                            // Same validation status, sort alphabetically by filename
                            let a_name = a.path.file_name().unwrap_or_default();
                            let b_name = b.path.file_name().unwrap_or_default();
                            a_name.cmp(b_name)
                        }
                    }
                });

                // Professional table formatting with wider columns
                println!("┌─────┬─────────────────────────────────────────────────────────────────────────────┐");
                println!("│ ✓/✗ │ Encrypted Filename → Original Filename                                     │");
                println!("├─────┼─────────────────────────────────────────────────────────────────────────────┤");
                
                for file_info in &files {
                    let status = if file_info.password_valid { "✓" } else { "✗" };
                    let encrypted_name = file_info.path.file_name().unwrap_or_default().to_string_lossy();
                    let original_name = file_info.original_filename.as_deref().unwrap_or("[Unable to decrypt]");
                    
                    // Format the main line with proper padding
                    let main_line = format!("{} → {}", encrypted_name, original_name);
                    println!("│  {}  │ {:<75} │", status, truncate_string(&main_line, 75));
                    
                    // Format the metadata line with modification time (more compact)
                    let size_str = format_file_size(file_info.size);
                    let modified_str = format_modified_time(&file_info.path);
                    let algo_short = match file_info.algorithm {
                        shadow_crypt::domain::shared::AlgorithmId::XChaCha20Poly1305 => "XChaCha20",
                        shadow_crypt::domain::shared::AlgorithmId::AesGcm256 => "AES-256",
                    };
                    let metadata = format!("{}, V{}, {}, {}", 
                        algo_short, file_info.version, size_str, modified_str);
                    println!("│     │ {:<75} │", truncate_string(&metadata, 75));
                }
                
                println!("└─────┴─────────────────────────────────────────────────────────────────────────────┘");
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

/// Helper function to format file sizes in human-readable format
fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size_f = size as f64;
    let mut unit_index = 0;
    
    while size_f >= 1024.0 && unit_index < UNITS.len() - 1 {
        size_f /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", size, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size_f, UNITS[unit_index])
    }
}

/// Helper function to truncate strings with ellipsis
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Helper function to format modification time
fn format_modified_time(path: &std::path::Path) -> String {
    use std::time::SystemTime;
    
    match std::fs::metadata(path) {
        Ok(metadata) => {
            match metadata.modified() {
                Ok(modified) => {
                    // Format as relative time (e.g., "2 hours ago")
                    match SystemTime::now().duration_since(modified) {
                        Ok(duration) => {
                            let secs = duration.as_secs();
                            if secs < 60 {
                                "just now".to_string()
                            } else if secs < 3600 {
                                format!("{}m ago", secs / 60)
                            } else if secs < 86400 {
                                format!("{}h ago", secs / 3600)
                            } else if secs < 604800 {
                                format!("{}d ago", secs / 86400)
                            } else {
                                format!("{}w ago", secs / 604800)
                            }
                        }
                        Err(_) => "in future".to_string(),
                    }
                }
                Err(_) => "unknown".to_string(),
            }
        }
        Err(_) => "unknown".to_string(),
    }
}