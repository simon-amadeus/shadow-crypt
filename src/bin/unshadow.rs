//! File decryption binary (unshadow)
//! 
//! This binary provides command-line interface for decrypting files with:
//! - Single and multiple file decryption
//! - Glob pattern expansion
//! - Progress reporting for batch operations
//! - Automatic filename restoration and metadata preservation

use shadow_crypt::decryption::{decrypt_single_file, decrypt_multiple_files, expand_glob_patterns, try_restore_filename_from_header};
use shadow_crypt::shared::errors::CryptoError;
use shadow_crypt::shared::secure_delete::{secure_delete_file, confirm_destructive_operation};
use shadow_crypt::shared::cli_utils::{display_error_and_exit, display_validation_error_and_exit, io_error_with_context, display_error_and_return};
use std::env;
use std::path::{Path, PathBuf};
use std::process;

fn main() -> Result<(), CryptoError> {
    let args: Vec<String> = env::args().collect();
    
    // Simple argument parsing with flags
    let (force_overwrite, remove_source, input_patterns) = parse_args(&args);
    
    // Expand glob patterns into file paths
    let file_paths = match expand_glob_patterns(&input_patterns) {
        Ok(paths) => paths,
        Err(e) => display_error_and_exit(e, 1),
    };

    if file_paths.is_empty() {
        display_validation_error_and_exit("No files found matching the specified patterns");
    }

    // Validate all files exist and are readable
    for file_path in &file_paths {
        if !file_path.exists() {
            display_error_and_exit(
                CryptoError::FileNotFound(file_path.display().to_string()), 
                1
            );
        }
        
        if !file_path.is_file() {
            display_validation_error_and_exit(&format!(
                "'{}' is not a regular file. Only individual files are supported", 
                file_path.display()
            ));
        }
        
        // Check if file is readable
        if let Err(e) = std::fs::File::open(&file_path) {
            display_error_and_exit(
                io_error_with_context(e, &format!("reading file '{}'", file_path.display())),
                1
            );
        }
    }
    
    // Get password securely from user
    let password = match rpassword::prompt_password("Enter password for decryption: ") {
        Ok(pass) => pass,
        Err(e) => {
            display_error_and_exit(
                CryptoError::CryptographicError(format!("Failed to read password: {}", e)),
                1
            );
        }
    };
    
    if password.is_empty() {
        display_validation_error_and_exit("Password cannot be empty");
    }

    // Handle single vs multiple files
    if file_paths.len() == 1 {
        // Single file - use existing logic for better UX
        let input_path = &file_paths[0];
        handle_single_file(input_path, &password, force_overwrite, remove_source)?;
    } else {
        // Multiple files - use batch processing
        handle_multiple_files(&file_paths, &password, force_overwrite, remove_source)?;
    }
    
    Ok(())
}

/// Handle single file decryption with detailed progress reporting
fn handle_single_file(
    input_path: &Path,
    password: &str,
    force_overwrite: bool,
    remove_source: bool
) -> Result<(), CryptoError> {
    // Determine output file path with automatic filename restoration
    let output_path = determine_output_path_with_restoration(input_path, password)?;
    
    // Check for file overwrite protection
    if output_path.exists() && !force_overwrite {
        return Err(display_error_and_return(
            CryptoError::FileSystemError(
                std::io::Error::new(std::io::ErrorKind::AlreadyExists, 
                                    format!("Output file '{}' already exists. Use --force flag to overwrite existing files", output_path.display()))
            )
        ));
    }
    
    // Perform decryption
    println!("🔓 Decrypting file: {}", input_path.display());
    println!("📄 Output file: {}", output_path.display());
    println!("🔑 Using password-based decryption with AES-256-GCM");
    
    match decrypt_single_file(input_path, &output_path, password) {
        Ok(()) => {
            println!("✅ Decryption successful!");
            println!("📄 Decrypted file: {}", output_path.display());
            
            // Handle source file removal if requested
            if remove_source {
                println!();
                if confirm_destructive_operation("Source file removal", input_path) {
                    match secure_delete_file(input_path) {
                        Ok(()) => {
                            println!("🗑️  Source file securely deleted: {}", input_path.display());
                        }
                        Err(e) => {
                            eprintln!("⚠️  Warning: Failed to delete source file: {}", e);
                            eprintln!("   Decryption was successful, but source file remains");
                            eprintln!("   You may need to delete it manually");
                        }
                    }
                } else {
                    println!("🔄 Source file removal cancelled - file remains at: {}", input_path.display());
                }
            }
        }
        Err(e) => {
            return Err(display_error_and_return(e));
        }
    }
    
    Ok(())
}

/// Handle multiple file decryption with progress reporting
fn handle_multiple_files(
    file_paths: &[PathBuf],
    password: &str,
    force_overwrite: bool,
    remove_source: bool
) -> Result<(), CryptoError> {
    println!("🔓 Decrypting {} files...", file_paths.len());
    println!("🔑 Using password-based decryption with AES-256-GCM");
    println!();

    let results = decrypt_multiple_files(
        file_paths,
        password,
        force_overwrite,
        remove_source
    )?;

    // Report results
    println!();
    println!("📊 Decryption Results:");
    println!("✅ Successful: {}", results.successful.len());
    println!("❌ Failed: {}", results.failed.len());
    println!("⏱️  Total time: {:.2?}", results.total_time);
    
    if !results.failed.is_empty() {
        println!();
        println!("❌ Failed decryptions:");
        for (path, error) in &results.failed {
            println!("  {} - {}", path.display(), error);
        }
    }

    if !results.successful.is_empty() {
        println!();
        println!("✅ Successfully decrypted {} files", results.successful.len());
    }

    // Exit with error code if any files failed
    if results.has_failures() {
        process::exit(1);
    }

    Ok(())
}

/// Determine output path using filename restoration
/// 
/// Attempts to restore the original filename from the encrypted file header.
/// Falls back to extension-based naming if restoration fails.
/// 
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `password` - Password for decryption
/// 
/// # Returns
/// * `Ok(PathBuf)` - Determined output path
/// * `Err(CryptoError)` - Failed to determine path
fn determine_output_path_with_restoration(
    input_path: &Path,
    password: &str
) -> Result<PathBuf, CryptoError> {
    // Try to restore original filename from header
    match try_restore_filename_from_header(input_path, password) {
        Ok(original_name) => {
            // Use the directory of input file + restored filename
            let input_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
            Ok(input_dir.join(original_name))
        }
        Err(_) => {
            // Fall back to extension-based naming
            if let Some(stem) = input_path.file_stem() {
                if input_path.to_string_lossy().ends_with(".shadow") {
                    Ok(input_path.with_file_name(stem))
                } else {
                    Ok(input_path.with_extension("dec"))
                }
            } else {
                Ok(input_path.with_extension("dec"))
            }
        }
    }
}

/// Try to restore filename from header without full decryption
/// Parse command line arguments for unshadow tool
/// 
/// Returns (force_overwrite, remove_source, input_patterns)
fn parse_args(args: &[String]) -> (bool, bool, Vec<String>) {
    if args.len() < 2 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_usage();
        std::process::exit(0);
    }
    
    let mut force = false;
    let mut remove_source = false;
    let mut input_patterns = Vec::new();
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--force" | "-f" => {
                force = true;
                i += 1;
            }
            "--remove-source" | "--inplace" | "-r" => {
                remove_source = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                // All remaining arguments are input patterns
                input_patterns.push(args[i].clone());
                i += 1;
            }
        }
    }
    
    if input_patterns.is_empty() {
        eprintln!("Error: At least one input file is required");
        print_usage();
        std::process::exit(1);
    }
    
    (force, remove_source, input_patterns)
}

fn print_usage() {
    println!("unshadow - File decryption tool");
    println!("");
    println!("USAGE:");
    println!("    unshadow [OPTIONS] <input-files>...");
    println!("");
    println!("ARGUMENTS:");
    println!("    <input-files>...     Path(s) to encrypted files or glob patterns");
    println!("");
    println!("OPTIONS:");
    println!("    -f, --force           Overwrite existing output files without prompting");
    println!("    -r, --remove-source   Remove source files after successful decryption");
    println!("        --inplace         Alias for --remove-source");
    println!("    -h, --help            Show this help message");
    println!("");
    println!("Multi-file Support:");
    println!("    unshadow file1.shadow file2.shadow file3.shadow");
    println!("    unshadow *.shadow");
    println!("    unshadow docs/**/*.shadow");
    println!("");
    println!("Behavior:");
    println!("    Automatically restores original filename from encrypted file header");
    println!("    'secret.txt.shadow' → 'secret.txt' (restored from header)");
    println!("    For multiple files, shows progress and success/failure summary");
    println!("");
    println!("Security:");
    println!("    Password will be prompted securely and not shown on screen");
    println!("    Existing files are protected from accidental overwrite");
    println!("");
    println!("EXAMPLES:");
    println!("    unshadow secret.txt.shadow");
    println!("    unshadow --force encrypted_file.shadow");
    println!("    unshadow --remove-source *.shadow");
    println!("    unshadow --inplace document1.shadow document2.shadow");
    println!("    unshadow 'backup/**/*.shadow'");
    println!("");
    println!("The tool will prompt for the password interactively.");
}