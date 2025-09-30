//! File decryption binary (unlock)
//! 
//! This binary provides command-line interface for decrypting files with automatic
//! filename restoration and metadata preservation.

use shadow_crypt::decryption::{decrypt_single_file, restore_original_filename};
use shadow_crypt::shared::errors::CryptoError;
use shadow_crypt::shared::header::Header;
use shadow_crypt::shared::crypto::{derive_master_key, Argon2Params};
use shadow_crypt::shared::secure_delete::{secure_delete_file, confirm_destructive_operation};
use std::env;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Read;

fn main() -> Result<(), CryptoError> {
    let args: Vec<String> = env::args().collect();
    
    // Simple argument parsing with flags
    let (force_overwrite, remove_source, input_file) = parse_args(&args);
    let input_path = Path::new(&input_file);
    
    // Validate input file exists
    if !input_path.exists() {
        eprintln!("Error: Input file '{}' does not exist", input_file);
        return Err(CryptoError::FileSystemError(
            std::io::Error::new(std::io::ErrorKind::NotFound, "Input file not found")
        ));
    }
    
    if !input_path.is_file() {
        eprintln!("Error: '{}' is not a regular file", input_file);
        eprintln!("Note: Only individual files are supported");
        return Err(CryptoError::FileSystemError(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Not a regular file")
        ));
    }
    
    // Check if file is readable
    if let Err(e) = std::fs::File::open(&input_path) {
        eprintln!("Error: Cannot read input file '{}': {}", input_file, e);
        return Err(CryptoError::FileSystemError(e));
    }
    
    // Get password securely from user
    let password = match rpassword::prompt_password("Enter password for decryption: ") {
        Ok(pass) => pass,
        Err(e) => {
            eprintln!("Error reading password: {}", e);
            return Err(CryptoError::FileSystemError(
                std::io::Error::new(std::io::ErrorKind::Other, "Failed to read password")
            ));
        }
    };
    
    if password.is_empty() {
        eprintln!("Error: Password cannot be empty");
        return Err(CryptoError::CryptographicError("Empty password".to_string()));
    }

    // Determine output file path with automatic filename restoration
    let output_path = determine_output_path_with_restoration(input_path, &password)?;
    
    // Check for file overwrite protection
    if output_path.exists() && !force_overwrite {
        eprintln!("Error: Output file '{}' already exists", output_path.display());
        eprintln!("Use --force flag to overwrite existing files");
        return Err(CryptoError::FileSystemError(
            std::io::Error::new(std::io::ErrorKind::AlreadyExists, "Output file exists")
        ));
    }
    
    // Perform decryption
    println!("Decrypting '{}' to '{}'...", input_file, output_path.display());
    
    match decrypt_single_file(input_path, &output_path, &password) {
        Ok(()) => {
            println!("✅ Decryption successful!");
            println!("   Output: {}", output_path.display());
            
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
            eprintln!("❌ Decryption failed: {}", e);
            
            // Provide helpful error messages
            match &e {
                CryptoError::CryptographicError(msg) if msg.contains("decrypt") => {
                    eprintln!("   This could be due to:");
                    eprintln!("   - Incorrect password");
                    eprintln!("   - Corrupted file");
                    eprintln!("   - File was not encrypted with this tool");
                }
                CryptoError::HeaderParsingError(_) => {
                    eprintln!("   The file does not appear to be properly encrypted");
                    eprintln!("   or may be corrupted.");
                }
                _ => {}
            }
            
            return Err(e);
        }
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
/// 
/// Reads just the header from the encrypted file and attempts to restore
/// the original filename. This is used for smart output path determination.
/// 
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `password` - Password for decryption
/// 
/// # Returns
/// * `Ok(String)` - Restored original filename
/// * `Err(CryptoError)` - Restoration failed
fn try_restore_filename_from_header(
    input_path: &Path,
    password: &str
) -> Result<String, CryptoError> {
    // Read encrypted file
    let mut input_file = File::open(input_path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    let mut encrypted_data = Vec::new();
    input_file.read_to_end(&mut encrypted_data)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    // Parse header from encrypted file
    let (header, _) = Header::deserialize(&encrypted_data)?;
    
    // Derive master key from password and salt
    let params = Argon2Params::default();
    let key_material = derive_master_key(password, &header.salt, &params)?;
    
    // Restore original filename
    restore_original_filename(&header, &key_material)
}

/// Parse command line arguments for unlock tool
/// 
/// Returns (force_overwrite, input_file, output_file_opt)
fn parse_args(args: &[String]) -> (bool, bool, String) {
    if args.len() < 2 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_usage();
        std::process::exit(0);
    }
    
    let mut force = false;
    let mut remove_source = false;
    let mut input_file = None;
    
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
                // Only one positional argument: input file
                if input_file.is_none() {
                    input_file = Some(args[i].clone());
                } else {
                    eprintln!("Error: Too many arguments");
                    print_usage();
                    std::process::exit(1);
                }
                i += 1;
            }
        }
    }
    
    if input_file.is_none() {
        eprintln!("Error: Input file is required");
        print_usage();
        std::process::exit(1);
    }
    
    let input_file_path = input_file.expect("Input file was validated as Some() above");
    
    (force, remove_source, input_file_path)
}

fn print_usage() {
    println!("unlock - File decryption tool");
    println!("");
    println!("USAGE:");
    println!("    unlock [OPTIONS] <input-file>");
    println!("");
    println!("ARGUMENTS:");
    println!("    <input-file>     Path to the encrypted file");
    println!("");
    println!("OPTIONS:");
    println!("    -f, --force           Overwrite existing output files without prompting");
    println!("    -r, --remove-source   Remove source file after successful decryption");
    println!("        --inplace         Alias for --remove-source");
    println!("    -h, --help            Show this help message");
    println!("");
    println!("Behavior:");
    println!("    Automatically restores original filename from encrypted file header");
    println!("    'secret.txt.shadow' → 'secret.txt' (restored from header)");
    println!("");
    println!("Security:");
    println!("    Password will be prompted securely and not shown on screen");
    println!("    Existing files are protected from accidental overwrite");
    println!("");
    println!("EXAMPLES:");
    println!("    unshadow secret.txt.shadow");
    println!("    unshadow --force encrypted_file.shadow");
    println!("    unshadow --remove-source secret.txt.shadow");
    println!("    unshadow --inplace document.shadow");
    println!("");
    println!("The tool will prompt for the password interactively.");
}