//! Lock binary - File encryption tool
//! 
//! This binary provides file encryption functionality using the encryption module.

use std::env;
use std::path::Path;
use std::process;
use crypto::encryption::encrypt_single_file;
use crypto::shared::secure_delete::{secure_delete_file, confirm_destructive_operation};

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Parse command line arguments - password will be prompted securely
    let (input_path, obfuscate_filename, force_overwrite, remove_source) = parse_args(&args);
    
    if !input_path.exists() {
        eprintln!("Error: Input file '{}' does not exist", input_path.display());
        process::exit(1);
    }
    
    if !input_path.is_file() {
        eprintln!("Error: '{}' is not a regular file", input_path.display());
        eprintln!("Note: Only individual files are supported");
        process::exit(1);
    }
    
    // Check if file is readable
    match std::fs::File::open(&input_path) {
        Ok(_) => {}, // File is readable
        Err(e) => {
            eprintln!("Error: Cannot read input file '{}': {}", input_path.display(), e);
            process::exit(1);
        }
    }
    
    // Get password securely from user
    let password = match rpassword::prompt_password("Enter password for encryption: ") {
        Ok(pass) => pass,
        Err(e) => {
            eprintln!("Error reading password: {}", e);
            process::exit(1);
        }
    };
    
    if password.is_empty() {
        eprintln!("Error: Password cannot be empty");
        process::exit(1);
    }
    
    // Determine output path automatically
    let output_path = if obfuscate_filename {
        // When obfuscating, use input file directory with .enc extension
        let parent_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = match input_path.file_name() {
            Some(name) => name.to_string_lossy(),
            None => {
                eprintln!("Error: Unable to determine filename from path: {}", input_path.display());
                process::exit(1);
            }
        };
        parent_dir.join(format!("{}.enc", file_name))
    } else {
        // Simple case: add .enc extension to the full filename
        format!("{}.enc", input_path.to_string_lossy()).into()
    };
    
    // Check for file overwrite protection
    if output_path.exists() && !force_overwrite {
        eprintln!("Error: Output file '{}' already exists", output_path.display());
        eprintln!("Use --force flag to overwrite existing files");
        process::exit(1);
    }
    
    println!("� Encrypting file: {}", input_path.display());
    if obfuscate_filename {
        println!("🎭 Filename obfuscation: ENABLED");
        println!("📄 Encrypted file will be saved with obfuscated name in: {}", 
                output_path.parent().unwrap_or_else(|| Path::new(".")).display());
    } else {
        println!("📄 Output file: {}", output_path.display());
        println!("🎭 Filename obfuscation: DISABLED");
    }
    println!("🔑 Using password-based encryption with AES-256-GCM");
    
    match encrypt_single_file(&input_path, &output_path, &password, obfuscate_filename) {
        Ok(()) => {
            println!("✅ File encrypted successfully!");
            if obfuscate_filename {
                println!("🎭 Original filename is obfuscated and stored securely in the file header");
                println!("🔒 Check the directory for the encrypted file with obfuscated name");
            } else {
                println!("🔒 Encrypted file: {}", output_path.display());
            }
            
            // Handle source file removal if requested
            if remove_source {
                println!();
                if confirm_destructive_operation("Source file removal", &input_path) {
                    match secure_delete_file(&input_path) {
                        Ok(()) => {
                            println!("🗑️  Source file securely deleted: {}", input_path.display());
                        }
                        Err(e) => {
                            eprintln!("⚠️  Warning: Failed to delete source file: {}", e);
                            eprintln!("   Encryption was successful, but source file remains");
                            eprintln!("   You may need to delete it manually");
                        }
                    }
                } else {
                    println!("🔄 Source file removal cancelled - file remains at: {}", input_path.display());
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Encryption failed: {}", e);
            process::exit(1);
        }
    }
}

/// Parse command line arguments
/// 
/// Simplified to only handle flags - output path is auto-generated
fn parse_args(args: &[String]) -> (std::path::PathBuf, bool, bool, bool) {
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    let mut input_file = None;
    let mut obfuscate = false;
    let mut force = false;
    let mut remove_source = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--obfuscate" | "-o" => {
                obfuscate = true;
                i += 1;
            }
            "--force" | "-f" => {
                force = true;
                i += 1;
            }
            "--remove-source" | "--inplace" | "-r" => {
                remove_source = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage(&args[0]);
                process::exit(0);
            }
            _ => {
                // Only one positional argument: input file
                if input_file.is_none() {
                    input_file = Some(args[i].clone());
                } else {
                    eprintln!("Error: Too many arguments");
                    print_usage(&args[0]);
                    process::exit(1);
                }
                i += 1;
            }
        }
    }
    
    // Validate required arguments
    if input_file.is_none() {
        eprintln!("Error: Input file is required");
        print_usage(&args[0]);
        process::exit(1);
    }
    
    let input_file_path = input_file.expect("Input file was validated as Some() above");
    
    (
        Path::new(&input_file_path).to_path_buf(),
        obfuscate,
        force,
        remove_source,
    )
}

/// Print usage information
fn print_usage(program_name: &str) {
    eprintln!("Usage: {} [OPTIONS] <input_file>", program_name);
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <input_file>   Path to the file to encrypt");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -o, --obfuscate       Obfuscate the original filename for privacy");
    eprintln!("  -f, --force           Overwrite existing output files without prompting");
    eprintln!("  -r, --remove-source   Remove source file after successful encryption");
    eprintln!("      --inplace         Alias for --remove-source");
    eprintln!("  -h, --help            Show this help message");
    eprintln!();
    eprintln!("Behavior:");
    eprintln!("  Normal mode: 'secret.txt' → 'secret.txt.enc'");
    eprintln!("  Obfuscated:  'secret.txt' → 'a1b2c3d4.enc' (random name)");
    eprintln!();
    eprintln!("Security:");
    eprintln!("  Password will be prompted securely and not shown on screen");
    eprintln!("  Existing files are protected from accidental overwrite");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} secret.txt", program_name);
    eprintln!("  {} --obfuscate document.pdf", program_name);
    eprintln!("  {} --remove-source secret.txt", program_name);
    eprintln!("  {} --inplace --obfuscate document.pdf", program_name);
}