//! Shadow binary - File encryption tool
//! 
//! This binary provides file encryption functionality with support for:
//! - Single and multiple file encryption
//! - Glob pattern expansion
//! - Progress reporting for batch operations
//! - Graceful error handling

use std::env;
use std::path::Path;
use std::process;
use shadow_crypt::encryption::{encrypt_multiple_files_with_progress, expand_glob_patterns, encrypt_single_file_with_algorithm_and_params};
use shadow_crypt::shared::algorithms::{Algorithm, Argon2Params as AESArgon2Params};
use shadow_crypt::shared::secure_delete::{secure_delete_file, confirm_destructive_operation};

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Parse command line arguments - password will be prompted securely
    let (input_patterns, obfuscate_filename, force_overwrite, remove_source, quiet, algorithm) = parse_args(&args);
    
    // Expand glob patterns into file paths
    let file_paths = match expand_glob_patterns(&input_patterns) {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("Error: Failed to expand file patterns: {}", e);
            process::exit(1);
        }
    };

    if file_paths.is_empty() {
        eprintln!("Error: No files found matching the specified patterns");
        process::exit(1);
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

    // Handle single vs multiple files
    if file_paths.len() == 1 {
        // Single file - use existing logic for better UX
        let input_path = &file_paths[0];
        handle_single_file(input_path, &password, obfuscate_filename, force_overwrite, remove_source, !quiet, &algorithm);
    } else {
        // Multiple files - use batch processing
        handle_multiple_files(&file_paths, &password, obfuscate_filename, force_overwrite, remove_source, !quiet, &algorithm);
    }
}

/// Handle single file encryption with detailed progress reporting
fn handle_single_file(
    input_path: &Path,
    password: &str,
    obfuscate_filename: bool,
    force_overwrite: bool,
    remove_source: bool,
    show_progress: bool,
    algorithm: &str
) {
    // Check if file is already encrypted (prevent double-encryption)
    match shadow_crypt::shared::file_detection::is_encrypted_file(input_path) {
        Ok(true) => {
            eprintln!("Error: The file '{}' is already encrypted", input_path.display());
            eprintln!("Hint: Use 'unshadow' to decrypt it first, or use 'shadowview' to view its contents");
            process::exit(1);
        }
        Ok(false) => {
            // File is not encrypted, proceed with encryption
        }
        Err(e) => {
            eprintln!("Warning: Could not check if file is encrypted ({})", e);
            eprintln!("Proceeding with encryption...");
        }
    }

    // Determine output path automatically
    let output_path = if obfuscate_filename {
        // When obfuscating, use input file directory with .shadow extension
        let parent_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = match input_path.file_name() {
            Some(name) => name.to_string_lossy(),
            None => {
                eprintln!("Error: Unable to determine filename from path: {}", input_path.display());
                process::exit(1);
            }
        };
        parent_dir.join(format!("{}.shadow", file_name))
    } else {
        // Simple case: add .shadow extension to the full filename
        format!("{}.shadow", input_path.to_string_lossy()).into()
    };
    
    // Check for file overwrite protection
    if output_path.exists() && !force_overwrite {
        eprintln!("Error: Output file '{}' already exists", output_path.display());
        eprintln!("Use --force flag to overwrite existing files");
        process::exit(1);
    }
    
    println!("🔐 Encrypting file: {}", input_path.display());
    if obfuscate_filename {
        println!("🎭 Filename obfuscation: ENABLED");
        println!("📄 Encrypted file will be saved with obfuscated name in: {}", 
                output_path.parent().unwrap_or_else(|| Path::new(".")).display());
    } else {
        println!("📄 Output file: {}", output_path.display());
        println!("🎭 Filename obfuscation: DISABLED");
    }
    
    // Parse algorithm first
    let selected_algorithm = match Algorithm::from_cli_string(algorithm) {
        Ok(alg) => alg,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };
    
    // Display algorithm information
    let algorithm_name = match selected_algorithm {
        Algorithm::AES256GCM => "AES-256-GCM",
        Algorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
    };
    println!("🔑 Using password-based encryption with {}", algorithm_name);
    
    // Perform encryption with progress indicators
    use std::time::Instant;
    let start_time = Instant::now();
    
    // Use fast test parameters for better development experience  
    let argon2_params = AESArgon2Params::default();
    
    if show_progress {
        print!("🔄 Encrypting file...");
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }
    
    match encrypt_single_file_with_algorithm_and_params(&input_path, &output_path, &password, obfuscate_filename, selected_algorithm, &argon2_params) {
        Ok(()) => {
            if show_progress {
                let duration = start_time.elapsed();
                println!(" ✓ ({})", shadow_crypt::shared::performance::format_duration(duration));
                println!("✅ Encryption completed in {}", shadow_crypt::shared::performance::format_duration(duration));
            }
            
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

/// Handle multiple file encryption with minimal progress reporting
fn handle_multiple_files(
    file_paths: &[std::path::PathBuf],
    password: &str,
    obfuscate_filename: bool,
    force_overwrite: bool,
    remove_source: bool,
    show_progress: bool,
    _algorithm: &str
) {
    let results = encrypt_multiple_files_with_progress(
        file_paths,
        password,
        obfuscate_filename,
        force_overwrite,
        remove_source,
        show_progress
    );

    // Handle the Result wrapper
    match results {
        Ok(_res) => {
            // Results already reported by the encryption function
        }
        Err(e) => {
            eprintln!("❌ Multi-file encryption failed: {}", e);
            process::exit(1);
        }
    }
}

/// Parse command line arguments
/// 
/// Now supports multiple input patterns for batch processing
fn parse_args(args: &[String]) -> (Vec<String>, bool, bool, bool, bool, String) {
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    let mut input_patterns = Vec::new();
    let mut obfuscate = false;
    let mut force = false;
    let mut remove_source = false;
    let mut quiet = false;
    let mut algorithm = "xchacha20".to_string(); // Default to XChaCha20-Poly1305 for enhanced security
    
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
            "--quiet" | "-q" => {
                quiet = true;
                i += 1;
            }
            "--algorithm" | "-a" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --algorithm requires a value");
                    print_usage(&args[0]);
                    process::exit(1);
                }
                algorithm = args[i + 1].clone();
                // Validate algorithm choice
                match algorithm.as_str() {
                    "aes-gcm" | "xchacha20" => {
                        // Valid algorithm
                    }
                    _ => {
                        eprintln!("Error: Unsupported algorithm '{}'. Supported: aes-gcm, xchacha20", algorithm);
                        process::exit(1);
                    }
                }
                i += 2;
            }
            "--help" | "-h" => {
                print_usage(&args[0]);
                process::exit(0);
            }
            _ => {
                // Collect all positional arguments as input patterns
                input_patterns.push(args[i].clone());
                i += 1;
            }
        }
    }
    
    // Validate required arguments
    if input_patterns.is_empty() {
        eprintln!("Error: At least one input file or pattern is required");
        print_usage(&args[0]);
        process::exit(1);
    }
    
    (input_patterns, obfuscate, force, remove_source, quiet, algorithm)
}

/// Print usage information
fn print_usage(program_name: &str) {
    eprintln!("Usage: {} [OPTIONS] <input_files_or_patterns>...", program_name);
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <input_files_or_patterns>  One or more files or glob patterns to encrypt");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -a, --algorithm <ALG>     Encryption algorithm: xchacha20 (default), aes-gcm");
    eprintln!("  -o, --obfuscate           Obfuscate the original filename for privacy");
    eprintln!("  -f, --force               Overwrite existing output files without prompting");
    eprintln!("  -r, --remove-source       Remove source files after successful encryption");
    eprintln!("      --inplace             Alias for --remove-source");
    eprintln!("  -q, --quiet               Minimal output (no progress indicators)");
    eprintln!("  -h, --help                Show this help message");
    eprintln!();
    eprintln!("Algorithms:");
    eprintln!("  xchacha20    XChaCha20-Poly1305 (default, enhanced security)");
    eprintln!("  aes-gcm      AES-256-GCM (maximum compatibility)");
    eprintln!();
    eprintln!("Behavior:");
    eprintln!("  Normal mode: 'secret.txt' → 'secret.txt.shadow'");
    eprintln!("  Obfuscated:  'secret.txt' → 'a1b2c3d4.shadow' (random name)");
    eprintln!();
    eprintln!("Security:");
    eprintln!("  Password will be prompted securely and not shown on screen");
    eprintln!("  Existing files are protected from accidental overwrite");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} secret.txt", program_name);
    eprintln!("  {} --algorithm xchacha20 secret.txt", program_name);
    eprintln!("  {} file1.txt file2.txt file3.txt", program_name);
    eprintln!("  {} *.txt", program_name);
    eprintln!("  {} --obfuscate documents/*.pdf", program_name);
    eprintln!("  {} --remove-source *.log", program_name);
    eprintln!("  {} --inplace --obfuscate sensitive/*", program_name);
}