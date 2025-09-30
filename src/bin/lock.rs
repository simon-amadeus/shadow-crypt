//! Lock binary - File encryption tool
//! 
//! This binary provides file encryption functionality using the encryption module.

use std::env;
use std::path::Path;
use std::process;
use crypto::encryption::encrypt_single_file;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Parse command line arguments - password will be prompted securely
    let (input_path, output_path_opt, obfuscate_filename, force_overwrite) = parse_args(&args);
    
    if !input_path.exists() {
        eprintln!("Error: Input file '{}' does not exist", input_path.display());
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
    
    // Determine output path
    let output_path = match output_path_opt {
        Some(path) => path,
        None => {
            // When obfuscating and no output specified, use input file directory
            let parent_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
            parent_dir.join(format!("{}.enc", input_path.file_name().unwrap().to_string_lossy()))
        }
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
        }
        Err(e) => {
            eprintln!("❌ Encryption failed: {}", e);
            process::exit(1);
        }
    }
}

/// Parse command line arguments
/// 
/// Supports both old format (2 args + optional flags) and new format with flags
/// When obfuscation is enabled and no output file is specified, uses input directory
fn parse_args(args: &[String]) -> (std::path::PathBuf, Option<std::path::PathBuf>, bool, bool) {
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    let mut input_file = None;
    let mut output_file = None;
    let mut obfuscate = false;
    let mut force = false;
    
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
            "--help" | "-h" => {
                print_usage(&args[0]);
                process::exit(0);
            }
            _ => {
                // Positional arguments: input, output (optional when obfuscating)
                if input_file.is_none() {
                    input_file = Some(args[i].clone());
                } else if output_file.is_none() {
                    output_file = Some(args[i].clone());
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
    
    // When obfuscating, output file is optional
    if !obfuscate && output_file.is_none() {
        eprintln!("Error: Output file is required when not obfuscating filename");
        print_usage(&args[0]);
        process::exit(1);
    }
    
    (
        Path::new(&input_file.unwrap()).to_path_buf(),
        output_file.map(|f| Path::new(&f).to_path_buf()),
        obfuscate,
        force,
    )
}

/// Print usage information
fn print_usage(program_name: &str) {
    eprintln!("Usage: {} [OPTIONS] <input_file> [output_file]", program_name);
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <input_file>   Path to the file to encrypt");
    eprintln!("  [output_file]  Path where encrypted file will be saved");
    eprintln!("                 (optional when using --obfuscate)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -o, --obfuscate    Obfuscate the original filename for privacy");
    eprintln!("                     When used, output_file becomes optional");
    eprintln!("  -f, --force        Overwrite existing output files without prompting");
    eprintln!("  -h, --help         Show this help message");
    eprintln!();
    eprintln!("Security:");
    eprintln!("  Password will be prompted securely and not shown on screen");
    eprintln!("  Existing files are protected from accidental overwrite");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} secret.txt secret.txt.enc", program_name);
    eprintln!("  {} --obfuscate document.pdf", program_name);
    eprintln!("  {} --force --obfuscate document.pdf ./encrypted/", program_name);
}