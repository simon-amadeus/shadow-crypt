//! Lock binary - File encryption tool
//! 
//! This binary provides file encryption functionality using the encryption module.

use std::env;
use std::path::Path;
use std::process;
use crypto::encryption::encrypt_single_file;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Parse command line arguments
    let (input_path, output_path, password, obfuscate_filename) = parse_args(&args);
    
    if !input_path.exists() {
        eprintln!("Error: Input file '{}' does not exist", input_path.display());
        process::exit(1);
    }
    
    println!("🔒 Encrypting file: {}", input_path.display());
    println!("📄 Output file: {}", output_path.display());
    println!("🔑 Using password-based encryption with AES-256-GCM");
    
    if obfuscate_filename {
        println!("🎭 Filename obfuscation: ENABLED");
    } else {
        println!("🎭 Filename obfuscation: DISABLED");
    }
    
    match encrypt_single_file(&input_path, &output_path, &password, obfuscate_filename) {
        Ok(()) => {
            println!("✅ File encrypted successfully!");
            println!("🔒 Encrypted file: {}", output_path.display());
            if obfuscate_filename {
                println!("🎭 Original filename is obfuscated and stored securely in the file header");
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
/// Supports both old format (3 args) and new format with flags
fn parse_args(args: &[String]) -> (std::path::PathBuf, std::path::PathBuf, String, bool) {
    if args.len() < 4 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    let mut input_file = None;
    let mut output_file = None;
    let mut password = None;
    let mut obfuscate = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--obfuscate" | "-o" => {
                obfuscate = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage(&args[0]);
                process::exit(0);
            }
            _ => {
                // Positional arguments: input, output, password
                if input_file.is_none() {
                    input_file = Some(args[i].clone());
                } else if output_file.is_none() {
                    output_file = Some(args[i].clone());
                } else if password.is_none() {
                    password = Some(args[i].clone());
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
    if input_file.is_none() || output_file.is_none() || password.is_none() {
        eprintln!("Error: Missing required arguments");
        print_usage(&args[0]);
        process::exit(1);
    }
    
    (
        Path::new(&input_file.unwrap()).to_path_buf(),
        Path::new(&output_file.unwrap()).to_path_buf(),
        password.unwrap(),
        obfuscate,
    )
}

/// Print usage information
fn print_usage(program_name: &str) {
    eprintln!("Usage: {} [OPTIONS] <input_file> <output_file> <password>", program_name);
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  <input_file>   Path to the file to encrypt");
    eprintln!("  <output_file>  Path where encrypted file will be saved");
    eprintln!("  <password>     Password for encryption");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -o, --obfuscate    Obfuscate the original filename for privacy");
    eprintln!("  -h, --help         Show this help message");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} secret.txt secret.txt.enc mypassword123", program_name);
    eprintln!("  {} --obfuscate document.pdf document.pdf.enc strongpass", program_name);
}