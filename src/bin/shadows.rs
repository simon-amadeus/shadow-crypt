//! File listing binary (cryptls)
//! 
//! This binary provides command-line interface for listing encrypted files
//! and showing their original names and metadata.

//! File listing binary (shadows)
//! 
//! This binary provides command-line interface for listing encrypted files
//! and showing their original names and metadata with beautiful, color-coded output.

use shadow_crypt::listing::{file_scanner, UIFormatter};
use shadow_crypt::shared::errors::CryptoError;
use std::env;
use std::path::Path;

fn main() -> Result<(), CryptoError> {
    let args: Vec<String> = env::args().collect();
    
    // Parse arguments - default to current directory if no arguments provided
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_help();
        return Ok(());
    }
    
    // Default to current directory if no directory specified
    let directory_path = if args.len() < 2 {
        "."
    } else {
        &args[1]
    };
    
    let directory = Path::new(directory_path);
    
    if !directory.exists() {
        eprintln!("{}", CryptoError::FileNotFound(directory_path.to_string()).user_friendly_message());
        return Ok(());
    }
    
    if !directory.is_dir() {
        eprintln!("Error: '{}' is not a directory", directory_path);
        return Ok(());
    }
    
    // Get password securely from user
    let password = match rpassword::prompt_password("Enter password to decrypt filenames: ") {
        Ok(pass) => pass,
        Err(e) => {
            eprintln!("Error reading password: {}", e);
            return Ok(());
        }
    };
    
    if password.is_empty() {
        eprintln!("Error: Password cannot be empty");
        return Ok(());
    }
    
    // List encrypted files in the directory
    match file_scanner::list_encrypted_files(directory, &password) {
        Ok(files) => {
            if files.is_empty() {
                let display_path = if directory_path == "." {
                    "current directory"
                } else {
                    directory_path
                };
                println!("No encrypted files found in '{}'", display_path);
                return Ok(());
            }
            
            // Create UI formatter for beautiful output
            let formatter = UIFormatter::new();
            
            // Print title and overview
            print!("{}", formatter.format_title(files.len()));
            
            // Print headers and separator
            println!("{}", formatter.format_headers());
            println!("{}", formatter.format_separator());
            
            // Print file information with beautiful formatting
            for file_info in &files {
                println!("{}", formatter.format_file_info(file_info));
            }
            
            // Print closing separator and legend
            println!("{}", formatter.format_separator());
            print!("{}", formatter.format_legend());
        },
        Err(e) => {
            eprintln!("{}", e.user_friendly_message());
            return Err(e);
        }
    }
    
    Ok(())
}

fn print_help() {
    println!("shadows - List encrypted files with original names");
    println!();
    println!("USAGE:");
    println!("    shadows [OPTIONS] [directory]");
    println!();
    println!("ARGUMENTS:");
    println!("    [directory]    Directory to scan for encrypted files (default: current directory)");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help     Show this help message");
    println!();
    println!("SECURITY:");
    println!("    Password will be prompted securely to decrypt filenames");
    println!();
    println!("EXAMPLES:");
    println!("    shadows                           # List files in current directory");
    println!("    shadows ./encrypted_files         # List files in specific directory");
    println!("    shadows /path/to/encrypted_docs   # List files in absolute path");
    println!("    shadows ~/backup/shadow_files     # List files in home directory");
    println!();
    println!("OUTPUT:");
    println!("    Color-coded display with visual hierarchy for easy reading");
    println!("    Shows filename mapping: obfuscated → original");
    println!("    Displays file sizes and modification times");
    println!("    Status indicators: ✓ (decrypted) ✗ (encrypted/wrong password)");
    println!();
}