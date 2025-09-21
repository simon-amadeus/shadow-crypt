//! File listing binary (cryptls)
//! 
//! This binary provides command-line interface for listing encrypted files
//! and showing their original names and metadata.

use crypto::listing::{file_scanner, metadata_extractor};
use crypto::shared::errors::CryptoError;
use std::env;
use std::path::Path;

fn main() -> Result<(), CryptoError> {
    let args: Vec<String> = env::args().collect();
    
    // Simple argument parsing - now only requires directory path
    if args.len() < 2 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_help();
        return Ok(());
    }
    
    let directory_path = &args[1];
    let directory = Path::new(directory_path);
    
    if !directory.exists() {
        eprintln!("Error: Directory '{}' does not exist", directory_path);
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
                println!("No encrypted files found in '{}'", directory_path);
                return Ok(());
            }
            
            // Print header
            println!("{}", metadata_extractor::format_header());
            println!("{}", metadata_extractor::format_separator());
            
            // Print file information
            for file_info in &files {
                println!("{}", metadata_extractor::format_file_info(file_info));
            }
            
            println!("{}", metadata_extractor::format_separator());
            println!("Found {} encrypted file(s)", files.len());
            println!();
            println!("Legend:");
            println!("  ✓ = Original filename successfully decrypted");
            println!("  ? = Filename encrypted (wrong password or corrupted)");
            println!("      [ENCRYPTED] entries show the obfuscated filename");
        },
        Err(e) => {
            eprintln!("Error listing files: {}", e);
            return Err(e);
        }
    }
    
    Ok(())
}

fn print_help() {
    println!("cryptls - List encrypted files with original names");
    println!();
    println!("USAGE:");
    println!("    cryptls <directory>");
    println!();
    println!("ARGUMENTS:");
    println!("    <directory>    Directory to scan for encrypted files");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help     Show this help message");
    println!();
    println!("SECURITY:");
    println!("    Password will be prompted securely to decrypt filenames");
    println!();
    println!("EXAMPLES:");
    println!("    cryptls ./encrypted_files");
    println!("    cryptls /path/to/files");
    println!();
    println!("NOTES:");
    println!("    - Only shows files that match the provided password");
    println!("    - Files with wrong passwords show encrypted filenames");
    println!("    - Requires password for filename decryption only");
}