//! File decryption binary (unlock)
//! 
//! This binary provides command-line interface for decrypting files with automatic
//! filename restoration and metadata preservation.

use crypto::decryption::decrypt_single_file;
use crypto::shared::errors::CryptoError;
use std::env;
use std::path::Path;
use std::io::{self, Write};

fn main() -> Result<(), CryptoError> {
    let args: Vec<String> = env::args().collect();
    
    // Simple argument parsing for Phase 5
    if args.len() < 2 || args.contains(&"--help".to_string()) {
        print_usage();
        return Ok(());
    }
    
    let input_file = &args[1];
    let input_path = Path::new(input_file);
    
    // Validate input file exists
    if !input_path.exists() {
        eprintln!("Error: Input file '{}' does not exist", input_file);
        return Err(CryptoError::FileSystemError(
            std::io::Error::new(std::io::ErrorKind::NotFound, "Input file not found")
        ));
    }
    
    // Determine output file path
    let output_path = if args.len() >= 3 {
        Path::new(&args[2]).to_path_buf()
    } else {
        // Remove .enc extension if present, otherwise add .dec
        if let Some(stem) = input_path.file_stem() {
            if input_file.ends_with(".enc") {
                input_path.with_file_name(stem)
            } else {
                input_path.with_extension("dec")
            }
        } else {
            input_path.with_extension("dec")
        }
    };
    
    // Get password from user
    print!("Enter password for decryption: ");
    io::stdout().flush().unwrap();
    let mut password = String::new();
    io::stdin().read_line(&mut password)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    let password = password.trim();
    
    if password.is_empty() {
        eprintln!("Error: Password cannot be empty");
        return Err(CryptoError::CryptographicError("Empty password".to_string()));
    }
    
    // Perform decryption
    println!("Decrypting '{}' to '{}'...", input_file, output_path.display());
    
    match decrypt_single_file(input_path, &output_path, password) {
        Ok(()) => {
            println!("✅ Decryption successful!");
            println!("   Output: {}", output_path.display());
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

fn print_usage() {
    println!("unlock - File decryption tool");
    println!("");
    println!("USAGE:");
    println!("    unlock <input-file> [output-file]");
    println!("");
    println!("ARGUMENTS:");
    println!("    <input-file>     Path to the encrypted file");
    println!("    [output-file]    Path for the decrypted file (optional)");
    println!("                     If not provided, removes .enc extension or adds .dec");
    println!("");
    println!("OPTIONS:");
    println!("    --help          Show this help message");
    println!("");
    println!("EXAMPLES:");
    println!("    unlock secret.txt.enc");
    println!("    unlock document.enc document.txt");
    println!("");
    println!("The tool will prompt for the password interactively.");
}