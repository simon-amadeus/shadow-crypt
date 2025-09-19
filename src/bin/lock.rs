//! Lock binary - File encryption tool
//! 
//! This binary provides file encryption functionality using the encryption module.

use std::env;
use std::path::Path;
use std::process;
use crypto::encryption::encrypt_single_file;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 4 {
        eprintln!("Usage: {} <input_file> <output_file> <password>", args[0]);
        eprintln!("Example: lock secret.txt secret.txt.enc mypassword123");
        process::exit(1);
    }
    
    let input_path = Path::new(&args[1]);
    let output_path = Path::new(&args[2]);
    let password = &args[3];
    
    if !input_path.exists() {
        eprintln!("Error: Input file '{}' does not exist", input_path.display());
        process::exit(1);
    }
    
    println!("🔒 Encrypting file: {}", input_path.display());
    println!("📄 Output file: {}", output_path.display());
    println!("🔑 Using password-based encryption with AES-256-GCM");
    
    match encrypt_single_file(input_path, output_path, password, false) {
        Ok(()) => {
            println!("✅ File encrypted successfully!");
            println!("🔒 Encrypted file: {}", output_path.display());
        }
        Err(e) => {
            eprintln!("❌ Encryption failed: {}", e);
            process::exit(1);
        }
    }
}