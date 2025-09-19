//! File listing binary (cryptls)
//! 
//! This binary provides command-line interface for listing encrypted files
//! and showing their original names and metadata.

use crypto::listing;
use crypto::shared::errors::CryptoError;

fn main() -> Result<(), CryptoError> {
    // TODO: Implement CLI argument parsing and main listing logic
    // This will be implemented in Phase 11
    println!("cryptls: Encrypted file listing tool");
    println!("Usage: cryptls [OPTIONS] <directory>");
    println!("  --help         Show this help message");
    
    Ok(())
}