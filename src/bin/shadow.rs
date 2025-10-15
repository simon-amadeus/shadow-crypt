//! Shadow encryption tool using functional pipeline architecture.

use std::env;
use shadow_crypt::{parse_encrypt_args, run_encrypt_command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    // Parse command line arguments
    let command = parse_encrypt_args(args)
        .map_err(|e| {
            eprintln!("Error: {}", e);
            print_usage();
            std::process::exit(1);
        })?;
    
    // Run the encryption command
    run_encrypt_command(command)?;
    
    Ok(())
}

fn print_usage() {
    eprintln!("Usage: shadow [OPTIONS] <file_patterns...>");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -o, --obfuscate    Obfuscate filenames");
    eprintln!("  -f, --force        Force overwrite existing files");
    eprintln!("  -k, --keep         Keep source files after encryption");
    eprintln!("  -q, --quiet        Suppress output");
    eprintln!("  -a, --algorithm    Encryption algorithm (aes256, xchacha20)");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  shadow document.txt");
    eprintln!("  shadow --obfuscate *.txt");
    eprintln!("  shadow --algorithm xchacha20 --force file.pdf");
}