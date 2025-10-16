// shadow-cli/src/bin/shadow.rs
// Main Shadow encryption binary
// Entry point for the encryption feature using shadow-encryption-shell

use shadow_encryption_shell::{parse_args, run_encryption};
use std::process;

fn main() {
    // Parse command line arguments
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error parsing arguments: {}", e);
            process::exit(1);
        }
    };

    // Run encryption workflow
    match run_encryption(args) {
        Ok(()) => {
            // Success - exit cleanly
        }
        Err(e) => {
            eprintln!("Encryption failed: {}", e);
            let exit_code = match &e {
                shadow_encryption_shell::runner::ApplicationError::FileNotFound(_) => 2,
                shadow_encryption_shell::runner::ApplicationError::NotAFile(_) => 2,
                shadow_encryption_shell::runner::ApplicationError::UserInput(_) => 64,
                shadow_encryption_shell::runner::ApplicationError::Shell(_) => 5,
                shadow_encryption_shell::runner::ApplicationError::FileOperation(_) => 74,
            };
            process::exit(exit_code);
        }
    }
}