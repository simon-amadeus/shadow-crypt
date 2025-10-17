// shadow-cli/src/bin/shadow.rs
// Main Shadow encryption binary
// Entry point for the encryption feature using shadow-shell

use shadow_shell::{ShellError, display_error, parse_args, run_encryption};
use shadow_shell::encryption::EncryptionError;
use std::process;

fn main() {
    // Parse command line arguments
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            let shell_error = ShellError::UserInput(format!("Error parsing arguments: {}", e));
            display_error(&shell_error);
            process::exit(1);
        }
    };

    // Run encryption workflow
    match run_encryption(args) {
        Ok(()) => {
            // Success - exit cleanly
        }
        Err(e) => {
            // Use display_error for consistent error display
            match &e {
                EncryptionError::FileNotFound(path) => {
                    let shell_error =
                        ShellError::UserInput(format!("File not found: {}", path.display()));
                    display_error(&shell_error);
                }
                EncryptionError::NotAFile(path) => {
                    let shell_error =
                        ShellError::UserInput(format!("Not a file: {}", path.display()));
                    display_error(&shell_error);
                }
                EncryptionError::UserInput(msg) => {
                    let shell_error = ShellError::UserInput(msg.clone());
                    display_error(&shell_error);
                }
                EncryptionError::Shell(shell_err) => {
                    display_error(shell_err);
                }
                EncryptionError::FileOperation(file_err) => {
                    let shell_error = ShellError::UserInput(format!(
                        "File operation failed: {}",
                        file_err
                    ));
                    display_error(&shell_error);
                }
                EncryptionError::Serialization(ser_err) => {
                    let shell_error = ShellError::UserInput(format!(
                        "Serialization failed: {}",
                        ser_err
                    ));
                    display_error(&shell_error);
                }
                EncryptionError::Io(io_err) => {
                    let shell_error = ShellError::UserInput(format!(
                        "I/O error: {}",
                        io_err
                    ));
                    display_error(&shell_error);
                }
                EncryptionError::InvalidShadowFile(path) => {
                    let shell_error = ShellError::UserInput(format!(
                        "Invalid shadow file: {}",
                        path.display()
                    ));
                    display_error(&shell_error);
                }
            };

            let exit_code = match &e {
                EncryptionError::FileNotFound(_) => 2,
                EncryptionError::NotAFile(_) => 2,
                EncryptionError::UserInput(_) => 64,
                EncryptionError::Shell(_) => 5,
                EncryptionError::FileOperation(_) => 74,
                EncryptionError::Serialization(_) => 74,
                EncryptionError::Io(_) => 74,
                EncryptionError::InvalidShadowFile(_) => 74,
            };
            process::exit(exit_code);
        }
    }
}
