// shadow-cli/src/bin/shadow.rs
// Main Shadow encryption binary
// Entry point for the encryption feature using shadow-shell

use shadow_shell::{ShellError, display_error, parse_args, run_encryption, ApplicationError, EncryptionFileError};
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
                ApplicationError::FileNotFound(path) => {
                    let shell_error =
                        ShellError::UserInput(format!("File not found: {}", path.display()));
                    display_error(&shell_error);
                }
                ApplicationError::NotAFile(path) => {
                    let shell_error =
                        ShellError::UserInput(format!("Not a file: {}", path.display()));
                    display_error(&shell_error);
                }
                ApplicationError::UserInput(msg) => {
                    let shell_error = ShellError::UserInput(msg.clone());
                    display_error(&shell_error);
                }
                ApplicationError::Shell(shell_err) => {
                    display_error(shell_err);
                }
                ApplicationError::FileOperation(file_err) => {
                    // Check if this is a wrapped ShellError
                    match file_err {
                        EncryptionFileError::Shell(
                            shell_err,
                        ) => {
                            // Display the structured shell error directly
                            display_error(shell_err);
                        }
                        _ => {
                            // For other file operation errors, wrap in UserInput
                            let shell_error = ShellError::UserInput(format!(
                                "File operation failed: {}",
                                file_err
                            ));
                            display_error(&shell_error);
                        }
                    }
                }
            };

            let exit_code = match &e {
                ApplicationError::FileNotFound(_) => 2,
                ApplicationError::NotAFile(_) => 2,
                ApplicationError::UserInput(_) => 64,
                ApplicationError::Shell(_) => 5,
                ApplicationError::FileOperation(_) => 74,
            };
            process::exit(exit_code);
        }
    }
}
