// shadow-cli/src/bin/shadow.rs
// Main Shadow encryption binary
// Entry point for the encryption feature using shadow-encryption-shell

use shadow_encryption_shell::{ShellError, display_error, parse_args, run_encryption};
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
                shadow_encryption_shell::runner::ApplicationError::FileNotFound(path) => {
                    let shell_error =
                        ShellError::UserInput(format!("File not found: {}", path.display()));
                    display_error(&shell_error);
                }
                shadow_encryption_shell::runner::ApplicationError::NotAFile(path) => {
                    let shell_error =
                        ShellError::UserInput(format!("Not a file: {}", path.display()));
                    display_error(&shell_error);
                }
                shadow_encryption_shell::runner::ApplicationError::UserInput(msg) => {
                    let shell_error = ShellError::UserInput(msg.clone());
                    display_error(&shell_error);
                }
                shadow_encryption_shell::runner::ApplicationError::Shell(shell_err) => {
                    display_error(shell_err);
                }
                shadow_encryption_shell::runner::ApplicationError::FileOperation(file_err) => {
                    let shell_error =
                        ShellError::UserInput(format!("File operation failed: {}", file_err));
                    display_error(&shell_error);
                }
            };

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
