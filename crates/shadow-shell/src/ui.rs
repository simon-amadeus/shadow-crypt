// shadow-shell/src/ui.rs
// User interface utilities with side effects (terminal output)

use colored::Colorize;

use crate::errors::ShellError;

/// Display simple progress for file operations
/// Side effect: Terminal output
pub fn display_progress(current: u64, total: u64, _file: &str) {
    if total == 0 {
        return;
    }

    println!("Processing file {} of {}", current, total);
}

/// Display success message
/// Side effect: Terminal output
pub fn display_success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

/// Display error message with appropriate formatting
/// Side effect: Terminal output
pub fn display_error(error: &ShellError) {
    eprintln!("{} {}", "✗".red().bold(), error.to_string().red());

    // Add helpful hints for common errors
    display_error_hint(error);
}

/// Display helpful hints for specific errors
/// Side effect: Terminal output
fn display_error_hint(error: &ShellError) {
    let hint = match error {
        ShellError::OutputExists(_) => Some("Use --force to overwrite existing files".dimmed()),
        ShellError::PermissionDenied(_) => {
            Some("Check file permissions or run with appropriate privileges".dimmed())
        }
        ShellError::PasswordMismatch => Some("Passwords must match exactly. Try again.".dimmed()),
        ShellError::DuplicateContent { .. } => {
            Some("Use --force to encrypt anyway, or delete existing encrypted file".dimmed())
        }
        ShellError::FileTooLarge { limit, .. } => {
            Some(format!("Maximum file size is {} bytes", limit).dimmed())
        }
        ShellError::TooManyFiles { limit, .. } => {
            Some(format!("Maximum {} files can be processed at once", limit).dimmed())
        }
        _ => None,
    };

    if let Some(hint) = hint {
        eprintln!("  {}", hint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_functions_dont_panic() {
        // These tests just ensure the functions don't panic
        display_success("Test success");
        display_progress(1, 5, "test.txt");
    }

    #[test]
    fn test_shell_error_hints() {
        use std::path::PathBuf;

        // Test that error display doesn't panic
        let errors = vec![
            ShellError::OutputExists(PathBuf::from("test.txt")),
            ShellError::PermissionDenied(PathBuf::from("test.txt")),
            ShellError::PasswordMismatch,
            ShellError::DuplicateContent {
                original_file: PathBuf::from("test.txt"),
                conflicting_file: PathBuf::from("existing.shadow"),
                content_hash: "abc123".to_string(),
            },
            ShellError::FileTooLarge {
                size: 1000,
                limit: 500,
            },
            ShellError::TooManyFiles {
                count: 1001,
                limit: 1000,
            },
            ShellError::Cancelled,
        ];

        for error in errors {
            display_error(&error);
        }
    }
}
