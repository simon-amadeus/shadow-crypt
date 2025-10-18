use colored::Colorize;

use crate::errors::EncryptionError;

/// Display simple progress for file operations
pub fn display_progress(current: u64, total: u64, _file: &str) {
    if total == 0 {
        return;
    }

    println!("Processing file {} of {}", current, total);
}

/// Display success message
pub fn display_success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

/// Display error message with appropriate formatting
pub fn display_error(error: EncryptionError) {
    eprintln!("{} {}", "✗".red().bold(), error);
}
