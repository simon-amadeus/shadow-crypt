//! Shared error display utilities for CLI tools
//! 
//! This module provides consistent error message formatting across all Shadow tools.

use crate::shared::errors::CryptoError;
use std::process;

/// Display an error message with consistent formatting and exit
pub fn display_error_and_exit(error: CryptoError, exit_code: i32) -> ! {
    eprintln!("{}", error.user_friendly_message());
    process::exit(exit_code);
}

/// Display a user-friendly error message and exit with code 1
pub fn display_error_and_exit_1(error: CryptoError) -> ! {
    display_error_and_exit(error, 1);
}

/// Display a custom error message with consistent formatting  
pub fn display_custom_error_and_exit(message: &str, suggestion: &str) -> ! {
    eprintln!("Error: {}\n\nSuggestion: {}", message, suggestion);
    process::exit(1);
}

/// Display a validation error for command-line arguments
pub fn display_validation_error_and_exit(message: &str) -> ! {
    eprintln!("Error: {}\n\nUse --help for usage information.", message);
    process::exit(1);
}

/// Display an error and return the error (for functions that need to return Result)
pub fn display_error_and_return(error: CryptoError) -> CryptoError {
    eprintln!("{}", error.user_friendly_message());
    error
}

/// Convert I/O errors to CryptoError with context
pub fn io_error_with_context(error: std::io::Error, context: &str) -> CryptoError {
    match error.kind() {
        std::io::ErrorKind::NotFound => {
            CryptoError::FileNotFound(context.to_string())
        },
        _ => CryptoError::FileSystemError(error)
    }
}

/// Display a simple informational message (not an error)
pub fn display_info(message: &str) {
    println!("{}", message);
}

/// Display a warning message  
pub fn display_warning(message: &str) {
    eprintln!("Warning: {}", message);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_io_error_conversion() {
        let not_found = std::io::Error::new(std::io::ErrorKind::NotFound, "test file");
        let crypto_error = io_error_with_context(not_found, "test_file.txt");
        match crypto_error {
            CryptoError::FileNotFound(path) => assert_eq!(path, "test_file.txt"),
            _ => panic!("Expected FileNotFound error"),
        }
    }
    
    #[test]
    fn test_display_error_and_return() {
        let error = CryptoError::InvalidFileFormat;
        let returned_error = display_error_and_return(error);
        // Just test that it returns the same error type
        match returned_error {
            CryptoError::InvalidFileFormat => (),
            _ => panic!("Expected InvalidFileFormat error"),
        }
    }
}