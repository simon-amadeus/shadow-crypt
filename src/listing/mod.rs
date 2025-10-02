//! File listing functionality
//! 
//! This module contains everything needed for the `shadows` binary:
//! - Scanning directories for encrypted files
//! - Extracting metadata from file headers
//! - Displaying original filenames without full decryption
//! - CLI interface and formatting options
//! - Beautiful UI formatting with colors and visual hierarchy

// Core listing functionality
pub mod cli;
pub mod file_scanner;
pub mod ui_formatter;
pub mod modern_grid;

// Export main functionality from sub-modules
pub use file_scanner::{list_encrypted_files, FileInfo};
pub use ui_formatter::UIFormatter;