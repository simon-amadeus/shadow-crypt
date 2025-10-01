//! File listing functionality
//! 
//! This module contains everything needed for the `shadows` binary:
//! - Scanning directories for encrypted files
//! - Extracting metadata from file headers
//! - Displaying original filenames without full decryption
//! - CLI interface and formatting options
//! - Beautiful UI formatting with colors and visual hierarchy

// Core listing functionality
pub mod file_scanner;
pub mod metadata_extractor;
pub mod cli;
pub mod ui_formatter;

// Re-export main functions for convenience
pub use file_scanner::list_encrypted_files;
pub use metadata_extractor::extract_file_info;
pub use ui_formatter::UIFormatter;