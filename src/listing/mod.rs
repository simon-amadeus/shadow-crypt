//! File listing functionality
//! 
//! This module contains everything needed for the `cryptls` binary:
//! - Scanning directories for encrypted files
//! - Extracting metadata from file headers
//! - Displaying original filenames without full decryption
//! - CLI interface and formatting options

// Core listing functionality
pub mod file_scanner;
pub mod metadata_extractor;
pub mod cli;

// Re-export main functions for convenience
pub use file_scanner::list_encrypted_files;
pub use metadata_extractor::extract_file_info;