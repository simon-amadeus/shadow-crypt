//! File decryption functionality
//! 
//! This module contains everything needed for the `unshadow` binary:
//! - Single file decryption with authentication verification
//! - Multi-file decryption with progress reporting
//! - Filename restoration from encrypted headers
//! - CLI interface and argument parsing

// Core decryption functionality
pub mod decrypt_file;
pub mod filename_restoration;
pub mod multi_file;
pub mod cli;

// Re-export main functions for convenience
pub use decrypt_file::{decrypt_single_file, decrypt_single_file_with_params};
pub use filename_restoration::restore_original_filename;
pub use multi_file::{decrypt_multiple_files, decrypt_multiple_files_with_params, expand_glob_patterns, MultiFileResults, try_restore_filename_from_header};