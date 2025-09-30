//! File encryption functionality
//! 
//! This module contains everything needed for the `lock` binary:
//! - Single file encryption with AES-256-GCM
//! - Directory encryption with recursive processing
//! - Filename obfuscation (optional)
//! - CLI interface and argument parsing

// Core encryption functionality
pub mod encrypt_file;
pub mod encrypt_directory;
pub mod filename_obfuscation;
pub mod cli;

// Re-export main functions for convenience
pub use encrypt_file::{encrypt_single_file, encrypt_single_file_with_params};
pub use encrypt_directory::encrypt_directory_parallel;
pub use filename_obfuscation::{obfuscate_filename, obfuscate_name_with_collision_resistance};