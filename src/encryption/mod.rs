//! File encryption functionality
//! 
//! This module contains everything needed for the `shadow` binary:
//! - Single file encryption with AES-256-GCM
//! - Multi-file encryption with progress reporting
//! - Filename obfuscation (optional)
//! - CLI interface and argument parsing

// Core encryption functionality
pub mod encrypt_file;
pub mod filename_obfuscation;
pub mod multi_file;
pub mod cli;

// Re-export main functions for convenience
pub use encrypt_file::{encrypt_single_file, encrypt_single_file_with_params, encrypt_single_file_with_progress, encrypt_single_file_with_algorithm_and_params};
pub use filename_obfuscation::{obfuscate_filename, obfuscate_name_with_collision_resistance};
pub use multi_file::{encrypt_multiple_files, encrypt_multiple_files_with_progress, encrypt_multiple_files_with_algorithm, expand_glob_patterns, MultiFileResults};