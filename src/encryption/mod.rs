//! File encryption functionality
//! 
//! This module provides comprehensive file encryption capabilities for the Shadow
//! cryptographic file manager. It implements the core encryption logic used by
//! the `shadow` binary for single and multi-file operations.
//! 
//! # Features
//! 
//! - **Single file encryption** with AES-256-GCM authenticated encryption
//! - **Multi-file encryption** with parallel processing and progress reporting
//! - **Filename obfuscation** with collision resistance and authentication
//! - **Algorithm flexibility** supporting multiple encryption algorithms
//! - **CLI integration** ready for command-line interface implementation
//! 
//! # Architecture
//! 
//! This module follows the standard Shadow use case pattern:
//! - `core.rs` - Core encryption implementation and primary API
//! - `cli.rs` - Command-line interface and argument parsing
//! - `utils.rs` - Internal utilities and helper functions
//! 
//! # Example Usage
//! 
//! ```rust,no_run
//! use shadow_crypt::encryption::encrypt_single_file;
//! use std::path::Path;
//! 
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let input = Path::new("document.txt");
//! let output = Path::new("document.txt.shadow");
//! let password = "secure_password".to_string();
//! 
//! encrypt_single_file(input, output, password, false)?;
//! # Ok(())
//! # }
//! ```
//! 
//! # Security
//! 
//! All encryption operations use cryptographically secure algorithms with:
//! - Argon2id key derivation with secure parameters
//! - Unique salts and nonces for each encryption operation
//! - Authenticated encryption preventing tampering
//! - Secure memory handling with automatic zeroization

// Core encryption functionality
pub mod encrypt_file;
pub mod filename_obfuscation;
pub mod multi_file;
pub mod cli;

// Re-export main functions for convenience
pub use encrypt_file::{
    encrypt_single_file, 
    encrypt_single_file_with_params, 
    encrypt_single_file_with_config,  // New trait-based function
    encrypt_single_file_with_progress, 
    encrypt_single_file_with_algorithm_and_params
};
pub use filename_obfuscation::{obfuscate_filename, obfuscate_name_with_collision_resistance};
pub use multi_file::{encrypt_multiple_files, encrypt_multiple_files_with_progress, encrypt_multiple_files_with_algorithm, expand_glob_patterns, MultiFileResults};