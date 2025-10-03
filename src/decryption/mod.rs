//! File decryption functionality
//! 
//! This module provides comprehensive file decryption capabilities for the Shadow
//! cryptographic file manager. It implements the core decryption logic used by
//! the `unshadow` binary for single and multi-file operations.
//! 
//! # Features
//! 
//! - **Single file decryption** with authenticated decryption verification
//! - **Multi-file decryption** with parallel processing and progress reporting
//! - **Filename restoration** from encrypted headers with collision handling
//! - **Algorithm flexibility** supporting multiple decryption algorithms
//! - **CLI integration** ready for command-line interface implementation
//! 
//! # Architecture
//! 
//! This module follows the standard Shadow use case pattern:
//! - `decrypt_file.rs` - Core decryption implementation and primary API
//! - `filename_restoration.rs` - Filename restoration utilities
//! - `multi_file.rs` - Batch decryption operations
//! - `cli.rs` - Command-line interface and argument parsing
//! 
//! # Example Usage
//! 
//! ```rust,no_run
//! use shadow_crypt::decryption::decrypt_single_file_with_config;
//! use shadow_crypt::shared::algorithms::aes_gcm_config::AesGcmConfig;
//! use shadow_crypt::shared::algorithms::config::CryptoConfig;
//! use std::path::Path;
//! 
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let input = Path::new("document.txt.shadow");
//! let output = Path::new("document.txt");
//! let password = "secure_password";
//! let config = AesGcmConfig::production_config();
//! 
//! decrypt_single_file_with_config(input, output, password, &config)?;
//! # Ok(())
//! # }
//! ```
//! 
//! # Security
//! 
//! All decryption operations provide:
//! - Authentication verification preventing tampered file acceptance
//! - Secure password verification with constant-time operations
//! - Memory-safe handling of decrypted data with automatic zeroization
//! - Metadata preservation and restoration from encrypted headers

// Core decryption functionality
pub mod decrypt_file;
pub mod filename_restoration;
pub mod multi_file;
pub mod cli;

// Re-export main functions for convenience
pub use decrypt_file::decrypt_single_file_with_config;  // New trait-based function
pub use filename_restoration::restore_original_filename;
pub use multi_file::{decrypt_multiple_files_with_params_and_progress, expand_glob_patterns, MultiFileResults, try_restore_filename_from_header};