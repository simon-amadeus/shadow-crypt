//! File decryption functionality
//! 
//! This module contains everything needed for the `unlock` binary:
//! - Single file decryption with authentication verification
//! - Multi-file decryption (planned)
//! - Filename restoration from encrypted headers
//! - CLI interface and argument parsing

// Core decryption functionality
pub mod decrypt_file;
pub mod filename_restoration;
pub mod cli;

// Re-export main functions for convenience
pub use decrypt_file::{decrypt_single_file, decrypt_single_file_with_params};
pub use filename_restoration::restore_original_filename;