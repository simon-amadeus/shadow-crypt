//! Secure file viewing functionality
//! 
//! This module provides secure viewing capabilities for encrypted files without
//! persistent decryption. It implements the core viewing logic used by the
//! `shadowview` binary for safe content inspection.
//! 
//! # Features
//! 
//! - **Streaming decryption** to secure temporary files
//! - **External viewer integration** with support for $PAGER and custom viewers
//! - **Secure temporary file handling** with automatic cleanup and secure deletion
//! - **Memory protection** preventing content exposure to system memory
//! - **Zero-persistence** ensuring no decrypted content remains after viewing
//! 
//! # Architecture
//! 
//! This module follows the standard Shadow use case pattern:
//! - `streaming_decrypt.rs` - Core streaming decryption implementation
//! - `viewer_integration.rs` - External viewer management and integration
//! - `cli.rs` - Command-line interface and argument parsing
//! 
//! # Example Usage
//! 
//! ```rust,no_run
//! use shadow_crypt::viewing::stream_decrypt_to_viewer;
//! use std::path::Path;
//! 
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let encrypted_file = Path::new("document.txt.shadow");
//! let password = "secure_password".to_string();
//! 
//! stream_decrypt_to_viewer(encrypted_file, password, None)?;
//! # Ok(())
//! # }
//! ```
//! 
//! # Security
//! 
//! Viewing operations provide:
//! - Temporary files created with restrictive permissions (600)
//! - Automatic secure deletion of temporary content after viewing
//! - No persistent decrypted files left on filesystem
//! - Memory-safe handling with automatic zeroization
//! - Read-only access with no modification capabilities

// Core viewing functionality
pub mod streaming_decrypt;
pub mod viewer_integration;
pub mod cli;

// Re-export main functions for convenience
pub use streaming_decrypt::{stream_decrypt_to_viewer, SecureTemporaryFile};
pub use viewer_integration::launch_viewer;