//! Secure file editing functionality
//! 
//! This module provides secure in-place editing capabilities for encrypted files
//! with atomic updates and rollback support. It implements the core editing logic
//! used by the `shadowedit` binary for safe content modification.
//! 
//! # Features
//! 
//! - **Atomic file updates** with backup creation and rollback capabilities
//! - **External editor integration** with support for $EDITOR and custom editors
//! - **Change detection** to avoid unnecessary re-encryption of unchanged files
//! - **Secure temporary handling** during the editing process
//! - **Metadata preservation** maintaining file attributes and timestamps
//! 
//! # Architecture
//! 
//! This module follows the standard Shadow use case pattern:
//! - `atomic_updates.rs` - Core atomic update implementation with rollback
//! - `editor_integration.rs` - External editor management and integration
//! - `cli.rs` - Command-line interface and argument parsing
//! 
//! # Example Usage
//! 
//! ```rust,no_run
//! use shadow_crypt::editing::edit_encrypted_file;
//! use std::path::Path;
//! 
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let encrypted_file = Path::new("document.txt.shadow");
//! let password = "secure_password";
//! 
//! edit_encrypted_file(encrypted_file, password, None)?;
//! # Ok(())
//! # }
//! ```
//! 
//! # Security
//! 
//! Editing operations provide:
//! - Atomic updates preventing data loss during editing
//! - Automatic backup creation before modification
//! - Secure temporary files with restrictive permissions (600)
//! - Automatic cleanup of temporary content after editing
//! - Memory-safe handling with automatic zeroization of sensitive data

// Core editing functionality
pub mod atomic_updates;
pub mod editor_integration;
pub mod cli;

// Re-export main functions for convenience
pub use atomic_updates::edit_encrypted_file;
pub use editor_integration::launch_editor;