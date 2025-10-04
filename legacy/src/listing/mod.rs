//! File listing functionality
//! 
//! This module provides comprehensive encrypted file discovery and metadata display
//! capabilities for the Shadow cryptographic file manager. It implements the core
//! listing logic used by the `shadows` binary for file scanning and visualization.
//! 
//! # Features
//! 
//! - **Directory scanning** for encrypted files with pattern matching
//! - **Metadata extraction** from file headers without full decryption
//! - **Original filename display** with secure header parsing
//! - **Beautiful UI formatting** with colors, grids, and visual hierarchy
//! - **Performance optimization** for large directory structures
//! 
//! # Architecture
//! 
//! This module follows the standard Shadow use case pattern:
//! - `file_scanner.rs` - Core file discovery and metadata extraction
//! - `ui_formatter.rs` - Output formatting and display logic
//! - `modern_grid.rs` - Grid-based layout system
//! - `cli.rs` - Command-line interface and argument parsing
//! 
//! # Example Usage
//! 
//! ```rust,no_run
//! use shadow_crypt::listing::{list_encrypted_files, UIFormatter};
//! use std::path::Path;
//! 
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let directory = Path::new("./encrypted_files");
//! let password = "secure_password";
//! let files = list_encrypted_files(directory, password)?;
//! 
//! let formatter = UIFormatter::new();
//! let output = formatter.format_file_listing(&files);
//! println!("{}", output);
//! # Ok(())
//! # }
//! ```
//! 
//! # Security
//! 
//! File listing operations provide:
//! - Read-only access to encrypted files (no decryption or modification)
//! - Safe header parsing with validation and error handling
//! - No exposure of sensitive file contents or encryption keys
//! - Tamper detection through header integrity verification

// Core listing functionality
pub mod cli;
pub mod file_scanner;
pub mod ui_formatter;
pub mod modern_grid;

// Export main functionality from sub-modules
pub use file_scanner::{list_encrypted_files, FileInfo};
pub use ui_formatter::UIFormatter;