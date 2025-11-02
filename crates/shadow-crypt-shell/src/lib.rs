//! # ⚠️ INTERNAL CRATE - NOT FOR PUBLIC USE
//!
//! This is an implementation detail of the `shadow-crypt` CLI binary.
//! No stability or API guarantees. Direct dependency may break without notice.
//! For audits/reviews: See full workspace docs at https://docs.rs/shadow-crypt.
//! Use the CLI: `cargo install shadow-crypt`.
//! 
//! 
//! # Shadow Crypt Shell
//!
//! Shell layer for shadow_crypt, handling main workflows and I/O operations.
//!
//! This crate provides the interface layer between the command-line interface and filesystem operations,
//! building on [`shadow_crypt_core`] to offer secure file encryption and decryption with filename obfuscation.
//! It manages I/O to keep the core library focused on deterministic types and operations.
//!
//! Modules are vertically sliced to separate concerns like encryption, decryption and listing.

/// Specific workflow and operations for encryption.
pub mod encryption;

/// Specific workflow and operations for decryption.
pub mod decryption;

/// Shared error types.
pub mod errors;

/// Specific workflow and operations for listing encrypted files.
pub mod listing;

/// Shared password handling utilities.
pub mod password;

/// Shared user interface utilities for displaying progress and results.
pub mod ui;

/// Shared utility functions for file operations and data parsing.
pub mod utils;

// Re-export commonly used items
pub use shadow_crypt_core::memory;
pub use shadow_crypt_core::profile::SecurityProfile;
pub use ui::{display_error, display_success};
