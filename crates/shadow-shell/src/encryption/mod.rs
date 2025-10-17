// shadow-shell/src/encryption/mod.rs
// Encryption module - CLI and I/O operations for encryption
// Side effects: file I/O, user interaction, CLI parsing

use std::path::PathBuf;
use crate::ShellError;
use shadow_core::{SerializationError};
use shadow_core::v1::FileOperationError;

pub mod cli;
pub mod file_ops;
pub mod runner;

/// Unified error type for all encryption operations
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    #[error("Not a file: {0}")]
    NotAFile(PathBuf),

    #[error("Shell error: {0}")]
    Shell(#[from] ShellError),

    #[error("File operation error: {0}")]
    FileOperation(#[from] FileOperationError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid shadow file format: {0}")]
    InvalidShadowFile(PathBuf),

    #[error("User input error: {0}")]
    UserInput(String),
}

// Re-export main items for convenient access
pub use cli::{EncryptionArgs, parse_args, parse_args_from_matches};
pub use file_ops::{
    process_single_file, write_encrypted_file, check_for_duplicate_content,
};
pub use runner::run_encryption;