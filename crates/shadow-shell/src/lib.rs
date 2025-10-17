// shadow-shell/src/lib.rs
// I/O and CLI utilities for Shadow encryption tool
//
// This crate handles all side effects including file I/O,
// user interaction, CLI parsing, and progress reporting.

pub mod cli_helpers;
pub mod encryption;
pub mod errors;
pub mod file_ops;
pub mod ui;

// Re-export commonly used items
pub use cli_helpers::{confirm_overwrite, parse_glob_patterns, prompt_for_password};
pub use errors::ShellError;
pub use file_ops::{read_file_safely, validate_input_paths, write_file_atomically};
pub use ui::{display_error, display_progress, display_success};

// Re-export encryption module for convenient access
pub use encryption::{
    EncryptionArgs, parse_args, parse_args_from_matches, run_encryption,
    process_single_file, write_encrypted_file, check_for_duplicate_content,
    EncryptionError,
};

// Re-export core types for convenience
pub use shadow_core::{
    CryptoError, SecureKey, SecureString, SerializationError, ValidationError,
};
pub use shadow_core::v1::{FileHeader, FilenameData};
