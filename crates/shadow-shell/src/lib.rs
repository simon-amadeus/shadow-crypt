// shadow-shell/src/lib.rs
// I/O and CLI utilities for Shadow encryption tool
//
// This crate handles all side effects including file I/O,
// user interaction, CLI parsing, and progress reporting.

pub mod file_ops;
pub mod cli_helpers;
pub mod ui;
pub mod errors;

// Re-export commonly used items
pub use file_ops::{
    read_file_safely, write_file_atomically,
    scan_shadow_files, validate_input_paths
};
pub use cli_helpers::{
    parse_glob_patterns, prompt_for_password,
    confirm_overwrite
};
pub use ui::{
    display_progress, display_error, display_success,
    display_warning, display_info
};
pub use errors::ShellError;

// Re-export core types for convenience
pub use shadow_core::{
    SecureString, SecureKey, FileHeader, FilenameData,
    CryptoError, ValidationError, SerializationError
};