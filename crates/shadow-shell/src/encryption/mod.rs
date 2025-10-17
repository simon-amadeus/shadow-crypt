// shadow-shell/src/encryption/mod.rs
// Encryption module - CLI and I/O operations for encryption
// Side effects: file I/O, user interaction, CLI parsing

pub mod cli;
pub mod file_ops;
pub mod runner;

// Re-export main items for convenient access
pub use cli::{EncryptionArgs, parse_args, parse_args_from_matches};
pub use file_ops::{
    process_single_file, write_encrypted_file, check_for_duplicate_content, EncryptionFileError,
};
pub use runner::{run_encryption, ApplicationError};