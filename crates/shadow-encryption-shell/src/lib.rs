// shadow-encryption-shell/src/lib.rs
// Encryption I/O and CLI - imperative shell with side effects
// Depends on shadow-core + shadow-shell + shadow-encryption-core per architecture

pub mod cli;
pub mod file_ops;
pub mod runner;

// Re-export main items for convenient access
pub use cli::{EncryptionArgs, parse_args};
pub use file_ops::{process_single_file, write_encrypted_file};
pub use runner::run_encryption;

// Re-export UI utilities for error handling in main binary
pub use shadow_shell::{ShellError, display_error};
