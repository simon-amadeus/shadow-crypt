// shadow-shell/src/lib.rs
// I/O and CLI utilities for Shadow encryption tool
//
// This crate handles all side effects including file I/O,
// user interaction, CLI parsing, and progress reporting.

pub mod decryption;
pub mod encryption;
pub mod errors;
pub mod listing;
pub mod password;
pub mod ui;
pub mod utils;

// Re-export commonly used items
pub use shadow_core::memory;
pub use shadow_core::profile::SecurityProfile;
pub use ui::{display_error, display_success};
