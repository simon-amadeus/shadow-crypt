// shadow-shell/src/lib.rs
// I/O and CLI utilities for Shadow encryption tool
//
// This crate handles all side effects including file I/O,
// user interaction, CLI parsing, and progress reporting.

pub mod encryption;
pub mod errors;
pub mod key;
pub mod ui;

// Re-export commonly used items
pub use shadow_core::{encryption::input::EncryptionInput, memory};
pub use ui::{display_error, display_progress, display_success};
