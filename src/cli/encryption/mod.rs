//! Simplified CLI module for the functional pipeline.

pub mod commands;
pub mod runner;

pub use commands::{EncryptCommand, parse_encrypt_args};
pub use runner::run_encrypt_command;