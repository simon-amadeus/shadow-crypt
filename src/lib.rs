//! # Shadow File Encryption Suite
//!
//! A secure, modern file encryption tool using state-of-the-art cryptography.
//! 
//! This implementation uses functional pipeline architecture with vertical slicing,
//! organized by business capabilities rather than technical layers.

// Functional core (new architecture)
pub mod core;

// Functional CLI (new simple CLI)
pub mod cli;

// Legacy modules (temporarily disabled for compilation)
// pub mod domain;
// pub mod application;

// Re-export core functional API
pub use core::{
    EncryptionPipeline, EncryptionOptions, EncryptionReport,
    AlgorithmId, CoreResult, CoreError,
};

// Re-export functional CLI
pub use cli::encryption::{EncryptCommand, parse_encrypt_args, run_encrypt_command};