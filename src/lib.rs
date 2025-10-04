//! # Shadow File Encryption Suite
//!
//! A secure, modern file encryption tool using state-of-the-art cryptography.
//! 
//! This rewrite implements clean architecture with domain-driven design,
//! following the specifications in docs/specs/DOMAIN_ARCHITECTURE.md

pub mod domain;
pub mod application;
pub mod infrastructure;

// Re-export commonly used items for easier access
pub use application::workflows::encryption_workflow::EncryptionWorkflow;
pub use infrastructure::terminal::TerminalPasswordRepository;