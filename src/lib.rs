//! Shadow Crypt - Secure file encryption with obfuscation
//! 
//! This crate provides secure file encryption with optional filename obfuscation.
//! Built with a functional core / imperative shell architecture.

// Simple re-export of the main functionality
pub use shadow_encryption_shell::*;

/// Version of the shadow-crypt package
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Package name
pub const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
