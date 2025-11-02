//! # Shadow Crypt
//!
//! Password-based file encryption with filename obfuscation.
//!
//! ## Features
//!
//! - **Strong Algorithms**: XChaCha20-Poly1305 cipher, Argon2id key derivation
//! - **No Storage**: Sensitive data is retained only in memory during operation
//! - **Memory Safety**: Zeroizes sensitive data in memory after use
//! - **No Dependencies**: Pure Rust implementation
//!
//! ## Command Line Usage
//!
//! This crate provides three command-line tools:
//!
//! - `shadow` - Encrypt files
//! - `unshadow` - Decrypt files  
//! - `shadows` - List encrypted files
//!
//! ## Architecture
//!
//! The implementation is split into two main modules:
//!
//! - [`core`] - Core cryptographic operations and types (deterministic, no I/O)
//! - [`shell`] - Command-line interface and file I/O operations
//!
//! ## Security
//!
//! All sensitive data is automatically zeroized from memory after use. The implementation
//! uses well-established cryptographic primitives and follows security best practices.
//!
//! ## Installation
//!
//! ```bash
//! cargo install shadow-crypt
//! ```
//!
//! ## Examples
//!
//! ### Encrypt Files
//! ```bash
//! shadow file1.txt file*.jpg
//! ```
//!
//! ### Decrypt Files
//! ```bash
//! unshadow mzpuTgQmBPJfTAJh.shadow RzxZGbTQAxxBseaI.shadow
//! ```
//!
//! ### List Encrypted Files
//! ```bash
//! shadows
//! ```

// Re-export the shell crate for unified documentation
/// Main workflows and I/O operations.
#[doc(inline)]
pub use shadow_crypt_shell as shell;

/// Core types and deterministic operations.
#[doc(inline)]
pub use shadow_crypt_core as core;
