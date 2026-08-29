//! # Shadow Crypt
//!
//! Password-based file encryption with filename obfuscation.
//!
//! `shadow` turns files and directories into anonymously named `.shadow`
//! containers. `unshadow` restores them. `shadows` lists them.
//!
//! ## Features
//!
//! - **Strong cryptography**: XChaCha20-Poly1305 authenticated encryption,
//!   Argon2id key derivation
//! - **Metadata encrypted**: filenames, timestamps, and permissions travel
//!   inside an encrypted metadata envelope; a directory becomes a single
//!   archive that hides even its file count and sizes
//! - **Tamper-evident**: headers are bound to the ciphertext as AEAD
//!   associated data; chunk counters make reordering and truncation fail
//! - **Any size**: streaming encryption and decryption with bounded memory
//! - **Pure Rust**: no C or system libraries
//!
//! ## Command line usage
//!
//! ```bash
//! shadow notes.txt photos/     # encrypt files and directories
//! unshadow mzpuTgQmBPJfTAJh.shadow
//! shadows                      # list .shadow files with original names
//! ```
//!
//! See the repository's `docs/FORMAT.md` for the file format specification
//! and `docs/THREAT_MODEL.md` for the threat model.
//!
//! ## Architecture
//!
//! - [`core`] - Core cryptographic operations and types (deterministic, no I/O)
//! - [`shell`] - Command-line interface and file I/O operations

// Re-export the shell crate for unified documentation
/// Main workflows and I/O operations.
#[doc(inline)]
pub use shadow_crypt_shell as shell;

/// Core types and deterministic operations.
#[doc(inline)]
pub use shadow_crypt_core as core;
