//! High-security file encryption library
//! 
//! This library provides a comprehensive file encryption system with:
//! - AES-256-GCM authenticated encryption
//! - Reversible filename obfuscation
//! - Secure memory handling with automatic zeroization
//! - Vertical slicing architecture with separate binaries for each use case
//! 
//! # Binaries
//! 
//! - `lock`: File and directory encryption
//! - `unlock`: File and directory decryption
//! - `cryptls`: List encrypted files with original names
//! - `cryptview`: Securely view encrypted files
//! - `cryptedit`: Securely edit encrypted files
//! 
//! # Architecture
//! 
//! The codebase is organized using vertical slicing by use case, with each
//! binary having its own module containing all necessary functionality.
//! Common cryptographic primitives and utilities are shared through the
//! `shared` module.

// Public modules for use cases (these contain everything needed for each binary)
pub mod encryption;
pub mod decryption;
pub mod listing;
pub mod viewing;
pub mod editing;

// Shared functionality used across all use cases
pub mod shared;

// Re-export commonly used types for convenience
pub use shared::{CryptoError, Header, AlgorithmId};
pub use shared::crypto::{SecretVec, KeyMaterial};