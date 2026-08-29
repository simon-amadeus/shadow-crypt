//! # Shadow Crypt Core
//!
//! Core layer for shadow_crypt providing types and deterministic operations without side effects.
//!
//! This crate implements version-specific file format and encryption.
//! Algorithm choices may differ across versions.

/// Supported encryption algorithms.
pub mod algorithm;

/// Error types for cryptographic operations.
pub mod errors;

/// Version-independent file types shared by all format versions.
pub mod file;

/// Secure memory management with automatic zeroization of sensitive data.
pub mod memory;

/// Security profiles for different operational contexts.
pub mod profile;

/// Progress tracking utilities for long-running operations.
pub mod progress;

/// Reporting structures for encryption and decryption operations.
pub mod report;

/// Version 1 implementation of the encryption protocol
///
/// Uses XChaCha20-Poly1305 with Argon2id key derivation.
pub mod v1;

/// Version 2 implementation of the encryption protocol
///
/// Same algorithms as v1, but authenticates the header via associated data
/// with domain separation between filename and content encryption.
pub mod v2;

/// Version-erased reading of shadow files across all format versions.
pub mod vault;

/// Version management for encryption formats.
pub mod version;
