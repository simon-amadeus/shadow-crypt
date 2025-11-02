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

/// Version management for encryption formats.
pub mod version;
