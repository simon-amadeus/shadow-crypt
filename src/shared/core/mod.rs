//! Core shared utilities for the Shadow encryption system
//! 
//! This module contains truly shared functionality that is used across
//! all versions and algorithms without any domain-specific logic.

pub mod errors;
pub mod file_detection;
pub mod secure_delete;
pub mod crypto;

// Re-export commonly used types for convenience
pub use errors::{CryptoError, Result};