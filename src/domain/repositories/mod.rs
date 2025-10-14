//! # Repository Interfaces
//!
//! Abstract interfaces for infrastructure concerns.
//! Note: Shadow follows stateless design - no configuration persistence.

pub mod password_repository;

// Re-export key types for convenience
pub use password_repository::{PasswordRepository, PasswordInputError, PasswordStrength, MockPasswordRepository};