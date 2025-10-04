//! # Repository Interfaces
//!
//! Abstract interfaces for infrastructure concerns.
//! Note: Shadow follows stateless design - no configuration persistence.

pub mod file_repository;
pub mod password_repository;

// Re-export key types for convenience
pub use file_repository::{FileRepository, FileMetadata, FileType, MockFileRepository};
pub use password_repository::{PasswordRepository, PasswordInputError, PasswordStrength, MockPasswordRepository};