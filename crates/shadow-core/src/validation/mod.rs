// shadow-core/src/validation/mod.rs
// Generic validation functions (version-agnostic)
// Only contains validation logic that applies across all format versions

pub mod duplicates; // Generic content hash comparison (version-agnostic)
pub mod password;   // Generic password validation (version-agnostic)

// Re-export the generic validation functions
pub use duplicates::{check_content_duplicate, find_duplicate_hashes};
pub use password::{validate_password_format, validate_password_strength};
