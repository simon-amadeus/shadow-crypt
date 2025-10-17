// shadow-core/src/validation/mod.rs
// Organized validation functions with improved cohesion
// Validation functions grouped by what they validate

pub mod duplicates;
pub mod entropy; // Professional entropy analysis and validation
pub mod file_data; // File content and metadata validation
pub mod header; // File header structure validation
pub mod password; // Password format validation (basic structure) // Duplicate detection and comparison

// Re-export the main validation functions
pub use duplicates::{check_content_duplicate, find_duplicate_hashes};
pub use entropy::validate_password_entropy;
pub use file_data::{validate_file_content, validate_file_metadata};
pub use header::{validate_file_header, validate_header_bytes};
pub use password::{validate_password_format, validate_password_strength};
