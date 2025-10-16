// shadow-core/src/validation/mod.rs
// Organized validation functions with improved cohesion
// Validation functions grouped by what they validate

pub mod password;       // Password format validation (basic structure)
pub mod entropy;        // Professional entropy analysis and validation
pub mod file_data;      // File content and metadata validation 
pub mod header;         // File header structure validation
pub mod duplicates;     // Duplicate detection and comparison

// Re-export the main validation functions
pub use password::{validate_password_format, validate_password_strength};
pub use entropy::validate_password_entropy;
pub use file_data::{validate_file_content, validate_file_metadata, validate_encryption_request};
pub use header::{validate_file_header, validate_header_bytes};
pub use duplicates::{check_content_duplicate, find_duplicate_hashes};