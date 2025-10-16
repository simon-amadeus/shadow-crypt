// shadow-core/src/format/mod.rs
// Unified file format handling - all format logic in one cohesive module
// This module owns the Shadow file format specification and all related operations

pub mod constants;      // Format constants and version info
pub mod types;          // Format-specific types and structures  
pub mod serialization;  // Binary serialization/deserialization
pub mod validation;     // Format structure validation
pub mod versioning;     // Format version handling and migration

// Re-export the main API for file format operations
pub use constants::*;
pub use types::{ShadowHeader, ShadowFile, FilenameEncoding};
pub use serialization::{serialize_shadow_file, deserialize_shadow_file};
pub use validation::{validate_shadow_format, validate_header_structure};
pub use versioning::{FormatVersion, check_compatibility};