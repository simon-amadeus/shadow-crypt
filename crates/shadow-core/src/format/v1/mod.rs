// shadow-core/src/format/v1/mod.rs
// V1 format module - contains all v1-specific format code

pub mod constants;
pub mod serialization;
pub mod types;
pub mod validation;

// Re-export main items for convenience
pub use constants::*;
pub use serialization::{deserialize_header, serialize_header};
pub use types::{EncryptedFile, FileHeader, FilenameData};
pub use validation::{validate_file_header, validate_header_bytes};
