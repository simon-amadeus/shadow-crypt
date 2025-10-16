// shadow-core/src/format/v1/mod.rs
// V1 format module - contains all v1-specific format code

pub mod types;
pub mod constants;
pub mod serialization;
pub mod validation;

// Re-export main items for convenience
pub use types::{FileHeader, FilenameData, EncryptedFile};
pub use constants::*;
pub use serialization::{serialize_header, deserialize_header};
pub use validation::{validate_file_header, validate_header_bytes};