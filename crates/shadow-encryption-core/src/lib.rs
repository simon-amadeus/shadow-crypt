// shadow-encryption-core/src/lib.rs
// Pure encryption business logic - functional core with no I/O
// Depends only on shadow-core per architecture strategy

pub mod pipeline;
pub mod types;
pub mod validation;

// Re-export main items for convenient access
pub use pipeline::encrypt_file;
pub use types::{EncryptedFile, EncryptionRequest};
pub use validation::validate_encryption_request;
