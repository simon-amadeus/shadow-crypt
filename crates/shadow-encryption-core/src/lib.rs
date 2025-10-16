// shadow-encryption-core/src/lib.rs
// Pure encryption business logic - functional core with no I/O
// Depends only on shadow-core per architecture strategy

pub mod types;
pub mod pipeline;
pub mod validation;

// Re-export main items for convenient access
pub use types::{EncryptionRequest, EncryptedFile};
pub use pipeline::encrypt_file;
pub use validation::validate_encryption_request;