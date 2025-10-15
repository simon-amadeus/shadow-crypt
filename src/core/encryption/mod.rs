//! Encryption vertical slice - encryption workflow functionality.

pub mod types;
pub mod pipeline;
pub mod jobs;
pub mod validation;

// Re-export commonly used types
pub use types::{EncryptionOptions, EncryptionJob, EncryptionResult, EncryptionReport};
pub use pipeline::EncryptionPipeline;