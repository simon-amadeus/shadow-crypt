//! # Encryption Vertical Slice
//!
//! Complete encryption workflow functionality including pipeline orchestration,
//! job management, and validation. This vertical slice encapsulates all
//! encryption-related business logic.
//!
//! ## Organization
//!
//! - `pipeline.rs` - Main encryption pipeline orchestration
//! - `jobs.rs` - Encryption job creation and management  
//! - `validation.rs` - Input validation and preprocessing
//! - `types.rs` - Encryption-specific types and data structures

pub mod types;
pub mod pipeline;
pub mod jobs;
pub mod validation;

// Re-export commonly used types
pub use types::{EncryptionOptions, EncryptionJob, EncryptionResult, EncryptionReport};
pub use pipeline::EncryptionPipeline;