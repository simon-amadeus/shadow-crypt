//! # Infrastructure Layer (I/O)
//!
//! External system integrations and implementations.

pub mod crypto;
pub mod file_system;
pub mod terminal;
pub mod tlv_serialization;
pub mod errors;

pub use errors::{InfrastructureError, InfrastructureResult};

// Re-export standard repository implementations
pub use file_system::StandardFileRepository;
pub use terminal::StandardPasswordRepository;