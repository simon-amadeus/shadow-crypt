//! Version management for Shadow file format
//! 
//! This module provides version-specific implementations and dispatch functionality
//! for different Shadow file format versions.

pub mod v1;
pub mod v2;
pub mod detection;
pub mod dispatch;

// Re-export commonly used types
pub use detection::detect_version;
pub use dispatch::AnyHeader;