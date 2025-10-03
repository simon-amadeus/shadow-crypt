//! Version management for Shadow file format
//! 
//! This module provides version-specific implementations and dispatch functionality
//! for different Shadow file format versions.

pub mod v1;
pub mod v2;
pub mod v3;
pub mod detection;
pub mod dispatch;

// Proof of concept for V3 design
pub mod v3_tlv_poc;

// Re-export commonly used types
pub use detection::detect_version;
pub use dispatch::AnyHeader;
pub use v3::HeaderV3;