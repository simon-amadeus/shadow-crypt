// shadow-core/src/format/mod.rs
// Shadow file format handling
// Currently supports version 1.0

// Version-specific modules
pub mod v1; // Version 1.0 implementation

// Re-export v1 as the current format
pub use v1::*;
