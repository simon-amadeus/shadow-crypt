//! # CLI Layer (Binaries)
//!
//! Command-line interface implementations for all Shadow binaries.

pub mod shadow;
pub mod unshadow;
pub mod shadows;
pub mod shadowmigrate;
pub mod shared;
pub mod errors;

pub use shared::{CommonModifyFlags, CommonListFlags, validate_input_patterns, validate_algorithm};