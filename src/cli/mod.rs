//! # CLI Layer (Binaries)
//!
//! Command-line interface implementations for all Shadow binaries.

pub mod shadow;
pub mod unshadow;
pub mod shadows;
pub mod shadowmigrate;
pub mod errors;

pub use errors::{CliError, CliErrorExt, exit_codes, print_success, print_warning, print_info};