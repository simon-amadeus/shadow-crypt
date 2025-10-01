//! Shadow file format Version 1 implementation
//! 
//! This module contains all Version 1 specific code including header format,
//! filename authentication, and crypto integration.

pub mod header;
pub mod filename_auth;

// Re-export key types for easier access
pub use header::Header;
pub use filename_auth::{compute_filename_auth_tag, verify_filename_auth_tag, extract_filename_for_auth};