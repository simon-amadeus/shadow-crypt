//! Secure file viewing functionality
//! 
//! This module contains everything needed for the `cryptview` binary:
//! - Streaming decryption to secure temporary files
//! - Integration with external viewers ($PAGER, etc.)
//! - Secure temporary file handling with cleanup
//! - Memory protection and secure deletion

// Core viewing functionality
pub mod streaming_decrypt;
pub mod viewer_integration;
pub mod cli;

// Re-export main functions for convenience
pub use streaming_decrypt::{stream_decrypt_to_viewer, SecureTemporaryFile};
pub use viewer_integration::launch_viewer;