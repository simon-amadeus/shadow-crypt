//! Secure file editing functionality
//! 
//! This module contains everything needed for the `cryptedit` binary:
//! - Atomic file updates with backup/rollback
//! - Integration with external editors ($EDITOR, etc.)
//! - Secure temporary file handling during editing
//! - Change detection and re-encryption

// Core editing functionality
pub mod atomic_updates;
pub mod editor_integration;
pub mod cli;

// Re-export main functions for convenience
pub use atomic_updates::edit_encrypted_file;
pub use editor_integration::launch_editor;