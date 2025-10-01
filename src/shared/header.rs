//! File header format - main interface
//! 
//! This module provides the main interface for file header operations,
//! re-exporting from the decomposed modules for backward compatibility.

// Re-export all the separated components
pub use crate::shared::metadata::{FileMetadata, CompressionType};
pub use crate::shared::algorithms::{
    AlgorithmId, VersionInfo, CURRENT_VERSION, MIN_SUPPORTED_VERSION, 
    MAX_SUPPORTED_VERSION, MAX_FILENAME_LENGTH, MAX_DIRECTORY_PATH_LENGTH, 
    MAX_METADATA_LENGTH
};
pub use crate::shared::header_core::Header;

// This maintains the existing public API while the implementation
// is now properly decomposed into focused, single-responsibility modules:
//
// - metadata.rs: File metadata handling and serialization  
// - algorithms.rs: Algorithm identification and versioning
// - header_core.rs: Main Header struct and serialization logic
//
// This refactoring reduces file sizes and improves maintainability
// while preserving all existing functionality and APIs.