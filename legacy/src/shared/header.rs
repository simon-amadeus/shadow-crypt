//! File header format - main interface
//! 
//! This module provides the main interface for file header operations,
//! using the current V3 header system.

// Re-export all the header components
pub use crate::shared::metadata::{FileMetadata, CompressionType};
pub use crate::shared::algorithms::{
    AlgorithmId, VersionInfo, CURRENT_VERSION, MIN_SUPPORTED_VERSION, 
    MAX_SUPPORTED_VERSION, MAX_FILENAME_LENGTH, MAX_DIRECTORY_PATH_LENGTH, 
    MAX_METADATA_LENGTH
};

// Use V3 header as the current header implementation
pub use crate::shared::versions::v3::HeaderV3 as Header;
pub use crate::shared::versions::{AnyHeader, detect_version};

// This provides a clean interface using the current V3 header system
// while maintaining API compatibility for the rest of the codebase.