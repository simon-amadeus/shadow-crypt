//! # Listing Domain Slice
//!
//! Business capability: Discovering and inspecting encrypted files.

pub mod service;
pub mod file_handler;

// Re-export public interface
pub use service::{
    ListingService,
    ListingOptions,
    FileInfo,
    DirectoryListing,
    ListingResult,
};

pub use file_handler::{
    ListingFileHandler,
    ListingFileResult,
};