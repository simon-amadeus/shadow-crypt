//! # Listing Domain Slice
//!
//! Business capability: Discovering and inspecting encrypted files.

pub mod service;

// Re-export public interface
pub use service::{
    ListingService,
    ListingOptions,
    FileInfo,
    DirectoryListing,
    ListingResult,
};