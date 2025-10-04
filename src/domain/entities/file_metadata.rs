//! # FileMetadata Entity
//!
//! Represents file system metadata and attributes.
//! Based on specs/DOMAIN_ARCHITECTURE.md

use std::time::SystemTime;

/// Represents file system metadata and attributes
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub original_filename: String,
    pub file_size: u64,
    pub modified_time: SystemTime,
    pub created_time: Option<SystemTime>,
    pub file_type: FileType,
}

/// Type of file system entity
#[derive(Debug, Clone)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Other,
}