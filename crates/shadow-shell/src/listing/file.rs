use std::path::PathBuf;

use shadow_core::version::Version;

use crate::memory::SecureString;

pub struct ListingInput {
    pub password: SecureString,
    pub work_dir: PathBuf,
}
impl ListingInput {
    pub fn new(password: SecureString, work_dir: PathBuf) -> Self {
        Self { password, work_dir }
    }
}

#[derive(Debug)]
pub struct ShadowFile {
    pub path: PathBuf,
    pub filename: String,
    pub version: Version,
    /// Size of the file in bytes
    pub size: u64,
}
impl ShadowFile {
    pub fn new(path: PathBuf, filename: String, version: Version, size: u64) -> Self {
        Self {
            path,
            filename,
            version,
            size,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShadowFileInfo {
    pub original_filename: Option<SecureString>,
    pub obfuscated_filename: String,
    pub version: Version,
    pub size: u64,
}
impl ShadowFileInfo {
    pub fn new(
        original_filename: Option<SecureString>,
        obfuscated_filename: String,
        version: Version,
        size: u64,
    ) -> Self {
        Self {
            original_filename,
            obfuscated_filename,
            version,
            size,
        }
    }
}

pub struct FileInfoList {
    pub items: Vec<ShadowFileInfo>,
}
impl FileInfoList {
    pub fn new(items: Vec<ShadowFileInfo>) -> Self {
        Self { items }
    }
}
