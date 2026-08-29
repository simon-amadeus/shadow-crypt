use std::path::PathBuf;

use shadow_crypt_core::version::Version;

use crate::memory::SecureString;

pub struct ListingInput {
    /// Password for decrypting original filenames; `None` lists only the
    /// plaintext header metadata without any key derivation.
    pub password: Option<SecureString>,
    pub work_dir: PathBuf,
    /// Print the listing as JSON instead of a table.
    pub json: bool,
}
impl ListingInput {
    pub fn new(password: Option<SecureString>, work_dir: PathBuf, json: bool) -> Self {
        Self {
            password,
            work_dir,
            json,
        }
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
