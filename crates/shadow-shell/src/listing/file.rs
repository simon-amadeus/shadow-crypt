use std::path::PathBuf;

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

pub struct ShadowFile {
    pub path: PathBuf,
}
impl ShadowFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}
