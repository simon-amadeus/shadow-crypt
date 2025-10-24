use std::path::PathBuf;

use crate::memory::SecureString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionInputFile {
    pub path: PathBuf,
    pub filename: String,
    pub size: u64,
}

pub struct DecryptionInput {
    pub files: Vec<DecryptionInputFile>,
    pub password: SecureString,
}
impl DecryptionInput {
    pub fn new(files: Vec<DecryptionInputFile>, password: SecureString) -> Self {
        Self { files, password }
    }
}

pub struct DecryptionOutputFile {
    pub path: PathBuf,
    pub filename: String,
}
