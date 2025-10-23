use std::path::PathBuf;

use crate::memory::SecureString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFile {
    pub path: PathBuf,
    pub filename: String,
    pub size: u64,
}

pub struct DecryptionInput {
    pub files: Vec<InputFile>,
    pub password: SecureString,
}
impl DecryptionInput {
    pub fn new(files: Vec<InputFile>, password: SecureString) -> Self {
        Self { files, password }
    }
}

pub struct OutputFile {
    pub path: PathBuf,
    pub filename: String,
}
