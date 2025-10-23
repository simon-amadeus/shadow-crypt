use std::path::PathBuf;

use crate::memory::SecureString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFile {
    pub path: PathBuf,
    pub filename: String,
    pub size: u64,
}

pub struct ValidEncryptionArgs {
    pub files: Vec<InputFile>,
    pub weak_password: bool,
}

pub struct EncryptionInput {
    pub files: Vec<InputFile>,
    pub password: SecureString,
}
impl EncryptionInput {
    pub fn new(files: Vec<InputFile>, password: SecureString) -> Self {
        Self { files, password }
    }
}
