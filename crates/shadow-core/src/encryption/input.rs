use std::path::PathBuf;

use crate::memory::SecureString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptableFile {
    pub path: PathBuf,
}

pub struct ValidEncryptionArgs {
    pub files: Vec<EncryptableFile>,
    pub weak_password: bool,
}

pub struct EncryptionInput {
    pub files: Vec<EncryptableFile>,
    pub password: SecureString,
}
impl EncryptionInput {
    pub fn new(files: Vec<EncryptableFile>, password: SecureString) -> Self {
        Self { files, password }
    }
}
