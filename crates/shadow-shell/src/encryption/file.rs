use std::path::PathBuf;

use shadow_core::profile::SecurityProfile;

use crate::memory::SecureString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFile {
    pub path: PathBuf,
    pub filename: String,
    pub size: u64,
}

pub struct EncryptionInput {
    pub files: Vec<InputFile>,
    pub password: SecureString,
    pub security_profile: SecurityProfile,
}
impl EncryptionInput {
    pub fn new(
        files: Vec<InputFile>,
        password: SecureString,
        security_profile: SecurityProfile,
    ) -> Self {
        Self {
            files,
            password,
            security_profile,
        }
    }
}

pub struct OutputFile {
    pub path: PathBuf,
    pub filename: String,
}
