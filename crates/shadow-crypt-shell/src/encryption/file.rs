use std::path::PathBuf;

use shadow_crypt_core::profile::SecurityProfile;

use crate::memory::SecureString;

/// What an encryption work item refers to on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// A single file; its content becomes the encrypted content.
    File,
    /// A directory; its tree is archived into one encrypted file.
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionInputFile {
    pub path: PathBuf,
    /// Stored name: the file's name (possibly a relative path in recursive
    /// mode) or the directory's name for archives.
    pub filename: String,
    pub size: u64,
    pub kind: InputKind,
}

pub struct EncryptionInput {
    pub files: Vec<EncryptionInputFile>,
    pub password: SecureString,
    pub security_profile: SecurityProfile,
    pub output_dir: PathBuf,
    /// Suppress progress and per-file success output (errors still shown).
    pub quiet: bool,
}
impl EncryptionInput {
    pub fn new(
        files: Vec<EncryptionInputFile>,
        password: SecureString,
        security_profile: SecurityProfile,
        output_dir: PathBuf,
        quiet: bool,
    ) -> Self {
        Self {
            files,
            password,
            security_profile,
            output_dir,
            quiet,
        }
    }
}

pub struct EncryptionOutputFile {
    pub path: PathBuf,
    pub filename: String,
}
