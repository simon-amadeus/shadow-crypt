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
    pub output_dir: PathBuf,
    /// Overwrite existing output files instead of failing.
    pub force: bool,
    /// Suppress progress and per-file success output (errors still shown).
    pub quiet: bool,
}
impl DecryptionInput {
    pub fn new(
        files: Vec<DecryptionInputFile>,
        password: SecureString,
        output_dir: PathBuf,
        force: bool,
        quiet: bool,
    ) -> Self {
        Self {
            files,
            password,
            output_dir,
            force,
            quiet,
        }
    }
}

pub struct DecryptionOutputFile {
    pub path: PathBuf,
    pub filename: String,
}
