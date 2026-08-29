//! Shared helpers for the integration tests.
//!
//! Each test file compiles as its own crate and uses only a subset of these.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use shadow_crypt_shell::{
    SecurityProfile,
    decryption::{
        cli::DecryptionCliArgs, file::DecryptionInput,
        validation::validate_input as validate_decryption_input,
        workflow::run_workflow as run_decryption_workflow,
    },
    encryption::{
        cli::EncryptionCliArgs, file::EncryptionInput,
        validation::validate_input as validate_encryption_input,
        workflow::run_workflow as run_encryption_workflow,
    },
    errors::WorkflowResult,
    memory::SecureString,
};

/// Password used by the integration tests and the committed fixtures.
/// DO NOT CHANGE: the files under tests/fixtures are encrypted with it.
pub const TEST_PASSWORD: &str = "testpassword";

/// Encrypts `files` into `output_dir` through the full validation + workflow
/// path, using the test security profile.
pub fn encrypt_files(files: &[&Path], password: &str, output_dir: &Path) -> WorkflowResult<()> {
    let cli_args = EncryptionCliArgs {
        input_files: files
            .iter()
            .map(|path| path.to_str().unwrap().to_string())
            .collect(),
        test_mode: true,
        ..Default::default()
    };
    let valid_args = validate_encryption_input(cli_args)?;
    run_encryption_workflow(EncryptionInput::new(
        valid_args.files,
        SecureString::new(password.to_string()),
        SecurityProfile::Test,
        output_dir.to_path_buf(),
    ))
}

/// Decrypts `files` into `output_dir` through the full validation + workflow
/// path.
pub fn decrypt_files(files: &[&Path], password: &str, output_dir: &Path) -> WorkflowResult<()> {
    let cli_args = DecryptionCliArgs {
        input_files: files
            .iter()
            .map(|path| path.to_str().unwrap().to_string())
            .collect(),
        ..Default::default()
    };
    let valid_args = validate_decryption_input(cli_args)?;
    run_decryption_workflow(DecryptionInput::new(
        valid_args.files,
        SecureString::new(password.to_string()),
        output_dir.to_path_buf(),
        false,
    ))
}

/// Returns all `.shadow` files in `dir`.
pub fn find_shadow_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "shadow"))
        .collect()
}

/// Returns the single `.shadow` file in `dir`, panicking if there is not
/// exactly one.
pub fn find_single_shadow_file(dir: &Path) -> PathBuf {
    let mut files = find_shadow_files(dir);
    assert_eq!(
        files.len(),
        1,
        "expected exactly one .shadow file in {dir:?}"
    );
    files.remove(0)
}
