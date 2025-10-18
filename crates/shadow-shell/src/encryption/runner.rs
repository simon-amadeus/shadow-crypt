// shadow-shell/src/encryption/runner.rs
// Main encryption workflow runner
// Side effects: coordinates file I/O, user interaction, and progress display

use shadow_core::memory::SecureString;

use super::cli::EncryptionArgs;
use super::file_ops::process_single_file;
use crate::{display_progress, display_success};
use std::path::PathBuf;

/// Main encryption runner - coordinates the entire encryption workflow
/// Side effects: file I/O, user interaction, progress display
pub fn run_encryption(args: EncryptionArgs) -> Result<(), EncryptionError> {
    // 1. Validate input files exist and are readable (I/O side effect)
    let validated_inputs = validate_inputs(&args.input_files)?;

    // 2. Duplicate content checking is now handled per-file during processing

    // 3. Get password from user (user interaction side effect)
    let password = get_encryption_password(args.allow_weak_password)?;

    // 4. Process each file
    let mut processed_files = Vec::new();
    for (i, input_path) in validated_inputs.iter().enumerate() {
        if !args.quiet {
            display_progress(
                (i + 1) as u64,
                validated_inputs.len() as u64,
                "Encrypting files",
            );
        }

        match process_single_file(input_path, &password, args.obfuscate, args.force, args.keep) {
            Ok(output_path) => {
                processed_files.push((input_path.clone(), output_path));
                if !args.quiet {
                    display_success(&format!(
                        "Encrypted: {} -> {}",
                        input_path.display(),
                        processed_files
                            .last()
                            .unwrap()
                            .1
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                    ));
                }
            }
            Err(e) => {
                // Handle different error types appropriately
                match e {
                    EncryptionError::Shell(shell_error) => {
                        // Return the structured shell error directly (don't display here)
                        return Err(EncryptionError::Shell(shell_error));
                    }
                    other_error => {
                        // For other encryption-specific errors, return directly
                        return Err(other_error);
                    }
                }
            }
        }
    }

    // 5. Display summary
    if !args.quiet {
        display_success(&format!(
            "Successfully encrypted {} file{}",
            processed_files.len(),
            if processed_files.len() == 1 { "" } else { "s" }
        ));
    }

    Ok(())
}

/// Validate that input files exist and are readable
/// Side effect: file system checks
fn validate_inputs(input_files: &[PathBuf]) -> Result<Vec<PathBuf>, EncryptionError> {
    let mut validated = Vec::new();

    for path in input_files {
        if !path.exists() {
            return Err(EncryptionError::FileNotFound(path.clone()));
        }
        if !path.is_file() {
            return Err(EncryptionError::NotAFile(path.clone()));
        }
        validated.push(path.clone());
    }

    Ok(validated)
}

/// Get encryption password from user
/// Side effect: user interaction via stdin/stdout
fn get_encryption_password(allow_weak_passwords: bool) -> Result<SecureString, EncryptionError> {
    match prompt_for_password(allow_weak_passwords) {
        Ok(password) => Ok(password),
        Err(e) => Err(EncryptionError::UserInput(e.to_string())),
    }
}

// ApplicationError is now unified as EncryptionError in parent module

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_inputs_success() {
        let temp_dir = TempDir::new().unwrap();
        let test_file1 = temp_dir.path().join("test1.txt");
        let test_file2 = temp_dir.path().join("test2.txt");

        fs::write(&test_file1, b"content1").unwrap();
        fs::write(&test_file2, b"content2").unwrap();

        let result = validate_inputs(&[test_file1, test_file2]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_validate_inputs_file_not_found() {
        let nonexistent = PathBuf::from("nonexistent.txt");
        let result = validate_inputs(&[nonexistent.clone()]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::FileNotFound(path) if path == nonexistent
        ));
    }

    #[test]
    fn test_validate_inputs_not_a_file() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().to_path_buf();

        let result = validate_inputs(&[dir_path.clone()]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::NotAFile(path) if path == dir_path
        ));
    }
}
