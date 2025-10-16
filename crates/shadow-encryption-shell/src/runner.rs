// shadow-encryption-shell/src/runner.rs
// Main encryption workflow runner
// Side effects: coordinates file I/O, user interaction, and progress display

use std::path::{Path, PathBuf};
use shadow_core::SecureString;
use shadow_shell::{prompt_for_password, display_progress, display_success, ShellError};
use crate::cli::EncryptionArgs;
use crate::file_ops::{process_single_file, check_for_duplicate_content, EncryptionFileError};

/// Main encryption runner - coordinates the entire encryption workflow
/// Side effects: file I/O, user interaction, progress display
pub fn run_encryption(args: EncryptionArgs) -> Result<(), ApplicationError> {
    // 1. Validate input files exist and are readable (I/O side effect)
    let validated_inputs = validate_inputs(&args.input_files)?;
    
    // 2. Check for duplicate content if not forcing (I/O side effect)
    if !args.force {
        check_for_duplicates(&validated_inputs)?;
    }
    
    // 3. Get password from user (user interaction side effect)
    let password = get_encryption_password(args.allow_weak_password)?;
    
    // 4. Process each file
    let mut processed_files = Vec::new();
    for (i, input_path) in validated_inputs.iter().enumerate() {
        if !args.quiet {
            display_progress((i + 1) as u64, validated_inputs.len() as u64, "Encrypting files");
        }
        
        match process_single_file(
            input_path,
            &password,
            args.obfuscate,
            args.force,
            args.keep,
        ) {
            Ok(output_path) => {
                processed_files.push((input_path.clone(), output_path));
                if !args.quiet {
                    display_success(&format!(
                        "Encrypted: {} -> {}",
                        input_path.display(),
                        processed_files.last().unwrap().1.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                    ));
                }
            }
            Err(e) => {
                eprintln!("Error processing {}: {}", input_path.display(), e);
                return Err(ApplicationError::FileOperation(e));
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
fn validate_inputs(input_files: &[PathBuf]) -> Result<Vec<PathBuf>, ApplicationError> {
    let mut validated = Vec::new();
    
    for path in input_files {
        if !path.exists() {
            return Err(ApplicationError::FileNotFound(path.clone()));
        }
        if !path.is_file() {
            return Err(ApplicationError::NotAFile(path.clone()));
        }
        validated.push(path.clone());
    }
    
    Ok(validated)
}

/// Check for duplicate content in target directories
/// Side effect: reads from file system
fn check_for_duplicates(input_files: &[PathBuf]) -> Result<(), ApplicationError> {
    // Group files by target directory
    let mut dirs_to_check = std::collections::HashSet::new();
    for file in input_files {
        let parent_dir = match file.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."), // Handle empty parent or None
        };
        dirs_to_check.insert(parent_dir);
    }
    
    // Check each directory for duplicates
    for dir in dirs_to_check {
        let files_in_dir: Vec<PathBuf> = input_files
            .iter()
            .filter(|f| f.parent() == Some(dir))
            .cloned()
            .collect();
        
        check_for_duplicate_content(&files_in_dir, dir)?;
    }
    
    Ok(())
}

/// Get encryption password from user
/// Side effect: user interaction via stdin/stdout
fn get_encryption_password(allow_weak_passwords: bool) -> Result<SecureString, ApplicationError> {
    match prompt_for_password(allow_weak_passwords) {
        Ok(password) => Ok(password),
        Err(e) => Err(ApplicationError::UserInput(e.to_string())),
    }
}

/// Application-level error type
#[derive(Debug, thiserror::Error)]
pub enum ApplicationError {
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),
    
    #[error("Not a file: {0}")]
    NotAFile(PathBuf),
    
    #[error("Shell error: {0}")]
    Shell(#[from] ShellError),
    
    #[error("File operation error: {0}")]
    FileOperation(#[from] EncryptionFileError),
    
    #[error("User input error: {0}")]
    UserInput(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

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
            ApplicationError::FileNotFound(path) if path == nonexistent
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
            ApplicationError::NotAFile(path) if path == dir_path
        ));
    }

    #[test]
    fn test_check_for_duplicates_no_duplicates() {
        let temp_dir = TempDir::new().unwrap();
        let test_file1 = temp_dir.path().join("test1.txt");
        let test_file2 = temp_dir.path().join("test2.txt");
        
        fs::write(&test_file1, b"unique content 1").unwrap();
        fs::write(&test_file2, b"unique content 2").unwrap();
        
        let result = check_for_duplicates(&[test_file1, test_file2]);
        assert!(result.is_ok());
    }
}