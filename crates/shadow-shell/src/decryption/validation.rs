use std::path::PathBuf;

use shadow_core::{
    v1::header_ops::{get_version_from_bytes, is_shadow_file},
    version::is_supported_version,
};

use crate::{
    decryption::{
        cli::DecryptionCliArgs, file::DecryptionInputFile, file_ops::read_n_bytes_from_file,
    },
    errors::{WorkflowError, WorkflowResult},
};

#[derive(Debug)]
pub struct ValidDecryptionArgs {
    pub files: Vec<DecryptionInputFile>,
}

pub fn validate_input(input: DecryptionCliArgs) -> WorkflowResult<ValidDecryptionArgs> {
    ensure_not_empty(&input)?;

    let validated_files: Vec<DecryptionInputFile> = input
        .input_files
        .iter()
        .map(PathBuf::from)
        .map(ensure_exists)
        .map(ensure_is_regular_file)
        .map(ensure_is_encrypted_shadow_file)
        .map(ensure_version_supported)
        .map(create_input_file)
        .collect::<WorkflowResult<Vec<DecryptionInputFile>>>()?;

    Ok(ValidDecryptionArgs {
        files: validated_files,
    })
}

fn ensure_not_empty(input: &DecryptionCliArgs) -> WorkflowResult<()> {
    if input.input_files.is_empty() {
        return Err(WorkflowError::UserInput(
            "No input files provided".to_string(),
        ));
    }
    Ok(())
}

fn ensure_exists(path: PathBuf) -> WorkflowResult<PathBuf> {
    if !path.exists() {
        return Err(WorkflowError::UserInput(format!(
            "Input file does not exist: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn ensure_is_regular_file(path: WorkflowResult<PathBuf>) -> WorkflowResult<PathBuf> {
    if let Ok(path) = &path
        && !path.is_file()
    {
        return Err(WorkflowError::UserInput(format!(
            "Input path is not a file: {}",
            path.display()
        )));
    }
    path
}

fn ensure_is_encrypted_shadow_file(path: WorkflowResult<PathBuf>) -> WorkflowResult<PathBuf> {
    let path = path?;
    let first_bytes = read_n_bytes_from_file(&path, 10)?;
    if !is_shadow_file(first_bytes.as_slice())? {
        return Err(WorkflowError::UserInput(format!(
            "File is not a valid Shadow encrypted file: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn ensure_version_supported(path: WorkflowResult<PathBuf>) -> WorkflowResult<PathBuf> {
    let path = path?;
    let first_bytes = read_n_bytes_from_file(&path, 10)?;
    let version: u8 = get_version_from_bytes(first_bytes.as_slice()).map_err(|_| {
        WorkflowError::UserInput(format!(
            "Unable to read version from file: {}",
            path.display()
        ))
    })?;
    if !is_supported_version(version) {
        return Err(WorkflowError::UserInput(format!(
            "Unsupported Shadow file version in file: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn create_input_file(path: WorkflowResult<PathBuf>) -> WorkflowResult<DecryptionInputFile> {
    let path = path?;
    let name: String = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            WorkflowError::UserInput(format!("Invalid filename for path: {}", path.display()))
        })?
        .to_string();
    let size: u64 = path
        .metadata()
        .map_err(|_| {
            WorkflowError::UserInput(format!(
                "Unable to read metadata for file: {}",
                path.display()
            ))
        })?
        .len();

    Ok(DecryptionInputFile {
        path,
        filename: name,
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decryption::cli::DecryptionCliArgs;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_input_no_files() {
        let args = DecryptionCliArgs {
            input_files: vec![],
        };
        let result = validate_input(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_input_file_does_not_exist() {
        let args = DecryptionCliArgs {
            input_files: vec!["nonexistent.txt".to_string()],
        };
        let result = validate_input(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_input_path_is_directory() {
        let temp_dir = TempDir::new().unwrap();
        let args = DecryptionCliArgs {
            input_files: vec![temp_dir.path().to_str().unwrap().to_string()],
        };
        let result = validate_input(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_input_valid_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, b"test").unwrap();

        let args = DecryptionCliArgs {
            input_files: vec![file_path.to_str().unwrap().to_string()],
        };
        let result = validate_input(args);
        // This will fail because the file is not a shadow file, but that's tested elsewhere
        // We just want to ensure the validation pipeline works for valid file paths
        assert!(result.is_err()); // Expected to fail at shadow file check
    }

    #[test]
    fn test_validate_input_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = temp_dir.path().join("test1.txt");
        let file2 = temp_dir.path().join("test2.txt");
        fs::write(&file1, b"test1").unwrap();
        fs::write(&file2, b"test2").unwrap();

        let args = DecryptionCliArgs {
            input_files: vec![
                file1.to_str().unwrap().to_string(),
                file2.to_str().unwrap().to_string(),
            ],
        };
        let result = validate_input(args);
        assert!(result.is_err()); // Expected to fail at shadow file check
    }

    #[test]
    fn test_validate_input_valid_shadow_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.shadow");
        // Create a valid shadow file header: "SHADOW" + version 1 + some dummy data
        let mut header = b"SHADOW".to_vec();
        header.push(1); // version 1
        // Add minimal header data to make it valid (at least 10 bytes total)
        header.extend_from_slice(&[0u8; 4]); // dummy data
        fs::write(&file_path, header).unwrap();

        let args = DecryptionCliArgs {
            input_files: vec![file_path.to_str().unwrap().to_string()],
        };
        let result = validate_input(args);
        assert!(result.is_ok());
        let valid_args = result.unwrap();
        assert_eq!(valid_args.files.len(), 1);
        assert_eq!(valid_args.files[0].filename, "test.shadow");
        assert_eq!(valid_args.files[0].size, 11); // "SHADOW" (6) + version (1) + dummy (4)
    }

    #[test]
    fn test_validate_input_invalid_magic_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("invalid.txt");
        // Write invalid magic bytes
        fs::write(&file_path, b"INVALID").unwrap();

        let args = DecryptionCliArgs {
            input_files: vec![file_path.to_str().unwrap().to_string()],
        };
        let result = validate_input(args);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WorkflowError::UserInput(msg) => {
                assert!(msg.contains("not a valid Shadow encrypted file"))
            }
            _ => panic!("Expected UserInput error"),
        }
    }

    #[test]
    fn test_validate_input_unsupported_version() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("unsupported.shadow");
        // Create file with "SHADOW" but unsupported version (e.g., 99)
        let mut header = b"SHADOW".to_vec();
        header.push(99); // unsupported version
        fs::write(&file_path, header).unwrap();

        let args = DecryptionCliArgs {
            input_files: vec![file_path.to_str().unwrap().to_string()],
        };
        let result = validate_input(args);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WorkflowError::UserInput(msg) => {
                assert!(msg.contains("Unsupported Shadow file version"))
            }
            _ => panic!("Expected UserInput error"),
        }
    }

    #[test]
    fn test_validate_input_insufficient_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("short.txt");
        // Write only 5 bytes, less than needed for header validation
        fs::write(&file_path, b"SHORT").unwrap();

        let args = DecryptionCliArgs {
            input_files: vec![file_path.to_str().unwrap().to_string()],
        };
        let result = validate_input(args);
        assert!(result.is_err());
        // This should fail at the magic bytes check due to insufficient bytes
    }

    #[test]
    fn test_validate_input_directory_instead_of_file() {
        // Test with a directory path instead of a file
        let temp_dir = TempDir::new().unwrap();

        let args = DecryptionCliArgs {
            input_files: vec![temp_dir.path().to_str().unwrap().to_string()],
        };
        let result = validate_input(args);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            WorkflowError::UserInput(msg) => assert!(msg.contains("Input path is not a file")),
            _ => panic!("Expected UserInput error"),
        }
    }
}
