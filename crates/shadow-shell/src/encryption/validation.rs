use std::path::PathBuf;

use crate::{
    encryption::{cli::CliArgs, file::InputFile},
    errors::{WorkflowError, WorkflowResult},
};

pub struct ValidEncryptionArgs {
    pub files: Vec<InputFile>,
    pub test_mode: bool,
}

pub fn validate_input(input: CliArgs) -> WorkflowResult<ValidEncryptionArgs> {
    ensure_not_empty(&input)?;

    let validated_files: Vec<InputFile> = input
        .input_files
        .iter()
        .map(PathBuf::from)
        .map(ensure_exists)
        .map(ensure_is_regular_file)
        .map(create_input_file)
        .collect::<WorkflowResult<Vec<InputFile>>>()?;

    Ok(ValidEncryptionArgs {
        files: validated_files,
        test_mode: input.test_mode,
    })
}

fn ensure_not_empty(input: &CliArgs) -> WorkflowResult<()> {
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
    if let Ok(path) = &path {
        if !path.is_file() {
            return Err(WorkflowError::UserInput(format!(
                "Input path is not a file: {}",
                path.display()
            )));
        }
    }
    path
}

fn create_input_file(path: WorkflowResult<PathBuf>) -> WorkflowResult<InputFile> {
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

    Ok(InputFile {
        path,
        filename: name,
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_validate_input_no_files() {
        let input = CliArgs {
            input_files: vec![],
            test_mode: false,
        };
        let result = validate_input(input);
        assert!(result.is_err());
        if let Err(WorkflowError::UserInput(msg)) = result {
            assert_eq!(msg, "No input files provided");
        } else {
            panic!("Expected UserInput error");
        }
    }

    #[test]
    fn test_validate_input_file_does_not_exist() {
        let input = CliArgs {
            input_files: vec!["nonexistent_file.txt".to_string()],
            test_mode: false,
        };
        let result = validate_input(input);
        assert!(result.is_err());
        if let Err(WorkflowError::UserInput(msg)) = result {
            assert!(msg.contains("Input file does not exist"));
        } else {
            panic!("Expected UserInput error");
        }
    }

    #[test]
    fn test_validate_input_path_is_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let input = CliArgs {
            input_files: vec![temp_dir.path().to_str().unwrap().to_string()],
            test_mode: false,
        };
        let result = validate_input(input);
        assert!(result.is_err());
        if let Err(WorkflowError::UserInput(msg)) = result {
            assert!(msg.contains("Input path is not a file"));
        } else {
            panic!("Expected UserInput error");
        }
    }

    #[test]
    fn test_validate_input_valid_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = b"Hello, world!";
        temp_file.write_all(content).unwrap();
        let file_path = temp_file.path().to_path_buf();

        let input = CliArgs {
            input_files: vec![file_path.to_str().unwrap().to_string()],
            test_mode: true,
        };
        let result = validate_input(input);
        assert!(result.is_ok());
        let valid_args = result.unwrap();
        assert_eq!(valid_args.files.len(), 1);
        assert_eq!(valid_args.test_mode, true);
        let file = &valid_args.files[0];
        assert_eq!(file.path, file_path);
        assert_eq!(
            file.filename,
            file_path.file_name().unwrap().to_str().unwrap()
        );
        assert_eq!(file.size, content.len() as u64);
    }

    #[test]
    fn test_validate_input_multiple_files() {
        let mut temp_file1 = NamedTempFile::new().unwrap();
        temp_file1.write_all(b"File 1").unwrap();
        let path1 = temp_file1.path().to_path_buf();

        let mut temp_file2 = NamedTempFile::new().unwrap();
        temp_file2.write_all(b"File 2 content").unwrap();
        let path2 = temp_file2.path().to_path_buf();

        let input = CliArgs {
            input_files: vec![
                path1.to_str().unwrap().to_string(),
                path2.to_str().unwrap().to_string(),
            ],
            test_mode: false,
        };
        let result = validate_input(input);
        assert!(result.is_ok());
        let valid_args = result.unwrap();
        assert_eq!(valid_args.files.len(), 2);
        assert_eq!(valid_args.test_mode, false);

        // Check first file
        let file1 = &valid_args.files[0];
        assert_eq!(file1.path, path1);
        assert_eq!(file1.filename, path1.file_name().unwrap().to_str().unwrap());
        assert_eq!(file1.size, 6); // "File 1".len()

        // Check second file
        let file2 = &valid_args.files[1];
        assert_eq!(file2.path, path2);
        assert_eq!(file2.filename, path2.file_name().unwrap().to_str().unwrap());
        assert_eq!(file2.size, 14); // "File 2 content".len()
    }
}
