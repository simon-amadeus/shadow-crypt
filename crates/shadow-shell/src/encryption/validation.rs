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
    let mut files = Vec::new();

    if input.input_files.is_empty() {
        return Err(WorkflowError::UserInput(
            "No input files provided".to_string(),
        ));
    }

    for file_str in input.input_files {
        let path = PathBuf::from(file_str);
        if !path.exists() {
            return Err(WorkflowError::UserInput(format!(
                "Input file does not exist: {}",
                path.display()
            )));
        }
        if !path.is_file() {
            return Err(WorkflowError::UserInput(format!(
                "Input path is not a file: {}",
                path.display()
            )));
        }
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

        files.push(InputFile {
            path,
            filename: name,
            size,
        });
    }

    Ok(ValidEncryptionArgs {
        files,
        test_mode: input.test_mode,
    })
}
