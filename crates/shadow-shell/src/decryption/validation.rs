use std::path::PathBuf;

use shadow_core::v1::header_ops::is_shadow_file;

use crate::{
    decryption::file_ops::read_n_bytes_from_file,
    encryption::{cli::CliArgs, file::InputFile},
    errors::{WorkflowError, WorkflowResult},
};

pub struct ValidEncryptionArgs {
    pub files: Vec<InputFile>,
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

        let first_bytes = read_n_bytes_from_file(&path, 4)?;
        if !is_shadow_file(first_bytes.as_slice())? {
            return Err(WorkflowError::UserInput(format!(
                "File is not a valid Shadow encrypted file: {}",
                path.display()
            )));
        }

        files.push(InputFile {
            path,
            filename: name,
            size,
        });
    }

    Ok(ValidEncryptionArgs { files })
}
