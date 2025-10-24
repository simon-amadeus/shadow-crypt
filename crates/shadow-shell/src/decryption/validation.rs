use std::path::PathBuf;

use shadow_core::{
    v1::header_ops::{get_version_from_bytes, is_shadow_file},
    version::is_supported_version,
};

use crate::{
    decryption::file_ops::read_n_bytes_from_file,
    encryption::{cli::CliArgs, file::InputFile},
    errors::{WorkflowError, WorkflowResult},
};

pub struct ValidDecryptionArgs {
    pub files: Vec<InputFile>,
}

pub fn validate_input(input: CliArgs) -> WorkflowResult<ValidDecryptionArgs> {
    ensure_not_empty(&input)?;

    let validated_files: Vec<InputFile> = input
        .input_files
        .iter()
        .map(PathBuf::from)
        .map(ensure_exists)
        .map(ensure_is_regular_file)
        .map(ensure_is_shadow_file)
        .map(ensure_version_supported)
        .map(create_input_file)
        .collect::<WorkflowResult<Vec<InputFile>>>()?;

    Ok(ValidDecryptionArgs {
        files: validated_files,
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

fn ensure_is_shadow_file(path: WorkflowResult<PathBuf>) -> WorkflowResult<PathBuf> {
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
