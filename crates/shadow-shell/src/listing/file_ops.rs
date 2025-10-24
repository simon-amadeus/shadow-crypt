use std::{fs, path::Path};

use shadow_core::v1::{header::FileHeader, header_ops};

use crate::{
    errors::{WorkflowError, WorkflowResult},
    listing::file::ShadowFile,
    shared_file_ops::read_n_bytes_from_file,
};

pub fn scan_directory_for_shadow_files(dir_path: &Path) -> WorkflowResult<Vec<ShadowFile>> {
    if !dir_path.is_dir() {
        return Err(WorkflowError::Listing(format!(
            "The path '{}' is not a directory.",
            dir_path.display()
        )));
    }

    let shadow_files: Vec<ShadowFile> = fs::read_dir(dir_path)?
        .filter_map(|entry| entry.ok()) // Skip entries we can't read
        .map(|entry| entry.path())
        .filter(|path| path.is_file()) // Only regular files
        .filter_map(|path| try_create_shadow_file(&path).ok())
        .collect();

    Ok(shadow_files)
}

fn try_create_shadow_file(path: &Path) -> WorkflowResult<ShadowFile> {
    let header_bytes = read_n_bytes_from_file(path, FileHeader::min_length())?;
    if header_ops::is_shadow_file(header_bytes.as_slice())
        .map_err(|_| WorkflowError::Listing("Invalid header format".to_string()))?
    {
        Ok(ShadowFile::new(path.to_path_buf()))
    } else {
        Err(WorkflowError::Listing("Not a shadow file".to_string()))
    }
}
