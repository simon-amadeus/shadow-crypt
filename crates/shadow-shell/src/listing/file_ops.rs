use std::{fs, path::Path};

use shadow_core::{
    v1::{
        header::FileHeader,
        header_ops::{self, get_length_from_bytes, get_version_from_bytes, try_deserialize},
    },
    version::Version,
};

use crate::{
    errors::{WorkflowError, WorkflowResult},
    listing::file::ShadowFile,
    utils::read_n_bytes_from_file,
};

pub fn scan_directory_for_shadow_files(dir_path: &Path) -> WorkflowResult<Vec<ShadowFile>> {
    if !dir_path.is_dir() {
        return Err(WorkflowError::Listing(format!(
            "The path '{}' is not a directory.",
            dir_path.display()
        )));
    }

    let files = fs::read_dir(dir_path)?
        .filter_map(|entry| entry.ok()) // Skip entries we can't read
        .map(|entry| entry.path())
        .filter(|path| path.is_file()) // Only regular files
        .collect::<Vec<_>>();

    let shadow_files: Vec<ShadowFile> = files
        .iter()
        .filter_map(|path| try_create_shadow_file(path).ok())
        .collect();

    Ok(shadow_files)
}

fn try_create_shadow_file(path: &Path) -> WorkflowResult<ShadowFile> {
    let header_bytes = read_n_bytes_from_file(path, FileHeader::min_length())?;

    if !header_ops::is_shadow_file(header_bytes.as_slice())? {
        println!("not a shadow file");
        return Err(WorkflowError::Listing(format!(
            "The file '{}' is not a valid Shadow file.",
            path.display()
        )));
    }
    let version_byte = get_version_from_bytes(header_bytes.as_slice())?;
    let version = Version::try_from(version_byte).map_err(|_| {
        WorkflowError::Listing(format!("Unsupported version in file '{}'.", path.display()))
    })?;
    let filename = path
        .file_name()
        .ok_or_else(|| {
            WorkflowError::Listing(format!(
                "Failed to get filename for file '{}'.",
                path.display()
            ))
        })?
        .to_string_lossy()
        .to_string();

    Ok(ShadowFile::new(
        path.to_path_buf(),
        filename,
        version,
        get_file_size(path)?,
    ))
}

fn get_file_size(path: &Path) -> WorkflowResult<u64> {
    let metadata = fs::metadata(path)?;
    Ok(metadata.len())
}

pub fn load_file_header(file: &ShadowFile) -> WorkflowResult<FileHeader> {
    let min_header_bytes = read_n_bytes_from_file(&file.path, FileHeader::min_length())?;
    let header_length = get_length_from_bytes(min_header_bytes.as_slice())? as usize;
    let full_header_bytes = read_n_bytes_from_file(&file.path, header_length)?;

    let header: FileHeader = try_deserialize(full_header_bytes.as_slice())?;
    Ok(header)
}
