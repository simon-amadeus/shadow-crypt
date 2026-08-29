use std::{fs, path::Path};

use shadow_crypt_core::{
    memory::SecureBytes,
    vault::MAX_HEADER_LEN,
    version::{PREAMBLE_LENGTH, read_file_version},
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
    let preamble = read_n_bytes_from_file(path, PREAMBLE_LENGTH)?;

    let version = read_file_version(preamble.as_slice()).map_err(|_| {
        WorkflowError::Listing(format!(
            "The file '{}' is not a supported Shadow file.",
            path.display()
        ))
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

/// Reads enough leading bytes of a shadow file to cover its complete header,
/// whatever its format version. Parsing happens in the workflow via
/// [`shadow_crypt_core::vault::ParsedFile`], which tolerates trailing
/// ciphertext bytes, so no version-specific length probing is needed here.
pub fn load_file_header_bytes(file: &ShadowFile) -> WorkflowResult<SecureBytes> {
    read_n_bytes_from_file(&file.path, MAX_HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_crypt_core::{profile::SecurityProfile, v1, v2, version::Version};
    use std::fs;
    use tempfile::TempDir;

    fn create_test_header_v1() -> v1::header::FileHeader {
        v1::header::FileHeader::new(
            [1u8; 16],
            v1::key::KeyDerivationParams::from(SecurityProfile::Test),
            [2u8; 24],
            [3u8; 24],
            vec![4, 5, 6, 7, 8],
        )
    }

    fn create_test_header_v2() -> v2::header::FileHeader {
        v2::header::FileHeader::new(
            [1u8; 16],
            v2::key::KeyDerivationParams::from(SecurityProfile::Test),
            [2u8; 24],
            [3u8; 24],
            vec![4, 5, 6, 7, 8],
        )
        .unwrap()
    }

    fn create_shadow_file(dir: &TempDir, filename: &str) -> std::path::PathBuf {
        let path = dir.path().join(filename);
        let serialized = create_test_header_v1().serialize();
        // Add some dummy content after header
        let mut content = serialized;
        content.extend_from_slice(b"dummy content");
        fs::write(&path, content).unwrap();
        path
    }

    fn create_shadow_file_v2(dir: &TempDir, filename: &str) -> std::path::PathBuf {
        let path = dir.path().join(filename);
        let serialized = create_test_header_v2().serialize();
        let mut content = serialized;
        content.extend_from_slice(b"dummy content");
        fs::write(&path, content).unwrap();
        path
    }

    fn create_non_shadow_file(dir: &TempDir, filename: &str) -> std::path::PathBuf {
        let path = dir.path().join(filename);
        fs::write(&path, b"not a shadow file").unwrap();
        path
    }

    #[test]
    fn test_scan_directory_for_shadow_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create shadow files of both versions
        create_shadow_file(&temp_dir, "file1.shadow");
        create_shadow_file(&temp_dir, "file2.shadow");
        create_shadow_file_v2(&temp_dir, "file5.shadow");

        // Create some non-shadow files
        create_non_shadow_file(&temp_dir, "file3.txt");
        create_non_shadow_file(&temp_dir, "file4.dat");

        let result = scan_directory_for_shadow_files(temp_dir.path()).unwrap();

        // Should find exactly 3 shadow files
        assert_eq!(result.len(), 3);

        // Check filenames
        let filenames: std::collections::HashSet<_> =
            result.iter().map(|f| f.filename.as_str()).collect();
        assert!(filenames.contains("file1.shadow"));
        assert!(filenames.contains("file2.shadow"));
        assert!(filenames.contains("file5.shadow"));
    }

    #[test]
    fn test_scan_directory_nonexistent() {
        let non_existent = std::path::Path::new("/non/existent/directory");
        let result = scan_directory_for_shadow_files(non_existent);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WorkflowError::Listing(_)));
    }

    #[test]
    fn test_try_create_shadow_file_valid() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_shadow_file(&temp_dir, "test.shadow");

        let result = try_create_shadow_file(&path).unwrap();

        assert_eq!(result.filename, "test.shadow");
        assert_eq!(result.version, Version::V1);
        assert_eq!(result.size, 90 + 5 + 13); // header min + filename + dummy content
    }

    #[test]
    fn test_try_create_shadow_file_valid_v2() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_shadow_file_v2(&temp_dir, "test.shadow");

        let result = try_create_shadow_file(&path).unwrap();

        assert_eq!(result.filename, "test.shadow");
        assert_eq!(result.version, Version::V2);
    }

    #[test]
    fn test_try_create_shadow_file_invalid_magic() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("invalid.shadow");
        fs::write(&path, b"NOTSHADOW").unwrap();

        let result = try_create_shadow_file(&path);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WorkflowError::Listing(_)));
    }

    #[test]
    fn test_try_create_shadow_file_insufficient_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("short.shadow");
        fs::write(&path, b"SHORT").unwrap();

        let result = try_create_shadow_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_file_size() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.txt");
        let content = b"Hello, world!";
        fs::write(&path, content).unwrap();

        let size = get_file_size(&path).unwrap();
        assert_eq!(size, content.len() as u64);
    }

    #[test]
    fn test_load_file_header_bytes_v1() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_shadow_file(&temp_dir, "test.shadow");
        let shadow_file = try_create_shadow_file(&path).unwrap();

        let header_bytes = load_file_header_bytes(&shadow_file).unwrap();
        let header = v1::header::FileHeader::try_deserialize(header_bytes.as_slice()).unwrap();

        assert_eq!(header.salt(), &[1u8; 16]);
    }

    #[test]
    fn test_load_file_header_bytes_v2() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_shadow_file_v2(&temp_dir, "test.shadow");
        let shadow_file = try_create_shadow_file(&path).unwrap();

        let header_bytes = load_file_header_bytes(&shadow_file).unwrap();
        let header = v2::header::FileHeader::try_deserialize(header_bytes.as_slice()).unwrap();

        assert_eq!(header.salt(), &[1u8; 16]);
    }
}
