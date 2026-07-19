use std::{fs, path::Path};

use shadow_crypt_core::{
    memory::SecureBytes,
    version::{Version, read_file_version},
};

use crate::{
    errors::{WorkflowError, WorkflowResult},
    listing::file::ShadowFile,
    utils::read_n_bytes_from_file,
};

/// Length of the magic + version preamble shared by all format versions.
const PREAMBLE_LENGTH: usize = 7;

/// Length of the fixed header fields (shared layout across v1 and v2),
/// including the header-length field needed to size the full header read.
const FIXED_HEADER_LENGTH: usize = 90;

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

/// Reads the complete raw header bytes of a shadow file. Deserialization
/// happens in the workflow, per format version.
pub fn load_file_header_bytes(file: &ShadowFile) -> WorkflowResult<SecureBytes> {
    let fixed_header_bytes = read_n_bytes_from_file(&file.path, FIXED_HEADER_LENGTH)?;
    let header_length = get_header_length(fixed_header_bytes.as_slice())? as usize;
    read_n_bytes_from_file(&file.path, header_length)
}

/// Reads the header-length field at its fixed offset (same in v1 and v2).
fn get_header_length(bytes: &[u8]) -> WorkflowResult<u32> {
    let length_bytes = bytes
        .get(7..11)
        .ok_or(shadow_crypt_core::errors::HeaderError::InsufficientBytes)?;
    Ok(u32::from_le_bytes(length_bytes.try_into().expect("4-byte slice")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadow_crypt_core::{
        profile::SecurityProfile,
        v1::{header::FileHeader, header_ops, key::KeyDerivationParams},
    };
    use std::fs;
    use tempfile::TempDir;

    fn create_test_header() -> FileHeader {
        let salt = [1u8; 16];
        let kdf_params = KeyDerivationParams::from(SecurityProfile::Test);
        let content_nonce = [2u8; 24];
        let filename_nonce = [3u8; 24];
        let filename_ciphertext = vec![4, 5, 6, 7, 8];

        FileHeader::new(
            salt,
            kdf_params,
            content_nonce,
            filename_nonce,
            filename_ciphertext,
        )
    }

    fn create_shadow_file(dir: &TempDir, filename: &str) -> std::path::PathBuf {
        let path = dir.path().join(filename);
        let header = create_test_header();
        let serialized = header_ops::serialize(&header);
        // Add some dummy content after header
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

        // Create some shadow files
        create_shadow_file(&temp_dir, "file1.shadow");
        create_shadow_file(&temp_dir, "file2.shadow");

        // Create some non-shadow files
        create_non_shadow_file(&temp_dir, "file3.txt");
        create_non_shadow_file(&temp_dir, "file4.dat");

        let result = scan_directory_for_shadow_files(temp_dir.path()).unwrap();

        // Should find exactly 2 shadow files
        assert_eq!(result.len(), 2);

        // Check filenames
        let filenames: std::collections::HashSet<_> =
            result.iter().map(|f| f.filename.as_str()).collect();
        assert!(filenames.contains("file1.shadow"));
        assert!(filenames.contains("file2.shadow"));
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
    fn test_load_file_header() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_shadow_file(&temp_dir, "test.shadow");
        let shadow_file = try_create_shadow_file(&path).unwrap();

        let header = load_file_header(&shadow_file).unwrap();

        // Check that it's the same as our test header
        assert_eq!(header.magic, *b"SHADOW");
        assert_eq!(header.version, 1);
        assert_eq!(header.salt, [1u8; 16]);
    }
}
