use std::io::{Read, Write};

use shadow_crypt_core::memory::{SecureBytes, SecureString};

use crate::{
    decryption::file::{DecryptionInputFile, DecryptionOutputFile},
    errors::{WorkflowError, WorkflowResult},
};

pub fn store_plaintext_file(
    filename: &SecureString,
    content: &SecureBytes,
    output_dir: &std::path::Path,
    force: bool,
) -> WorkflowResult<DecryptionOutputFile> {
    // Reject any path traversal by taking only the bare filename component.
    // This prevents a malicious .shadow file from writing to an arbitrary path.
    let safe_name = std::path::Path::new(filename.as_str())
        .file_name()
        .ok_or_else(|| {
            WorkflowError::File("Decrypted filename contains invalid path components".to_string())
        })?;
    let safe_name_str = safe_name
        .to_str()
        .ok_or_else(|| WorkflowError::File("Decrypted filename is not valid UTF-8".to_string()))?
        .to_string();

    let output_file = DecryptionOutputFile {
        path: output_dir.join(safe_name),
        filename: safe_name_str,
    };

    // With --force, remove the existing file first (rather than truncating)
    // so a symlink at the target is never followed to clobber elsewhere.
    if force {
        match std::fs::remove_file(output_file.path.as_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }

    // create_new makes the no-overwrite check atomic: no window between an
    // exists() check and creation, and symlinks are never followed to clobber
    // an existing target.
    let mut f = std::fs::File::create_new(output_file.path.as_path()).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            WorkflowError::File(format!(
                "Output file '{}' already exists (use --force to overwrite)",
                output_file.filename
            ))
        } else {
            WorkflowError::Io(e)
        }
    })?;
    f.write_all(content.as_slice())?;

    Ok(output_file)
}

/// Reads the complete raw bytes of an encrypted input file. Parsing happens
/// in the workflow, per format version.
pub fn load_file_bytes(file: &DecryptionInputFile) -> WorkflowResult<Vec<u8>> {
    let size: usize = file.size as usize;

    let mut f = std::fs::File::open(&file.path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(size);

    f.read_to_end(&mut buffer)?;

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_store_plaintext_file() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let filename = SecureString::new("test.txt".to_string());
        let content = SecureBytes::new(b"test content".to_vec());

        let output = store_plaintext_file(&filename, &content, temp_dir.path(), false).unwrap();
        assert_eq!(output.filename, "test.txt");

        let read_content = fs::read(&output.path).unwrap();
        assert_eq!(read_content, b"test content");
    }

    #[test]
    fn test_store_plaintext_file_path_traversal_rejected() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        for malicious_name in &["../../etc/passwd", "../sibling", "/abs/path", ".."] {
            let filename = SecureString::new(malicious_name.to_string());
            let content = SecureBytes::new(b"evil".to_vec());
            let result = store_plaintext_file(&filename, &content, temp_dir.path(), false);

            match malicious_name {
                &".." => {
                    assert!(
                        result.is_err(),
                        "Expected error for filename '{malicious_name}'"
                    );
                }
                _ => {
                    // file_name() strips leading directories, so it succeeds
                    // but writes into temp_dir, not to the traversed path
                    if let Ok(output) = result {
                        assert!(
                            output.path.starts_with(temp_dir.path()),
                            "Output escaped temp_dir for '{malicious_name}'"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_store_plaintext_file_no_overwrite() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        let filename = SecureString::new("test.txt".to_string());
        let content = SecureBytes::new(b"new content".to_vec());

        // Create existing file
        let output_path = temp_dir.path().join("test.txt");
        let existing_content = b"existing content";
        std::fs::write(&output_path, existing_content).unwrap();

        let result = store_plaintext_file(&filename, &content, temp_dir.path(), false);
        assert!(result.is_err());
        if let Err(WorkflowError::File(msg)) = result {
            assert!(msg.contains("already exists"));
        } else {
            panic!("Expected File error");
        }

        // Check existing content unchanged
        let read_content = std::fs::read(&output_path).unwrap();
        assert_eq!(read_content, existing_content);
    }

    #[test]
    fn test_store_plaintext_file_force_overwrites() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        let filename = SecureString::new("test.txt".to_string());
        let content = SecureBytes::new(b"new content".to_vec());

        let output_path = temp_dir.path().join("test.txt");
        std::fs::write(&output_path, b"existing content").unwrap();

        let output = store_plaintext_file(&filename, &content, temp_dir.path(), true).unwrap();
        assert_eq!(std::fs::read(&output.path).unwrap(), b"new content");
    }

    #[test]
    fn test_store_plaintext_file_force_without_existing_file() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        let filename = SecureString::new("test.txt".to_string());
        let content = SecureBytes::new(b"content".to_vec());

        let output = store_plaintext_file(&filename, &content, temp_dir.path(), true).unwrap();
        assert_eq!(std::fs::read(&output.path).unwrap(), b"content");
    }

    #[test]
    fn test_load_file_bytes() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"raw file data";
        temp_file.write_all(data).unwrap();
        temp_file.flush().unwrap();

        let input_file = DecryptionInputFile {
            path: temp_file.path().to_path_buf(),
            filename: "test.shadow".to_string(),
            size: data.len() as u64,
        };

        let bytes = load_file_bytes(&input_file).unwrap();
        assert_eq!(bytes, data);
    }
}
