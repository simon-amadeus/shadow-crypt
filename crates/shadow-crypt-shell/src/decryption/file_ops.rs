use std::io::{Read, Write};

use shadow_crypt_core::v1::{
    file::{EncryptedFile, PlaintextFile},
    file_ops::get_encrypted_file_from_bytes,
};

use crate::{
    decryption::file::{DecryptionInputFile, DecryptionOutputFile},
    errors::{WorkflowError, WorkflowResult},
};

pub fn store_plaintext_file(
    file: &PlaintextFile,
    output_dir: &std::path::Path,
) -> WorkflowResult<DecryptionOutputFile> {
    let output_file = DecryptionOutputFile {
        path: output_dir.join(file.filename().as_str()),
        filename: file.filename().as_str().to_string(),
    };

    if output_file.path.exists() {
        return Err(WorkflowError::File(format!(
            "Output file '{}' already exists",
            output_file.filename
        )));
    }

    let mut f = std::fs::File::create(output_file.path.as_path())?;
    f.write_all(file.content().as_slice())?;

    Ok(output_file)
}

pub fn load_encrypted_file(file: &DecryptionInputFile) -> WorkflowResult<EncryptedFile> {
    let size: usize = file.size as usize;

    let mut f = std::fs::File::open(&file.path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(size);

    f.read_to_end(&mut buffer)?;

    Ok(get_encrypted_file_from_bytes(buffer.as_slice())?)
}

#[cfg(test)]
mod tests {
    use crate::utils::read_n_bytes_from_file;

    use super::*;
    use shadow_crypt_core::memory::{SecureBytes, SecureString};
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_n_bytes_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"hello world";
        temp_file.write_all(data).unwrap();
        temp_file.flush().unwrap();
        let path = temp_file.path();

        let result = read_n_bytes_from_file(path, 5).unwrap();
        assert_eq!(result.as_slice(), b"hello");
    }

    #[test]
    fn test_read_n_bytes_from_file_more_than_size() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"hi";
        temp_file.write_all(data).unwrap();
        temp_file.flush().unwrap();
        let path = temp_file.path();

        let result = read_n_bytes_from_file(path, 10).unwrap();
        assert_eq!(result.as_slice(), b"hi");
    }

    #[test]
    fn test_store_plaintext_file() {
        let filename = SecureString::new("test.txt".to_string());
        let content = SecureBytes::new(b"test content".to_vec());
        let plaintext = PlaintextFile::new(filename, content);

        let output = store_plaintext_file(&plaintext, &std::env::current_dir().unwrap()).unwrap();
        assert_eq!(output.filename, "test.txt");

        let read_content = fs::read(&output.path).unwrap();
        assert_eq!(read_content, b"test content");

        // Clean up
        fs::remove_file(&output.path).unwrap();
    }

    #[test]
    fn test_store_plaintext_file_no_overwrite() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let original_dir = std::env::current_dir().unwrap();

        std::env::set_current_dir(&temp_dir).unwrap();

        let filename = SecureString::new("test.txt".to_string());
        let content = SecureBytes::new(b"new content".to_vec());
        let plaintext = PlaintextFile::new(filename, content);

        // Create existing file
        let output_path = temp_dir.path().join("test.txt");
        let existing_content = b"existing content";
        std::fs::write(&output_path, existing_content).unwrap();

        let result = store_plaintext_file(&plaintext, temp_dir.path());
        assert!(result.is_err());
        if let Err(WorkflowError::File(msg)) = result {
            assert!(msg.contains("already exists"));
        } else {
            panic!("Expected File error");
        }

        // Check existing content unchanged
        let read_content = std::fs::read(&output_path).unwrap();
        assert_eq!(read_content, existing_content);

        std::env::set_current_dir(original_dir).unwrap();
    }

    #[test]
    fn test_load_encrypted_file_invalid_data() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"invalid encrypted data";
        temp_file.write_all(data).unwrap();
        temp_file.flush().unwrap();
        let path = temp_file.path();

        let input_file = DecryptionInputFile {
            path: path.to_path_buf(),
            filename: "test.shadow".to_string(),
            size: data.len() as u64,
        };

        let result = load_encrypted_file(&input_file);
        // Should error due to invalid data
        assert!(result.is_err());
    }
}
