use std::io::{Read, Write};

use shadow_core::{
    memory::SecureBytes,
    v1::{
        file::{EncryptedFile, PlaintextFile},
        file_ops::get_encrypted_file_from_bytes,
    },
};

use crate::{
    decryption::file::{DecryptionInputFile, DecryptionOutputFile},
    errors::WorkflowResult,
};

pub fn read_n_bytes_from_file(path: &std::path::Path, n: usize) -> WorkflowResult<SecureBytes> {
    let f = std::fs::File::open(path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(n);
    f.take(n as u64).read_to_end(&mut buffer)?;

    Ok(SecureBytes::new(buffer))
}

pub fn store_plaintext_file(file: &PlaintextFile) -> WorkflowResult<DecryptionOutputFile> {
    let output_file = DecryptionOutputFile {
        path: std::env::current_dir()?.join(file.filename()),
        filename: file.filename().to_string(),
    };

    let mut f = std::fs::File::create(output_file.path.as_path())?;
    f.write_all(file.content().as_slice())?;

    Ok(output_file)
}

pub fn load_encrypted_file(file: &DecryptionInputFile) -> WorkflowResult<EncryptedFile> {
    let size: usize = file.size as usize;

    let mut f = std::fs::File::open(&file.path)?;
    let mut buffer: Vec<u8> = Vec::with_capacity(size);

    f.read_to_end(&mut buffer)?;

    let content = SecureBytes::new(buffer.clone());

    use zeroize::Zeroize;
    buffer.zeroize(); // Clear the temporary buffer

    Ok(get_encrypted_file_from_bytes(&content)?)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let content = SecureBytes::new(b"test content".to_vec());
        let plaintext = PlaintextFile::new("test.txt".to_string(), content);

        let output = store_plaintext_file(&plaintext).unwrap();
        assert_eq!(output.filename, "test.txt");

        let read_content = fs::read(&output.path).unwrap();
        assert_eq!(read_content, b"test content");

        // Clean up
        fs::remove_file(&output.path).unwrap();
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
