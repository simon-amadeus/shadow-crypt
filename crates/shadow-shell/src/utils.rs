use std::io::Read;

use shadow_core::memory::{SecureBytes, SecureString};

use crate::errors::{WorkflowError, WorkflowResult};

pub fn read_n_bytes_from_file(path: &std::path::Path, n: usize) -> WorkflowResult<SecureBytes> {
    let f = std::fs::File::open(path)?;
    let mut buffer = Vec::new();
    f.take(n as u64).read_to_end(&mut buffer)?;

    Ok(SecureBytes::new(buffer))
}

pub fn parse_string_from_bytes(bytes: &SecureBytes) -> WorkflowResult<SecureString> {
    match String::from_utf8(bytes.as_slice().to_vec()) {
        Ok(s) => Ok(SecureString::new(s)),
        Err(_) => Err(WorkflowError::Parse(
            "Failed to decode string from bytes".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_string_from_bytes_valid() {
        let input_bytes = SecureBytes::new(b"test_filename.txt".to_vec());
        let result = parse_string_from_bytes(&input_bytes).unwrap();
        assert_eq!(result.as_str(), "test_filename.txt");
    }

    #[test]
    fn test_parse_string_from_bytes_invalid() {
        let input_bytes = SecureBytes::new(vec![0xff, 0xfe, 0xfd]);
        let result = parse_string_from_bytes(&input_bytes);
        assert!(result.is_err());
        if let Err(WorkflowError::Parse(msg)) = result {
            assert_eq!(msg, "Failed to decode string from bytes");
        } else {
            panic!("Expected Parse error");
        }
    }

    #[test]
    fn test_read_n_bytes_from_file_exact() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"hello world";
        temp_file.write_all(data).unwrap();
        let path = temp_file.path();

        let result = read_n_bytes_from_file(path, 11).unwrap();
        assert_eq!(result.as_slice(), data);
    }

    #[test]
    fn test_read_n_bytes_from_file_more_than_available() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"hello";
        temp_file.write_all(data).unwrap();
        let path = temp_file.path();

        let result = read_n_bytes_from_file(path, 10).unwrap();
        assert_eq!(result.as_slice(), data);
    }

    #[test]
    fn test_read_n_bytes_from_file_less_than_requested() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"hello world this is a test";
        temp_file.write_all(data).unwrap();
        let path = temp_file.path();

        let result = read_n_bytes_from_file(path, 5).unwrap();
        assert_eq!(result.as_slice(), b"hello");
    }

    #[test]
    fn test_read_n_bytes_from_file_zero() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let data = b"hello";
        temp_file.write_all(data).unwrap();
        let path = temp_file.path();

        let result = read_n_bytes_from_file(path, 0).unwrap();
        assert_eq!(result.as_slice(), b"");
    }

    #[test]
    fn test_read_n_bytes_from_file_nonexistent() {
        let path = std::path::Path::new("/nonexistent/file");
        let result = read_n_bytes_from_file(path, 10);
        assert!(result.is_err());
        // Should be Io error
        assert!(matches!(result, Err(WorkflowError::Io(_))));
    }
}
