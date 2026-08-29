use std::io::Read;

use shadow_crypt_core::memory::SecureBytes;

use crate::errors::WorkflowResult;

pub fn read_n_bytes_from_file(path: &std::path::Path, n: usize) -> WorkflowResult<SecureBytes> {
    let f = std::fs::File::open(path)?;
    let mut buffer = Vec::new();
    f.take(n as u64).read_to_end(&mut buffer)?;

    Ok(SecureBytes::new(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::WorkflowError;
    use std::io::Write;
    use tempfile::NamedTempFile;

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
