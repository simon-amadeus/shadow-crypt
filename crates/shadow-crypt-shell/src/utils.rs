use std::io::Read;

use shadow_crypt_core::memory::SecureBytes;

use crate::errors::{WorkflowError, WorkflowResult};

pub fn read_n_bytes_from_file(path: &std::path::Path, n: usize) -> WorkflowResult<SecureBytes> {
    let f = std::fs::File::open(path)?;
    let mut buffer = Vec::new();
    f.take(n as u64).read_to_end(&mut buffer)?;

    Ok(SecureBytes::new(buffer))
}

/// Sanitizes a '/'-separated path from decrypted metadata into a relative
/// path that cannot escape the output directory: rejects `..` components and
/// backslashes, drops empty and `.` components (which also relativizes
/// absolute paths). The decrypted name is deliberately not echoed into
/// error messages.
pub fn sanitize_relative_path(name: &str) -> WorkflowResult<std::path::PathBuf> {
    if name.contains('\\') {
        return Err(WorkflowError::File(
            "Decrypted path contains unsupported separators".to_string(),
        ));
    }
    let mut out = std::path::PathBuf::new();
    for component in name.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                return Err(WorkflowError::File(
                    "Decrypted path contains unsafe components".to_string(),
                ));
            }
            component => out.push(component),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(WorkflowError::File(
            "Decrypted path contains no usable components".to_string(),
        ));
    }
    Ok(out)
}

/// Reads from `reader` until `buf` is full or EOF; returns the bytes read.
/// Unlike a bare `read` call this only returns short on EOF, which the
/// streaming loops rely on to spot the final chunk.
pub fn read_up_to(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Resolves the output directory for a workflow: the given path (created if
/// missing) or the current directory.
pub fn resolve_output_dir(
    output_dir: Option<std::path::PathBuf>,
) -> WorkflowResult<std::path::PathBuf> {
    match output_dir {
        Some(dir) => {
            std::fs::create_dir_all(&dir)?;
            Ok(dir)
        }
        None => Ok(std::env::current_dir()?),
    }
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

    #[test]
    fn test_sanitize_relative_path() {
        use std::path::PathBuf;

        assert_eq!(
            sanitize_relative_path("a/b/c.txt").unwrap(),
            PathBuf::from("a/b/c.txt")
        );
        assert_eq!(
            sanitize_relative_path("plain.txt").unwrap(),
            PathBuf::from("plain.txt")
        );
        // Absolute and dot components are relativized/dropped.
        assert_eq!(
            sanitize_relative_path("/abs/path").unwrap(),
            PathBuf::from("abs/path")
        );
        assert_eq!(
            sanitize_relative_path("./a//b/.").unwrap(),
            PathBuf::from("a/b")
        );
        // Escapes and unsupported separators are rejected outright.
        for evil in ["..", "../x", "a/../b", "a/..", "a\\b", "", ".", "//"] {
            assert!(sanitize_relative_path(evil).is_err(), "accepted {evil:?}");
        }
    }

    #[test]
    fn test_resolve_output_dir_creates_missing_directory() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let nested = temp_dir.path().join("a").join("b");

        let resolved = resolve_output_dir(Some(nested.clone())).unwrap();
        assert_eq!(resolved, nested);
        assert!(nested.is_dir());
    }

    #[test]
    fn test_resolve_output_dir_defaults_to_current_dir() {
        let resolved = resolve_output_dir(None).unwrap();
        assert_eq!(resolved, std::env::current_dir().unwrap());
    }
}
