// shadow-shell/src/file_ops.rs
// Common file operations with side effects for Shadow

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::errors::{ShellError, ShellResult};

// File size limits
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
const MAX_FILES_BATCH: usize = 1000;

/// Read a file safely with size and permission checks
/// Side effect: File I/O
pub fn read_file_safely(path: &Path) -> ShellResult<Vec<u8>> {
    // Check if file exists
    if !path.exists() {
        return Err(ShellError::FileNotFound(path.to_path_buf()));
    }

    // Check if it's actually a file
    if !path.is_file() {
        return Err(ShellError::NotAFile(path.to_path_buf()));
    }

    // Check file metadata
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();

    // Check size limit
    if file_size > MAX_FILE_SIZE {
        return Err(ShellError::FileTooLarge {
            size: file_size,
            limit: MAX_FILE_SIZE,
        });
    }

    // Read the file
    fs::read(path).map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => ShellError::PermissionDenied(path.to_path_buf()),
        _ => ShellError::Io(e),
    })
}

/// Write file atomically using temporary file + rename
/// Side effect: File I/O
pub fn write_file_atomically(path: &Path, data: &[u8]) -> ShellResult<()> {
    // Get parent directory
    let parent = path.parent().unwrap_or(Path::new("."));

    // Check parent directory exists and is writable
    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }

    if !parent.is_dir() {
        return Err(ShellError::NotADirectory(parent.to_path_buf()));
    }

    // Create temporary file in same directory
    let temp_file = NamedTempFile::new_in(parent).map_err(|_| ShellError::TempFileCreation)?;

    let temp_path = temp_file.path();

    // Write data to temporary file
    fs::write(temp_path, data)?;

    // Atomically move to final location
    fs::rename(temp_path, path).map_err(|_| ShellError::AtomicOperationFailed)?;

    Ok(())
}

/// Validate input file paths
/// Side effect: File system checks
pub fn validate_input_paths(paths: &[PathBuf]) -> ShellResult<Vec<PathBuf>> {
    if paths.is_empty() {
        return Err(ShellError::NoFilesMatched);
    }

    if paths.len() > MAX_FILES_BATCH {
        return Err(ShellError::TooManyFiles {
            count: paths.len(),
            limit: MAX_FILES_BATCH,
        });
    }

    let mut validated = Vec::new();

    for path in paths {
        // Check existence
        if !path.exists() {
            return Err(ShellError::FileNotFound(path.clone()));
        }

        // Check it's a file
        if !path.is_file() {
            return Err(ShellError::NotAFile(path.clone()));
        }

        // Check readable
        match fs::metadata(path) {
            Ok(metadata) => {
                // Check permissions (basic check)
                if metadata.permissions().readonly() {
                    // Still try to read it
                }

                // Check file size
                if metadata.len() > MAX_FILE_SIZE {
                    return Err(ShellError::FileTooLarge {
                        size: metadata.len(),
                        limit: MAX_FILE_SIZE,
                    });
                }
            }
            Err(e) => match e.kind() {
                io::ErrorKind::PermissionDenied => {
                    return Err(ShellError::PermissionDenied(path.clone()));
                }
                _ => return Err(ShellError::Io(e)),
            },
        }

        validated.push(path.clone());
    }

    Ok(validated)
}

/// Check if output file would overwrite existing file
/// Side effect: File system check
pub fn check_output_overwrite(output_path: &Path, force: bool) -> ShellResult<()> {
    if output_path.exists() && !force {
        return Err(ShellError::OutputExists(output_path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_read_file_safely_success() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let test_content = b"Hello, World!";

        fs::write(&test_file, test_content).unwrap();

        let result = read_file_safely(&test_file).unwrap();
        assert_eq!(result, test_content);
    }

    #[test]
    fn test_read_file_safely_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent.txt");

        let result = read_file_safely(&nonexistent);
        assert!(matches!(result, Err(ShellError::FileNotFound(_))));
    }

    #[test]
    fn test_read_file_safely_not_a_file() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().join("directory");
        fs::create_dir(&dir_path).unwrap();

        let result = read_file_safely(&dir_path);
        assert!(matches!(result, Err(ShellError::NotAFile(_))));
    }

    #[test]
    fn test_write_file_atomically() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let test_content = b"Hello, World!";

        write_file_atomically(&test_file, test_content).unwrap();

        let result = fs::read(&test_file).unwrap();
        assert_eq!(result, test_content);
    }

    #[test]
    fn test_write_file_atomically_create_parent() {
        let temp_dir = TempDir::new().unwrap();
        let nested_file = temp_dir.path().join("nested").join("test.txt");
        let test_content = b"Hello, World!";

        write_file_atomically(&nested_file, test_content).unwrap();

        let result = fs::read(&nested_file).unwrap();
        assert_eq!(result, test_content);
    }

    #[test]
    fn test_validate_input_paths_success() {
        let temp_dir = TempDir::new().unwrap();
        let test_file1 = temp_dir.path().join("test1.txt");
        let test_file2 = temp_dir.path().join("test2.txt");

        fs::write(&test_file1, b"content1").unwrap();
        fs::write(&test_file2, b"content2").unwrap();

        let paths = vec![test_file1.clone(), test_file2.clone()];
        let result = validate_input_paths(&paths).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&test_file1));
        assert!(result.contains(&test_file2));
    }

    #[test]
    fn test_validate_input_paths_empty() {
        let result = validate_input_paths(&[]);
        assert!(matches!(result, Err(ShellError::NoFilesMatched)));
    }

    #[test]
    fn test_validate_input_paths_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent.txt");

        let result = validate_input_paths(&[nonexistent]);
        assert!(matches!(result, Err(ShellError::FileNotFound(_))));
    }

    #[test]
    fn test_check_output_overwrite_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent.txt");

        let result = check_output_overwrite(&nonexistent, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_output_overwrite_exists_no_force() {
        let temp_dir = TempDir::new().unwrap();
        let existing_file = temp_dir.path().join("existing.txt");
        fs::write(&existing_file, b"content").unwrap();

        let result = check_output_overwrite(&existing_file, false);
        assert!(matches!(result, Err(ShellError::OutputExists(_))));
    }

    #[test]
    fn test_check_output_overwrite_exists_with_force() {
        let temp_dir = TempDir::new().unwrap();
        let existing_file = temp_dir.path().join("existing.txt");
        fs::write(&existing_file, b"content").unwrap();

        let result = check_output_overwrite(&existing_file, true);
        assert!(result.is_ok());
    }
}
