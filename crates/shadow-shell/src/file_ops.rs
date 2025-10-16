// shadow-shell/src/file_ops.rs
// Common file operations with side effects for Shadow

use std::fs;
use std::path::{Path, PathBuf};
use std::io::{self, Read};
use tempfile::NamedTempFile;

use crate::errors::{ShellError, ShellResult};
use shadow_core::{
    FileHeader, deserialize_header, validate_header_bytes,
    hash_content, check_content_duplicate
};

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
    let temp_file = NamedTempFile::new_in(parent)
        .map_err(|_| ShellError::TempFileCreation)?;
    
    let temp_path = temp_file.path();
    
    // Write data to temporary file
    fs::write(temp_path, data)?;
    
    // Atomically move to final location
    fs::rename(temp_path, path)
        .map_err(|_| ShellError::AtomicOperationFailed)?;
    
    Ok(())
}

/// Scan directory for Shadow files and extract content hashes
/// Side effect: Directory traversal and file I/O
pub fn scan_shadow_files(dir: &Path) -> ShellResult<Vec<[u8; 32]>> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    
    if !dir.is_dir() {
        return Err(ShellError::NotADirectory(dir.to_path_buf()));
    }
    
    let mut hashes = Vec::new();
    
    // Read directory entries
    let entries = fs::read_dir(dir)?;
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        
        // Check if it's a Shadow file
        if let Some(extension) = path.extension() {
            if extension == "shadow" && path.is_file() {
                // Try to read header and extract content hash
                if let Ok(header) = read_shadow_file_header(&path) {
                    hashes.push(header.content_hash);
                }
            }
        }
    }
    
    Ok(hashes)
}

/// Read and parse Shadow file header
/// Side effect: File I/O
pub fn read_shadow_file_header(path: &Path) -> ShellResult<FileHeader> {
    // Read enough bytes for header (estimate max header size)
    let mut file = fs::File::open(path)?;
    let mut buffer = vec![0u8; 1024]; // Should be enough for any header
    
    // Read initial portion
    let bytes_read = file.read(&mut buffer)?;
    buffer.truncate(bytes_read);
    
    // Validate header bytes first
    validate_header_bytes(&buffer)?;
    
    // Deserialize header
    let header = deserialize_header(&buffer)?;
    
    Ok(header)
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
            }
        }
        
        validated.push(path.clone());
    }
    
    Ok(validated)
}

/// Check for duplicate content in target directory
/// Side effect: File I/O and directory scanning
pub fn check_for_duplicates(
    input_paths: &[PathBuf],
    force: bool,
) -> ShellResult<()> {
    if force {
        return Ok(());
    }
    
    for input_path in input_paths {
        // Read and hash the input file
        let content = read_file_safely(input_path)?;
        let content_hash = hash_content(&content);
        
        // Scan target directory for existing Shadow files
        let target_dir = input_path.parent().unwrap_or(Path::new("."));
        let existing_hashes = scan_shadow_files(target_dir)?;
        
        // Check for duplicates
        if check_content_duplicate(&content_hash, &existing_hashes) {
            return Err(ShellError::duplicate_content(
                input_path.clone(),
                &content_hash,
            ));
        }
    }
    
    Ok(())
}

/// Check if output file would overwrite existing file
/// Side effect: File system check
pub fn check_output_overwrite(
    output_path: &Path,
    force: bool,
) -> ShellResult<()> {
    if output_path.exists() && !force {
        return Err(ShellError::OutputExists(output_path.to_path_buf()));
    }
    Ok(())
}

/// Safely delete file (with error handling)
/// Side effect: File deletion
pub fn delete_file_safely(path: &Path) -> ShellResult<()> {
    if path.exists() {
        fs::remove_file(path).map_err(|e| match e.kind() {
            io::ErrorKind::PermissionDenied => ShellError::PermissionDenied(path.to_path_buf()),
            _ => ShellError::Io(e),
        })?;
    }
    Ok(())
}

/// Calculate available disk space (basic check)
/// Side effect: File system query
pub fn check_disk_space(path: &Path, _required_bytes: u64) -> ShellResult<()> {
    // Basic implementation - in production you'd use platform-specific APIs
    // For now, just do a simple check by trying to create a temp file
    let parent = path.parent().unwrap_or(Path::new("."));
    
    // Try to create a small temp file to test writability
    let _temp = NamedTempFile::new_in(parent)
        .map_err(|_| ShellError::InsufficientDiskSpace)?;
    
    // In a real implementation, you'd check actual available space
    // against required_bytes using platform-specific calls
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

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
    fn test_scan_shadow_files_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let result = scan_shadow_files(temp_dir.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_scan_shadow_files_nonexistent_dir() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent");
        let result = scan_shadow_files(&nonexistent).unwrap();
        assert!(result.is_empty());
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

    #[test]
    fn test_delete_file_safely_success() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"content").unwrap();
        
        assert!(test_file.exists());
        delete_file_safely(&test_file).unwrap();
        assert!(!test_file.exists());
    }

    #[test]
    fn test_delete_file_safely_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent.txt");
        
        let result = delete_file_safely(&nonexistent);
        assert!(result.is_ok()); // Should not error for nonexistent files
    }

    #[test]
    fn test_check_disk_space() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join("test.txt");
        
        let result = check_disk_space(&test_path, 1024);
        assert!(result.is_ok());
    }
}