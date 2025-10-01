//! Secure file deletion utilities
//! 
//! Provides secure file deletion with overwriting capabilities to prevent
//! data recovery on supported filesystems.

use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use std::path::Path;
use std::fs;
use crate::shared::errors::CryptoError;

/// Securely delete a file by overwriting its contents before removal
/// 
/// This function attempts to prevent data recovery by:
/// 1. Overwriting the file with random data
/// 2. Synchronizing to ensure data is written to disk
/// 3. Removing the file from the filesystem
/// 
/// Note: Effectiveness depends on the underlying filesystem and storage medium.
/// SSDs and modern filesystems may not guarantee secure deletion due to
/// wear leveling and copy-on-write mechanisms.
pub fn secure_delete_file<P: AsRef<Path>>(file_path: P) -> Result<(), CryptoError> {
    let path = file_path.as_ref();
    
    // Ensure file exists before attempting deletion
    if !path.exists() {
        return Err(CryptoError::FileSystemError(
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("File does not exist: {}", path.display())
            )
        ));
    }
    
    // Get file size to determine how much to overwrite
    let metadata = fs::metadata(path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    let file_size = metadata.len();
    
    if file_size == 0 {
        // Empty file, just remove it directly
        fs::remove_file(path)
            .map_err(|e| CryptoError::FileSystemError(e))?;
        return Ok(());
    }
    
    // Open file for writing (preserving original size)
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    // Seek to beginning
    file.seek(SeekFrom::Start(0))
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    // Overwrite with random data
    overwrite_with_random_data(&mut file, file_size)?;
    
    // Ensure data is written to disk
    file.sync_all()
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    // Drop the file handle to close it
    drop(file);
    
    // Finally, remove the file from filesystem
    fs::remove_file(path)
        .map_err(|e| CryptoError::FileSystemError(e))?;
    
    Ok(())
}

/// Overwrite file contents with random data
fn overwrite_with_random_data(file: &mut File, size: u64) -> Result<(), CryptoError> {
    use getrandom::getrandom;
    
    const BUFFER_SIZE: usize = 8192; // 8KB buffer for efficiency
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut remaining = size;
    
    while remaining > 0 {
        let chunk_size = std::cmp::min(remaining, BUFFER_SIZE as u64) as usize;
        
        // Fill buffer with random data
        getrandom(&mut buffer[..chunk_size])
            .map_err(|e| CryptoError::CryptographicError(
                format!("Failed to generate random data for secure deletion: {}", e)
            ))?;
        
        // Write random data to file
        file.write_all(&buffer[..chunk_size])
            .map_err(|e| CryptoError::FileSystemError(e))?;
        
        remaining -= chunk_size as u64;
    }
    
    Ok(())
}

/// Prompt user for confirmation before destructive operations
/// 
/// Returns true if user confirms, false otherwise
pub fn confirm_destructive_operation(operation: &str, file_path: &Path) -> bool {
    use std::io::{self, Write};
    
    println!("⚠️  {} will permanently delete: {}", operation, file_path.display());
    print!("This operation cannot be undone. Continue? (y/N): ");
    if io::stdout().flush().is_err() {
        eprintln!("Warning: Failed to flush output");
    }
    
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            let response = input.trim().to_lowercase();
            response == "y" || response == "yes"
        }
        Err(_) => false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_secure_delete_existing_file() {
        // Create a temporary file with some content
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = b"This is test content that should be securely deleted";
        temp_file.write_all(test_content).unwrap();
        temp_file.flush().unwrap();
        
        let file_path = temp_file.path().to_path_buf();
        
        // Ensure file exists before deletion
        assert!(file_path.exists());
        
        // Perform secure deletion
        let result = secure_delete_file(&file_path);
        assert!(result.is_ok(), "Secure deletion should succeed");
        
        // Verify file no longer exists
        assert!(!file_path.exists(), "File should be deleted");
    }
    
    #[test]
    fn test_secure_delete_nonexistent_file() {
        let nonexistent_path = Path::new("/tmp/this_file_does_not_exist_12345");
        
        // Attempt to delete non-existent file
        let result = secure_delete_file(nonexistent_path);
        
        // Should return an error
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::FileSystemError(io_error) => {
                assert_eq!(io_error.kind(), std::io::ErrorKind::NotFound);
            }
            _ => panic!("Expected FileSystemError with NotFound kind"),
        }
    }
    
    #[test]
    fn test_secure_delete_empty_file() {
        // Create an empty temporary file
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_path_buf();
        
        // Ensure file exists and is empty
        assert!(file_path.exists());
        assert_eq!(fs::metadata(&file_path).unwrap().len(), 0);
        
        // Perform secure deletion
        let result = secure_delete_file(&file_path);
        assert!(result.is_ok(), "Secure deletion of empty file should succeed");
        
        // Verify file no longer exists
        assert!(!file_path.exists(), "Empty file should be deleted");
    }
}