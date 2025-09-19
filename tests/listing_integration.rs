//! Integration tests for Phase 8 - File Listing
//! 
//! These tests verify the file listing functionality works correctly
//! with encrypted files from previous phases.

use crypto::listing::file_scanner::list_encrypted_files;
use crypto::listing::metadata_extractor::{format_file_size, format_header, format_separator, format_file_info};
use crypto::encryption::encrypt_file::encrypt_single_file;
use crypto::shared::errors::CryptoError;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

/// Create test files for listing tests
fn create_test_files(temp_dir: &Path) -> Result<(), CryptoError> {
    // Create some test files with different content
    let test_files = vec![
        ("document.txt", "This is a test document with some content."),
        ("data.json", r#"{"name": "test", "value": 42, "active": true}"#),
        ("readme.md", "# Test README\n\nThis is a markdown file for testing.\n"),
        ("unicode_文件.txt", "Unicode filename test with emoji 🔒"),
    ];
    
    for (filename, content) in test_files {
        let file_path = temp_dir.join(filename);
        let mut file = File::create(&file_path)?;
        file.write_all(content.as_bytes())?;
        
        // Encrypt the file
        let encrypted_path = temp_dir.join(format!("{}.enc", filename));
        encrypt_single_file(&file_path, &encrypted_path, "testpassword123", false)?;
        
        // Remove the original file
        fs::remove_file(&file_path)?;
    }
    
    Ok(())
}

#[test]
fn test_list_encrypted_files_basic() -> Result<(), CryptoError> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test files
    create_test_files(temp_path)?;
    
    // List encrypted files
    let files = list_encrypted_files(temp_path, "testpassword123")?;
    
    // Should find all encrypted files
    assert_eq!(files.len(), 4);
    
    // Check that original names are restored
    let names: Vec<&str> = files.iter().map(|f| f.original_name.as_str()).collect();
    assert!(names.contains(&"document.txt"));
    assert!(names.contains(&"data.json"));
    assert!(names.contains(&"readme.md"));
    assert!(names.contains(&"unicode_文件.txt"));
    
    // Check that files are sorted by name
    let sorted_names: Vec<&str> = files.iter().map(|f| f.original_name.as_str()).collect();
    let mut expected_names = names.clone();
    expected_names.sort();
    assert_eq!(sorted_names, expected_names);
    
    Ok(())
}

#[test]
fn test_list_encrypted_files_wrong_password() -> Result<(), CryptoError> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test files
    create_test_files(temp_path)?;
    
    // List with wrong password
    let files = list_encrypted_files(temp_path, "wrongpassword")?;
    
    // Should still find files but with encrypted names
    assert_eq!(files.len(), 4);
    
    // Names should be the encrypted filenames (not original names)
    for file_info in &files {
        assert!(file_info.original_name.ends_with(".enc"));
    }
    
    Ok(())
}

#[test]
fn test_list_encrypted_files_mixed_directory() -> Result<(), CryptoError> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test files
    create_test_files(temp_path)?;
    
    // Add some non-encrypted files
    let regular_file = temp_path.join("regular.txt");
    let mut file = File::create(&regular_file)?;
    file.write_all(b"This is a regular file")?;
    
    // List encrypted files
    let files = list_encrypted_files(temp_path, "testpassword123")?;
    
    // Should only find encrypted files (not the regular file)
    assert_eq!(files.len(), 4);
    
    // Regular file should not appear in results
    let names: Vec<&str> = files.iter().map(|f| f.original_name.as_str()).collect();
    assert!(!names.contains(&"regular.txt"));
    
    Ok(())
}

#[test]
fn test_list_empty_directory() -> Result<(), CryptoError> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // List files in empty directory
    let files = list_encrypted_files(temp_path, "testpassword123")?;
    
    // Should return empty list
    assert_eq!(files.len(), 0);
    
    Ok(())
}

#[test]
fn test_list_nonexistent_directory() {
    let nonexistent_path = Path::new("/nonexistent/directory");
    
    // Should return error for nonexistent directory
    let result = list_encrypted_files(nonexistent_path, "testpassword123");
    assert!(result.is_err());
}

#[test]
fn test_file_info_structure() -> Result<(), CryptoError> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create a single test file
    let content = "Test content for size checking";
    let file_path = temp_path.join("test.txt");
    let mut file = File::create(&file_path)?;
    file.write_all(content.as_bytes())?;
    
    let encrypted_path = temp_path.join("test.txt.enc");
    encrypt_single_file(&file_path, &encrypted_path, "testpassword123", false)?;
    fs::remove_file(&file_path)?;
    
    // List files
    let files = list_encrypted_files(temp_path, "testpassword123")?;
    assert_eq!(files.len(), 1);
    
    let file_info = &files[0];
    
    // Check FileInfo structure
    assert_eq!(file_info.original_name, "test.txt");
    assert_eq!(file_info.size, content.len() as u64);
    assert!(file_info.encrypted_size > file_info.size); // Should be larger due to encryption overhead
    assert!(file_info.encrypted_path.ends_with("test.txt.enc"));
    
    Ok(())
}

#[test]
fn test_format_file_size() {
    assert_eq!(format_file_size(0), "0 B");
    assert_eq!(format_file_size(512), "512 B");
    assert_eq!(format_file_size(1024), "1.0 KB");
    assert_eq!(format_file_size(1536), "1.5 KB");
    assert_eq!(format_file_size(1048576), "1.0 MB");
    assert_eq!(format_file_size(1073741824), "1.0 GB");
    assert_eq!(format_file_size(1099511627776), "1.0 TB");
}

#[test]
fn test_format_functions() {
    let header = format_header();
    assert!(header.contains("ORIGINAL NAME"));
    assert!(header.contains("SIZE"));
    assert!(header.contains("ENCRYPTED SIZE"));
    assert!(header.contains("MODIFIED"));
    
    let separator = format_separator();
    assert_eq!(separator.len(), 80);
    assert!(separator.chars().all(|c| c == '-'));
}

#[test]
fn test_format_file_info() -> Result<(), CryptoError> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test file
    let content = "Test content";
    let file_path = temp_path.join("test.txt");
    let mut file = File::create(&file_path)?;
    file.write_all(content.as_bytes())?;
    
    let encrypted_path = temp_path.join("test.txt.enc");
    encrypt_single_file(&file_path, &encrypted_path, "testpassword123", false)?;
    fs::remove_file(&file_path)?;
    
    // Get file info
    let files = list_encrypted_files(temp_path, "testpassword123")?;
    assert_eq!(files.len(), 1);
    
    let formatted = format_file_info(&files[0]);
    
    // Should contain the filename and size information
    assert!(formatted.contains("test.txt"));
    assert!(formatted.contains("12 B")); // Content size
    
    Ok(())
}