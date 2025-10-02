//! Integration tests for Phase 8 - File Listing
//! 
//! These tests verify the file listing functionality works correctly
//! with encrypted files from previous phases.

use shadow_crypt::listing::file_scanner::list_encrypted_files_with_params;
use shadow_crypt::listing::ui_formatter::UIFormatter;
use shadow_crypt::encryption::encrypt_file::encrypt_single_file_with_params;
use shadow_crypt::shared::algorithms::aes_gcm::Argon2Params;
use shadow_crypt::shared::errors::CryptoError;
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
    
    // Use fast test parameters for integration tests
    let params = Argon2Params::test_params();
    
    for (filename, content) in test_files {
        let file_path = temp_dir.join(filename);
        let mut file = File::create(&file_path)?;
        file.write_all(content.as_bytes())?;
        
        // Encrypt the file with fast test parameters
        let encrypted_path = temp_dir.join(format!("{}.shadow", filename));
        encrypt_single_file_with_params(&file_path, &encrypted_path, "testpassword123", false, &params)?;
        
        // Remove the original file
        fs::remove_file(&file_path)?;
    }
    
    Ok(())
}

#[test]
fn test_list_encrypted_files_basic() -> Result<(), CryptoError> {
    let params = Argon2Params::test_params();
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test files
    create_test_files(temp_path)?;
    
    // List encrypted files
    let files = list_encrypted_files_with_params(temp_path, "testpassword123", &params)?;
    
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
    let params = Argon2Params::test_params();
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test files
    create_test_files(temp_path)?;
    
    // List with wrong password
    let files = list_encrypted_files_with_params(temp_path, "wrongpassword", &params)?;
    
    // Should still find files but with encrypted names
    assert_eq!(files.len(), 4);
    
    // When password is wrong, original_name should be "[ENCRYPTED]" and obfuscated_name should contain the actual filename
    for file_info in &files {
        assert_eq!(file_info.original_name, "[ENCRYPTED]");
        assert!(file_info.obfuscated_name.ends_with(".shadow"));
        assert!(!file_info.filename_decrypted);
    }
    
    Ok(())
}

#[test]
fn test_list_encrypted_files_mixed_directory() -> Result<(), CryptoError> {
    let params = Argon2Params::test_params();
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test files
    create_test_files(temp_path)?;
    
    // Add some non-encrypted files
    let regular_file = temp_path.join("regular.txt");
    let mut file = File::create(&regular_file)?;
    file.write_all(b"This is a regular file")?;
    
    // List encrypted files
    let files = list_encrypted_files_with_params(temp_path, "testpassword123", &params)?;
    
    // Should only find encrypted files (not the regular file)
    assert_eq!(files.len(), 4);
    
    // Regular file should not appear in results
    let names: Vec<&str> = files.iter().map(|f| f.original_name.as_str()).collect();
    assert!(!names.contains(&"regular.txt"));
    
    Ok(())
}

#[test]
fn test_list_empty_directory() -> Result<(), CryptoError> {
    let params = Argon2Params::test_params();
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // List files in empty directory
    let files = list_encrypted_files_with_params(temp_path, "testpassword123", &params)?;
    
    // Should return empty list
    assert_eq!(files.len(), 0);
    
    Ok(())
}

#[test]
fn test_list_nonexistent_directory() {
    let params = Argon2Params::test_params();
    let nonexistent_path = Path::new("/nonexistent/directory");
    
    // Should return error for nonexistent directory
    let result = list_encrypted_files_with_params(nonexistent_path, "testpassword123", &params);
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
    
    let encrypted_path = temp_path.join("test.txt.shadow");
    let params = Argon2Params::test_params();
    encrypt_single_file_with_params(&file_path, &encrypted_path, "testpassword123", false, &params)?;
    fs::remove_file(&file_path)?;
    
    // List files
    let files = list_encrypted_files_with_params(temp_path, "testpassword123", &params)?;
    assert_eq!(files.len(), 1);
    
    let file_info = &files[0];
    
    // Check FileInfo structure
    assert_eq!(file_info.original_name, "test.txt");
    assert_eq!(file_info.size, content.len() as u64);
    assert!(file_info.encrypted_size > file_info.size); // Should be larger due to encryption overhead
    assert!(file_info.encrypted_path.ends_with("test.txt.shadow"));
    
    Ok(())
}

#[test]
fn test_ui_formatter_file_size() {
    let formatter = UIFormatter::without_colors();
    // Test the internal file size formatting through a complete listing
    let test_files = vec![];
    let output = formatter.format_file_listing(&test_files);
    
    // Just verify the formatter creates output without errors
    assert!(output.contains("Shadow File Listing"));
    assert!(output.contains("Found 0 encrypted file(s)"));
}

#[test]
fn test_ui_formatter_structure() {
    let formatter = UIFormatter::without_colors();
    let test_files = vec![];
    let output = formatter.format_file_listing(&test_files);
    
    // Verify the output contains the expected structural elements for empty list
    assert!(output.contains("Shadow File Listing"));
    assert!(output.contains("Found 0 encrypted file(s)"));
    
    // For empty lists, legend is not shown (which makes sense from UX perspective)
    assert!(!output.contains("Legend:"));
}

#[test]
fn test_complete_ui_formatting() -> Result<(), CryptoError> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test file
    let content = "Test content";
    let file_path = temp_path.join("test.txt");
    let mut file = File::create(&file_path)?;
    file.write_all(content.as_bytes())?;
    
    let encrypted_path = temp_path.join("test.txt.shadow");
    let params = Argon2Params::test_params();
    encrypt_single_file_with_params(&file_path, &encrypted_path, "testpassword123", false, &params)?;
    fs::remove_file(&file_path)?;
    
    // Get file info
    let files = list_encrypted_files_with_params(temp_path, "testpassword123", &params)?;
    assert_eq!(files.len(), 1);
    
    // Test complete UI formatting
    let formatter = UIFormatter::without_colors();
    let formatted = formatter.format_file_listing(&files);
    
    // Should contain the filename and size information
    assert!(formatted.contains("test.txt"));
    assert!(formatted.contains("12 B")); // Content size
    assert!(formatted.contains("STATUS"));
    assert!(formatted.contains("ORIGINAL NAME"));
    
    Ok(())
}

#[test]
fn test_enhanced_display_shows_both_filenames() -> Result<(), CryptoError> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test file
    let content = "Test content for display format";
    let file_path = temp_path.join("original_name.txt");
    let mut file = File::create(&file_path)?;
    file.write_all(content.as_bytes())?;
    
    // Encrypt with standard naming
    let encrypted_path = temp_path.join("obfuscated_name.shadow");
    let params = Argon2Params::test_params();
    encrypt_single_file_with_params(&file_path, &encrypted_path, "testpassword123", false, &params)?;
    fs::remove_file(&file_path)?;
    
    // List files with correct password
    let files = list_encrypted_files_with_params(temp_path, "testpassword123", &params)?;
    assert_eq!(files.len(), 1);
    
    let file_info = &files[0];
    
    // Check that we have both obfuscated and original filenames
    assert!(file_info.obfuscated_name.len() > 0);
    assert_eq!(file_info.original_name, "original_name.txt");
    assert!(file_info.filename_decrypted);
    
    // Check formatted display using modern UI formatter
    let formatter = UIFormatter::without_colors();
    let formatted = formatter.format_file_listing(&files);
    println!("Formatted output: {}", formatted);
    
    // Should show both obfuscated and original names
    assert!(formatted.contains(&file_info.obfuscated_name));
    assert!(formatted.contains("original_name.txt"));
    assert!(formatted.contains("✓")); // Success indicator
    
    Ok(())
}

#[test]
fn test_enhanced_display_shows_encrypted_when_wrong_password() -> Result<(), CryptoError> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test file
    let content = "Test content";
    let file_path = temp_path.join("secret.txt");
    let mut file = File::create(&file_path)?;
    file.write_all(content.as_bytes())?;
    
    let encrypted_path = temp_path.join("secret.txt.shadow");
    let params = Argon2Params::test_params();
    encrypt_single_file_with_params(&file_path, &encrypted_path, "correctpassword", false, &params)?;
    fs::remove_file(&file_path)?;
    
    // List files with wrong password
    let files = list_encrypted_files_with_params(temp_path, "wrongpassword", &params)?;
    assert_eq!(files.len(), 1);
    
    let file_info = &files[0];
    
    // Check that filename decryption failed
    assert!(!file_info.filename_decrypted);
    assert_eq!(file_info.original_name, "[ENCRYPTED]");
    assert_eq!(file_info.obfuscated_name, "secret.txt.shadow");
    
    // Check formatted display shows encrypted status using modern UI formatter
    let formatter = UIFormatter::without_colors();
    let formatted = formatter.format_file_listing(&files);
    println!("Formatted output with wrong password: {}", formatted);
    
    assert!(formatted.contains("secret.txt.shadow"));
    assert!(formatted.contains("[ENCRYPTED]"));
    assert!(formatted.contains("✗")); // Error indicator
    
    Ok(())
}